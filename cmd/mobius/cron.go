package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	kitlog "github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/hashicorp/go-multierror"
	"github.com/notawar/mobius/server"
	"github.com/notawar/mobius/server/config"
	"github.com/notawar/mobius/server/contexts/ctxerr"
	"github.com/notawar/mobius/server/contexts/license"
	"github.com/notawar/mobius/server/datastore/mysql"
	"github.com/notawar/mobius/server/mdm"
	apple_mdm "github.com/notawar/mobius/server/mdm/apple"
	"github.com/notawar/mobius/server/mdm/apple/vpp"
	"github.com/notawar/mobius/server/mdm/assets"
	maintained_apps "github.com/notawar/mobius/server/mdm/maintainedapps"
	"github.com/notawar/mobius/server/mdm/nanodep/godep"
	"github.com/notawar/mobius/server/mobius"
	"github.com/notawar/mobius/server/policies"
	"github.com/notawar/mobius/server/ptr"
	"github.com/notawar/mobius/server/service"
	"github.com/notawar/mobius/server/service/externalsvc"
	"github.com/notawar/mobius/server/service/schedule"
	"github.com/notawar/mobius/server/vulnerabilities/customcve"
	"github.com/notawar/mobius/server/vulnerabilities/goval_dictionary"
	"github.com/notawar/mobius/server/vulnerabilities/macoffice"
	"github.com/notawar/mobius/server/vulnerabilities/msrc"
	"github.com/notawar/mobius/server/vulnerabilities/nvd"
	"github.com/notawar/mobius/server/vulnerabilities/oval"
	"github.com/notawar/mobius/server/vulnerabilities/utils"
	"github.com/notawar/mobius/server/webhooks"
	"github.com/notawar/mobius/server/worker"
)

func errHandler(ctx context.Context, logger kitlog.Logger, msg string, err error) {
	level.Error(logger).Log("msg", msg, "err", err)
	ctxerr.Handle(ctx, err)
}

func newVulnerabilitiesSchedule(
	ctx context.Context,
	instanceID string,
	ds mobius.Datastore,
	logger kitlog.Logger,
	config *config.VulnerabilitiesConfig,
) (*schedule.Schedule, error) {
	const name = string(mobius.CronVulnerabilities)
	interval := config.Periodicity
	vulnerabilitiesLogger := kitlog.With(logger, "cron", name)

	var options []schedule.Option

	options = append(options, schedule.WithLogger(vulnerabilitiesLogger))

	vulnFuncs := getVulnFuncs(ctx, ds, vulnerabilitiesLogger, config)
	for _, fn := range vulnFuncs {
		options = append(options, schedule.WithJob(fn.Name, fn.VulnFunc))
	}

	s := schedule.New(ctx, name, instanceID, interval, ds, ds, options...)

	return s, nil
}

func cronVulnerabilities(
	ctx context.Context,
	ds mobius.Datastore,
	logger kitlog.Logger,
	config *config.VulnerabilitiesConfig,
) error {
	if config == nil {
		return errors.New("nil configuration")
	}

	level.Info(logger).Log("periodicity", config.Periodicity)

	appConfig, err := ds.AppConfig(ctx)
	if err != nil {
		return fmt.Errorf("reading app config: %w", err)
	}

	if !appConfig.Features.EnableSoftwareInventory {
		level.Info(logger).Log("msg", "software inventory not configured")
		return nil
	}

	vulnPath := configureVulnPath(*config, appConfig, logger)
	if vulnPath != "" {
		level.Info(logger).Log("msg", "scanning vulnerabilities")
		if err := scanVulnerabilities(ctx, ds, logger, config, appConfig, vulnPath); err != nil {
			return fmt.Errorf("scanning vulnerabilities: %w", err)
		}

		if err := updateVulnHostCounts(ctx, ds, logger, config.MaxConcurrency); err != nil {
			return err
		}

	}

	return nil
}

func updateVulnHostCounts(ctx context.Context, ds mobius.Datastore, logger kitlog.Logger, maxConcurrency int) error {
	// Prevent invalid values for max concurrency
	if maxConcurrency <= 0 {
		level.Info(logger).Log("msg", "invalid maxConcurrency value provided, setting value to 1", "providedValue", maxConcurrency)
		maxConcurrency = 1
	}

	start := time.Now()
	level.Info(logger).Log("msg", "updating vulnerability host counts")

	if err := ds.UpdateVulnerabilityHostCounts(ctx, maxConcurrency); err != nil {
		return fmt.Errorf("updating vulnerability host counts: %w", err)
	}
	level.Info(logger).Log("msg", "vulnerability host counts updated", "took", time.Since(start).Seconds())

	return nil
}

func scanVulnerabilities(
	ctx context.Context,
	ds mobius.Datastore,
	logger kitlog.Logger,
	config *config.VulnerabilitiesConfig,
	appConfig *mobius.AppConfig,
	vulnPath string,
) error {
	level.Debug(logger).Log("msg", "creating vulnerabilities databases path", "databases_path", vulnPath)
	err := os.MkdirAll(vulnPath, 0o755)
	if err != nil {
		return fmt.Errorf("create vulnerabilities databases directory: %w", err)
	}

	var vulnAutomationEnabled string

	// only one vuln automation (i.e. webhook or integration) can be enabled at a
	// time, enforced when updating the appconfig.
	if appConfig.WebhookSettings.VulnerabilitiesWebhook.Enable {
		vulnAutomationEnabled = "webhook"
	}

	// check for jira integrations
	for _, j := range appConfig.Integrations.Jira {
		if j.EnableSoftwareVulnerabilities {
			if vulnAutomationEnabled != "" {
				err := ctxerr.New(ctx, "jira check")
				errHandler(ctx, logger, "more than one automation enabled", err)
			}
			vulnAutomationEnabled = "jira"
			break
		}
	}

	// check for Zendesk integrations
	for _, z := range appConfig.Integrations.Zendesk {
		if z.EnableSoftwareVulnerabilities {
			if vulnAutomationEnabled != "" {
				err := ctxerr.New(ctx, "zendesk check")
				errHandler(ctx, logger, "more than one automation enabled", err)
			}
			vulnAutomationEnabled = "zendesk"
			break
		}
	}

	level.Debug(logger).Log("vulnAutomationEnabled", vulnAutomationEnabled)

	nvdVulns := checkNVDVulnerabilities(ctx, ds, logger, vulnPath, config, vulnAutomationEnabled != "")
	ovalVulns := checkOvalVulnerabilities(ctx, ds, logger, vulnPath, config, vulnAutomationEnabled != "")
	govalDictVulns := checkGovalDictionaryVulnerabilities(ctx, ds, logger, vulnPath, config, vulnAutomationEnabled != "")
	macOfficeVulns := checkMacOfficeVulnerabilities(ctx, ds, logger, vulnPath, config, vulnAutomationEnabled != "")
	customVulns := checkCustomVulnerabilities(ctx, ds, logger, config, vulnAutomationEnabled != "")

	checkWinVulnerabilities(ctx, ds, logger, vulnPath, config, vulnAutomationEnabled != "")

	// If no automations enabled, then there is nothing else to do...
	if vulnAutomationEnabled == "" {
		return nil
	}

	vulns := make([]mobius.SoftwareVulnerability, 0, len(nvdVulns)+len(ovalVulns)+len(macOfficeVulns))
	vulns = append(vulns, nvdVulns...)
	vulns = append(vulns, ovalVulns...)
	vulns = append(vulns, macOfficeVulns...)
	vulns = append(vulns, govalDictVulns...)
	vulns = append(vulns, customVulns...)

	meta, err := ds.ListCVEs(ctx, config.RecentVulnerabilityMaxAge)
	if err != nil {
		errHandler(ctx, logger, "could not fetch CVE meta", err)
		return nil
	}

	recentV, matchingMeta := utils.RecentVulns(vulns, meta)

	if len(recentV) > 0 {
		switch vulnAutomationEnabled {
		case "webhook":
			args := webhooks.VulnArgs{
				Vulnerablities: recentV,
				Meta:           matchingMeta,
				AppConfig:      appConfig,
				Time:           time.Now(),
			}
			mapper := webhooks.NewMapper()
			// Enterprise webhook features removed
			/*
				if license.IsPremium(ctx) {
					mapper = eewebhooks.NewMapper()
				}
			*/
			// send recent vulnerabilities via webhook
			if err := webhooks.TriggerVulnerabilitiesWebhook(
				ctx,
				ds,
				kitlog.With(logger, "webhook", "vulnerabilities"),
				args,
				mapper,
			); err != nil {
				errHandler(ctx, logger, "triggering vulnerabilities webhook", err)
			}

		case "jira":
			// queue job to create jira issues
			if err := worker.QueueJiraVulnJobs(
				ctx,
				ds,
				kitlog.With(logger, "jira", "vulnerabilities"),
				recentV,
				matchingMeta,
			); err != nil {
				errHandler(ctx, logger, "queueing vulnerabilities to jira", err)
			}

		case "zendesk":
			// queue job to create zendesk ticket
			if err := worker.QueueZendeskVulnJobs(
				ctx,
				ds,
				kitlog.With(logger, "zendesk", "vulnerabilities"),
				recentV,
				matchingMeta,
			); err != nil {
				errHandler(ctx, logger, "queueing vulnerabilities to Zendesk", err)
			}

		default:
			err = ctxerr.New(ctx, "no vuln automations enabled")
			errHandler(ctx, logger, "attempting to process vuln automations", err)
		}
	}

	return nil
}

func checkCustomVulnerabilities(
	ctx context.Context,
	ds mobius.Datastore,
	logger kitlog.Logger,
	config *config.VulnerabilitiesConfig,
	collectVulns bool,
) []mobius.SoftwareVulnerability {
	vulns, err := customcve.CheckCustomVulnerabilities(ctx, ds, logger, config.Periodicity)
	if err != nil {
		errHandler(ctx, logger, "checking custom vulnerabilities", err)
	}

	level.Debug(logger).Log("msg", "custom-vulnerabilities-analysis-done", "found new", len(vulns))

	if !collectVulns {
		return nil
	}

	return vulns
}

func checkWinVulnerabilities(
	ctx context.Context,
	ds mobius.Datastore,
	logger kitlog.Logger,
	vulnPath string,
	config *config.VulnerabilitiesConfig,
	collectVulns bool,
) []mobius.OSVulnerability {
	var results []mobius.OSVulnerability

	// Get OS
	os, err := ds.ListOperatingSystems(ctx)
	if err != nil {
		errHandler(ctx, logger, "fetching list of operating systems", err)
		return nil
	}

	if !config.DisableDataSync {
		// Sync MSRC definitions
		err = msrc.SyncFromGithub(ctx, vulnPath, os)
		if err != nil {
			errHandler(ctx, logger, "updating msrc definitions", err)
		}
	}

	// Analyze all Win OS using the synched MSRC artifact.
	if !config.DisableWinOSVulnerabilities {
		for _, o := range os {
			if !o.IsWindows() {
				continue
			}

			start := time.Now()
			r, err := msrc.Analyze(ctx, ds, o, vulnPath, collectVulns, logger)
			elapsed := time.Since(start)
			level.Debug(logger).Log(
				"msg", "msrc-analysis-done",
				"os name", o.Name,
				"os version", o.Version,
				"display version", o.DisplayVersion,
				"elapsed", elapsed,
				"found new", len(r))
			results = append(results, r...)
			if err != nil {
				errHandler(ctx, kitlog.With(logger, "os name", o.Name, "display version", o.DisplayVersion), "analyzing hosts for Windows vulnerabilities", err)
			}
		}
	}

	return results
}

func checkOvalVulnerabilities(
	ctx context.Context,
	ds mobius.Datastore,
	logger kitlog.Logger,
	vulnPath string,
	config *config.VulnerabilitiesConfig,
	collectVulns bool,
) []mobius.SoftwareVulnerability {
	var results []mobius.SoftwareVulnerability

	// Get Platforms
	versions, err := ds.OSVersions(ctx, nil, nil, nil, nil)
	if err != nil {
		errHandler(ctx, logger, "updating oval definitions", err)
		return nil
	}

	if !config.DisableDataSync {
		// Sync on disk OVAL definitions with current OS Versions.
		downloaded, err := oval.Refresh(ctx, versions, vulnPath)
		if err != nil {
			errHandler(ctx, logger, "updating oval definitions", err)
		}
		for _, d := range downloaded {
			level.Debug(logger).Log("oval-sync-downloaded", d)
		}
	}

	// Analyze all supported os versions using the synched OVAL definitions.
	for _, version := range versions.OSVersions {
		start := time.Now()
		r, err := oval.Analyze(ctx, ds, version, vulnPath, collectVulns)
		if err != nil && errors.Is(err, oval.ErrUnsupportedPlatform) {
			level.Debug(logger).Log("msg", "oval-analysis-unsupported", "platform", version.Name)
			continue
		}

		elapsed := time.Since(start)
		level.Debug(logger).Log(
			"msg", "oval-analysis-done",
			"platform", version.Name,
			"elapsed", elapsed,
			"found new", len(r))
		results = append(results, r...)
		if err != nil {
			errHandler(ctx, logger, "analyzing oval definitions", err)
		}
	}

	return results
}

func checkGovalDictionaryVulnerabilities(
	ctx context.Context,
	ds mobius.Datastore,
	logger kitlog.Logger,
	vulnPath string,
	config *config.VulnerabilitiesConfig,
	collectVulns bool,
) []mobius.SoftwareVulnerability {
	var results []mobius.SoftwareVulnerability

	// Get Platforms
	versions, err := ds.OSVersions(ctx, nil, nil, nil, nil)
	if err != nil {
		errHandler(ctx, logger, "listing platforms for goval_dictionary pulls", err)
		return nil
	}

	if !config.DisableDataSync {
		// Sync on disk goval_dictionary sqlite with current OS Versions.
		downloaded, err := goval_dictionary.Refresh(versions, vulnPath, logger)
		if err != nil {
			errHandler(ctx, logger, "updating goval_dictionary databases", err)
		}
		for _, d := range downloaded {
			level.Debug(logger).Log("goval_dictionary-sync-downloaded", d)
		}
	}

	// Analyze all supported os versions using the synced goval_dictionary definitions.
	for _, version := range versions.OSVersions {
		start := time.Now()
		r, err := goval_dictionary.Analyze(ctx, ds, version, vulnPath, collectVulns, logger)
		if err != nil && errors.Is(err, goval_dictionary.ErrUnsupportedPlatform) {
			level.Debug(logger).Log("msg", "goval_dictionary-analysis-unsupported", "platform", version.Name)
			continue
		}
		elapsed := time.Since(start)
		level.Debug(logger).Log(
			"msg", "goval_dictionary-analysis-done",
			"platform", version.Name,
			"elapsed", elapsed,
			"found new", len(r))
		results = append(results, r...)
		if err != nil {
			errHandler(ctx, logger, "analyzing goval_dictionary definitions", err)
		}
	}

	return results
}

func checkNVDVulnerabilities(
	ctx context.Context,
	ds mobius.Datastore,
	logger kitlog.Logger,
	vulnPath string,
	config *config.VulnerabilitiesConfig,
	collectVulns bool,
) []mobius.SoftwareVulnerability {
	if !config.DisableDataSync {
		opts := nvd.SyncOptions{
			VulnPath:           config.DatabasesPath,
			CPEDBURL:           config.CPEDatabaseURL,
			CPETranslationsURL: config.CPETranslationsURL,
			CVEFeedPrefixURL:   config.CVEFeedPrefixURL,
		}
		err := nvd.Sync(opts, logger)
		if err != nil {
			errHandler(ctx, logger, "syncing vulnerability database", err)
			// don't return, continue on ...
		}
	}

	if err := nvd.LoadCVEMeta(ctx, logger, vulnPath, ds); err != nil {
		errHandler(ctx, logger, "load cve meta", err)
		// don't return, continue on ...
	}

	err := nvd.TranslateSoftwareToCPE(ctx, ds, vulnPath, logger)
	if err != nil {
		errHandler(ctx, logger, "analyzing vulnerable software: Software->CPE", err)
		return nil
	}

	vulns, err := nvd.TranslateCPEToCVE(ctx, ds, vulnPath, logger, collectVulns, config.Periodicity)
	if err != nil {
		errHandler(ctx, logger, "analyzing vulnerable software: CPE->CVE", err)
		return nil
	}

	return vulns
}

func checkMacOfficeVulnerabilities(
	ctx context.Context,
	ds mobius.Datastore,
	logger kitlog.Logger,
	vulnPath string,
	config *config.VulnerabilitiesConfig,
	collectVulns bool,
) []mobius.SoftwareVulnerability {
	if !config.DisableDataSync {
		err := macoffice.SyncFromGithub(ctx, vulnPath)
		if err != nil {
			errHandler(ctx, logger, "updating mac office release notes", err)
		}

		level.Debug(logger).Log("msg", "finished sync mac office release notes")
	}

	start := time.Now()
	r, err := macoffice.Analyze(ctx, ds, vulnPath, collectVulns)
	elapsed := time.Since(start)

	level.Debug(logger).Log(
		"msg", "mac-office-analysis-done",
		"elapsed", elapsed,
		"found new", len(r))

	if err != nil {
		errHandler(ctx, logger, "analyzing mac office products for vulnerabilities", err)
	}

	return r
}

func newAutomationsSchedule(
	ctx context.Context,
	instanceID string,
	ds mobius.Datastore,
	logger kitlog.Logger,
	intervalReload time.Duration,
	failingPoliciesSet mobius.FailingPolicySet,
) (*schedule.Schedule, error) {
	const (
		name            = string(mobius.CronAutomations)
		defaultInterval = 24 * time.Hour
	)
	appConfig, err := ds.AppConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting app config: %w", err)
	}
	s := schedule.New(
		// TODO(sarah): Reconfigure settings so automations interval doesn't reside under webhook settings
		ctx, name, instanceID, appConfig.WebhookSettings.Interval.ValueOr(defaultInterval), ds, ds,
		schedule.WithLogger(kitlog.With(logger, "cron", name)),
		schedule.WithConfigReloadInterval(intervalReload, func(ctx context.Context) (time.Duration, error) {
			appConfig, err := ds.AppConfig(ctx)
			if err != nil {
				return 0, err
			}
			newInterval := appConfig.WebhookSettings.Interval.ValueOr(defaultInterval)
			return newInterval, nil
		}),
		schedule.WithJob(
			"host_status_webhook",
			func(ctx context.Context) error {
				return webhooks.TriggerHostStatusWebhook(
					ctx, ds, kitlog.With(logger, "automation", "host_status"),
				)
			},
		),
		schedule.WithJob(
			"fire_outdated_automations",
			func(ctx context.Context) error {
				return scheduleFailingPoliciesAutomation(ctx, ds, kitlog.With(logger, "automation", "fire_outdated_automations"), failingPoliciesSet)
			},
		),
		schedule.WithJob(
			"failing_policies_automation",
			func(ctx context.Context) error {
				return triggerFailingPoliciesAutomation(ctx, ds, kitlog.With(logger, "automation", "failing_policies"), failingPoliciesSet)
			},
		),
	)

	return s, nil
}

func scheduleFailingPoliciesAutomation(
	ctx context.Context,
	ds mobius.Datastore,
	logger kitlog.Logger,
	failingPoliciesSet mobius.FailingPolicySet,
) error {
	for {
		batch, err := ds.OutdatedAutomationBatch(ctx)
		if err != nil {
			return ctxerr.Wrap(ctx, err, "OutdatedAutomationBatch")
		}
		if len(batch) == 0 {
			break
		}
		level.Debug(logger).Log("adding_hosts", len(batch))
		for _, p := range batch {
			if err := failingPoliciesSet.AddHost(p.PolicyID, p.Host); err != nil {
				return ctxerr.Wrap(ctx, err, "failingPolicesSet.AddHost")
			}
		}
	}
	return nil
}

func triggerFailingPoliciesAutomation(
	ctx context.Context,
	ds mobius.Datastore,
	logger kitlog.Logger,
	failingPoliciesSet mobius.FailingPolicySet,
) error {
	appConfig, err := ds.AppConfig(ctx)
	if err != nil {
		return fmt.Errorf("getting app config: %w", err)
	}
	serverURL, err := url.Parse(appConfig.ServerSettings.ServerURL)
	if err != nil {
		return fmt.Errorf("parsing appConfig.ServerSettings.ServerURL: %w", err)
	}

	err = policies.TriggerFailingPoliciesAutomation(ctx, ds, logger, failingPoliciesSet, func(policy *mobius.Policy, cfg policies.FailingPolicyAutomationConfig) error {
		switch cfg.AutomationType {
		case policies.FailingPolicyWebhook:
			return webhooks.SendFailingPoliciesBatchedPOSTs(
				ctx, policy, failingPoliciesSet, cfg.HostBatchSize, serverURL, cfg.WebhookURL, time.Now(), logger)

		case policies.FailingPolicyJira:
			hosts, err := failingPoliciesSet.ListHosts(policy.ID)
			if err != nil {
				return ctxerr.Wrapf(ctx, err, "listing hosts for failing policies set %d", policy.ID)
			}
			if err := worker.QueueJiraFailingPolicyJob(ctx, ds, logger, policy, hosts); err != nil {
				return err
			}
			if err := failingPoliciesSet.RemoveHosts(policy.ID, hosts); err != nil {
				return ctxerr.Wrapf(ctx, err, "removing %d hosts from failing policies set %d", len(hosts), policy.ID)
			}

		case policies.FailingPolicyZendesk:
			hosts, err := failingPoliciesSet.ListHosts(policy.ID)
			if err != nil {
				return ctxerr.Wrapf(ctx, err, "listing hosts for failing policies set %d", policy.ID)
			}
			if err := worker.QueueZendeskFailingPolicyJob(ctx, ds, logger, policy, hosts); err != nil {
				return err
			}
			if err := failingPoliciesSet.RemoveHosts(policy.ID, hosts); err != nil {
				return ctxerr.Wrapf(ctx, err, "removing %d hosts from failing policies set %d", len(hosts), policy.ID)
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("triggering failing policies automation: %w", err)
	}

	return nil
}

func newWorkerIntegrationsSchedule(
	ctx context.Context,
	instanceID string,
	ds mobius.Datastore,
	logger kitlog.Logger,
	depStorage *mysql.NanoDEPStorage,
	commander *apple_mdm.MDMAppleCommander,
	bootstrapPackageStore mobius.MDMBootstrapPackageStore,
) (*schedule.Schedule, error) {
	const (
		name = string(mobius.CronWorkerIntegrations)

		// the schedule interval is shorter than the max run time of the scheduled
		// job, but that's ok - the job will acquire and extend the lock as long as
		// it runs, the shorter interval is to make sure we don't wait more than
		// that interval to start a new job when none is running.
		scheduleInterval = 1 * time.Minute  // schedule a worker to run every minute if none is running
		maxRunTime       = 10 * time.Minute // allow the worker to run for 10 minutes
	)

	logger = kitlog.With(logger, "cron", name)

	// create the worker and register the Jira and Zendesk jobs even if no
	// integration is enabled, as that config can change live (and if it's not
	// there won't be any records to process so it will mostly just sleep).
	w := worker.NewWorker(ds, logger)
	// leave the url empty for now, will be filled when the lock is acquired with
	// the up-to-date config.
	jira := &worker.Jira{
		Datastore:     ds,
		Log:           logger,
		NewClientFunc: newJiraClient,
	}
	zendesk := &worker.Zendesk{
		Datastore:     ds,
		Log:           logger,
		NewClientFunc: newZendeskClient,
	}
	var (
		depSvc *apple_mdm.DEPService
		depCli *godep.Client
	)
	// depStorage could be nil if mdm is not configured for mobius, in which case
	// we leave depSvc and deCli nil and macos setup assistants jobs will be
	// no-ops.
	if depStorage != nil {
		depSvc = apple_mdm.NewDEPService(ds, depStorage, logger)
		depCli = apple_mdm.NewDEPClient(depStorage, ds, logger)
	}
	macosSetupAsst := &worker.MacosSetupAssistant{
		Datastore:  ds,
		Log:        logger,
		DEPService: depSvc,
		DEPClient:  depCli,
	}
	appleMDM := &worker.AppleMDM{
		Datastore:             ds,
		Log:                   logger,
		Commander:             commander,
		BootstrapPackageStore: bootstrapPackageStore,
	}
	vppVerify := &worker.VPPVerification{
		Datastore: ds,
		Log:       logger,
		Commander: commander,
	}
	dbMigrate := &worker.DBMigration{
		Datastore: ds,
		Log:       logger,
	}
	w.Register(jira, zendesk, macosSetupAsst, appleMDM, dbMigrate, vppVerify)

	// Read app config a first time before starting, to clear up any failer client
	// configuration if we're not on a mobius-owned server. Technically, the ServerURL
	// could change dynamically, but for the needs of forced client failures, this
	// is not a possible scenario.
	appConfig, err := ds.AppConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting app config: %w", err)
	}

	// we clear it even if we fail to load the app config, not a likely scenario
	// in our test environments for the needs of forced failures.
	if !strings.Contains(appConfig.ServerSettings.ServerURL, "mobiusmdm") {
		os.Unsetenv("MOBIUS_JIRA_CLIENT_FORCED_FAILURES")
		os.Unsetenv("MOBIUS_ZENDESK_CLIENT_FORCED_FAILURES")
	}

	s := schedule.New(
		ctx, name, instanceID, scheduleInterval, ds, ds,
		schedule.WithAltLockID("worker"),
		schedule.WithLogger(logger),
		schedule.WithJob("integrations_worker", func(ctx context.Context) error {
			// Read app config to be able to use the latest configuration for integrations.
			appConfig, err := ds.AppConfig(ctx)
			if err != nil {
				return fmt.Errorf("getting app config: %w", err)
			}

			jira.MobiusURL = appConfig.ServerSettings.ServerURL
			zendesk.MobiusURL = appConfig.ServerSettings.ServerURL

			workCtx, cancel := context.WithTimeout(ctx, maxRunTime)
			defer cancel()

			if err := w.ProcessJobs(workCtx); err != nil {
				return fmt.Errorf("processing integrations jobs: %w", err)
			}
			return nil
		}),
		schedule.WithJob("dep_cooldowns", func(ctx context.Context) error {
			return worker.ProcessDEPCooldowns(ctx, ds, logger)
		}),
	)

	return s, nil
}

func newJiraClient(opts *externalsvc.JiraOptions) (worker.JiraClient, error) {
	client, err := externalsvc.NewJiraClient(opts)
	if err != nil {
		return nil, err
	}

	// create client wrappers to introduce forced failures if configured
	// to do so via the environment variable.
	// format is "<modulo number>;<cve1>,<cve2>,<cve3>,..."
	failerClient := newFailerClient(os.Getenv("MOBIUS_JIRA_CLIENT_FORCED_FAILURES"))
	if failerClient != nil {
		failerClient.JiraClient = client
		return failerClient, nil
	}
	return client, nil
}

func newZendeskClient(opts *externalsvc.ZendeskOptions) (worker.ZendeskClient, error) {
	client, err := externalsvc.NewZendeskClient(opts)
	if err != nil {
		return nil, err
	}

	// create client wrappers to introduce forced failures if configured
	// to do so via the environment variable.
	// format is "<modulo number>;<cve1>,<cve2>,<cve3>,..."
	failerClient := newFailerClient(os.Getenv("MOBIUS_ZENDESK_CLIENT_FORCED_FAILURES"))
	if failerClient != nil {
		failerClient.ZendeskClient = client
		return failerClient, nil
	}
	return client, nil
}

func newFailerClient(forcedFailures string) *worker.TestAutomationFailer {
	var failerClient *worker.TestAutomationFailer
	if forcedFailures != "" {

		parts := strings.Split(forcedFailures, ";")
		if len(parts) == 2 {
			mod, _ := strconv.Atoi(parts[0])
			cves := strings.Split(parts[1], ",")
			if mod > 0 || len(cves) > 0 {
				failerClient = &worker.TestAutomationFailer{
					FailCallCountModulo: mod,
					AlwaysFailCVEs:      cves,
				}
			}
		}
	}
	return failerClient
}

func newCleanupsAndAggregationSchedule(
	ctx context.Context,
	instanceID string,
	ds mobius.Datastore,
	logger kitlog.Logger,
	enrollHostLimiter mobius.EnrollHostLimiter,
	config *config.MobiusConfig,
	commander *apple_mdm.MDMAppleCommander,
	softwareInstallStore mobius.SoftwareInstallerStore,
	bootstrapPackageStore mobius.MDMBootstrapPackageStore,
) (*schedule.Schedule, error) {
	const (
		name            = string(mobius.CronCleanupsThenAggregation)
		defaultInterval = 1 * time.Hour
	)
	s := schedule.New(
		ctx, name, instanceID, defaultInterval, ds, ds,
		// Using leader for the lock to be backwards compatilibity with old deployments.
		schedule.WithAltLockID("leader"),
		schedule.WithLogger(kitlog.With(logger, "cron", name)),
		// Run cleanup jobs first.
		schedule.WithJob(
			"distributed_query_campaigns",
			func(ctx context.Context) error {
				_, err := ds.CleanupDistributedQueryCampaigns(ctx, time.Now().UTC())
				return err
			},
		),
		schedule.WithJob(
			"incoming_hosts",
			func(ctx context.Context) error {
				_, err := ds.CleanupIncomingHosts(ctx, time.Now())
				return err
			},
		),
		schedule.WithJob(
			"carves",
			func(ctx context.Context) error {
				_, err := ds.CleanupCarves(ctx, time.Now())
				return err
			},
		),
		schedule.WithJob(
			"expired_hosts",
			func(ctx context.Context) error {
				_, err := ds.CleanupExpiredHosts(ctx)
				return err
			},
		),
		schedule.WithJob(
			"policy_membership",
			func(ctx context.Context) error {
				return ds.CleanupPolicyMembership(ctx, time.Now())
			},
		),
		schedule.WithJob(
			"cleanup_host_issues",
			func(ctx context.Context) error {
				return ds.CleanupHostIssues(ctx)
			},
		),
		schedule.WithJob(
			"sync_enrolled_host_ids",
			func(ctx context.Context) error {
				return enrollHostLimiter.SyncEnrolledHostIDs(ctx)
			},
		),
		schedule.WithJob(
			"cleanup_host_operating_systems",
			func(ctx context.Context) error {
				return ds.CleanupHostOperatingSystems(ctx)
			},
		),
		schedule.WithJob(
			"cleanup_expired_password_reset_requests",
			func(ctx context.Context) error {
				return ds.CleanupExpiredPasswordResetRequests(ctx)
			},
		),
		schedule.WithJob(
			"expired_challenges",
			func(ctx context.Context) error {
				_, err := ds.CleanupExpiredChallenges(ctx)
				return err
			},
		),
		// Run aggregation jobs after cleanups.
		schedule.WithJob(
			"query_aggregated_stats",
			func(ctx context.Context) error {
				return ds.UpdateQueryAggregatedStats(ctx)
			},
		),
		schedule.WithJob(
			"policy_aggregated_stats",
			func(ctx context.Context) error {
				return ds.UpdateHostPolicyCounts(ctx)
			},
		),
		schedule.WithJob(
			"aggregated_munki_and_mdm",
			func(ctx context.Context) error {
				return ds.GenerateAggregatedMunkiAndMDM(ctx)
			},
		),
		schedule.WithJob(
			"increment_policy_violation_days",
			func(ctx context.Context) error {
				return ds.IncrementPolicyViolationDays(ctx)
			},
		),
		schedule.WithJob(
			"update_os_versions",
			func(ctx context.Context) error {
				return ds.UpdateOSVersions(ctx)
			},
		),
		schedule.WithJob(
			"verify_disk_encryption_keys",
			func(ctx context.Context) error {
				return verifyDiskEncryptionKeys(ctx, logger, ds)
			},
		),
		schedule.WithJob(
			"renew_scep_certificates",
			func(ctx context.Context) error {
				return service.RenewSCEPCertificates(ctx, logger, ds, config, commander)
			},
		),
		schedule.WithJob("renew_host_mdm_managed_certificates", func(ctx context.Context) error {
			return ds.RenewMDMManagedCertificates(ctx)
		}),
		schedule.WithJob("query_results_cleanup", func(ctx context.Context) error {
			config, err := ds.AppConfig(ctx)
			if err != nil {
				return err
			}

			if config.ServerSettings.QueryReportsDisabled {
				if err = ds.CleanupGlobalDiscardQueryResults(ctx); err != nil {
					return err
				}
			}

			if err = ds.CleanupDiscardedQueryResults(ctx); err != nil {
				return err
			}

			return nil
		}),
		schedule.WithJob("cleanup_unused_script_contents", func(ctx context.Context) error {
			return ds.CleanupUnusedScriptContents(ctx)
		}),
		schedule.WithJob("cleanup_activities", func(ctx context.Context) error {
			appConfig, err := ds.AppConfig(ctx)
			if err != nil {
				return err
			}
			if !appConfig.ActivityExpirySettings.ActivityExpiryEnabled {
				return nil
			}
			// A maxCount of 5,000 means that the cron job will keep the activities (and associated tables)
			// sizes in control for deployments that generate (5k x 24 hours) ~120,000 activities per day.
			const maxCount = 5000
			return ds.CleanupActivitiesAndAssociatedData(ctx, maxCount, appConfig.ActivityExpirySettings.ActivityExpiryWindow)
		}),
		schedule.WithJob("cleanup_unused_software_installers", func(ctx context.Context) error {
			// remove only those unused created more than a minute ago to avoid a
			// race where we delete those created after the mysql query to get those
			// in use.
			return ds.CleanupUnusedSoftwareInstallers(ctx, softwareInstallStore, time.Now().Add(-time.Minute))
		}),
		schedule.WithJob("cleanup_unused_bootstrap_packages", func(ctx context.Context) error {
			// remove only those unused created more than a minute ago to avoid a
			// race where we delete those created after the mysql query to get those
			// in use.
			return ds.CleanupUnusedBootstrapPackages(ctx, bootstrapPackageStore, time.Now().Add(-time.Minute))
		}),
		schedule.WithJob("cleanup_host_mdm_commands", func(ctx context.Context) error {
			return ds.CleanupHostMDMCommands(ctx)
		}),
		schedule.WithJob("cleanup_host_mdm_managed_certificates", func(ctx context.Context) error {
			return ds.CleanUpMDMManagedCertificates(ctx)
		}),
		schedule.WithJob("cleanup_host_mdm_apple_profiles", func(ctx context.Context) error {
			return ds.CleanupHostMDMAppleProfiles(ctx)
		}),
		schedule.WithJob("cleanup_worker_jobs", func(ctx context.Context) error {
			const (
				failedSince    = 365 * 24 * time.Hour // keep failed jobs for 1 year
				completedSince = 90 * 24 * time.Hour  // keep completed (successful) jobs for ~3 months
			)
			_, err := ds.CleanupWorkerJobs(ctx, failedSince, completedSince)
			return err
		}),
	)

	return s, nil
}

func newFrequentCleanupsSchedule(
	ctx context.Context,
	instanceID string,
	ds mobius.Datastore,
	lq mobius.LiveQueryStore,
	logger kitlog.Logger,
) (*schedule.Schedule, error) {
	const (
		name            = string(mobius.CronFrequentCleanups)
		defaultInterval = 15 * time.Minute
	)
	s := schedule.New(
		ctx, name, instanceID, defaultInterval, ds, ds,
		// Using leader for the lock to be backwards compatilibity with old deployments.
		schedule.WithAltLockID("leader_frequent_cleanups"),
		schedule.WithLogger(kitlog.With(logger, "cron", name)),
		// Run cleanup jobs first.
		schedule.WithJob("redis_live_queries", func(ctx context.Context) error {
			// It's necessary to avoid lingering live queries in case of:
			// - (Unknown) bug in the implementation, or,
			// - Redis is so overloaded already that the lq.StopQuery in svc.CompleteCampaign fails to execute, or,
			// - MySQL is so overloaded that ds.SaveDistributedQueryCampaign in svc.CompleteCampaign fails to execute.
			names, err := lq.LoadActiveQueryNames()
			if err != nil {
				return err
			}
			ids := stringSliceToUintSlice(names, logger)
			completed, err := ds.GetCompletedCampaigns(ctx, ids)
			if err != nil {
				return err
			}
			err = lq.CleanupInactiveQueries(ctx, completed)
			return err
		}),
	)

	return s, nil
}

func verifyDiskEncryptionKeys(
	ctx context.Context,
	logger kitlog.Logger,
	ds mobius.Datastore,
) error {
	appCfg, err := ds.AppConfig(ctx)
	if err != nil {
		logger.Log("err", "unable to get app config", "details", err)
		return ctxerr.Wrap(ctx, err, "fetching app config")
	}

	if !appCfg.MDM.EnabledAndConfigured {
		logger.Log("inf", "skipping verification of macOS encryption keys as MDM is not fully configured")
		return nil
	}

	keys, err := ds.GetUnverifiedDiskEncryptionKeys(ctx)
	if err != nil {
		logger.Log("err", "unable to get unverified disk encryption keys from the database", "details", err)
		return err
	}

	cert, err := assets.CAKeyPair(ctx, ds)
	if err != nil {
		logger.Log("err", "unable to get CA keypair", "details", err)
		return ctxerr.Wrap(ctx, err, "parsing SCEP keypair")
	}

	decryptable := []uint{}
	undecryptable := []uint{}
	var latest time.Time
	for _, key := range keys {
		if key.UpdatedAt.After(latest) {
			latest = key.UpdatedAt
		}
		if _, err := mdm.DecryptBase64CMS(key.Base64Encrypted, cert.Leaf, cert.PrivateKey); err != nil {
			undecryptable = append(undecryptable, key.HostID)
			continue
		}
		decryptable = append(decryptable, key.HostID)
	}

	if err := ds.SetHostsDiskEncryptionKeyStatus(ctx, decryptable, true, latest); err != nil {
		logger.Log("err", "unable to update decryptable status", "details", err)
		return err
	}
	if err := ds.SetHostsDiskEncryptionKeyStatus(ctx, undecryptable, false, latest); err != nil {
		logger.Log("err", "unable to update decryptable status", "details", err)
		return err
	}

	return nil
}

func newUsageStatisticsSchedule(ctx context.Context, instanceID string, ds mobius.Datastore, config config.MobiusConfig, license *mobius.LicenseInfo, logger kitlog.Logger) (*schedule.Schedule, error) {
	const (
		name            = string(mobius.CronUsageStatistics)
		defaultInterval = 1 * time.Hour
	)
	s := schedule.New(
		ctx, name, instanceID, defaultInterval, ds, ds,
		schedule.WithLogger(kitlog.With(logger, "cron", name)),
		schedule.WithJob(
			"try_send_statistics",
			func(ctx context.Context) error {
				// NOTE(mna): this is not a route from the mobius server (not in server/service/handler.go) so it
				// will not automatically support the /latest/ versioning. Leaving it as /v1/ for that reason.
				return trySendStatistics(ctx, ds, mobius.StatisticsFrequency, "https://mobiusmdm.com/api/v1/webhooks/receive-usage-analytics", config)
			},
		),
	)

	return s, nil
}

func trySendStatistics(ctx context.Context, ds mobius.Datastore, frequency time.Duration, url string, config config.MobiusConfig) error {
	ac, err := ds.AppConfig(ctx)
	if err != nil {
		return err
	}

	// If the license is Premium, we should always send usage statisics.
	if !ac.ServerSettings.EnableAnalytics && license.IsAllowDisableTelemetry(ctx) {
		return nil
	}

	stats, shouldSend, err := ds.ShouldSendStatistics(ctx, frequency, config)
	if err != nil {
		return err
	}
	if !shouldSend {
		return nil
	}

	if err := server.PostJSONWithTimeout(ctx, url, stats); err != nil {
		return err
	}

	if err := ds.CleanupStatistics(ctx); err != nil {
		return err
	}

	return ds.RecordStatisticsSent(ctx)
}

// newAppleMDMDEPProfileAssigner creates the schedule to run the DEP syncer+assigner.
// The DEP syncer+assigner fetches devices from Apple Business Manager (aka ABM) and applies
// the current configured DEP profile to them.
func newAppleMDMDEPProfileAssigner(
	ctx context.Context,
	instanceID string,
	periodicity time.Duration,
	ds mobius.Datastore,
	depStorage *mysql.NanoDEPStorage,
	logger kitlog.Logger,
) (*schedule.Schedule, error) {
	const name = string(mobius.CronAppleMDMDEPProfileAssigner)
	logger = kitlog.With(logger, "cron", name, "component", "nanodep-syncer")
	s := schedule.New(
		ctx, name, instanceID, periodicity, ds, ds,
		schedule.WithLogger(logger),
		schedule.WithJob("dep_syncer", appleMDMDEPSyncerJob(ds, depStorage, logger)),
	)

	return s, nil
}

func appleMDMDEPSyncerJob(
	ds mobius.Datastore,
	depStorage *mysql.NanoDEPStorage,
	logger kitlog.Logger,
) func(context.Context) error {
	var mobiusSyncer *apple_mdm.DEPService
	return func(ctx context.Context) error {
		appCfg, err := ds.AppConfig(ctx)
		if err != nil {
			return ctxerr.Wrap(ctx, err, "retrieving app config")
		}

		if !appCfg.MDM.AppleBMEnabledAndConfigured {
			return nil
		}

		// As part of the DB migration of the single ABM token to the multi-ABM
		// token world (where the token was migrated from mdm_config_assets to
		// abm_tokens), we need to complete migration of the existing token as
		// during the DB migration we didn't have the organization name, apple id
		// and renewal date.
		incompleteToken, err := ds.GetABMTokenByOrgName(ctx, "")
		if err != nil && !mobius.IsNotFound(err) {
			return ctxerr.Wrap(ctx, err, "retrieving migrated ABM token")
		}
		if incompleteToken != nil {
			logger.Log("msg", "migrated ABM token found, updating its metadata")
			if err := apple_mdm.SetABMTokenMetadata(ctx, incompleteToken, depStorage, ds, logger, false); err != nil {
				return ctxerr.Wrap(ctx, err, "updating migrated ABM token metadata")
			}
			if err := ds.SaveABMToken(ctx, incompleteToken); err != nil {
				return ctxerr.Wrap(ctx, err, "saving updated migrated ABM token")
			}
			logger.Log("msg", "completed migration of existing ABM token")
		}

		if mobiusSyncer == nil {
			mobiusSyncer = apple_mdm.NewDEPService(ds, depStorage, logger)
		}

		return mobiusSyncer.RunAssigner(ctx)
	}
}

func newAppleMDMProfileManagerSchedule(
	ctx context.Context,
	instanceID string,
	ds mobius.Datastore,
	commander *apple_mdm.MDMAppleCommander,
	logger kitlog.Logger,
) (*schedule.Schedule, error) {
	const (
		name = string(mobius.CronMDMAppleProfileManager)
		// Note: per a request from #g-product we are running this cron
		// every 30 seconds, we should re-evaluate how we handle the
		// cron interval as we scale to more hosts.
		defaultInterval = 30 * time.Second
	)

	logger = kitlog.With(logger, "cron", name)
	s := schedule.New(
		ctx, name, instanceID, defaultInterval, ds, ds,
		schedule.WithLogger(logger),
		schedule.WithJob("manage_apple_profiles", func(ctx context.Context) error {
			return service.ReconcileAppleProfiles(ctx, ds, commander, logger)
		}),
		schedule.WithJob("manage_apple_declarations", func(ctx context.Context) error {
			return service.ReconcileAppleDeclarations(ctx, ds, commander, logger)
		}),
	)

	return s, nil
}

func newWindowsMDMProfileManagerSchedule(
	ctx context.Context,
	instanceID string,
	ds mobius.Datastore,
	logger kitlog.Logger,
) (*schedule.Schedule, error) {
	const (
		name = string(mobius.CronMDMWindowsProfileManager)
		// Note: per a request from #g-product we are running this cron
		// every 30 seconds, we should re-evaluate how we handle the
		// cron interval as we scale to more hosts.
		defaultInterval = 30 * time.Second
	)

	logger = kitlog.With(logger, "cron", name)
	s := schedule.New(
		ctx, name, instanceID, defaultInterval, ds, ds,
		schedule.WithLogger(logger),
		schedule.WithJob("manage_windows_profiles", func(ctx context.Context) error {
			return service.ReconcileWindowsProfiles(ctx, ds, logger)
		}),
	)

	return s, nil
}

func newMDMAPNsPusher(
	ctx context.Context,
	instanceID string,
	ds mobius.Datastore,
	commander *apple_mdm.MDMAppleCommander,
	logger kitlog.Logger,
) (*schedule.Schedule, error) {
	const name = string(mobius.CronAppleMDMAPNsPusher)

	interval := 1 * time.Minute
	if intervalEnv := os.Getenv("MOBIUS_DEV_CUSTOM_APNS_PUSHER_INTERVAL"); intervalEnv != "" {
		var err error
		interval, err = time.ParseDuration(intervalEnv)
		if err != nil {
			level.Warn(logger).Log("msg", "invalid duration provided for MOBIUS_DEV_CUSTOM_APNS_PUSHER_INTERVAL, using default interval")
			interval = 1 * time.Minute
		}
	}

	logger = kitlog.With(logger, "cron", name)
	s := schedule.New(
		ctx, name, instanceID, interval, ds, ds,
		schedule.WithLogger(logger),
		schedule.WithJob("apns_push_to_pending_hosts", func(ctx context.Context) error {
			appCfg, err := ds.AppConfig(ctx)
			if err != nil {
				return ctxerr.Wrap(ctx, err, "retrieving app config")
			}

			if !appCfg.MDM.EnabledAndConfigured {
				return nil
			}

			return service.SendPushesToPendingDevices(ctx, ds, commander, logger)
		}),
	)

	return s, nil
}

func cleanupCronStatsOnShutdown(ctx context.Context, ds mobius.Datastore, logger kitlog.Logger, instanceID string) {
	if err := ds.UpdateAllCronStatsForInstance(ctx, instanceID, mobius.CronStatsStatusPending, mobius.CronStatsStatusCanceled); err != nil {
		logger.Log("err", "cancel pending cron stats for instance", "details", err)
	}
}

func newActivitiesStreamingSchedule(
	ctx context.Context,
	instanceID string,
	ds mobius.Datastore,
	logger kitlog.Logger,
	auditLogger mobius.JSONLogger,
) (*schedule.Schedule, error) {
	const (
		name     = string(mobius.CronActivitiesStreaming)
		interval = 5 * time.Minute
	)
	logger = kitlog.With(logger, "cron", name)
	s := schedule.New(
		ctx, name, instanceID, interval, ds, ds,
		schedule.WithLogger(logger),
		schedule.WithJob(
			"cron_activities_streaming",
			func(ctx context.Context) error {
				return cronActivitiesStreaming(ctx, ds, logger, auditLogger)
			},
		),
	)
	return s, nil
}

var ActivitiesToStreamBatchCount uint = 500

func cronActivitiesStreaming(
	ctx context.Context,
	ds mobius.Datastore,
	logger kitlog.Logger,
	auditLogger mobius.JSONLogger,
) error {
	page := uint(0)
	for {
		// (1) Get batch of activities that haven't been streamed.
		activitiesToStream, _, err := ds.ListActivities(ctx, mobius.ListActivitiesOptions{
			ListOptions: mobius.ListOptions{
				OrderKey:       "id",
				OrderDirection: mobius.OrderAscending,
				PerPage:        ActivitiesToStreamBatchCount,
				Page:           page,
			},
			Streamed: ptr.Bool(false),
		})
		if err != nil {
			return ctxerr.Wrap(ctx, err, "list activities")
		}
		if len(activitiesToStream) == 0 {
			return nil
		}

		// (2) Stream the activities.
		var (
			streamedIDs []uint
			multiErr    error
		)
		// We stream one activity at a time (instead of writing them all with
		// one auditLogger.Write call) to know which ones succeeded/failed,
		// and also because this method happens asynchronously,
		// so we don't need real-time performance.
		for _, activity := range activitiesToStream {
			b, err := json.Marshal(activity)
			if err != nil {
				return ctxerr.Wrap(ctx, err, "marshal activity")
			}
			if err := auditLogger.Write(ctx, []json.RawMessage{json.RawMessage(b)}); err != nil {
				if len(streamedIDs) == 0 {
					return ctxerr.Wrapf(ctx, err, "stream first activity: %d", activity.ID)
				}
				multiErr = multierror.Append(multiErr, ctxerr.Wrapf(ctx, err, "stream activity: %d", activity.ID))
				// We stop streaming upon the first error (will retry on next cron iteration)
				break
			}
			streamedIDs = append(streamedIDs, activity.ID)
		}

		logger.Log("streamed-events", len(streamedIDs))

		// (3) Mark the streamed activities as streamed.
		if err := ds.MarkActivitiesAsStreamed(ctx, streamedIDs); err != nil {
			multiErr = multierror.Append(multiErr, ctxerr.Wrap(ctx, err, "mark activities as streamed"))
		}

		// If there was an error while streaming or updating activities, return.
		if multiErr != nil {
			return multiErr
		}

		if len(activitiesToStream) < int(ActivitiesToStreamBatchCount) { //nolint:gosec // dismiss G115
			return nil
		}
		page += 1
	}
}

func stringSliceToUintSlice(s []string, logger kitlog.Logger) []uint {
	result := make([]uint, 0, len(s))
	for _, v := range s {
		i, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			level.Warn(logger).Log("msg", "failed to parse string to uint", "string", v, "err", err)
			continue
		}
		result = append(result, uint(i))
	}
	return result
}

// newIPhoneIPadRefetcher will enqueue DeviceInformation commands on iOS/iPadOS devices
// to refetch their host details.
//
// See https://developer.apple.com/documentation/devicemanagement/get_device_information.
//
// We will refetch iPhones/iPads every 1 hour (to match the default
// detail interval of all (osquery-capable) hosts in Mobius).
func newIPhoneIPadRefetcher(
	ctx context.Context,
	instanceID string,
	periodicity time.Duration,
	ds mobius.Datastore,
	commander *apple_mdm.MDMAppleCommander,
	logger kitlog.Logger,
) (*schedule.Schedule, error) {
	const name = string(mobius.CronAppleMDMIPhoneIPadRefetcher)
	logger = kitlog.With(logger, "cron", name, "component", "iphone-ipad-refetcher")
	s := schedule.New(
		ctx, name, instanceID, periodicity, ds, ds,
		schedule.WithLogger(logger),
		schedule.WithJob("cron_iphone_ipad_refetcher", func(ctx context.Context) error {
			return apple_mdm.IOSiPadOSRefetch(ctx, ds, commander, logger)
		}),
	)

	return s, nil
}

// cronUninstallSoftwareMigration will update uninstall scripts for software.
// Once all customers are using on Mobius 4.57 or later, this job can be removed.
func cronUninstallSoftwareMigration(
	ctx context.Context,
	instanceID string,
	ds mobius.Datastore,
	softwareInstallStore mobius.SoftwareInstallerStore,
	logger kitlog.Logger,
) (*schedule.Schedule, error) {
	const (
		name            = string(mobius.CronUninstallSoftwareMigration)
		defaultInterval = 24 * time.Hour
	)
	logger = kitlog.With(logger, "cron", name, "component", name)
	s := schedule.New(
		ctx, name, instanceID, defaultInterval, ds, ds,
		schedule.WithLogger(logger),
		schedule.WithRunOnce(true),
		schedule.WithJob(name, func(ctx context.Context) error {
			// Enterprise software uninstall migration removed
			return nil // service.UninstallSoftwareMigration(ctx, ds, softwareInstallStore, logger)
		}),
	)
	return s, nil
}

func newMaintainedAppSchedule(
	ctx context.Context,
	instanceID string,
	ds mobius.Datastore,
	logger kitlog.Logger,
) (*schedule.Schedule, error) {
	const (
		name            = string(mobius.CronMaintainedApps)
		defaultInterval = 24 * time.Hour
		priorJobDiff    = -(defaultInterval - 30*time.Second)
	)

	logger = kitlog.With(logger, "cron", name)
	s := schedule.New(
		ctx, name, instanceID, defaultInterval, ds, ds,
		schedule.WithLogger(logger),
		// ensures it runs a few seconds after Mobius is started
		schedule.WithDefaultPrevRunCreatedAt(time.Now().Add(priorJobDiff)),
		schedule.WithJob("refresh_maintained_apps", func(ctx context.Context) error {
			return maintained_apps.Refresh(ctx, ds, logger)
		}),
	)

	return s, nil
}

func newRefreshVPPAppVersionsSchedule(
	ctx context.Context,
	instanceID string,
	ds mobius.Datastore,
	logger kitlog.Logger,
) (*schedule.Schedule, error) {
	const (
		name            = string(mobius.CronRefreshVPPAppVersions)
		defaultInterval = 1 * time.Hour
	)

	logger = kitlog.With(logger, "cron", name)
	s := schedule.New(
		ctx, name, instanceID, defaultInterval, ds, ds,
		schedule.WithLogger(logger),
		schedule.WithJob("refresh_vpp_app_version", func(ctx context.Context) error {
			return vpp.RefreshVersions(ctx, ds)
		}),
	)

	return s, nil
}

// newIPhoneIPadReviver sends APNs push notifications to iPhone/iPad devices
// that were deleted from Mobius but are still enrolled in Mobius MDM as BYOD
// devices (ADE devices are never deleted from Mobius, their phantom host entry
// always persists).
func newIPhoneIPadReviver(
	ctx context.Context,
	instanceID string,
	ds mobius.Datastore,
	commander *apple_mdm.MDMAppleCommander,
	logger kitlog.Logger,
) (*schedule.Schedule, error) {
	const name = string(mobius.CronAppleMDMIPhoneIPadReviver)
	logger = kitlog.With(logger, "cron", name, "component", "iphone-ipad-reviver")
	s := schedule.New(
		ctx, name, instanceID, 1*time.Hour, ds, ds,
		schedule.WithLogger(logger),
		schedule.WithJob("cron_iphone_ipad_reviver", func(ctx context.Context) error {
			return apple_mdm.IOSiPadOSRevive(ctx, ds, commander, logger)
		}),
	)

	return s, nil
}

func newUpcomingActivitiesSchedule(
	ctx context.Context,
	instanceID string,
	ds mobius.Datastore,
	logger kitlog.Logger,
) (*schedule.Schedule, error) {
	const (
		name            = string(mobius.CronUpcomingActivitiesMaintenance)
		defaultInterval = 10 * time.Minute
	)
	s := schedule.New(
		ctx, name, instanceID, defaultInterval, ds, ds,
		schedule.WithLogger(kitlog.With(logger, "cron", name)),
		schedule.WithJob("unblock_hosts_upcoming_activity_queue", func(ctx context.Context) error {
			const maxUnblockHosts = 500
			_, err := ds.UnblockHostsUpcomingActivityQueue(ctx, maxUnblockHosts)
			return err
		}),
	)

	return s, nil
}
