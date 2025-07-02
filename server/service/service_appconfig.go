package service

import (
	"context"
	"html/template"
	"strings"

	"github.com/notawar/mobius/server"
	authz_ctx "github.com/notawar/mobius/server/contexts/authz"
	"github.com/notawar/mobius/server/contexts/ctxerr"
	"github.com/notawar/mobius/server/contexts/license"
	"github.com/notawar/mobius/server/contexts/viewer"
	"github.com/notawar/mobius/server/mobius"
	"github.com/notawar/mobius/server/mail"
	"github.com/notawar/mobius/server/service/middleware/endpoint_utils"
)

func (svc *Service) NewAppConfig(ctx context.Context, p mobius.AppConfig) (*mobius.AppConfig, error) {
	// skipauth: No user context yet when the app config is first created.
	svc.authz.SkipAuthorization(ctx)

	newConfig, err := svc.ds.NewAppConfig(ctx, &p)
	if err != nil {
		return nil, err
	}

	// Set up a default enroll secret
	secret := svc.config.Packaging.GlobalEnrollSecret
	if secret == "" {
		secret, err = server.GenerateRandomText(mobius.EnrollSecretDefaultLength)
		if err != nil {
			return nil, ctxerr.Wrap(ctx, err, "generate enroll secret string")
		}
	}
	secrets := []*mobius.EnrollSecret{
		{
			Secret: secret,
		},
	}
	err = svc.ds.ApplyEnrollSecrets(ctx, nil, secrets)
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err, "save enroll secret")
	}

	return newConfig, nil
}

func (svc *Service) sendTestEmail(ctx context.Context, config *mobius.AppConfig) error {
	vc, ok := viewer.FromContext(ctx)
	if !ok {
		return mobius.ErrNoContext
	}

	var smtpSettings mobius.SMTPSettings
	if config.SMTPSettings != nil {
		smtpSettings = *config.SMTPSettings
	}

	testMail := mobius.Email{
		Subject: "Hello from Mobius",
		To:      []string{vc.User.Email},
		Mailer: &mail.SMTPTestMailer{
			BaseURL:  template.URL(config.ServerSettings.ServerURL + svc.config.Server.URLPrefix),
			AssetURL: getAssetURL(),
		},
		SMTPSettings: smtpSettings,
		ServerURL:    config.ServerSettings.ServerURL,
	}

	if err := mail.Test(svc.mailService, testMail); err != nil {
		return endpoint_utils.MailError{Message: err.Error()}
	}
	return nil
}

func cleanupURL(url string) string {
	return strings.TrimRight(strings.Trim(url, " \t\n"), "/")
}

func (svc *Service) License(ctx context.Context) (*mobius.LicenseInfo, error) {
	if !svc.authz.IsAuthenticatedWith(ctx, authz_ctx.AuthnDeviceToken) {
		if err := svc.authz.Authorize(ctx, &mobius.AppConfig{}, mobius.ActionRead); err != nil {
			return nil, err
		}
	}

	lic, _ := license.FromContext(ctx)

	// Currently we use the presence of Microsoft Compliance Partner settings
	// (only configured in cloud instances) to determine if a Mobius instance
	// is a cloud managed instance.
	if svc.config.MicrosoftCompliancePartner.IsSet() {
		lic.ManagedCloud = true
	}

	return lic, nil
}

func (svc *Service) SetupRequired(ctx context.Context) (bool, error) {
	hasUsers, err := svc.ds.HasUsers(ctx)
	if err != nil {
		return false, err
	}
	return !hasUsers, nil
}

func (svc *Service) UpdateIntervalConfig(ctx context.Context) (*mobius.UpdateIntervalConfig, error) {
	return &mobius.UpdateIntervalConfig{
		OSQueryDetail: svc.config.Osquery.DetailUpdateInterval,
		OSQueryPolicy: svc.config.Osquery.PolicyUpdateInterval,
	}, nil
}

func (svc *Service) VulnerabilitiesConfig(ctx context.Context) (*mobius.VulnerabilitiesConfig, error) {
	return &mobius.VulnerabilitiesConfig{
		DatabasesPath:               svc.config.Vulnerabilities.DatabasesPath,
		Periodicity:                 svc.config.Vulnerabilities.Periodicity,
		CPEDatabaseURL:              svc.config.Vulnerabilities.CPEDatabaseURL,
		CPETranslationsURL:          svc.config.Vulnerabilities.CPETranslationsURL,
		CVEFeedPrefixURL:            svc.config.Vulnerabilities.CVEFeedPrefixURL,
		CurrentInstanceChecks:       svc.config.Vulnerabilities.CurrentInstanceChecks,
		DisableDataSync:             svc.config.Vulnerabilities.DisableDataSync,
		RecentVulnerabilityMaxAge:   svc.config.Vulnerabilities.RecentVulnerabilityMaxAge,
		DisableWinOSVulnerabilities: svc.config.Vulnerabilities.DisableWinOSVulnerabilities,
	}, nil
}

func (svc *Service) LoggingConfig(ctx context.Context) (*mobius.Logging, error) {
	conf := svc.config
	logging := &mobius.Logging{
		Debug: conf.Logging.Debug,
		Json:  conf.Logging.JSON,
	}

	loggings := []struct {
		plugin string
		target *mobius.LoggingPlugin
	}{
		{
			plugin: conf.Osquery.StatusLogPlugin,
			target: &logging.Status,
		},
		{
			plugin: conf.Osquery.ResultLogPlugin,
			target: &logging.Result,
		},
	}

	if conf.Activity.EnableAuditLog {
		loggings = append(loggings, struct {
			plugin string
			target *mobius.LoggingPlugin
		}{
			plugin: conf.Activity.AuditLogPlugin,
			target: &logging.Audit,
		})
	}

	for _, lp := range loggings {
		switch lp.plugin {
		case "", "filesystem":
			*lp.target = mobius.LoggingPlugin{
				Plugin: "filesystem",
				Config: mobius.FilesystemConfig{
					FilesystemConfig: conf.Filesystem,
				},
			}
		case "webhook":
			*lp.target = mobius.LoggingPlugin{
				Plugin: "webhook",
				Config: mobius.WebhookConfig{
					WebhookConfig: conf.Webhook,
				},
			}
		case "kinesis":
			*lp.target = mobius.LoggingPlugin{
				Plugin: "kinesis",
				Config: mobius.KinesisConfig{
					Region:       conf.Kinesis.Region,
					StatusStream: conf.Kinesis.StatusStream,
					ResultStream: conf.Kinesis.ResultStream,
					AuditStream:  conf.Kinesis.AuditStream,
				},
			}
		case "firehose":
			*lp.target = mobius.LoggingPlugin{
				Plugin: "firehose",
				Config: mobius.FirehoseConfig{
					Region:       conf.Firehose.Region,
					StatusStream: conf.Firehose.StatusStream,
					ResultStream: conf.Firehose.ResultStream,
					AuditStream:  conf.Firehose.AuditStream,
				},
			}
		case "lambda":
			*lp.target = mobius.LoggingPlugin{
				Plugin: "lambda",
				Config: mobius.LambdaConfig{
					Region:         conf.Lambda.Region,
					StatusFunction: conf.Lambda.StatusFunction,
					ResultFunction: conf.Lambda.ResultFunction,
					AuditFunction:  conf.Lambda.AuditFunction,
				},
			}
		case "pubsub":
			*lp.target = mobius.LoggingPlugin{
				Plugin: "pubsub",
				Config: mobius.PubSubConfig{
					PubSubConfig: conf.PubSub,
				},
			}
		case "stdout":
			*lp.target = mobius.LoggingPlugin{Plugin: "stdout"}
		case "kafkarest":
			*lp.target = mobius.LoggingPlugin{
				Plugin: "kafkarest",
				Config: mobius.KafkaRESTConfig{
					StatusTopic: conf.KafkaREST.StatusTopic,
					ResultTopic: conf.KafkaREST.ResultTopic,
					AuditTopic:  conf.KafkaREST.AuditTopic,
					ProxyHost:   conf.KafkaREST.ProxyHost,
				},
			}
		default:
			return nil, ctxerr.Errorf(ctx, "unrecognized logging plugin: %s", lp.plugin)
		}
	}
	return logging, nil
}

func (svc *Service) EmailConfig(ctx context.Context) (*mobius.EmailConfig, error) {
	if err := svc.authz.Authorize(ctx, &mobius.AppConfig{}, mobius.ActionRead); err != nil {
		return nil, err
	}

	conf := svc.config
	var email *mobius.EmailConfig
	switch conf.Email.EmailBackend {
	case "ses":
		email = &mobius.EmailConfig{
			Backend: conf.Email.EmailBackend,
			Config: mobius.SESConfig{
				Region:    conf.SES.Region,
				SourceARN: conf.SES.SourceArn,
			},
		}
	default:
		// SES is the only email provider configured as server envs/yaml file, the default implementation, SMTP, is configured via API/UI
		// SMTP config gets its own dedicated section in the AppConfig response
	}

	return email, nil
}

func (svc *Service) PartnershipsConfig(ctx context.Context) (*mobius.Partnerships, error) {
	if err := svc.authz.Authorize(ctx, &mobius.AppConfig{}, mobius.ActionRead); err != nil {
		return nil, err
	}
	enablePrimo := svc.config.Partnerships.EnablePrimo
	if !enablePrimo {
		// for now, since this is the only partnership of this type, exclude the whole struct if not enabled
		return nil, nil
	}
	return &mobius.Partnerships{
		EnablePrimo: svc.config.Partnerships.EnablePrimo,
	}, nil
}
