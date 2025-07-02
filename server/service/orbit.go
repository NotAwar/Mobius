package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/notawar/mobius/server"
	"github.com/notawar/mobius/server/contexts/capabilities"
	"github.com/notawar/mobius/server/contexts/ctxerr"
	hostctx "github.com/notawar/mobius/server/contexts/host"
	"github.com/notawar/mobius/server/contexts/license"
	"github.com/notawar/mobius/server/contexts/logging"
	"github.com/notawar/mobius/server/mobius"
	"github.com/notawar/mobius/server/mdm"
	microsoft_mdm "github.com/notawar/mobius/server/mdm/microsoft"
	"github.com/notawar/mobius/server/ptr"
	"github.com/notawar/mobius/server/service/middleware/endpoint_utils"
	"github.com/notawar/mobius/server/worker"
	"github.com/go-kit/log/level"
)

type setOrbitNodeKeyer interface {
	setOrbitNodeKey(nodeKey string)
}

// EnrollOrbitRequest is the request Orbit instances use to enroll to Mobius.
type EnrollOrbitRequest struct {
	// EnrollSecret is the secret to authenticate the enroll request.
	EnrollSecret string `json:"enroll_secret"`
	// HardwareUUID is the device's hardware UUID.
	HardwareUUID string `json:"hardware_uuid"`
	// HardwareSerial is the device's serial number.
	HardwareSerial string `json:"hardware_serial"`
	// Hostname is the device's hostname.
	Hostname string `json:"hostname"`
	// Platform is the device's platform as defined by osquery.
	Platform string `json:"platform"`
	// OsqueryIdentifier holds the identifier used by osquery.
	// If not set, then the hardware UUID is used to match orbit and osquery.
	OsqueryIdentifier string `json:"osquery_identifier"`
	// ComputerName is the device's friendly name (optional).
	ComputerName string `json:"computer_name"`
	// HardwareModel is the device's hardware model.
	HardwareModel string `json:"hardware_model"`
}

type EnrollOrbitResponse struct {
	OrbitNodeKey string `json:"orbit_node_key,omitempty"`
	Err          error  `json:"error,omitempty"`
}

type orbitGetConfigRequest struct {
	OrbitNodeKey string `json:"orbit_node_key"`
}

func (r *orbitGetConfigRequest) setOrbitNodeKey(nodeKey string) {
	r.OrbitNodeKey = nodeKey
}

func (r *orbitGetConfigRequest) orbitHostNodeKey() string {
	return r.OrbitNodeKey
}

type orbitGetConfigResponse struct {
	mobius.OrbitConfig
	Err error `json:"error,omitempty"`
}

func (r orbitGetConfigResponse) Error() error { return r.Err }

func (r EnrollOrbitResponse) Error() error { return r.Err }

// HijackRender so we can add a header with the server capabilities in the
// response, allowing Orbit to know what features are available without the
// need to enroll.
func (r EnrollOrbitResponse) HijackRender(ctx context.Context, w http.ResponseWriter) {
	writeCapabilitiesHeader(w, mobius.GetServerOrbitCapabilities())
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")

	if err := enc.Encode(r); err != nil {
		endpoint_utils.EncodeError(ctx, newOsqueryError(fmt.Sprintf("orbit enroll failed: %s", err)), w)
	}
}

func enrollOrbitEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*EnrollOrbitRequest)
	nodeKey, err := svc.EnrollOrbit(ctx, mobius.OrbitHostInfo{
		HardwareUUID:      req.HardwareUUID,
		HardwareSerial:    req.HardwareSerial,
		Hostname:          req.Hostname,
		Platform:          req.Platform,
		OsqueryIdentifier: req.OsqueryIdentifier,
		ComputerName:      req.ComputerName,
		HardwareModel:     req.HardwareModel,
	}, req.EnrollSecret)
	if err != nil {
		return EnrollOrbitResponse{Err: err}, nil
	}
	return EnrollOrbitResponse{OrbitNodeKey: nodeKey}, nil
}

func (svc *Service) AuthenticateOrbitHost(ctx context.Context, orbitNodeKey string) (*mobius.Host, bool, error) {
	svc.authz.SkipAuthorization(ctx)

	if orbitNodeKey == "" {
		return nil, false, ctxerr.Wrap(ctx, mobius.NewAuthRequiredError("authentication error: missing orbit node key"))
	}

	host, err := svc.ds.LoadHostByOrbitNodeKey(ctx, orbitNodeKey)
	switch {
	case err == nil:
		// OK
	case mobius.IsNotFound(err):
		return nil, false, ctxerr.Wrap(ctx, mobius.NewAuthRequiredError("authentication error: invalid orbit node key"))
	default:
		return nil, false, ctxerr.Wrap(ctx, err, "authentication error orbit")
	}

	return host, svc.debugEnabledForHost(ctx, host.ID), nil
}

// EnrollOrbit enrolls an Orbit instance to Mobius and returns the orbit node key.
func (svc *Service) EnrollOrbit(ctx context.Context, hostInfo mobius.OrbitHostInfo, enrollSecret string) (string, error) {
	// this is not a user-authenticated endpoint
	svc.authz.SkipAuthorization(ctx)

	logging.WithLevel(
		logging.WithExtras(ctx,
			"hardware_uuid", hostInfo.HardwareUUID,
			"hardware_serial", hostInfo.HardwareSerial,
			"hostname", hostInfo.Hostname,
			"platform", hostInfo.Platform,
			"osquery_identifier", hostInfo.OsqueryIdentifier,
			"computer_name", hostInfo.ComputerName,
			"hardware_model", hostInfo.HardwareModel,
		),
		level.Info,
	)

	secret, err := svc.ds.VerifyEnrollSecret(ctx, enrollSecret)
	if err != nil {
		if mobius.IsNotFound(err) {
			// OK - This can happen if the following sequence of events take place:
			// 	1. User deletes global/team enroll secret.
			// 	2. User deletes the host in Mobius.
			// 	3. Orbit tries to re-enroll using old secret.
			return "", mobius.NewAuthFailedError("invalid secret")
		}
		return "", mobius.OrbitError{Message: err.Error()}
	}

	orbitNodeKey, err := server.GenerateRandomText(svc.config.Osquery.NodeKeySize)
	if err != nil {
		return "", mobius.OrbitError{Message: "failed to generate orbit node key: " + err.Error()}
	}

	appConfig, err := svc.ds.AppConfig(ctx)
	if err != nil {
		return "", mobius.OrbitError{Message: "app config load failed: " + err.Error()}
	}

	host, err := svc.ds.EnrollOrbit(ctx, appConfig.MDM.EnabledAndConfigured, hostInfo, orbitNodeKey, secret.TeamID)
	if err != nil {
		return "", mobius.OrbitError{Message: "failed to enroll " + err.Error()}
	}

	if err := svc.NewActivity(
		ctx,
		nil,
		mobius.ActivityTypeMobiusEnrolled{
			HostID:          host.ID,
			HostSerial:      hostInfo.HardwareSerial,
			HostDisplayName: host.DisplayName(),
		},
	); err != nil {
		level.Error(svc.logger).Log("msg", "record mobius enroll activity", "err", err)
	}

	return orbitNodeKey, nil
}

func getOrbitConfigEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	cfg, err := svc.GetOrbitConfig(ctx)
	if err != nil {
		return orbitGetConfigResponse{Err: err}, nil
	}
	return orbitGetConfigResponse{OrbitConfig: cfg}, nil
}

func (svc *Service) GetOrbitConfig(ctx context.Context) (mobius.OrbitConfig, error) {
	// this is not a user-authenticated endpoint
	svc.authz.SkipAuthorization(ctx)

	host, ok := hostctx.FromContext(ctx)
	if !ok {
		return mobius.OrbitConfig{}, mobius.OrbitError{Message: "internal error: missing host from request context"}
	}

	appConfig, err := svc.ds.AppConfig(ctx)
	if err != nil {
		return mobius.OrbitConfig{}, err
	}

	isConnectedToMobiusMDM, err := svc.ds.IsHostConnectedToMobiusMDM(ctx, host)
	if err != nil {
		return mobius.OrbitConfig{}, ctxerr.Wrap(ctx, err, "checking if host is connected to Mobius")
	}

	mdmInfo, err := svc.ds.GetHostMDM(ctx, host.ID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return mobius.OrbitConfig{}, ctxerr.Wrap(ctx, err, "retrieving host mdm info")
	}

	// set the host's orbit notifications for macOS MDM
	var notifs mobius.OrbitConfigNotifications
	if appConfig.MDM.EnabledAndConfigured && host.IsOsqueryEnrolled() && host.Platform == "darwin" {
		needsDEPEnrollment := mdmInfo != nil && !mdmInfo.Enrolled && host.IsDEPAssignedToMobius()

		if needsDEPEnrollment {
			notifs.RenewEnrollmentProfile = true
		}

		manualMigrationEligible, err := mobius.IsEligibleForManualMigration(host, mdmInfo, isConnectedToMobiusMDM)
		if err != nil {
			return mobius.OrbitConfig{}, ctxerr.Wrap(ctx, err, "checking manual migration eligibility")
		}

		if appConfig.MDM.MacOSMigration.Enable &&
			(mobius.IsEligibleForDEPMigration(host, mdmInfo, isConnectedToMobiusMDM) || manualMigrationEligible) {
			notifs.NeedsMDMMigration = true
		}

		if isConnectedToMobiusMDM {
			// If there is no software or script configured for setup experience and this is the
			// first time orbit is calling the /config endpoint, then this host
			// will not have a row in host_mdm_apple_awaiting_configuration.
			// On subsequent calls to /config, the host WILL have a row in
			// host_mdm_apple_awaiting_configuration.
			inSetupAssistant, err := svc.ds.GetHostAwaitingConfiguration(ctx, host.UUID)
			if err != nil && !mobius.IsNotFound(err) {
				return mobius.OrbitConfig{}, ctxerr.Wrap(ctx, err, "checking if host is in setup experience")
			}

			if inSetupAssistant {
				notifs.RunSetupExperience = true
			}

			if inSetupAssistant {
				// If the client is running a mobiusdaemon that doesn't support setup
				// experience, then we should fall back to the "old way" of releasing
				// the device.
				mp, ok := capabilities.FromContext(ctx)
				if !ok || !mp.Has(mobius.CapabilitySetupExperience) {
					level.Debug(svc.logger).Log("msg", "host doesn't support setup experience, falling back to worker-based device release", "host_uuid", host.UUID)
					if err := svc.processReleaseDeviceForOldMobiusd(ctx, host); err != nil {
						return mobius.OrbitConfig{}, err
					}
				}
			}
		}
	}

	// set the host's orbit notifications for Windows MDM
	if appConfig.MDM.WindowsEnabledAndConfigured {
		if isEligibleForWindowsMDMEnrollment(host, mdmInfo) {
			discoURL, err := microsoft_mdm.ResolveWindowsMDMDiscovery(appConfig.ServerSettings.ServerURL)
			if err != nil {
				return mobius.OrbitConfig{}, err
			}
			notifs.WindowsMDMDiscoveryEndpoint = discoURL
			notifs.NeedsProgrammaticWindowsMDMEnrollment = true
		} else if appConfig.MDM.WindowsMigrationEnabled && isEligibleForWindowsMDMMigration(host, mdmInfo) {
			notifs.NeedsMDMMigration = true

			// Set the host to refetch the "critical queries" quickly for some time,
			// to improve ingestion time of the unenroll and make the host eligible to
			// enroll into Mobius faster.
			if host.RefetchCriticalQueriesUntil == nil {
				refetchUntil := svc.clock.Now().Add(mobius.RefetchMDMUnenrollCriticalQueryDuration)
				host.RefetchCriticalQueriesUntil = &refetchUntil
				if err := svc.ds.UpdateHostRefetchCriticalQueriesUntil(ctx, host.ID, &refetchUntil); err != nil {
					return mobius.OrbitConfig{}, err
				}
			}
		}
	}
	if !appConfig.MDM.WindowsEnabledAndConfigured {
		if host.IsEligibleForWindowsMDMUnenrollment(isConnectedToMobiusMDM) {
			notifs.NeedsProgrammaticWindowsMDMUnenrollment = true
		}
	}

	// load the (active, ready to execute) pending script executions for that host
	pending, err := svc.ds.ListReadyToExecuteScriptsForHost(ctx, host.ID, appConfig.ServerSettings.ScriptsDisabled)
	if err != nil {
		return mobius.OrbitConfig{}, err
	}
	if len(pending) > 0 {
		execIDs := make([]string, 0, len(pending))
		for _, p := range pending {
			execIDs = append(execIDs, p.ExecutionID)
		}
		notifs.PendingScriptExecutionIDs = execIDs
	}

	notifs.RunDiskEncryptionEscrow = host.IsLUKSSupported() &&
		host.DiskEncryptionEnabled != nil &&
		*host.DiskEncryptionEnabled &&
		svc.ds.IsHostPendingEscrow(ctx, host.ID)

	// load the (active, ready to execute) pending software install executions for that host
	pendingInstalls, err := svc.ds.ListReadyToExecuteSoftwareInstalls(ctx, host.ID)
	if err != nil {
		return mobius.OrbitConfig{}, err
	}
	if len(pendingInstalls) > 0 {
		notifs.PendingSoftwareInstallerIDs = pendingInstalls
	}

	// team ID is not nil, get team specific flags and options
	if host.TeamID != nil {
		teamAgentOptions, err := svc.ds.TeamAgentOptions(ctx, *host.TeamID)
		if err != nil {
			return mobius.OrbitConfig{}, err
		}

		var opts mobius.AgentOptions
		if teamAgentOptions != nil && len(*teamAgentOptions) > 0 {
			if err := json.Unmarshal(*teamAgentOptions, &opts); err != nil {
				return mobius.OrbitConfig{}, err
			}
		}

		extensionsFiltered, err := svc.filterExtensionsForHost(ctx, opts.Extensions, host)
		if err != nil {
			return mobius.OrbitConfig{}, err
		}

		mdmConfig, err := svc.ds.TeamMDMConfig(ctx, *host.TeamID)
		if err != nil {
			return mobius.OrbitConfig{}, err
		}

		var nudgeConfig *mobius.NudgeConfig
		if appConfig.MDM.EnabledAndConfigured &&
			mdmConfig != nil &&
			host.IsOsqueryEnrolled() &&
			isConnectedToMobiusMDM &&
			mdmConfig.MacOSUpdates.Configured() {

			hostOS, err := svc.ds.GetHostOperatingSystem(ctx, host.ID)
			if errors.Is(err, sql.ErrNoRows) {
				// host os has not been collected yet (no details query)
				hostOS = &mobius.OperatingSystem{}
			} else if err != nil {
				return mobius.OrbitConfig{}, err
			}
			requiresNudge, err := hostOS.RequiresNudge()
			if err != nil {
				return mobius.OrbitConfig{}, err
			}

			if requiresNudge {
				nudgeConfig, err = mobius.NewNudgeConfig(mdmConfig.MacOSUpdates)
				if err != nil {
					return mobius.OrbitConfig{}, err
				}
			}
		}

		err = svc.setDiskEncryptionNotifications(
			ctx,
			&notifs,
			host,
			appConfig,
			mdmConfig.EnableDiskEncryption,
			isConnectedToMobiusMDM,
			mdmInfo,
		)
		if err != nil {
			return mobius.OrbitConfig{}, ctxerr.Wrap(ctx, err, "setting team disk encryption notifications")
		}

		var updateChannels *mobius.OrbitUpdateChannels
		if len(opts.UpdateChannels) > 0 {
			var uc mobius.OrbitUpdateChannels
			if err := json.Unmarshal(opts.UpdateChannels, &uc); err != nil {
				return mobius.OrbitConfig{}, err
			}
			updateChannels = &uc
		}

		// only unset this flag once we know there were no errors so this notification will be picked up by the agent
		if notifs.RunDiskEncryptionEscrow {
			_ = svc.ds.ClearPendingEscrow(ctx, host.ID)
		}

		return mobius.OrbitConfig{
			ScriptExeTimeout: opts.ScriptExecutionTimeout,
			Flags:            opts.CommandLineStartUpFlags,
			Extensions:       extensionsFiltered,
			Notifications:    notifs,
			NudgeConfig:      nudgeConfig,
			UpdateChannels:   updateChannels,
		}, nil
	}

	// team ID is nil, get global flags and options
	var opts mobius.AgentOptions
	if appConfig.AgentOptions != nil {
		if err := json.Unmarshal(*appConfig.AgentOptions, &opts); err != nil {
			return mobius.OrbitConfig{}, err
		}
	}

	extensionsFiltered, err := svc.filterExtensionsForHost(ctx, opts.Extensions, host)
	if err != nil {
		return mobius.OrbitConfig{}, err
	}

	var nudgeConfig *mobius.NudgeConfig
	if appConfig.MDM.EnabledAndConfigured &&
		isConnectedToMobiusMDM &&
		host.IsOsqueryEnrolled() &&
		appConfig.MDM.MacOSUpdates.Configured() {
		hostOS, err := svc.ds.GetHostOperatingSystem(ctx, host.ID)
		if errors.Is(err, sql.ErrNoRows) {
			// host os has not been collected yet (no details query)
			hostOS = &mobius.OperatingSystem{}
		} else if err != nil {
			return mobius.OrbitConfig{}, err
		}
		requiresNudge, err := hostOS.RequiresNudge()
		if err != nil {
			return mobius.OrbitConfig{}, err
		}

		if requiresNudge {
			nudgeConfig, err = mobius.NewNudgeConfig(appConfig.MDM.MacOSUpdates)
			if err != nil {
				return mobius.OrbitConfig{}, err
			}
		}
	}

	err = svc.setDiskEncryptionNotifications(
		ctx,
		&notifs,
		host,
		appConfig,
		appConfig.MDM.EnableDiskEncryption.Value,
		isConnectedToMobiusMDM,
		mdmInfo,
	)
	if err != nil {
		return mobius.OrbitConfig{}, ctxerr.Wrap(ctx, err, "setting no-team disk encryption notifications")
	}

	var updateChannels *mobius.OrbitUpdateChannels
	if len(opts.UpdateChannels) > 0 {
		var uc mobius.OrbitUpdateChannels
		if err := json.Unmarshal(opts.UpdateChannels, &uc); err != nil {
			return mobius.OrbitConfig{}, err
		}
		updateChannels = &uc
	}

	// only unset this flag once we know there were no errors so this notification will be picked up by the agent
	if notifs.RunDiskEncryptionEscrow {
		_ = svc.ds.ClearPendingEscrow(ctx, host.ID)
	}

	return mobius.OrbitConfig{
		ScriptExeTimeout: opts.ScriptExecutionTimeout,
		Flags:            opts.CommandLineStartUpFlags,
		Extensions:       extensionsFiltered,
		Notifications:    notifs,
		NudgeConfig:      nudgeConfig,
		UpdateChannels:   updateChannels,
	}, nil
}

func (svc *Service) processReleaseDeviceForOldMobiusd(ctx context.Context, host *mobius.Host) error {
	var manualRelease bool
	if host.TeamID == nil {
		ac, err := svc.ds.AppConfig(ctx)
		if err != nil {
			return ctxerr.Wrap(ctx, err, "get AppConfig to read enable_release_device_manually")
		}
		manualRelease = ac.MDM.MacOSSetup.EnableReleaseDeviceManually.Value
	} else {
		tm, err := svc.ds.Team(ctx, *host.TeamID)
		if err != nil {
			return ctxerr.Wrap(ctx, err, "get Team to read enable_release_device_manually")
		}
		manualRelease = tm.Config.MDM.MacOSSetup.EnableReleaseDeviceManually.Value
	}

	if !manualRelease {
		// For the commands to await, since we're in an orbit endpoint we know that
		// mobiusdaemon has already been installed, so we only need to check for the
		// bootstrap package install and the SSO account configuration (both are
		// optional).
		bootstrapCmdUUID, err := svc.ds.GetHostBootstrapPackageCommand(ctx, host.UUID)
		if err != nil && !mobius.IsNotFound(err) {
			return ctxerr.Wrap(ctx, err, "get bootstrap package command")
		}

		// AccountConfiguration covers the (optional) command to setup SSO.
		adminTeamFilter := mobius.TeamFilter{
			User: &mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)},
		}
		acctCmds, err := svc.ds.ListMDMCommands(ctx, adminTeamFilter, &mobius.MDMCommandListOptions{
			Filters: mobius.MDMCommandFilters{
				HostIdentifier: host.UUID,
				RequestType:    "AccountConfiguration",
			},
		})
		if err != nil {
			return ctxerr.Wrap(ctx, err, "list AccountConfiguration commands")
		}
		var acctConfigCmdUUID string
		if len(acctCmds) > 0 {
			// there may be more than one if e.g. the worker job that sends them had to
			// retry, but they would all be processed anyway so we can only care about
			// the first one.
			acctConfigCmdUUID = acctCmds[0].CommandUUID
		}

		// Enroll reference arg is not used in the release device task, passing empty string.
		if err := worker.QueueAppleMDMJob(ctx, svc.ds, svc.logger, worker.AppleMDMPostDEPReleaseDeviceTask,
			host.UUID, host.Platform, host.TeamID, "", false, bootstrapCmdUUID, acctConfigCmdUUID); err != nil {
			return ctxerr.Wrap(ctx, err, "queue Apple Post-DEP release device job")
		}
	}

	// at this point we know for sure that it will get released, but we need to
	// ensure we won't continually enqueue new worker jobs for that host until it
	// is released. To do so, we clear up the setup experience data (since anyway
	// this host will not go through that new flow).
	if err := svc.ds.SetHostAwaitingConfiguration(ctx, host.UUID, false); err != nil {
		return ctxerr.Wrap(ctx, err, "unset host awaiting configuration")
	}

	return nil
}

func (svc *Service) setDiskEncryptionNotifications(
	ctx context.Context,
	notifs *mobius.OrbitConfigNotifications,
	host *mobius.Host,
	appConfig *mobius.AppConfig,
	diskEncryptionConfigured bool,
	isConnectedToMobiusMDM bool,
	mdmInfo *mobius.HostMDM,
) error {
	anyMDMConfigured := appConfig.MDM.EnabledAndConfigured || appConfig.MDM.WindowsEnabledAndConfigured
	if !anyMDMConfigured ||
		!isConnectedToMobiusMDM ||
		!host.IsOsqueryEnrolled() ||
		!diskEncryptionConfigured {
		return nil
	}

	encryptionKey, err := svc.ds.GetHostDiskEncryptionKey(ctx, host.ID)
	if err != nil {
		if !mobius.IsNotFound(err) {
			return ctxerr.Wrap(ctx, err, "fetching host disk encryption key")
		}
	}

	switch host.MobiusPlatform() {
	case "darwin":
		mp, ok := capabilities.FromContext(ctx)
		if !ok {
			level.Debug(svc.logger).Log("msg", "no capabilities in context, skipping disk encryption notification")
			return nil
		}

		if !mp.Has(mobius.CapabilityEscrowBuddy) {
			level.Debug(svc.logger).Log("msg", "host doesn't support Escrow Buddy, skipping disk encryption notification", "host_uuid", host.UUID)
			return nil
		}

		notifs.RotateDiskEncryptionKey = encryptionKey != nil && encryptionKey.Decryptable != nil && !*encryptionKey.Decryptable
	case "windows":
		isServer := mdmInfo != nil && mdmInfo.IsServer
		needsEncryption := host.DiskEncryptionEnabled != nil && !*host.DiskEncryptionEnabled
		keyWasDecrypted := encryptionKey != nil && encryptionKey.Decryptable != nil && *encryptionKey.Decryptable
		encryptedWithoutKey := host.DiskEncryptionEnabled != nil && *host.DiskEncryptionEnabled && !keyWasDecrypted
		notifs.EnforceBitLockerEncryption = !isServer &&
			mdmInfo != nil &&
			(needsEncryption || encryptedWithoutKey)
	}

	return nil
}

// filterExtensionsForHost filters a extensions configuration depending on the host platform and label membership.
//
// If all extensions are filtered, then it returns (nil, nil) (Orbit expects empty extensions if there
// are no extensions for the host.)
func (svc *Service) filterExtensionsForHost(ctx context.Context, extensions json.RawMessage, host *mobius.Host) (json.RawMessage, error) {
	if len(extensions) == 0 {
		return nil, nil
	}
	var extensionsInfo mobius.Extensions
	if err := json.Unmarshal(extensions, &extensionsInfo); err != nil {
		return nil, ctxerr.Wrap(ctx, err, "unmarshal extensions config")
	}

	// Filter the extensions by platform.
	extensionsInfo.FilterByHostPlatform(host.Platform)

	// Filter the extensions by labels (premium only feature).
	if license, _ := license.FromContext(ctx); license != nil && license.IsPremium() {
		for extensionName, extensionInfo := range extensionsInfo {
			hostIsMemberOfAllLabels, err := svc.ds.HostMemberOfAllLabels(ctx, host.ID, extensionInfo.Labels)
			if err != nil {
				return nil, ctxerr.Wrap(ctx, err, "check host labels")
			}
			if hostIsMemberOfAllLabels {
				// Do not filter out, but there's no need to send the label names to the devices.
				extensionInfo.Labels = nil
				extensionsInfo[extensionName] = extensionInfo
			} else {
				delete(extensionsInfo, extensionName)
			}
		}
	}
	// Orbit expects empty message if no extensions apply.
	if len(extensionsInfo) == 0 {
		return nil, nil
	}
	extensionsFiltered, err := json.Marshal(extensionsInfo)
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err, "marshal extensions config")
	}
	return extensionsFiltered, nil
}

/////////////////////////////////////////////////////////////////////////////////
// Ping orbit endpoint
/////////////////////////////////////////////////////////////////////////////////

type orbitPingRequest struct{}

type orbitPingResponse struct{}

func (r orbitPingResponse) HijackRender(ctx context.Context, w http.ResponseWriter) {
	writeCapabilitiesHeader(w, mobius.GetServerOrbitCapabilities())
}

func (r orbitPingResponse) Error() error { return nil }

// NOTE: we're intentionally not reading the capabilities header in this
// endpoint as is unauthenticated and we don't want to trust whatever comes in
// there.
func orbitPingEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	svc.DisableAuthForPing(ctx)
	return orbitPingResponse{}, nil
}

/////////////////////////////////////////////////////////////////////////////////
// SetOrUpdateDeviceToken endpoint
/////////////////////////////////////////////////////////////////////////////////

type setOrUpdateDeviceTokenRequest struct {
	OrbitNodeKey    string `json:"orbit_node_key"`
	DeviceAuthToken string `json:"device_auth_token"`
}

func (r *setOrUpdateDeviceTokenRequest) setOrbitNodeKey(nodeKey string) {
	r.OrbitNodeKey = nodeKey
}

func (r *setOrUpdateDeviceTokenRequest) orbitHostNodeKey() string {
	return r.OrbitNodeKey
}

type setOrUpdateDeviceTokenResponse struct {
	Err error `json:"error,omitempty"`
}

func (r setOrUpdateDeviceTokenResponse) Error() error { return r.Err }

func setOrUpdateDeviceTokenEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*setOrUpdateDeviceTokenRequest)
	if err := svc.SetOrUpdateDeviceAuthToken(ctx, req.DeviceAuthToken); err != nil {
		return setOrUpdateDeviceTokenResponse{Err: err}, nil
	}
	return setOrUpdateDeviceTokenResponse{}, nil
}

func (svc *Service) SetOrUpdateDeviceAuthToken(ctx context.Context, deviceAuthToken string) error {
	// this is not a user-authenticated endpoint
	svc.authz.SkipAuthorization(ctx)

	if len(deviceAuthToken) == 0 {
		return badRequest("device auth token cannot be empty")
	}

	if url.QueryEscape(deviceAuthToken) != deviceAuthToken {
		return badRequest("device auth token contains invalid characters")
	}

	host, ok := hostctx.FromContext(ctx)
	if !ok {
		return newOsqueryError("internal error: missing host from request context")
	}

	if err := svc.ds.SetOrUpdateDeviceAuthToken(ctx, host.ID, deviceAuthToken); err != nil {
		if errors.As(err, &mobius.ConflictError{}) {
			return err
		}
		return newOsqueryError(fmt.Sprintf("internal error: failed to set or update device auth token: %s", err))
	}

	return nil
}

/////////////////////////////////////////////////////////////////////////////////
// Get Orbit pending script execution request
/////////////////////////////////////////////////////////////////////////////////

type orbitGetScriptRequest struct {
	OrbitNodeKey string `json:"orbit_node_key"`
	ExecutionID  string `json:"execution_id"`
}

// interface implementation required by the OrbitClient
func (r *orbitGetScriptRequest) setOrbitNodeKey(nodeKey string) {
	r.OrbitNodeKey = nodeKey
}

// interface implementation required by orbit authentication
func (r *orbitGetScriptRequest) orbitHostNodeKey() string {
	return r.OrbitNodeKey
}

type orbitGetScriptResponse struct {
	Err error `json:"error,omitempty"`
	*mobius.HostScriptResult
}

func (r orbitGetScriptResponse) Error() error { return r.Err }

func getOrbitScriptEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*orbitGetScriptRequest)
	script, err := svc.GetHostScript(ctx, req.ExecutionID)
	if err != nil {
		return orbitGetScriptResponse{Err: err}, nil
	}
	return orbitGetScriptResponse{HostScriptResult: script}, nil
}

func (svc *Service) GetHostScript(ctx context.Context, execID string) (*mobius.HostScriptResult, error) {
	// this is not a user-authenticated endpoint
	svc.authz.SkipAuthorization(ctx)

	host, ok := hostctx.FromContext(ctx)
	if !ok {
		return nil, mobius.OrbitError{Message: "internal error: missing host from request context"}
	}

	// get the script's details
	script, err := svc.ds.GetHostScriptExecutionResult(ctx, execID)
	if err != nil {
		return nil, err
	}
	// ensure it cannot get access to a different host's script
	if script.HostID != host.ID {
		return nil, ctxerr.Wrap(ctx, newNotFoundError(), "no script found for this host")
	}

	// We expose secret variables in the script content to the host. The exposed secrets are only intended to go to the device and not accessible via the UI/API.
	script.ScriptContents, err = svc.ds.ExpandEmbeddedSecrets(ctx, script.ScriptContents)
	if err != nil {
		// This error should never occur because we validate secret variables on script upload.
		return nil, ctxerr.Wrap(ctx, err, fmt.Sprintf("expand embedded secrets for host %d and script %s", host.ID, execID))
	}

	return script, nil
}

/////////////////////////////////////////////////////////////////////////////////
// Post Orbit script execution result
/////////////////////////////////////////////////////////////////////////////////

type orbitPostScriptResultRequest struct {
	OrbitNodeKey string `json:"orbit_node_key"`
	*mobius.HostScriptResultPayload
}

// interface implementation required by the OrbitClient
func (r *orbitPostScriptResultRequest) setOrbitNodeKey(nodeKey string) {
	r.OrbitNodeKey = nodeKey
}

// interface implementation required by orbit authentication
func (r *orbitPostScriptResultRequest) orbitHostNodeKey() string {
	return r.OrbitNodeKey
}

type orbitPostScriptResultResponse struct {
	Err error `json:"error,omitempty"`
}

func (r orbitPostScriptResultResponse) Error() error { return r.Err }

func postOrbitScriptResultEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*orbitPostScriptResultRequest)
	if err := svc.SaveHostScriptResult(ctx, req.HostScriptResultPayload); err != nil {
		return orbitPostScriptResultResponse{Err: err}, nil
	}
	return orbitPostScriptResultResponse{}, nil
}

func (svc *Service) SaveHostScriptResult(ctx context.Context, result *mobius.HostScriptResultPayload) error {
	// this is not a user-authenticated endpoint
	svc.authz.SkipAuthorization(ctx)

	host, ok := hostctx.FromContext(ctx)
	if !ok {
		return mobius.OrbitError{Message: "internal error: missing host from request context"}
	}
	if result == nil {
		return ctxerr.Wrap(ctx, &mobius.BadRequestError{Message: "missing script result"}, "save host script result")
	}

	// always use the authenticated host's ID as host_id
	result.HostID = host.ID
	hsr, action, err := svc.ds.SetHostScriptExecutionResult(ctx, result)
	if err != nil {
		return ctxerr.Wrap(ctx, err, "save host script result")
	}

	// FIXME: datastore implementation of action seems rather brittle, can it be refactored?
	if action == "" && mobius.IsSetupExperienceSupported(host.Platform) {
		// this might be a setup experience script result
		if updated, err := maybeUpdateSetupExperienceStatus(ctx, svc.ds, mobius.SetupExperienceScriptResult{
			HostUUID:    host.UUID,
			ExecutionID: result.ExecutionID,
			ExitCode:    result.ExitCode,
		}, true); err != nil {
			return ctxerr.Wrap(ctx, err, "update setup experience status")
		} else if updated {
			level.Debug(svc.logger).Log("msg", "setup experience script result updated", "host_uuid", host.UUID, "execution_id", result.ExecutionID)
			_, err := svc.EnterpriseOverrides.SetupExperienceNextStep(ctx, host.UUID)
			if err != nil {
				return ctxerr.Wrap(ctx, err, "getting next step for host setup experience")
			}
		}
	}

	// don't create a "past" activity if the result was for a canceled activity
	if hsr != nil && !hsr.Canceled {
		var user *mobius.User
		if hsr.UserID != nil {
			user, err = svc.ds.UserByID(ctx, *hsr.UserID)
			if err != nil {
				return ctxerr.Wrap(ctx, err, "get host script execution user")
			}
		}
		var scriptName string

		switch {
		case hsr.ScriptID != nil:
			scr, err := svc.ds.Script(ctx, *hsr.ScriptID)
			if err != nil {
				return ctxerr.Wrap(ctx, err, "get saved script")
			}
			scriptName = scr.Name
		case hsr.SetupExperienceScriptID != nil:
			scr, err := svc.ds.GetSetupExperienceScriptByID(ctx, *hsr.SetupExperienceScriptID)
			if err != nil {
				return ctxerr.Wrap(ctx, err, "get setup experience script")
			}

			scriptName = scr.Name
		}

		switch action {
		case "uninstall":
			softwareTitleName, selfService, err := svc.ds.GetDetailsForUninstallFromExecutionID(ctx, hsr.ExecutionID)
			if err != nil {
				return ctxerr.Wrap(ctx, err, "get software title from execution ID")
			}
			activityStatus := "failed"
			if hsr.ExitCode != nil && *hsr.ExitCode == 0 {
				activityStatus = "uninstalled"
			}
			if err := svc.NewActivity(
				ctx,
				user,
				mobius.ActivityTypeUninstalledSoftware{
					HostID:          host.ID,
					HostDisplayName: host.DisplayName(),
					SoftwareTitle:   softwareTitleName,
					ExecutionID:     hsr.ExecutionID,
					Status:          activityStatus,
					SelfService:     selfService,
				},
			); err != nil {
				return ctxerr.Wrap(ctx, err, "create activity for script execution request")
			}
		default:
			// TODO(sarah): We may need to special case lock/unlock script results here?
			var policyName *string
			if hsr.PolicyID != nil {
				if policy, err := svc.ds.PolicyLite(ctx, *hsr.PolicyID); err == nil {
					policyName = &policy.Name // fall back to blank policy name if we can't retrieve the policy
				}
			}

			if err := svc.NewActivity(
				ctx,
				user,
				mobius.ActivityTypeRanScript{
					HostID:            host.ID,
					HostDisplayName:   host.DisplayName(),
					ScriptExecutionID: hsr.ExecutionID,
					ScriptName:        scriptName,
					Async:             !hsr.SyncRequest,
					PolicyID:          hsr.PolicyID,
					PolicyName:        policyName,
				},
			); err != nil {
				return ctxerr.Wrap(ctx, err, "create activity for script execution request")
			}
		}

	}
	return nil
}

/////////////////////////////////////////////////////////////////////////////////
// Post Orbit device mapping (custom email)
/////////////////////////////////////////////////////////////////////////////////

type orbitPutDeviceMappingRequest struct {
	OrbitNodeKey string `json:"orbit_node_key"`
	Email        string `json:"email"`
}

// interface implementation required by the OrbitClient
func (r *orbitPutDeviceMappingRequest) setOrbitNodeKey(nodeKey string) {
	r.OrbitNodeKey = nodeKey
}

// interface implementation required by orbit authentication
func (r *orbitPutDeviceMappingRequest) orbitHostNodeKey() string {
	return r.OrbitNodeKey
}

type orbitPutDeviceMappingResponse struct {
	Err error `json:"error,omitempty"`
}

func (r orbitPutDeviceMappingResponse) Error() error { return r.Err }

func putOrbitDeviceMappingEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*orbitPutDeviceMappingRequest)

	host, ok := hostctx.FromContext(ctx)
	if !ok {
		err := newOsqueryError("internal error: missing host from request context")
		return orbitPutDeviceMappingResponse{Err: err}, nil
	}

	_, err := svc.SetCustomHostDeviceMapping(ctx, host.ID, req.Email)
	return orbitPutDeviceMappingResponse{Err: err}, nil
}

/////////////////////////////////////////////////////////////////////////////////
// Post Orbit disk encryption key
/////////////////////////////////////////////////////////////////////////////////

type orbitPostDiskEncryptionKeyRequest struct {
	OrbitNodeKey  string `json:"orbit_node_key"`
	EncryptionKey []byte `json:"encryption_key"`
	ClientError   string `json:"client_error"`
}

// interface implementation required by the OrbitClient
func (r *orbitPostDiskEncryptionKeyRequest) setOrbitNodeKey(nodeKey string) {
	r.OrbitNodeKey = nodeKey
}

// interface implementation required by orbit authentication
func (r *orbitPostDiskEncryptionKeyRequest) orbitHostNodeKey() string {
	return r.OrbitNodeKey
}

type orbitPostDiskEncryptionKeyResponse struct {
	Err error `json:"error,omitempty"`
}

func (r orbitPostDiskEncryptionKeyResponse) Error() error { return r.Err }
func (r orbitPostDiskEncryptionKeyResponse) Status() int  { return http.StatusNoContent }

func postOrbitDiskEncryptionKeyEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*orbitPostDiskEncryptionKeyRequest)
	if err := svc.SetOrUpdateDiskEncryptionKey(ctx, string(req.EncryptionKey), req.ClientError); err != nil {
		return orbitPostDiskEncryptionKeyResponse{Err: err}, nil
	}
	return orbitPostDiskEncryptionKeyResponse{}, nil
}

func (svc *Service) SetOrUpdateDiskEncryptionKey(ctx context.Context, encryptionKey, clientError string) error {
	// this is not a user-authenticated endpoint
	svc.authz.SkipAuthorization(ctx)

	host, ok := hostctx.FromContext(ctx)
	if !ok {
		return newOsqueryError("internal error: missing host from request context")
	}

	connected, err := svc.ds.IsHostConnectedToMobiusMDM(ctx, host)
	if err != nil {
		return ctxerr.Wrap(ctx, err, "checking if host is connected to Mobius")
	}

	if !connected {
		return badRequest("host is not enrolled with mobius")
	}

	var (
		encryptedEncryptionKey string
		decryptable            *bool
	)

	// only set the encryption key if there was no client error
	if clientError == "" && encryptionKey != "" {
		wstepCert, _, _, err := svc.config.MDM.MicrosoftWSTEP()
		if err != nil {
			// should never return an error because the WSTEP is first parsed and
			// cached at the start of the mobius serve process.
			return ctxerr.Wrap(ctx, err, "get WSTEP certificate")
		}
		enc, err := microsoft_mdm.Encrypt(encryptionKey, wstepCert.Leaf)
		if err != nil {
			return ctxerr.Wrap(ctx, err, "encrypt the key with WSTEP certificate")
		}
		encryptedEncryptionKey = enc
		decryptable = ptr.Bool(true)
	}

	if err := svc.ds.SetOrUpdateHostDiskEncryptionKey(ctx, host, encryptedEncryptionKey, clientError, decryptable); err != nil {
		return ctxerr.Wrap(ctx, err, "set or update disk encryption key")
	}

	return nil
}

/////////////////////////////////////////////////////////////////////////////////
// Post Orbit LUKS (Linux disk encryption) data
/////////////////////////////////////////////////////////////////////////////////

type orbitPostLUKSRequest struct {
	OrbitNodeKey string `json:"orbit_node_key"`
	Passphrase   string `json:"passphrase"`
	Salt         string `json:"salt"`
	KeySlot      *uint  `json:"key_slot"`
	ClientError  string `json:"client_error"`
}

// interface implementation required by the OrbitClient
func (r *orbitPostLUKSRequest) setOrbitNodeKey(nodeKey string) {
	r.OrbitNodeKey = nodeKey
}

// interface implementation required by orbit authentication
func (r *orbitPostLUKSRequest) orbitHostNodeKey() string {
	return r.OrbitNodeKey
}

type orbitPostLUKSResponse struct {
	Err error `json:"error,omitempty"`
}

func (r orbitPostLUKSResponse) Error() error { return r.Err }
func (r orbitPostLUKSResponse) Status() int  { return http.StatusNoContent }

func postOrbitLUKSEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*orbitPostLUKSRequest)
	if err := svc.EscrowLUKSData(ctx, req.Passphrase, req.Salt, req.KeySlot, req.ClientError); err != nil {
		return orbitPostLUKSResponse{Err: err}, nil
	}
	return orbitPostLUKSResponse{}, nil
}

func (svc *Service) EscrowLUKSData(ctx context.Context, passphrase string, salt string, keySlot *uint, clientError string) error {
	// this is not a user-authenticated endpoint
	svc.authz.SkipAuthorization(ctx)

	host, ok := hostctx.FromContext(ctx)
	if !ok {
		return newOsqueryError("internal error: missing host from request context")
	}

	if clientError != "" {
		return svc.ds.ReportEscrowError(ctx, host.ID, clientError)
	}

	encryptedPassphrase, encryptedSalt, validatedKeySlot, err := svc.validateAndEncrypt(ctx, passphrase, salt, keySlot)
	if err != nil {
		_ = svc.ds.ReportEscrowError(ctx, host.ID, err.Error())
		return err
	}

	return svc.ds.SaveLUKSData(ctx, host, encryptedPassphrase, encryptedSalt, validatedKeySlot)
}

func (svc *Service) validateAndEncrypt(ctx context.Context, passphrase string, salt string, keySlot *uint) (encryptedPassphrase string, encryptedSalt string, validatedKeySlot uint, err error) {
	if passphrase == "" || salt == "" || keySlot == nil {
		return "", "", 0, badRequest("passphrase, salt, and key_slot must be provided to escrow LUKS data")
	}
	if svc.config.Server.PrivateKey == "" {
		return "", "", 0, newOsqueryError("internal error: missing server private key")
	}

	encryptedPassphrase, err = mdm.EncryptAndEncode(passphrase, svc.config.Server.PrivateKey)
	if err != nil {
		return "", "", 0, ctxerr.Wrap(ctx, err, "internal error: could not encrypt LUKS data")
	}
	encryptedSalt, err = mdm.EncryptAndEncode(salt, svc.config.Server.PrivateKey)
	if err != nil {
		return "", "", 0, ctxerr.Wrap(ctx, err, "internal error: could not encrypt LUKS data")
	}

	return encryptedPassphrase, encryptedSalt, *keySlot, nil
}

/////////////////////////////////////////////////////////////////////////////////
// Get Orbit pending software installations
/////////////////////////////////////////////////////////////////////////////////

type orbitGetSoftwareInstallRequest struct {
	OrbitNodeKey string `json:"orbit_node_key"`
	OrbotNodeKey string `json:"orbot_node_key"` // legacy typo -- keep for backwards compatibility with orbit <= 1.38.0
	InstallUUID  string `json:"install_uuid"`
}

// interface implementation required by the OrbitClient
func (r *orbitGetSoftwareInstallRequest) setOrbitNodeKey(nodeKey string) {
	r.OrbitNodeKey = nodeKey
	r.OrbotNodeKey = nodeKey // legacy typo -- keep for backwards compatability with mobius server < 4.63.0
}

// interface implementation required by the OrbitClient
func (r *orbitGetSoftwareInstallRequest) orbitHostNodeKey() string {
	if r.OrbitNodeKey != "" {
		return r.OrbitNodeKey
	}
	return r.OrbotNodeKey
}

type orbitGetSoftwareInstallResponse struct {
	Err error `json:"error,omitempty"`
	*mobius.SoftwareInstallDetails
}

func (r orbitGetSoftwareInstallResponse) Error() error { return r.Err }

func getOrbitSoftwareInstallDetails(ctx context.Context, request any, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*orbitGetSoftwareInstallRequest)
	details, err := svc.GetSoftwareInstallDetails(ctx, req.InstallUUID)
	if err != nil {
		return orbitGetSoftwareInstallResponse{Err: err}, nil
	}

	return orbitGetSoftwareInstallResponse{SoftwareInstallDetails: details}, nil
}

func (svc *Service) GetSoftwareInstallDetails(ctx context.Context, installUUID string) (*mobius.SoftwareInstallDetails, error) {
	// this is not a user-authenticated endpoint
	svc.authz.SkipAuthorization(ctx)

	host, ok := hostctx.FromContext(ctx)
	if !ok {
		return nil, mobius.OrbitError{Message: "internal error: missing host from request context"}
	}

	details, err := svc.ds.GetSoftwareInstallDetails(ctx, installUUID)
	if err != nil {
		return nil, err
	}

	// ensure it cannot get access to a different host's installers
	if details.HostID != host.ID {
		return nil, ctxerr.Wrap(ctx, newNotFoundError(), "no installer found for this host")
	}
	return details, nil
}

// Download Orbit software installer request
/////////////////////////////////////////////////////////////////////////////////

type orbitDownloadSoftwareInstallerRequest struct {
	Alt          string `query:"alt"`
	OrbitNodeKey string `json:"orbit_node_key"`
	InstallerID  uint   `json:"installer_id"`
}

// interface implementation required by the OrbitClient
func (r *orbitDownloadSoftwareInstallerRequest) setOrbitNodeKey(nodeKey string) {
	r.OrbitNodeKey = nodeKey
}

// interface implementation required by orbit authentication
func (r *orbitDownloadSoftwareInstallerRequest) orbitHostNodeKey() string {
	return r.OrbitNodeKey
}

func orbitDownloadSoftwareInstallerEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*orbitDownloadSoftwareInstallerRequest)

	downloadRequested := req.Alt == "media"
	if !downloadRequested {
		// TODO: confirm error handling
		return orbitDownloadSoftwareInstallerResponse{Err: &mobius.BadRequestError{Message: "only alt=media is supported"}}, nil
	}

	p, err := svc.OrbitDownloadSoftwareInstaller(ctx, req.InstallerID)
	if err != nil {
		return orbitDownloadSoftwareInstallerResponse{Err: err}, nil
	}
	return orbitDownloadSoftwareInstallerResponse{payload: p}, nil
}

func (svc *Service) OrbitDownloadSoftwareInstaller(ctx context.Context, installerID uint) (*mobius.DownloadSoftwareInstallerPayload, error) {
	// skipauth: No authorization check needed due to implementation returning
	// only license error.
	svc.authz.SkipAuthorization(ctx)

	return nil, mobius.ErrMissingLicense
}

/////////////////////////////////////////////////////////////////////////////////
// Post Orbit software install result
/////////////////////////////////////////////////////////////////////////////////

type orbitPostSoftwareInstallResultRequest struct {
	OrbitNodeKey string `json:"orbit_node_key"`
	*mobius.HostSoftwareInstallResultPayload
}

// interface implementation required by the OrbitClient
func (r *orbitPostSoftwareInstallResultRequest) setOrbitNodeKey(nodeKey string) {
	r.OrbitNodeKey = nodeKey
}

func (r *orbitPostSoftwareInstallResultRequest) orbitHostNodeKey() string {
	return r.OrbitNodeKey
}

type orbitPostSoftwareInstallResultResponse struct {
	Err error `json:"error,omitempty"`
}

func (r orbitPostSoftwareInstallResultResponse) Error() error { return r.Err }
func (r orbitPostSoftwareInstallResultResponse) Status() int  { return http.StatusNoContent }

func postOrbitSoftwareInstallResultEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*orbitPostSoftwareInstallResultRequest)
	if err := svc.SaveHostSoftwareInstallResult(ctx, req.HostSoftwareInstallResultPayload); err != nil {
		return orbitPostSoftwareInstallResultResponse{Err: err}, nil
	}
	return orbitPostSoftwareInstallResultResponse{}, nil
}

func (svc *Service) SaveHostSoftwareInstallResult(ctx context.Context, result *mobius.HostSoftwareInstallResultPayload) error {
	// this is not a user-authenticated endpoint
	svc.authz.SkipAuthorization(ctx)

	host, ok := hostctx.FromContext(ctx)
	if !ok {
		return newOsqueryError("internal error: missing host from request context")
	}

	// always use the authenticated host's ID as host_id
	result.HostID = host.ID
	installWasCanceled, err := svc.ds.SetHostSoftwareInstallResult(ctx, result)
	if err != nil {
		return ctxerr.Wrap(ctx, err, "save host software installation result")
	}

	if mobius.IsSetupExperienceSupported(host.Platform) {
		// this might be a setup experience software install result
		if updated, err := maybeUpdateSetupExperienceStatus(ctx, svc.ds, mobius.SetupExperienceSoftwareInstallResult{
			HostUUID:        host.UUID,
			ExecutionID:     result.InstallUUID,
			InstallerStatus: result.Status(),
		}, true); err != nil {
			return ctxerr.Wrap(ctx, err, "update setup experience status")
		} else if updated {
			// TODO: call next step of setup experience?
			level.Debug(svc.logger).Log("msg", "setup experience script result updated", "host_uuid", host.UUID, "execution_id", result.InstallUUID)
		}
	}

	// do not create a "past" activity if the status is not terminal or if the activity
	// was canceled.
	if status := result.Status(); status != mobius.SoftwareInstallPending && !installWasCanceled {
		hsi, err := svc.ds.GetSoftwareInstallResults(ctx, result.InstallUUID)
		if err != nil {
			return ctxerr.Wrap(ctx, err, "get host software installation result information")
		}

		// Self-Service installs, and installs made by automations, will have a nil author for the activity.
		var user *mobius.User
		if !hsi.SelfService && hsi.UserID != nil {
			user, err = svc.ds.UserByID(ctx, *hsi.UserID)
			if err != nil {
				return ctxerr.Wrap(ctx, err, "get host software installation user")
			}
		}

		var policyName *string
		if hsi.PolicyID != nil {
			if policy, err := svc.ds.PolicyLite(ctx, *hsi.PolicyID); err == nil && policy != nil {
				policyName = &policy.Name // fall back to blank policy name if we can't retrieve the policy
			}
		}

		if err := svc.NewActivity(
			ctx,
			user,
			mobius.ActivityTypeInstalledSoftware{
				HostID:          host.ID,
				HostDisplayName: host.DisplayName(),
				SoftwareTitle:   hsi.SoftwareTitle,
				SoftwarePackage: hsi.SoftwarePackage,
				InstallUUID:     result.InstallUUID,
				Status:          string(status),
				SelfService:     hsi.SelfService,
				PolicyID:        hsi.PolicyID,
				PolicyName:      policyName,
			},
		); err != nil {
			return ctxerr.Wrap(ctx, err, "create activity for software installation")
		}
	}
	return nil
}

/////////////////////////////////////////////////////////////////////////////////
// Get Orbit setup experience status
/////////////////////////////////////////////////////////////////////////////////

type getOrbitSetupExperienceStatusRequest struct {
	OrbitNodeKey string `json:"orbit_node_key"`
	ForceRelease bool   `json:"force_release"`
}

func (r *getOrbitSetupExperienceStatusRequest) setOrbitNodeKey(nodeKey string) {
	r.OrbitNodeKey = nodeKey
}

func (r *getOrbitSetupExperienceStatusRequest) orbitHostNodeKey() string {
	return r.OrbitNodeKey
}

type getOrbitSetupExperienceStatusResponse struct {
	Results *mobius.SetupExperienceStatusPayload `json:"setup_experience_results,omitempty"`
	Err     error                               `json:"error,omitempty"`
}

func (r getOrbitSetupExperienceStatusResponse) Error() error { return r.Err }

func getOrbitSetupExperienceStatusEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*getOrbitSetupExperienceStatusRequest)
	results, err := svc.GetOrbitSetupExperienceStatus(ctx, req.OrbitNodeKey, req.ForceRelease)
	if err != nil {
		return &getOrbitSetupExperienceStatusResponse{Err: err}, nil
	}
	return &getOrbitSetupExperienceStatusResponse{Results: results}, nil
}

func (svc *Service) GetOrbitSetupExperienceStatus(ctx context.Context, orbitNodeKey string, forceRelease bool) (*mobius.SetupExperienceStatusPayload, error) {
	// skipauth: No authorization check needed due to implementation returning
	// only license error.
	svc.authz.SkipAuthorization(ctx)

	return nil, mobius.ErrMissingLicense
}
