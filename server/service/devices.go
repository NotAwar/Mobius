package service

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/notawar/mobius/server/contexts/authz"
	"github.com/notawar/mobius/server/contexts/ctxerr"
	hostctx "github.com/notawar/mobius/server/contexts/host"
	"github.com/notawar/mobius/server/contexts/logging"
	"github.com/notawar/mobius/server/mobius"
	apple_mdm "github.com/notawar/mobius/server/mdm/apple"
	mdmcrypto "github.com/notawar/mobius/server/mdm/crypto"
	"github.com/notawar/mobius/server/ptr"
	"github.com/go-kit/log/level"
)

/////////////////////////////////////////////////////////////////////////////////
// Ping device endpoint
/////////////////////////////////////////////////////////////////////////////////

type devicePingRequest struct{}

type deviceAuthPingRequest struct {
	Token string `url:"token"`
}

func (r *deviceAuthPingRequest) deviceAuthToken() string {
	return r.Token
}

type devicePingResponse struct{}

func (r devicePingResponse) Error() error { return nil }

func (r devicePingResponse) HijackRender(ctx context.Context, w http.ResponseWriter) {
	writeCapabilitiesHeader(w, mobius.GetServerDeviceCapabilities())
}

// NOTE: we're intentionally not reading the capabilities header in this
// endpoint as is unauthenticated and we don't want to trust whatever comes in
// there.
func devicePingEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	svc.DisableAuthForPing(ctx)
	return devicePingResponse{}, nil
}

func (svc *Service) DisableAuthForPing(ctx context.Context) {
	// skipauth: this endpoint is intentionally public to allow devices to ping
	// the server and among other things, get the mobius.Capabilities header to
	// determine which capabilities are enabled in the server.
	svc.authz.SkipAuthorization(ctx)
}

/////////////////////////////////////////////////////////////////////////////////
// Mobius Desktop endpoints
/////////////////////////////////////////////////////////////////////////////////

type mobiusDesktopResponse struct {
	Err error `json:"error,omitempty"`
	mobius.DesktopSummary
}

func (r mobiusDesktopResponse) Error() error { return r.Err }

type getMobiusDesktopRequest struct {
	Token string `url:"token"`
}

func (r *getMobiusDesktopRequest) deviceAuthToken() string {
	return r.Token
}

// getMobiusDesktopEndpoint is meant to be the only API endpoint used by Mobius Desktop. This
// endpoint should not include any kind of identifying information about the host.
func getMobiusDesktopEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	sum, err := svc.GetMobiusDesktopSummary(ctx)
	if err != nil {
		return mobiusDesktopResponse{Err: err}, nil
	}
	return mobiusDesktopResponse{DesktopSummary: sum}, nil
}

func (svc *Service) GetMobiusDesktopSummary(ctx context.Context) (mobius.DesktopSummary, error) {
	// skipauth: No authorization check needed due to implementation returning
	// only license error.
	svc.authz.SkipAuthorization(ctx)

	return mobius.DesktopSummary{}, mobius.ErrMissingLicense
}

/////////////////////////////////////////////////////////////////////////////////
// Get Current Device's Host
/////////////////////////////////////////////////////////////////////////////////

type getDeviceHostRequest struct {
	Token           string `url:"token"`
	ExcludeSoftware bool   `query:"exclude_software,optional"`
}

func (r *getDeviceHostRequest) deviceAuthToken() string {
	return r.Token
}

type getDeviceHostResponse struct {
	Host                      *HostDetailResponse      `json:"host"`
	SelfService               bool                     `json:"self_service"`
	OrgLogoURL                string                   `json:"org_logo_url"`
	OrgLogoURLLightBackground string                   `json:"org_logo_url_light_background"`
	OrgContactURL             string                   `json:"org_contact_url"`
	Err                       error                    `json:"error,omitempty"`
	License                   mobius.LicenseInfo        `json:"license"`
	GlobalConfig              mobius.DeviceGlobalConfig `json:"global_config"`
}

func (r getDeviceHostResponse) Error() error { return r.Err }

func getDeviceHostEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*getDeviceHostRequest)
	host, ok := hostctx.FromContext(ctx)
	if !ok {
		err := ctxerr.Wrap(ctx, mobius.NewAuthRequiredError("internal error: missing host from request context"))
		return getDeviceHostResponse{Err: err}, nil
	}

	// must still load the full host details, as it returns more information
	opts := mobius.HostDetailOptions{
		IncludeCVEScores: false,
		IncludePolicies:  false,
		ExcludeSoftware:  req.ExcludeSoftware,
	}
	hostDetails, err := svc.GetHost(ctx, host.ID, opts)
	if err != nil {
		return getDeviceHostResponse{Err: err}, nil
	}

	resp, err := hostDetailResponseForHost(ctx, svc, hostDetails)
	if err != nil {
		return getDeviceHostResponse{Err: err}, nil
	}

	// the org logo URL config is required by the frontend to render the page;
	// we need to be careful with what we return from AppConfig in the response
	// as this is a weakly authenticated endpoint (with the device auth token).
	ac, err := svc.AppConfigObfuscated(ctx)
	if err != nil {
		return getDeviceHostResponse{Err: err}, nil
	}

	license, err := svc.License(ctx)
	if err != nil {
		return getDeviceHostResponse{Err: err}, nil
	}

	resp.DEPAssignedToMobius = ptr.Bool(false)
	if ac.MDM.EnabledAndConfigured && license.IsPremium() {
		hdep, err := svc.GetHostDEPAssignment(ctx, host)
		if err != nil && !mobius.IsNotFound(err) {
			return getDeviceHostResponse{Err: err}, nil
		}
		resp.DEPAssignedToMobius = ptr.Bool(hdep.IsDEPAssignedToMobius())
	}

	softwareInventoryEnabled := ac.Features.EnableSoftwareInventory
	if resp.TeamID != nil {
		// load the team to get the device's team's software inventory config.
		tm, err := svc.GetTeam(ctx, *resp.TeamID)
		if err != nil && !mobius.IsNotFound(err) {
			return getDeviceHostResponse{Err: err}, nil
		}
		if tm != nil {
			softwareInventoryEnabled = tm.Config.Features.EnableSoftwareInventory // TODO: We should look for opportunities to fix the confusing name of the `global_config` object in the API response. Also, how can we better clarify/document the expected order of precedence for team and global feature flags?
		}
	}

	hasSelfService := false
	if softwareInventoryEnabled {
		hasSelfService, err = svc.HasSelfServiceSoftwareInstallers(ctx, host)
		if err != nil {
			return getDeviceHostResponse{Err: err}, nil
		}
	}

	deviceGlobalConfig := mobius.DeviceGlobalConfig{
		MDM: mobius.DeviceGlobalMDMConfig{
			// TODO(mna): It currently only returns the Apple enabled and configured,
			// regardless of the platform of the device. See
			// https://github.com/notawar/mobius/pull/19304#discussion_r1618792410.
			EnabledAndConfigured: ac.MDM.EnabledAndConfigured,
		},
		Features: mobius.DeviceFeatures{
			EnableSoftwareInventory: softwareInventoryEnabled,
		},
	}

	return getDeviceHostResponse{
		Host:          resp,
		OrgLogoURL:    ac.OrgInfo.OrgLogoURL,
		OrgContactURL: ac.OrgInfo.ContactURL,
		License:       *license,
		GlobalConfig:  deviceGlobalConfig,
		SelfService:   hasSelfService,
	}, nil
}

func (svc *Service) GetHostDEPAssignment(ctx context.Context, host *mobius.Host) (*mobius.HostDEPAssignment, error) {
	alreadyAuthd := svc.authz.IsAuthenticatedWith(ctx, authz.AuthnDeviceToken)
	if !alreadyAuthd {
		if err := svc.authz.Authorize(ctx, host, mobius.ActionRead); err != nil {
			return nil, err
		}
	}
	return svc.ds.GetHostDEPAssignment(ctx, host.ID)
}

// AuthenticateDevice returns the host identified by the device authentication
// token, along with a boolean indicating if debug logging is enabled for that
// host.
func (svc *Service) AuthenticateDevice(ctx context.Context, authToken string) (*mobius.Host, bool, error) {
	const deviceAuthTokenTTL = time.Hour
	// skipauth: Authorization is currently for user endpoints only.
	svc.authz.SkipAuthorization(ctx)

	if authToken == "" {
		return nil, false, ctxerr.Wrap(ctx, mobius.NewAuthRequiredError("authentication error: missing device authentication token"))
	}

	host, err := svc.ds.LoadHostByDeviceAuthToken(ctx, authToken, deviceAuthTokenTTL)
	switch {
	case err == nil:
		// OK
	case mobius.IsNotFound(err):
		return nil, false, ctxerr.Wrap(ctx, mobius.NewAuthRequiredError("authentication error: invalid device authentication token"))
	default:
		return nil, false, ctxerr.Wrap(ctx, err, "authenticate device")
	}

	return host, svc.debugEnabledForHost(ctx, host.ID), nil
}

/////////////////////////////////////////////////////////////////////////////////
// Refetch Current Device's Host
/////////////////////////////////////////////////////////////////////////////////

type refetchDeviceHostRequest struct {
	Token string `url:"token"`
}

func (r *refetchDeviceHostRequest) deviceAuthToken() string {
	return r.Token
}

func refetchDeviceHostEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	host, ok := hostctx.FromContext(ctx)
	if !ok {
		err := ctxerr.Wrap(ctx, mobius.NewAuthRequiredError("internal error: missing host from request context"))
		return refetchHostResponse{Err: err}, nil
	}

	err := svc.RefetchHost(ctx, host.ID)
	if err != nil {
		return refetchHostResponse{Err: err}, nil
	}
	return refetchHostResponse{}, nil
}

////////////////////////////////////////////////////////////////////////////////
// List Current Device's Host Device Mappings
////////////////////////////////////////////////////////////////////////////////

type listDeviceHostDeviceMappingRequest struct {
	Token string `url:"token"`
}

func (r *listDeviceHostDeviceMappingRequest) deviceAuthToken() string {
	return r.Token
}

func listDeviceHostDeviceMappingEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	host, ok := hostctx.FromContext(ctx)
	if !ok {
		err := ctxerr.Wrap(ctx, mobius.NewAuthRequiredError("internal error: missing host from request context"))
		return listHostDeviceMappingResponse{Err: err}, nil
	}

	dms, err := svc.ListHostDeviceMapping(ctx, host.ID)
	if err != nil {
		return listHostDeviceMappingResponse{Err: err}, nil
	}
	return listHostDeviceMappingResponse{HostID: host.ID, DeviceMapping: dms}, nil
}

////////////////////////////////////////////////////////////////////////////////
// Get Current Device's Macadmins
////////////////////////////////////////////////////////////////////////////////

type getDeviceMacadminsDataRequest struct {
	Token string `url:"token"`
}

func (r *getDeviceMacadminsDataRequest) deviceAuthToken() string {
	return r.Token
}

func getDeviceMacadminsDataEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	host, ok := hostctx.FromContext(ctx)
	if !ok {
		err := ctxerr.Wrap(ctx, mobius.NewAuthRequiredError("internal error: missing host from request context"))
		return getMacadminsDataResponse{Err: err}, nil
	}

	data, err := svc.MacadminsData(ctx, host.ID)
	if err != nil {
		return getMacadminsDataResponse{Err: err}, nil
	}
	return getMacadminsDataResponse{Macadmins: data}, nil
}

////////////////////////////////////////////////////////////////////////////////
// List Current Device's Policies
////////////////////////////////////////////////////////////////////////////////

type listDevicePoliciesRequest struct {
	Token string `url:"token"`
}

func (r *listDevicePoliciesRequest) deviceAuthToken() string {
	return r.Token
}

type listDevicePoliciesResponse struct {
	Err      error               `json:"error,omitempty"`
	Policies []*mobius.HostPolicy `json:"policies"`
}

func (r listDevicePoliciesResponse) Error() error { return r.Err }

func listDevicePoliciesEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	host, ok := hostctx.FromContext(ctx)
	if !ok {
		err := ctxerr.Wrap(ctx, mobius.NewAuthRequiredError("internal error: missing host from request context"))
		return listDevicePoliciesResponse{Err: err}, nil
	}

	data, err := svc.ListDevicePolicies(ctx, host)
	if err != nil {
		return listDevicePoliciesResponse{Err: err}, nil
	}

	return listDevicePoliciesResponse{Policies: data}, nil
}

func (svc *Service) ListDevicePolicies(ctx context.Context, host *mobius.Host) ([]*mobius.HostPolicy, error) {
	// skipauth: No authorization check needed due to implementation returning
	// only license error.
	svc.authz.SkipAuthorization(ctx)

	return nil, mobius.ErrMissingLicense
}

////////////////////////////////////////////////////////////////////////////////
// Get software MDM command results
////////////////////////////////////////////////////////////////////////////////

type getDeviceMDMCommandResultsRequest struct {
	Token       string `url:"token"`
	CommandUUID string `url:"command_uuid"`
}

func (r *getDeviceMDMCommandResultsRequest) deviceAuthToken() string {
	return r.Token
}

func getDeviceMDMCommandResultsEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	_, ok := hostctx.FromContext(ctx)
	if !ok {
		err := ctxerr.Wrap(ctx, mobius.NewAuthRequiredError("internal error: missing host from request context"))
		return getMDMCommandResultsResponse{Err: err}, nil
	}

	req := request.(*getDeviceMDMCommandResultsRequest)
	results, err := svc.GetMDMCommandResults(ctx, req.CommandUUID)
	if err != nil {
		return getMDMCommandResultsResponse{
			Err: err,
		}, nil
	}

	return getMDMCommandResultsResponse{
		Results: results,
	}, nil
}

////////////////////////////////////////////////////////////////////////////////
// Transparency URL Redirect
////////////////////////////////////////////////////////////////////////////////

type transparencyURLRequest struct {
	Token string `url:"token"`
}

func (r *transparencyURLRequest) deviceAuthToken() string {
	return r.Token
}

type transparencyURLResponse struct {
	RedirectURL string `json:"-"` // used to control the redirect, see HijackRender method
	Err         error  `json:"error,omitempty"`
}

func (r transparencyURLResponse) HijackRender(ctx context.Context, w http.ResponseWriter) {
	w.Header().Set("Location", r.RedirectURL)
	w.WriteHeader(http.StatusTemporaryRedirect)
}

func (r transparencyURLResponse) Error() error { return r.Err }

func transparencyURL(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	transparencyURL, err := svc.GetTransparencyURL(ctx)

	return transparencyURLResponse{RedirectURL: transparencyURL, Err: err}, nil
}

func (svc *Service) GetTransparencyURL(ctx context.Context) (string, error) {
	config, err := svc.AppConfigObfuscated(ctx)
	if err != nil {
		return "", err
	}

	license, err := svc.License(ctx)
	if err != nil {
		return "", err
	}

	transparencyURL := mobius.DefaultTransparencyURL
	// See #27309; overridden if on Mobius Premium and custom transparency URL is set
	if svc.config.Partnerships.EnableSecureframe {
		transparencyURL = mobius.SecureframeTransparencyURL
	}

	// Mobius Premium license is required for custom transparency URL
	if license.IsPremium() && config.MobiusDesktop.TransparencyURL != "" {
		transparencyURL = config.MobiusDesktop.TransparencyURL
	}

	return transparencyURL, nil
}

////////////////////////////////////////////////////////////////////////////////
// Receive errors from the client
////////////////////////////////////////////////////////////////////////////////

type mobiusdErrorRequest struct {
	Token string `url:"token"`
	mobius.MobiusdError
}

func (f *mobiusdErrorRequest) deviceAuthToken() string {
	return f.Token
}

// Since we're directly storing what we get in Redis, limit the request size to
// 5MB, this combined with the rate limit of this endpoint should be enough to
// prevent a malicious actor.
const maxMobiusdErrorReportSize int64 = 5 * 1024 * 1024

func (f *mobiusdErrorRequest) DecodeBody(ctx context.Context, r io.Reader, u url.Values, c []*x509.Certificate) error {
	limitedReader := io.LimitReader(r, maxMobiusdErrorReportSize+1)
	decoder := json.NewDecoder(limitedReader)

	for {
		if err := decoder.Decode(&f.MobiusdError); err == io.EOF {
			break
		} else if err == io.ErrUnexpectedEOF {
			return &mobius.BadRequestError{Message: "payload exceeds maximum accepted size"}
		} else if err != nil {
			return &mobius.BadRequestError{Message: "invalid payload"}
		}
	}

	return nil
}

type mobiusdErrorResponse struct{}

func (r mobiusdErrorResponse) Error() error { return nil }

func mobiusdError(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*mobiusdErrorRequest)
	err := svc.LogMobiusdError(ctx, req.MobiusdError)
	if err != nil {
		return nil, err
	}
	return mobiusdErrorResponse{}, nil
}

func (svc *Service) LogMobiusdError(ctx context.Context, mobiusdError mobius.MobiusdError) error {
	if !svc.authz.IsAuthenticatedWith(ctx, authz.AuthnDeviceToken) {
		return ctxerr.Wrap(ctx, mobius.NewPermissionError("forbidden: only device-authenticated hosts can access this endpoint"))
	}

	err := ctxerr.WrapWithData(ctx, mobiusdError, "receive mobiusdaemon error", mobiusdError.ToMap())
	level.Warn(svc.logger).Log(
		"msg",
		"mobiusdaemon error",
		"error",
		err,
	)
	// Send to Redis/telemetry (if enabled)
	ctxerr.Handle(ctx, err)

	return nil
}

////////////////////////////////////////////////////////////////////////////////
// Get Current Device's MDM Apple Enrollment Profile
////////////////////////////////////////////////////////////////////////////////

type getDeviceMDMManualEnrollProfileRequest struct {
	Token string `url:"token"`
}

func (r *getDeviceMDMManualEnrollProfileRequest) deviceAuthToken() string {
	return r.Token
}

type getDeviceMDMManualEnrollProfileResponse struct {
	// Profile field is used in HijackRender for the response.
	Profile []byte

	Err error `json:"error,omitempty"`
}

func (r getDeviceMDMManualEnrollProfileResponse) HijackRender(ctx context.Context, w http.ResponseWriter) {
	// make the browser download the content to a file
	w.Header().Add("Content-Disposition", `attachment; filename="mobius-mdm-enrollment-profile.mobileconfig"`)
	// explicitly set the content length before the write, so the caller can
	// detect short writes (if it fails to send the full content properly)
	w.Header().Set("Content-Length", strconv.FormatInt(int64(len(r.Profile)), 10))
	// this content type will make macos open the profile with the proper application
	w.Header().Set("Content-Type", "application/x-apple-aspen-config; charset=utf-8")
	// prevent detection of content, obey the provided content-type
	w.Header().Set("X-Content-Type-Options", "nosniff")

	if n, err := w.Write(r.Profile); err != nil {
		logging.WithExtras(ctx, "err", err, "written", n)
	}
}

func (r getDeviceMDMManualEnrollProfileResponse) Error() error { return r.Err }

func getDeviceMDMManualEnrollProfileEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	// this call ensures that the authentication was done, no need to actually
	// use the host
	if _, ok := hostctx.FromContext(ctx); !ok {
		err := ctxerr.Wrap(ctx, mobius.NewAuthRequiredError("internal error: missing host from request context"))
		return getDeviceMDMManualEnrollProfileResponse{Err: err}, nil
	}

	profile, err := svc.GetDeviceMDMAppleEnrollmentProfile(ctx)
	if err != nil {
		return getDeviceMDMManualEnrollProfileResponse{Err: err}, nil
	}
	return getDeviceMDMManualEnrollProfileResponse{Profile: profile}, nil
}

func (svc *Service) GetDeviceMDMAppleEnrollmentProfile(ctx context.Context) ([]byte, error) {
	// must be device-authenticated, no additional authorization is required
	if !svc.authz.IsAuthenticatedWith(ctx, authz.AuthnDeviceToken) {
		return nil, ctxerr.Wrap(ctx, mobius.NewPermissionError("forbidden: only device-authenticated hosts can access this endpoint"))
	}

	cfg, err := svc.ds.AppConfig(ctx)
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err, "fetching app config")
	}

	host, ok := hostctx.FromContext(ctx)
	if !ok {
		return nil, ctxerr.Wrap(ctx, mobius.NewAuthRequiredError("internal error: missing host from request context"))
	}

	tmSecrets, err := svc.ds.GetEnrollSecrets(ctx, host.TeamID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, ctxerr.Wrap(ctx, err, "getting host team enroll secrets")
	}
	if len(tmSecrets) == 0 && host.TeamID != nil {
		tmSecrets, err = svc.ds.GetEnrollSecrets(ctx, nil)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, ctxerr.Wrap(ctx, err, "getting no team enroll secrets")
		}
	}
	if len(tmSecrets) == 0 {
		return nil, &mobius.BadRequestError{Message: "unable to find an enroll secret to generate enrollment profile"}
	}

	enrollSecret := tmSecrets[0].Secret
	profBytes, err := apple_mdm.GenerateOTAEnrollmentProfileMobileconfig(cfg.OrgInfo.OrgName, cfg.MDMUrl(), enrollSecret)
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err, "generating ota mobileconfig file for manual enrollment")
	}

	signed, err := mdmcrypto.Sign(ctx, profBytes, svc.ds)
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err, "signing profile")
	}

	return signed, nil
}

////////////////////////////////////////////////////////////////////////////////
// Signal start of mdm migration on a device
////////////////////////////////////////////////////////////////////////////////

type deviceMigrateMDMRequest struct {
	Token string `url:"token"`
}

func (r *deviceMigrateMDMRequest) deviceAuthToken() string {
	return r.Token
}

type deviceMigrateMDMResponse struct {
	Err error `json:"error,omitempty"`
}

func (r deviceMigrateMDMResponse) Error() error { return r.Err }

func (r deviceMigrateMDMResponse) Status() int { return http.StatusNoContent }

func migrateMDMDeviceEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	host, ok := hostctx.FromContext(ctx)
	if !ok {
		err := ctxerr.Wrap(ctx, mobius.NewAuthRequiredError("internal error: missing host from request context"))
		return deviceMigrateMDMResponse{Err: err}, nil
	}

	if err := svc.TriggerMigrateMDMDevice(ctx, host); err != nil {
		return deviceMigrateMDMResponse{Err: err}, nil
	}
	return deviceMigrateMDMResponse{}, nil
}

func (svc *Service) TriggerMigrateMDMDevice(ctx context.Context, host *mobius.Host) error {
	return mobius.ErrMissingLicense
}

////////////////////////////////////////////////////////////////////////////////
// Trigger linux key escrow
////////////////////////////////////////////////////////////////////////////////

type triggerLinuxDiskEncryptionEscrowRequest struct {
	Token string `url:"token"`
}

func (r *triggerLinuxDiskEncryptionEscrowRequest) deviceAuthToken() string {
	return r.Token
}

type triggerLinuxDiskEncryptionEscrowResponse struct {
	Err error `json:"error,omitempty"`
}

func (r triggerLinuxDiskEncryptionEscrowResponse) Error() error { return r.Err }

func (r triggerLinuxDiskEncryptionEscrowResponse) Status() int { return http.StatusNoContent }

func triggerLinuxDiskEncryptionEscrowEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	host, ok := hostctx.FromContext(ctx)
	if !ok {
		err := ctxerr.Wrap(ctx, mobius.NewAuthRequiredError("internal error: missing host from request context"))
		return triggerLinuxDiskEncryptionEscrowResponse{Err: err}, nil
	}

	if err := svc.TriggerLinuxDiskEncryptionEscrow(ctx, host); err != nil {
		return triggerLinuxDiskEncryptionEscrowResponse{Err: err}, nil
	}
	return triggerLinuxDiskEncryptionEscrowResponse{}, nil
}

func (svc *Service) TriggerLinuxDiskEncryptionEscrow(ctx context.Context, host *mobius.Host) error {
	return mobius.ErrMissingLicense
}

////////////////////////////////////////////////////////////////////////////////
// Get Current Device's Software
////////////////////////////////////////////////////////////////////////////////

type getDeviceSoftwareRequest struct {
	Token string `url:"token"`
	mobius.HostSoftwareTitleListOptions
}

func (r *getDeviceSoftwareRequest) deviceAuthToken() string {
	return r.Token
}

type getDeviceSoftwareResponse struct {
	Software []*mobius.HostSoftwareWithInstaller `json:"software"`
	Count    int                                `json:"count"`
	Meta     *mobius.PaginationMetadata          `json:"meta,omitempty"`
	Err      error                              `json:"error,omitempty"`
}

func (r getDeviceSoftwareResponse) Error() error { return r.Err }

func getDeviceSoftwareEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	host, ok := hostctx.FromContext(ctx)
	if !ok {
		err := ctxerr.Wrap(ctx, mobius.NewAuthRequiredError("internal error: missing host from request context"))
		return getDeviceSoftwareResponse{Err: err}, nil
	}

	req := request.(*getDeviceSoftwareRequest)
	res, meta, err := svc.ListHostSoftware(ctx, host.ID, req.HostSoftwareTitleListOptions)
	if err != nil {
		return getDeviceSoftwareResponse{Err: err}, nil
	}
	if res == nil {
		res = []*mobius.HostSoftwareWithInstaller{}
	}
	return getDeviceSoftwareResponse{Software: res, Meta: meta, Count: int(meta.TotalResults)}, nil //nolint:gosec // dismiss G115
}

////////////////////////////////////////////////////////////////////////////////
// List Current Device's Certificates
////////////////////////////////////////////////////////////////////////////////

type listDeviceCertificatesRequest struct {
	Token string `url:"token"`
	mobius.ListOptions
}

func (r *listDeviceCertificatesRequest) ValidateRequest() error {
	if r.ListOptions.OrderKey != "" && !listHostCertificatesSortCols[r.ListOptions.OrderKey] {
		return badRequest("invalid order key")
	}
	return nil
}

func (r *listDeviceCertificatesRequest) deviceAuthToken() string {
	return r.Token
}

type listDeviceCertificatesResponse struct {
	Certificates []*mobius.HostCertificatePayload `json:"certificates"`
	Meta         *mobius.PaginationMetadata       `json:"meta,omitempty"`
	Err          error                           `json:"error,omitempty"`
}

func (r listDeviceCertificatesResponse) Error() error { return r.Err }

func listDeviceCertificatesEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	host, ok := hostctx.FromContext(ctx)
	if !ok {
		err := ctxerr.Wrap(ctx, mobius.NewAuthRequiredError("internal error: missing host from request context"))
		return listDevicePoliciesResponse{Err: err}, nil
	}

	req := request.(*listDeviceCertificatesRequest)
	res, meta, err := svc.ListHostCertificates(ctx, host.ID, req.ListOptions)
	if err != nil {
		return listDeviceCertificatesResponse{Err: err}, nil
	}
	if res == nil {
		res = []*mobius.HostCertificatePayload{}
	}
	return listDeviceCertificatesResponse{Certificates: res, Meta: meta}, nil
}
