package service

import (
	"bytes"
	"context"
	"crypto/md5" // nolint:gosec // used for declarative management token
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"maps"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/docker/go-units"
	// eeservice "github.com/notawar/mobius/v4/ee/server/service" // Removed enterprise dependency
	// "github.com/notawar/mobius/v4/ee/server/service/digicert" // Removed enterprise dependency
	"github.com/notawar/mobius/v4/pkg/file"
	"github.com/notawar/mobius/v4/pkg/optjson"
	"github.com/notawar/mobius/v4/server"
	"github.com/notawar/mobius/v4/server/authz"
	"github.com/notawar/mobius/v4/server/config"
	"github.com/notawar/mobius/v4/server/contexts/ctxerr"
	"github.com/notawar/mobius/v4/server/contexts/license"
	"github.com/notawar/mobius/v4/server/contexts/logging"
	"github.com/notawar/mobius/v4/server/contexts/viewer"
	"github.com/notawar/mobius/v4/server/mobius"
	mdm_types "github.com/notawar/mobius/v4/server/mdm"
	apple_mdm "github.com/notawar/mobius/v4/server/mdm/apple"
	"github.com/notawar/mobius/v4/server/mdm/apple/appmanifest"
	"github.com/notawar/mobius/v4/server/mdm/apple/gdmf"
	"github.com/notawar/mobius/v4/server/mdm/apple/mobileconfig"
	"github.com/notawar/mobius/v4/server/mdm/assets"
	mdmcrypto "github.com/notawar/mobius/v4/server/mdm/crypto"
	mdmlifecycle "github.com/notawar/mobius/v4/server/mdm/lifecycle"
	"github.com/notawar/mobius/v4/server/mdm/nanomdm/cryptoutil"
	"github.com/notawar/mobius/v4/server/mdm/nanomdm/mdm"
	nano_service "github.com/notawar/mobius/v4/server/mdm/nanomdm/service"
	"github.com/notawar/mobius/v4/server/ptr"
	"github.com/notawar/mobius/v4/server/service/middleware/endpoint_utils"
	"github.com/notawar/mobius/v4/server/sso"
	"github.com/notawar/mobius/v4/server/worker"
	kitlog "github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/google/uuid"
	"github.com/micromdm/plist"
	"github.com/smallstep/pkcs7"
)

const (
	maxValueCharsInError          = 100
	SameProfileNameUploadErrorMsg = "Couldn't add. A configuration profile with this name already exists (PayloadDisplayName for .mobileconfig and file name for .json and .xml)."
	limit10KiB                    = 10 * 1024
)

var (
	mobiusVarNDESSCEPChallengeRegexp               = regexp.MustCompile(fmt.Sprintf(`(\$MOBIUS_VAR_%s)|(\${MOBIUS_VAR_%[1]s})`, mobius.MobiusVarNDESSCEPChallenge))
	mobiusVarNDESSCEPProxyURLRegexp                = regexp.MustCompile(fmt.Sprintf(`(\$MOBIUS_VAR_%s)|(\${MOBIUS_VAR_%[1]s})`, mobius.MobiusVarNDESSCEPProxyURL))
	mobiusVarHostEndUserEmailIDPRegexp             = regexp.MustCompile(fmt.Sprintf(`(\$MOBIUS_VAR_%s)|(\${MOBIUS_VAR_%[1]s})`, mobius.MobiusVarHostEndUserEmailIDP))
	mobiusVarHostHardwareSerialRegexp              = regexp.MustCompile(fmt.Sprintf(`(\$MOBIUS_VAR_%s)|(\${MOBIUS_VAR_%[1]s})`, mobius.MobiusVarHostHardwareSerial))
	mobiusVarHostEndUserIDPUsernameRegexp          = regexp.MustCompile(fmt.Sprintf(`(\$MOBIUS_VAR_%s)|(\${MOBIUS_VAR_%[1]s})`, mobius.MobiusVarHostEndUserIDPUsername))
	mobiusVarHostEndUserIDPDepartmentRegexp        = regexp.MustCompile(fmt.Sprintf(`(\$MOBIUS_VAR_%s)|(\${MOBIUS_VAR_%[1]s})`, mobius.MobiusVarHostEndUserIDPDepartment))
	mobiusVarHostEndUserIDPUsernameLocalPartRegexp = regexp.MustCompile(fmt.Sprintf(`(\$MOBIUS_VAR_%s)|(\${MOBIUS_VAR_%[1]s})`, mobius.MobiusVarHostEndUserIDPUsernameLocalPart))
	mobiusVarHostEndUserIDPGroupsRegexp            = regexp.MustCompile(fmt.Sprintf(`(\$MOBIUS_VAR_%s)|(\${MOBIUS_VAR_%[1]s})`, mobius.MobiusVarHostEndUserIDPGroups))
	mobiusVarSCEPRenewalIDRegexp                   = regexp.MustCompile(fmt.Sprintf(`(\$MOBIUS_VAR_%s)|(\${MOBIUS_VAR_%[1]s})`, mobius.MobiusVarSCEPRenewalID))

	mobiusVarsSupportedInConfigProfiles = []string{
		mobius.MobiusVarNDESSCEPChallenge, mobius.MobiusVarNDESSCEPProxyURL, mobius.MobiusVarHostEndUserEmailIDP,
		mobius.MobiusVarHostHardwareSerial, mobius.MobiusVarHostEndUserIDPUsername, mobius.MobiusVarHostEndUserIDPUsernameLocalPart,
		mobius.MobiusVarHostEndUserIDPGroups, mobius.MobiusVarHostEndUserIDPDepartment, mobius.MobiusVarSCEPRenewalID,
	}
)

type hostProfileUUID struct {
	HostUUID    string
	ProfileUUID string
}

type getMDMAppleCommandResultsRequest struct {
	CommandUUID string `query:"command_uuid,optional"`
}

type getMDMAppleCommandResultsResponse struct {
	Results []*mobius.MDMCommandResult `json:"results,omitempty"`
	Err     error                     `json:"error,omitempty"`
}

func (r getMDMAppleCommandResultsResponse) Error() error { return r.Err }

func getMDMAppleCommandResultsEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*getMDMAppleCommandResultsRequest)
	results, err := svc.GetMDMAppleCommandResults(ctx, req.CommandUUID)
	if err != nil {
		return getMDMAppleCommandResultsResponse{
			Err: err,
		}, nil
	}

	return getMDMAppleCommandResultsResponse{
		Results: results,
	}, nil
}

func (svc *Service) GetMDMAppleCommandResults(ctx context.Context, commandUUID string) ([]*mobius.MDMCommandResult, error) {
	// first, authorize that the user has the right to list hosts
	if err := svc.authz.Authorize(ctx, &mobius.Host{}, mobius.ActionList); err != nil {
		return nil, ctxerr.Wrap(ctx, err)
	}

	vc, ok := viewer.FromContext(ctx)
	if !ok {
		return nil, mobius.ErrNoContext
	}

	// check that command exists first, to return 404 on invalid commands
	// (the command may exist but have no results yet).
	if _, err := svc.ds.GetMDMAppleCommandRequestType(ctx, commandUUID); err != nil {
		return nil, err
	}

	// next, we need to read the command results before we know what hosts (and
	// therefore what teams) we're dealing with.
	results, err := svc.ds.GetMDMAppleCommandResults(ctx, commandUUID)
	if err != nil {
		return nil, err
	}

	// now we can load the hosts (lite) corresponding to those command results,
	// and do the final authorization check with the proper team(s). Include observers,
	// as they are able to view command results for their teams' hosts.
	filter := mobius.TeamFilter{User: vc.User, IncludeObserver: true}
	hostUUIDs := make([]string, len(results))
	for i, res := range results {
		hostUUIDs[i] = res.HostUUID
	}
	hosts, err := svc.ds.ListHostsLiteByUUIDs(ctx, filter, hostUUIDs)
	if err != nil {
		return nil, err
	}
	if len(hosts) == 0 {
		// do not return 404 here, as it's possible for a command to not have
		// results yet
		return nil, nil
	}

	// collect the team IDs and verify that the user has access to view commands
	// on all affected teams. Index the hosts by uuid for easly lookup as
	// afterwards we'll want to store the hostname on the returned results.
	hostsByUUID := make(map[string]*mobius.Host, len(hosts))
	teamIDs := make(map[uint]bool)
	for _, h := range hosts {
		var id uint
		if h.TeamID != nil {
			id = *h.TeamID
		}
		teamIDs[id] = true
		hostsByUUID[h.UUID] = h
	}

	var commandAuthz mobius.MDMCommandAuthz
	for tmID := range teamIDs {
		commandAuthz.TeamID = &tmID
		if tmID == 0 {
			commandAuthz.TeamID = nil
		}

		if err := svc.authz.Authorize(ctx, commandAuthz, mobius.ActionRead); err != nil {
			return nil, ctxerr.Wrap(ctx, err)
		}
	}

	// add the hostnames to the results
	for _, res := range results {
		if h := hostsByUUID[res.HostUUID]; h != nil {
			res.Hostname = hostsByUUID[res.HostUUID].Hostname
		}
	}
	return results, nil
}

type listMDMAppleCommandsRequest struct {
	ListOptions mobius.ListOptions `url:"list_options"`
}

type listMDMAppleCommandsResponse struct {
	Results []*mobius.MDMAppleCommand `json:"results"`
	Err     error                    `json:"error,omitempty"`
}

func (r listMDMAppleCommandsResponse) Error() error { return r.Err }

func listMDMAppleCommandsEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*listMDMAppleCommandsRequest)
	results, err := svc.ListMDMAppleCommands(ctx, &mobius.MDMCommandListOptions{
		ListOptions: req.ListOptions,
	})
	if err != nil {
		return listMDMAppleCommandsResponse{
			Err: err,
		}, nil
	}

	return listMDMAppleCommandsResponse{
		Results: results,
	}, nil
}

func (svc *Service) ListMDMAppleCommands(ctx context.Context, opts *mobius.MDMCommandListOptions) ([]*mobius.MDMAppleCommand, error) {
	// first, authorize that the user has the right to list hosts
	if err := svc.authz.Authorize(ctx, &mobius.Host{}, mobius.ActionList); err != nil {
		return nil, ctxerr.Wrap(ctx, err)
	}

	vc, ok := viewer.FromContext(ctx)
	if !ok {
		return nil, mobius.ErrNoContext
	}

	// get the list of commands so we know what hosts (and therefore what teams)
	// we're dealing with. Including the observers as they are allowed to view
	// MDM Apple commands.
	results, err := svc.ds.ListMDMAppleCommands(ctx, mobius.TeamFilter{
		User:            vc.User,
		IncludeObserver: true,
	}, opts)
	if err != nil {
		return nil, err
	}

	// collect the different team IDs and verify that the user has access to view
	// commands on all affected teams, do not assume that ListMDMAppleCommands
	// only returned hosts that the user is authorized to view the command
	// results of (that is, always verify with our rego authz policy).
	teamIDs := make(map[uint]bool)
	for _, res := range results {
		var id uint
		if res.TeamID != nil {
			id = *res.TeamID
		}
		teamIDs[id] = true
	}

	// instead of returning an authz error if the user is not authorized for a
	// team, we remove those commands from the results (as we want to return
	// whatever the user is allowed to see). Since this can only be done after
	// retrieving the list of commands, this may result in returning less results
	// than requested, but it's ok - it's expected that the results retrieved
	// from the datastore will all be authorized for the user.
	var commandAuthz mobius.MDMCommandAuthz
	var authzErr error
	for tmID := range teamIDs {
		commandAuthz.TeamID = &tmID
		if tmID == 0 {
			commandAuthz.TeamID = nil
		}
		if err := svc.authz.Authorize(ctx, commandAuthz, mobius.ActionRead); err != nil {
			if authzErr == nil {
				authzErr = err
			}
			teamIDs[tmID] = false
		}
	}

	if authzErr != nil {
		level.Error(svc.logger).Log("err", "unauthorized to view some team commands", "details", authzErr)

		// filter-out the teams that the user is not allowed to view
		allowedResults := make([]*mobius.MDMAppleCommand, 0, len(results))
		for _, res := range results {
			var id uint
			if res.TeamID != nil {
				id = *res.TeamID
			}
			if teamIDs[id] {
				allowedResults = append(allowedResults, res)
			}
		}
		results = allowedResults
	}

	return results, nil
}

type newMDMAppleConfigProfileRequest struct {
	TeamID  uint
	Profile *multipart.FileHeader
}

type newMDMAppleConfigProfileResponse struct {
	ProfileID uint  `json:"profile_id"`
	Err       error `json:"error,omitempty"`
}

// TODO(lucas): We parse the whole body before running svc.authz.Authorize.
// An authenticated but unauthorized user could abuse this.
func (newMDMAppleConfigProfileRequest) DecodeRequest(ctx context.Context, r *http.Request) (interface{}, error) {
	decoded := newMDMAppleConfigProfileRequest{}

	err := r.ParseMultipartForm(512 * units.MiB)
	if err != nil {
		return nil, &mobius.BadRequestError{
			Message:     "failed to parse multipart form",
			InternalErr: err,
		}
	}

	val, ok := r.MultipartForm.Value["team_id"]
	if !ok || len(val) < 1 {
		// default is no team
		decoded.TeamID = 0
	} else {
		teamID, err := strconv.Atoi(val[0])
		if err != nil {
			return nil, &mobius.BadRequestError{Message: fmt.Sprintf("failed to decode team_id in multipart form: %s", err.Error())}
		}
		decoded.TeamID = uint(teamID) //nolint:gosec // dismiss G115
	}

	fhs, ok := r.MultipartForm.File["profile"]
	if !ok || len(fhs) < 1 {
		return nil, &mobius.BadRequestError{Message: "no file headers for profile"}
	}
	decoded.Profile = fhs[0]

	return &decoded, nil
}

func (r newMDMAppleConfigProfileResponse) Error() error { return r.Err }

func newMDMAppleConfigProfileEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*newMDMAppleConfigProfileRequest)

	ff, err := req.Profile.Open()
	if err != nil {
		return &newMDMAppleConfigProfileResponse{Err: err}, nil
	}
	defer ff.Close()
	// providing an empty set of labels since this endpoint is only maintained for backwards compat
	cp, err := svc.NewMDMAppleConfigProfile(ctx, req.TeamID, ff, nil, mobius.LabelsIncludeAll)
	if err != nil {
		return &newMDMAppleConfigProfileResponse{Err: err}, nil
	}
	return &newMDMAppleConfigProfileResponse{
		ProfileID: cp.ProfileID,
	}, nil
}

func (svc *Service) NewMDMAppleConfigProfile(ctx context.Context, teamID uint, r io.Reader, labels []string, labelsMembershipMode mobius.MDMLabelsMode) (*mobius.MDMAppleConfigProfile, error) {
	if err := svc.authz.Authorize(ctx, &mobius.MDMConfigProfileAuthz{TeamID: &teamID}, mobius.ActionWrite); err != nil {
		return nil, ctxerr.Wrap(ctx, err)
	}

	// check that Apple MDM is enabled - the middleware of that endpoint checks
	// only that any MDM is enabled, maybe it's just Windows
	if err := svc.VerifyMDMAppleConfigured(ctx); err != nil {
		err := mobius.NewInvalidArgumentError("profile", mobius.AppleMDMNotConfiguredMessage).WithStatus(http.StatusBadRequest)
		return nil, ctxerr.Wrap(ctx, err, "check macOS MDM enabled")
	}

	var teamName string
	if teamID >= 1 {
		tm, err := svc.EnterpriseOverrides.TeamByIDOrName(ctx, &teamID, nil)
		if err != nil {
			return nil, ctxerr.Wrap(ctx, err)
		}
		teamName = tm.Name
	}

	b, err := io.ReadAll(r)
	if err != nil {
		return nil, ctxerr.Wrap(ctx, &mobius.BadRequestError{
			Message:     "failed to read Apple config profile",
			InternalErr: err,
		})
	}

	// Expand and validate secrets in profile
	expanded, secretsUpdatedAt, err := svc.ds.ExpandEmbeddedSecretsAndUpdatedAt(ctx, string(b))
	if err != nil {
		return nil, ctxerr.Wrap(ctx, mobius.NewInvalidArgumentError("profile", err.Error()))
	}

	// We validate Mobius variables before we unmarshal the profile because bad variables can break unmarshal.
	// For example: <data>$MOBIUS_VAR_BOZO</data>
	appConfig, err := svc.ds.AppConfig(ctx)
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err)
	}
	profileVars, err := validateConfigProfileMobiusVariables(appConfig, expanded)
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err, "validating mobius variables")
	}

	cp, err := mobius.NewMDMAppleConfigProfile([]byte(expanded), &teamID)
	if err != nil {
		return nil, ctxerr.Wrap(ctx, &mobius.BadRequestError{
			Message: fmt.Sprintf("failed to parse config profile: %s", err.Error()),
		})
	}

	if err := cp.ValidateUserProvided(); err != nil {
		if strings.Contains(err.Error(), mobileconfig.DiskEncryptionProfileRestrictionErrMsg) {
			return nil, ctxerr.Wrap(ctx, &mobius.BadRequestError{Message: err.Error() + ` To control these settings use disk encryption endpoint.`})
		}
		return nil, ctxerr.Wrap(ctx, &mobius.BadRequestError{Message: err.Error()})
	}

	// Save the original unexpanded profile
	cp.Mobileconfig = b
	cp.SecretsUpdatedAt = secretsUpdatedAt

	labelMap, err := svc.validateProfileLabels(ctx, labels)
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err, "validating labels")
	}
	switch labelsMembershipMode {
	case mobius.LabelsIncludeAll:
		cp.LabelsIncludeAll = labelMap
	case mobius.LabelsIncludeAny:
		cp.LabelsIncludeAny = labelMap
	case mobius.LabelsExcludeAny:
		cp.LabelsExcludeAny = labelMap
	default:
		// TODO what happens if mode is not set?s
	}

	newCP, err := svc.ds.NewMDMAppleConfigProfile(ctx, *cp, slices.Collect(maps.Keys(profileVars)))
	if err != nil {
		var existsErr endpoint_utils.ExistsErrorInterface
		if errors.As(err, &existsErr) {
			msg := SameProfileNameUploadErrorMsg
			if re, ok := existsErr.(interface{ Resource() string }); ok {
				if re.Resource() == "MDMAppleConfigProfile.PayloadIdentifier" {
					msg = "Couldn't add. A configuration profile with this identifier (PayloadIdentifier) already exists."
				}
			}
			err = mobius.NewInvalidArgumentError("profile", msg).
				WithStatus(http.StatusConflict)
		}
		return nil, ctxerr.Wrap(ctx, err)
	}
	if _, err := svc.ds.BulkSetPendingMDMHostProfiles(ctx, nil, nil, []string{newCP.ProfileUUID}, nil); err != nil {
		return nil, ctxerr.Wrap(ctx, err, "bulk set pending host profiles")
	}

	var (
		actTeamID   *uint
		actTeamName *string
	)
	if teamID > 0 {
		actTeamID = &teamID
		actTeamName = &teamName
	}
	if err := svc.NewActivity(
		ctx, authz.UserFromContext(ctx), &mobius.ActivityTypeCreatedMacosProfile{
			TeamID:            actTeamID,
			TeamName:          actTeamName,
			ProfileName:       newCP.Name,
			ProfileIdentifier: newCP.Identifier,
		}); err != nil {
		return nil, ctxerr.Wrap(ctx, err, "logging activity for create mdm apple config profile")
	}

	return newCP, nil
}

func validateConfigProfileMobiusVariables(appConfig *mobius.AppConfig, contents string) (map[string]struct{}, error) {
	mobiusVars := findMobiusVariablesKeepDuplicates(contents)
	if len(mobiusVars) == 0 {
		return nil, nil
	}
	var (
		digiCertVars   *digiCertVarsFound
		customSCEPVars *customSCEPVarsFound
		ndesVars       *ndesVarsFound
	)
	for _, k := range mobiusVars {
		ok := true
		if !slices.Contains(mobiusVarsSupportedInConfigProfiles, k) {
			found := false
			switch {
			case strings.HasPrefix(k, mobius.MobiusVarDigiCertDataPrefix):
				caName := strings.TrimPrefix(k, mobius.MobiusVarDigiCertDataPrefix)
				for _, ca := range appConfig.Integrations.DigiCert.Value {
					if ca.Name == caName {
						found = true
						digiCertVars, ok = digiCertVars.SetData(caName)
						break
					}
				}
			case strings.HasPrefix(k, mobius.MobiusVarDigiCertPasswordPrefix):
				caName := strings.TrimPrefix(k, mobius.MobiusVarDigiCertPasswordPrefix)
				for _, ca := range appConfig.Integrations.DigiCert.Value {
					if ca.Name == caName {
						found = true
						digiCertVars, ok = digiCertVars.SetPassword(caName)
						break
					}
				}
			case strings.HasPrefix(k, mobius.MobiusVarCustomSCEPProxyURLPrefix):
				caName := strings.TrimPrefix(k, mobius.MobiusVarCustomSCEPProxyURLPrefix)
				for _, ca := range appConfig.Integrations.CustomSCEPProxy.Value {
					if ca.Name == caName {
						found = true
						customSCEPVars, ok = customSCEPVars.SetURL(caName)
						break
					}
				}
			case strings.HasPrefix(k, mobius.MobiusVarCustomSCEPChallengePrefix):
				caName := strings.TrimPrefix(k, mobius.MobiusVarCustomSCEPChallengePrefix)
				for _, ca := range appConfig.Integrations.CustomSCEPProxy.Value {
					if ca.Name == caName {
						found = true
						customSCEPVars, ok = customSCEPVars.SetChallenge(caName)
						break
					}
				}
			}
			if !found {
				return nil, &mobius.BadRequestError{Message: fmt.Sprintf("Mobius variable $MOBIUS_VAR_%s is not supported in configuration profiles.", k)}
			}
		} else {
			switch k {
			case mobius.MobiusVarNDESSCEPProxyURL:
				ndesVars, ok = ndesVars.SetURL()
			case mobius.MobiusVarNDESSCEPChallenge:
				ndesVars, ok = ndesVars.SetChallenge()
			case mobius.MobiusVarSCEPRenewalID:
				customSCEPVars, ok = customSCEPVars.SetRenewalID()
				if ok {
					ndesVars, ok = ndesVars.SetRenewalID()
				}
			}
		}
		if !ok {
			// We limit CA variables to once per profile
			return nil, &mobius.BadRequestError{Message: fmt.Sprintf("Mobius variable $MOBIUS_VAR_%s is already present in configuration profile.", k)}
		}
	}
	if digiCertVars.Found() {
		if !digiCertVars.Ok() {
			return nil, &mobius.BadRequestError{Message: digiCertVars.ErrorMessage()}
		}
		err := additionalDigiCertValidation(contents, digiCertVars)
		if err != nil {
			return nil, err
		}
	}
	// Since both custom SCEP and NDES share the renewal ID Mobius variable, we need to figure out which one to validate.
	if customSCEPVars.Found() && ndesVars.Found() {
		if ndesVars.RenewalOnly() {
			ndesVars = nil
		} else if customSCEPVars.RenewalOnly() {
			customSCEPVars = nil
		}
	}
	if customSCEPVars.Found() {
		if !customSCEPVars.Ok() {
			return nil, &mobius.BadRequestError{Message: customSCEPVars.ErrorMessage()}
		}
		err := additionalCustomSCEPValidation(contents, customSCEPVars)
		if err != nil {
			return nil, err
		}
	}
	if ndesVars.Found() {
		if !ndesVars.Ok() {
			return nil, &mobius.BadRequestError{Message: ndesVars.ErrorMessage()}
		}
		err := additionalNDESValidation(contents, ndesVars)
		if err != nil {
			return nil, err
		}
	}
	return dedupeMobiusVariables(mobiusVars), nil
}

// additionalDigiCertValidation checks that Password/ContentType fields match DigiCert Mobius variables exactly,
// and that these variables are only present in a "com.apple.security.pkcs12" payload
func additionalDigiCertValidation(contents string, digiCertVars *digiCertVarsFound) error {
	// Find and replace matches in base64 encoded data contents so we can unmarshal the plist and keep the Mobius vars.
	contents = mdm_types.ProfileDataVariableRegex.ReplaceAllStringFunc(contents, func(match string) string {
		return base64.StdEncoding.EncodeToString([]byte(match))
	})

	var pkcs12Prof PKCS12ProfileContent
	err := plist.Unmarshal([]byte(contents), &pkcs12Prof)
	if err != nil {
		return &mobius.BadRequestError{Message: fmt.Sprintf("Failed to parse PKCS12 payload with Mobius variables: %s", err.Error())}
	}
	var foundCAs []string
	passwordPrefix := "MOBIUS_VAR_" + mobius.MobiusVarDigiCertPasswordPrefix
	dataPrefix := "MOBIUS_VAR_" + mobius.MobiusVarDigiCertDataPrefix
	for _, payload := range pkcs12Prof.PayloadContent {
		if payload.PayloadType == "com.apple.security.pkcs12" {
			for _, ca := range digiCertVars.CAs() {
				// Check for exact match on password and data
				if payload.Password == "$"+passwordPrefix+ca || payload.Password == "${"+passwordPrefix+ca+"}" {
					if string(payload.PayloadContent) == "$"+dataPrefix+ca || string(payload.PayloadContent) == "${"+dataPrefix+ca+"}" {
						foundCAs = append(foundCAs, ca)
						break
					}
					payloadContent := string(payload.PayloadContent)
					if len(payloadContent) > maxValueCharsInError {
						payloadContent = payloadContent[:maxValueCharsInError] + "..."
					}
					return &mobius.BadRequestError{Message: "CA name mismatch between $" + passwordPrefix + ca + " and " +
						payloadContent + " in PKCS12 payload."}
				}
			}
		}
	}
	if len(foundCAs) < len(digiCertVars.CAs()) {
		for _, ca := range digiCertVars.CAs() {
			if !slices.Contains(foundCAs, ca) {
				return &mobius.BadRequestError{Message: fmt.Sprintf("Variables $%s and $%s can only be included in the 'com.apple.security.pkcs12' payload under Password and PayloadContent, respectively.",
					passwordPrefix+ca, dataPrefix+ca)}
			}
		}
	}
	return nil
}

type PKCS12ProfileContent struct {
	PayloadContent []PKCS12Payload `plist:"PayloadContent"`
}
type PKCS12Payload struct {
	Password       string               `plist:"Password"`
	PayloadContent PKCS12PayloadContent `plist:"PayloadContent"`
	PayloadType    string               `plist:"PayloadType"`
}

type PKCS12PayloadContent []byte

func (p *PKCS12PayloadContent) UnmarshalPlist(f func(interface{}) error) error {
	var val []byte
	err := f(&val)
	if err != nil {
		// Ignore unmarshalling issues
		return nil
	}
	*p = val
	return nil
}

// additionalCustomSCEPValidation checks that Challenge/URL fields march Custom SCEP Mobius variables
// exactly, that the SCEP renewal ID variable is present in the CN and that these variables are only
// present in a "com.apple.security.scep" payload
func additionalCustomSCEPValidation(contents string, customSCEPVars *customSCEPVarsFound) error {
	scepProf, err := unmarshalSCEPProfile(contents)
	if err != nil {
		return err
	}
	scepPayloadContent, err := checkThatOnlyOneSCEPPayloadIsPresent(scepProf)
	if err != nil {
		return err
	}

	var foundCAs []string
	for _, ca := range customSCEPVars.CAs() {
		// Although this is a loop, we know that we can only have 1 set of SCEP vars because Apple only allows 1 SCEP payload in a profile.
		// Check for the exact match on challenge and URL
		challengePrefix := "MOBIUS_VAR_" + mobius.MobiusVarCustomSCEPChallengePrefix
		if scepPayloadContent.Challenge != "$"+challengePrefix+ca && scepPayloadContent.Challenge != "${"+challengePrefix+ca+"}" {
			payloadChallenge := scepPayloadContent.Challenge
			if len(payloadChallenge) > maxValueCharsInError {
				payloadChallenge = payloadChallenge[:maxValueCharsInError] + "..."
			}
			return &mobius.BadRequestError{
				Message: "Variable \"$MOBIUS_VAR_" +
					mobius.MobiusVarCustomSCEPChallengePrefix + ca + "\" must be in the SCEP certificate's \"Challenge\" field.",
				InternalErr: fmt.Errorf("Challenge: %s", payloadChallenge),
			}
		}
		urlPrefix := "MOBIUS_VAR_" + mobius.MobiusVarCustomSCEPProxyURLPrefix
		if scepPayloadContent.URL != "$"+urlPrefix+ca && scepPayloadContent.URL != "${"+urlPrefix+ca+"}" {
			payloadURL := scepPayloadContent.URL
			if len(payloadURL) > maxValueCharsInError {
				payloadURL = payloadURL[:maxValueCharsInError] + "..."
			}
			return &mobius.BadRequestError{
				Message: "Variable \"$MOBIUS_VAR_" +
					mobius.MobiusVarCustomSCEPProxyURLPrefix + ca + "\" must be in the SCEP certificate's \"URL\" field.",
				InternalErr: fmt.Errorf("URL: %s", payloadURL),
			}
		}
		foundCAs = append(foundCAs, ca)
	}
	if !mobiusVarSCEPRenewalIDRegexp.MatchString(scepPayloadContent.CommonName) {
		return &mobius.BadRequestError{Message: "Variable $MOBIUS_VAR_" + mobius.MobiusVarSCEPRenewalID + " must be in the SCEP certificate's common name (CN)."}
	}
	if len(foundCAs) < len(customSCEPVars.CAs()) {
		for _, ca := range customSCEPVars.CAs() {
			if !slices.Contains(foundCAs, ca) {
				return &mobius.BadRequestError{Message: mobius.SCEPVariablesNotInSCEPPayloadErrMsg}
			}
		}
	}
	return nil
}

func checkThatOnlyOneSCEPPayloadIsPresent(scepProf SCEPProfileContent) (SCEPPayloadContent, error) {
	scepPayloadsFound := 0
	var scepPayloadContent SCEPPayloadContent
	for _, payload := range scepProf.PayloadContent {
		if payload.PayloadType == "com.apple.security.scep" {
			scepPayloadContent = payload.PayloadContent
			scepPayloadsFound++
		}
	}
	if scepPayloadsFound > 1 {
		return SCEPPayloadContent{}, &mobius.BadRequestError{Message: mobius.MultipleSCEPPayloadsErrMsg}
	}
	if scepPayloadsFound == 0 {
		return SCEPPayloadContent{}, &mobius.BadRequestError{Message: mobius.SCEPVariablesNotInSCEPPayloadErrMsg}
	}
	return scepPayloadContent, nil
}

func unmarshalSCEPProfile(contents string) (SCEPProfileContent, error) {
	// Replace any Mobius variables in data fields. SCEP payload does not need them and we cannot unmarshal if they are present.
	contents = mdm_types.ProfileDataVariableRegex.ReplaceAllString(contents, "")
	var scepProf SCEPProfileContent
	err := plist.Unmarshal([]byte(contents), &scepProf)
	if err != nil {
		return SCEPProfileContent{}, &mobius.BadRequestError{Message: fmt.Sprintf("Failed to parse SCEP payload with Mobius variables: %s",
			err.Error())}
	}
	return scepProf, nil
}

type SCEPProfileContent struct {
	PayloadContent []SCEPPayload `plist:"PayloadContent"`
}
type SCEPPayload struct {
	PayloadContent SCEPPayloadContent `plist:"PayloadContent"`
	PayloadType    string             `plist:"PayloadType"`
}
type SCEPPayloadContent struct {
	Challenge  string
	URL        string
	CommonName string
}

func (p *SCEPPayloadContent) UnmarshalPlist(f func(interface{}) error) error {
	val := &struct {
		Challenge string `plist:"Challenge"`
		URL       string `plist:"URL"`
		// Subject is an RDN Sequence which is ultimately a nested key-value pair structure with a
		// shape like the one shown below. We just need to extract the CN value from it.
		// Subject: [
		//   [
		//     [ "CN", "Mobius" ]
		//   ],
		//   [
		//      [ "OU", "Mobius Device Management"]
		//   ]
		// ]
		Subject [][][]string
	}{}
	err := f(&val)
	if err != nil {
		// Ignore unmarshalling issues
		*p = SCEPPayloadContent{}
		return nil
	}
	commonName := ""
	for i := 0; i < len(val.Subject) && commonName == ""; i++ {
		for j := 0; j < len(val.Subject[i]); j++ {
			if len(val.Subject[i][j]) == 2 && val.Subject[i][j][0] == "CN" {
				commonName = val.Subject[i][j][1]
				break
			}
		}
	}
	*p = SCEPPayloadContent{
		Challenge:  val.Challenge,
		URL:        val.URL,
		CommonName: commonName,
	}
	return nil
}

// additionalNDESValidation checks that Challenge/URL fields match NDES Mobius variables
// exactly, that the SCEP renewal ID variable is present in the CN, and that these variables are only
// present in a "com.apple.security.scep" payload
func additionalNDESValidation(contents string, ndesVars *ndesVarsFound) error {
	scepProf, err := unmarshalSCEPProfile(contents)
	if err != nil {
		return err
	}
	scepPayloadContent, err := checkThatOnlyOneSCEPPayloadIsPresent(scepProf)
	if err != nil {
		return err
	}

	if !mobiusVarSCEPRenewalIDRegexp.MatchString(scepPayloadContent.CommonName) {
		return &mobius.BadRequestError{Message: "Variable $MOBIUS_VAR_" + mobius.MobiusVarSCEPRenewalID + " must be in the SCEP certificate's common name (CN)."}
	}

	// Check for the exact match on challenge and URL
	challenge := "MOBIUS_VAR_" + mobius.MobiusVarNDESSCEPChallenge
	if scepPayloadContent.Challenge != "$"+challenge && scepPayloadContent.Challenge != "${"+challenge+"}" {
		payloadChallenge := scepPayloadContent.Challenge
		if len(payloadChallenge) > maxValueCharsInError {
			payloadChallenge = payloadChallenge[:maxValueCharsInError] + "..."
		}
		return &mobius.BadRequestError{
			Message: "Variable \"$MOBIUS_VAR_" +
				mobius.MobiusVarNDESSCEPChallenge + "\" must be in the SCEP certificate's \"Challenge\" field.",
			InternalErr: fmt.Errorf("Challenge: %s", payloadChallenge),
		}
	}
	ndesURL := "MOBIUS_VAR_" + mobius.MobiusVarNDESSCEPProxyURL
	if scepPayloadContent.URL != "$"+ndesURL && scepPayloadContent.URL != "${"+ndesURL+"}" {
		payloadURL := scepPayloadContent.URL
		if len(payloadURL) > maxValueCharsInError {
			payloadURL = payloadURL[:maxValueCharsInError] + "..."
		}
		return &mobius.BadRequestError{
			Message: "Variable \"$MOBIUS_VAR_" +
				mobius.MobiusVarNDESSCEPProxyURL + "\" must be in the SCEP certificate's \"URL\" field.",
			InternalErr: fmt.Errorf("URL: %s", payloadURL),
		}
	}
	return nil
}

func (svc *Service) NewMDMAppleDeclaration(ctx context.Context, teamID uint, r io.Reader, labels []string, name string, labelsMembershipMode mobius.MDMLabelsMode) (*mobius.MDMAppleDeclaration, error) {
	if err := svc.authz.Authorize(ctx, &mobius.MDMConfigProfileAuthz{TeamID: &teamID}, mobius.ActionWrite); err != nil {
		return nil, ctxerr.Wrap(ctx, err)
	}

	// check that Apple MDM is enabled - the middleware of that endpoint checks
	// only that any MDM is enabled, maybe it's just Windows
	if err := svc.VerifyMDMAppleConfigured(ctx); err != nil {
		err := mobius.NewInvalidArgumentError("declaration", mobius.AppleMDMNotConfiguredMessage).WithStatus(http.StatusBadRequest)
		return nil, ctxerr.Wrap(ctx, err, "check macOS MDM enabled")
	}

	mobiusNames := mdm_types.MobiusReservedProfileNames()
	if _, ok := mobiusNames[name]; ok {
		err := mobius.NewInvalidArgumentError("declaration", fmt.Sprintf("Profile name %q is not allowed.", name)).WithStatus(http.StatusBadRequest)
		return nil, err
	}

	var teamName string
	if teamID >= 1 {
		tm, err := svc.EnterpriseOverrides.TeamByIDOrName(ctx, &teamID, nil)
		if err != nil {
			return nil, ctxerr.Wrap(ctx, err)
		}
		teamName = tm.Name
	}

	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	var tmID *uint
	if teamID >= 1 {
		tmID = &teamID
	}

	validatedLabels, err := svc.validateDeclarationLabels(ctx, labels)
	if err != nil {
		return nil, err
	}

	dataWithSecrets, secretsUpdatedAt, err := svc.ds.ExpandEmbeddedSecretsAndUpdatedAt(ctx, string(data))
	if err != nil {
		return nil, mobius.NewInvalidArgumentError("profile", err.Error())
	}

	if err := validateDeclarationMobiusVariables(dataWithSecrets); err != nil {
		return nil, err
	}

	// TODO(roberto): Maybe GetRawDeclarationValues belongs inside NewMDMAppleDeclaration? We can refactor this in a follow up.
	rawDecl, err := mobius.GetRawDeclarationValues([]byte(dataWithSecrets))
	if err != nil {
		return nil, err
	}
	// After validation, we should no longer need to keep the expanded secrets.

	if err := rawDecl.ValidateUserProvided(); err != nil {
		return nil, err
	}

	d := mobius.NewMDMAppleDeclaration(data, tmID, name, rawDecl.Type, rawDecl.Identifier)
	d.SecretsUpdatedAt = secretsUpdatedAt

	switch labelsMembershipMode {
	case mobius.LabelsIncludeAny:
		d.LabelsIncludeAny = validatedLabels
	case mobius.LabelsExcludeAny:
		d.LabelsExcludeAny = validatedLabels
	default:
		// default to include all
		d.LabelsIncludeAll = validatedLabels
	}

	decl, err := svc.ds.NewMDMAppleDeclaration(ctx, d)
	if err != nil {
		return nil, err
	}

	if _, err := svc.ds.BulkSetPendingMDMHostProfiles(ctx, nil, nil, []string{decl.DeclarationUUID}, nil); err != nil {
		return nil, ctxerr.Wrap(ctx, err, "bulk set pending host declarations")
	}

	var (
		actTeamID   *uint
		actTeamName *string
	)
	if teamID > 0 {
		actTeamID = &teamID
		actTeamName = &teamName
	}
	if err := svc.NewActivity(
		ctx, authz.UserFromContext(ctx), &mobius.ActivityTypeCreatedDeclarationProfile{
			TeamID:      actTeamID,
			TeamName:    actTeamName,
			ProfileName: decl.Name,
			Identifier:  decl.Identifier,
		}); err != nil {
		return nil, ctxerr.Wrap(ctx, err, "logging activity for create mdm apple declaration")
	}

	return decl, nil
}

func validateDeclarationMobiusVariables(contents string) error {
	if len(findMobiusVariables(contents)) > 0 {
		return &mobius.BadRequestError{Message: "Mobius variables ($MOBIUS_VAR_*) are not currently supported in DDM profiles"}
	}
	return nil
}

func (svc *Service) batchValidateDeclarationLabels(ctx context.Context, labelNames []string) (map[string]mobius.ConfigurationProfileLabel, error) {
	if len(labelNames) == 0 {
		return nil, nil
	}

	labels, err := svc.ds.LabelIDsByName(ctx, labelNames)
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err, "getting label IDs by name")
	}

	uniqueNames := make(map[string]bool)
	for _, entry := range labelNames {
		if _, value := uniqueNames[entry]; !value {
			uniqueNames[entry] = true
		}
	}

	if len(labels) != len(uniqueNames) {
		return nil, &mobius.BadRequestError{
			Message:     "some or all the labels provided don't exist",
			InternalErr: fmt.Errorf("names provided: %v", labelNames),
		}
	}

	profLabels := make(map[string]mobius.ConfigurationProfileLabel)
	for labelName, labelID := range labels {
		profLabels[labelName] = mobius.ConfigurationProfileLabel{
			LabelName: labelName,
			LabelID:   labelID,
		}
	}
	return profLabels, nil
}

func (svc *Service) validateDeclarationLabels(ctx context.Context, labelNames []string) ([]mobius.ConfigurationProfileLabel, error) {
	labelMap, err := svc.batchValidateDeclarationLabels(ctx, labelNames)
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err, "validating declaration labels")
	}

	var declLabels []mobius.ConfigurationProfileLabel
	for _, label := range labelMap {
		declLabels = append(declLabels, label)
	}
	return declLabels, nil
}

type listMDMAppleConfigProfilesRequest struct {
	TeamID uint `query:"team_id,optional"`
}

type listMDMAppleConfigProfilesResponse struct {
	ConfigProfiles []*mobius.MDMAppleConfigProfile `json:"profiles"`
	Err            error                          `json:"error,omitempty"`
}

func (r listMDMAppleConfigProfilesResponse) Error() error { return r.Err }

func listMDMAppleConfigProfilesEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*listMDMAppleConfigProfilesRequest)

	cps, err := svc.ListMDMAppleConfigProfiles(ctx, req.TeamID)
	if err != nil {
		return &listMDMAppleConfigProfilesResponse{Err: err}, nil
	}

	res := listMDMAppleConfigProfilesResponse{ConfigProfiles: cps}
	if cps == nil {
		res.ConfigProfiles = []*mobius.MDMAppleConfigProfile{} // return empty json array instead of json null
	}
	return &res, nil
}

func (svc *Service) ListMDMAppleConfigProfiles(ctx context.Context, teamID uint) ([]*mobius.MDMAppleConfigProfile, error) {
	if err := svc.authz.Authorize(ctx, &mobius.MDMConfigProfileAuthz{TeamID: &teamID}, mobius.ActionRead); err != nil {
		return nil, ctxerr.Wrap(ctx, err)
	}

	if teamID >= 1 {
		// confirm that team exists
		if _, err := svc.ds.Team(ctx, teamID); err != nil {
			return nil, ctxerr.Wrap(ctx, err)
		}
	}

	cps, err := svc.ds.ListMDMAppleConfigProfiles(ctx, &teamID)
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err)
	}

	return cps, nil
}

type getMDMAppleConfigProfileRequest struct {
	ProfileID uint `url:"profile_id"`
}

type getMDMAppleConfigProfileResponse struct {
	Err error `json:"error,omitempty"`

	// file fields below are used in hijackRender for the response
	fileReader io.ReadCloser
	fileLength int64
	fileName   string
}

func (r getMDMAppleConfigProfileResponse) Error() error { return r.Err }

func (r getMDMAppleConfigProfileResponse) HijackRender(ctx context.Context, w http.ResponseWriter) {
	w.Header().Set("Content-Length", strconv.FormatInt(r.fileLength, 10))
	w.Header().Set("Content-Type", "application/x-apple-aspen-config")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment;filename="%s.mobileconfig"`, r.fileName))

	// OK to just log the error here as writing anything on
	// `http.ResponseWriter` sets the status code to 200 (and it can't be
	// changed.) Clients should rely on matching content-length with the
	// header provided
	wl, err := io.Copy(w, r.fileReader)
	if err != nil {
		logging.WithExtras(ctx, "mobileconfig_copy_error", err, "bytes_copied", wl)
	}
	r.fileReader.Close()
}

func getMDMAppleConfigProfileEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*getMDMAppleConfigProfileRequest)

	cp, err := svc.GetMDMAppleConfigProfileByDeprecatedID(ctx, req.ProfileID)
	if err != nil {
		return getMDMAppleConfigProfileResponse{Err: err}, nil
	}
	reader := bytes.NewReader(cp.Mobileconfig)
	fileName := fmt.Sprintf("%s_%s", time.Now().Format("2006-01-02"), strings.ReplaceAll(cp.Name, " ", "_"))

	return getMDMAppleConfigProfileResponse{fileReader: io.NopCloser(reader), fileLength: reader.Size(), fileName: fileName}, nil
}

func (svc *Service) GetMDMAppleConfigProfileByDeprecatedID(ctx context.Context, profileID uint) (*mobius.MDMAppleConfigProfile, error) {
	// first we perform a perform basic authz check
	if err := svc.authz.Authorize(ctx, &mobius.Team{}, mobius.ActionRead); err != nil {
		return nil, err
	}

	cp, err := svc.ds.GetMDMAppleConfigProfileByDeprecatedID(ctx, profileID)
	if err != nil {
		if mobius.IsNotFound(err) {
			// call the standard service method with a profile UUID that will not be
			// found, just to ensure the same sequence of validations are applied.
			return svc.GetMDMAppleConfigProfile(ctx, "-")
		}
		return nil, ctxerr.Wrap(ctx, err)
	}
	return svc.GetMDMAppleConfigProfile(ctx, cp.ProfileUUID)
}

func (svc *Service) GetMDMAppleConfigProfile(ctx context.Context, profileUUID string) (*mobius.MDMAppleConfigProfile, error) {
	// first we perform a perform basic authz check
	if err := svc.authz.Authorize(ctx, &mobius.Team{}, mobius.ActionRead); err != nil {
		return nil, err
	}

	cp, err := svc.ds.GetMDMAppleConfigProfile(ctx, profileUUID)
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err)
	}

	// now we can do a specific authz check based on team id of profile before we return the profile
	if err := svc.authz.Authorize(ctx, &mobius.MDMConfigProfileAuthz{TeamID: cp.TeamID}, mobius.ActionRead); err != nil {
		return nil, err
	}

	return cp, nil
}

func (svc *Service) GetMDMAppleDeclaration(ctx context.Context, profileUUID string) (*mobius.MDMAppleDeclaration, error) {
	// first we perform a perform basic authz check
	if err := svc.authz.Authorize(ctx, &mobius.Team{}, mobius.ActionRead); err != nil {
		return nil, err
	}

	cp, err := svc.ds.GetMDMAppleDeclaration(ctx, profileUUID)
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err)
	}

	// now we can do a specific authz check based on team id of profile before we return the profile
	if err := svc.authz.Authorize(ctx, &mobius.MDMConfigProfileAuthz{TeamID: cp.TeamID}, mobius.ActionRead); err != nil {
		return nil, err
	}

	return cp, nil
}

type deleteMDMAppleConfigProfileRequest struct {
	ProfileID uint `url:"profile_id"`
}

type deleteMDMAppleConfigProfileResponse struct {
	Err error `json:"error,omitempty"`
}

func (r deleteMDMAppleConfigProfileResponse) Error() error { return r.Err }

func deleteMDMAppleConfigProfileEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*deleteMDMAppleConfigProfileRequest)

	if err := svc.DeleteMDMAppleConfigProfileByDeprecatedID(ctx, req.ProfileID); err != nil {
		return &deleteMDMAppleConfigProfileResponse{Err: err}, nil
	}

	return &deleteMDMAppleConfigProfileResponse{}, nil
}

func (svc *Service) DeleteMDMAppleConfigProfileByDeprecatedID(ctx context.Context, profileID uint) error {
	// first we perform a perform basic authz check
	if err := svc.authz.Authorize(ctx, &mobius.Team{}, mobius.ActionRead); err != nil {
		return ctxerr.Wrap(ctx, err)
	}

	// get the profile by ID and call the standard delete function
	cp, err := svc.ds.GetMDMAppleConfigProfileByDeprecatedID(ctx, profileID)
	if err != nil {
		if mobius.IsNotFound(err) {
			// call the standard service method with a profile UUID that will not be
			// found, just to ensure the same sequence of validations are applied.
			return svc.DeleteMDMAppleConfigProfile(ctx, "-")
		}
		return ctxerr.Wrap(ctx, err)
	}
	return svc.DeleteMDMAppleConfigProfile(ctx, cp.ProfileUUID)
}

func (svc *Service) DeleteMDMAppleConfigProfile(ctx context.Context, profileUUID string) error {
	// first we perform a perform basic authz check
	if err := svc.authz.Authorize(ctx, &mobius.Team{}, mobius.ActionRead); err != nil {
		return ctxerr.Wrap(ctx, err)
	}

	// check that Apple MDM is enabled - the middleware of that endpoint checks
	// only that any MDM is enabled, maybe it's just Windows
	if err := svc.VerifyMDMAppleConfigured(ctx); err != nil {
		err := mobius.NewInvalidArgumentError("profile_uuid", mobius.AppleMDMNotConfiguredMessage).WithStatus(http.StatusBadRequest)
		return ctxerr.Wrap(ctx, err, "check macOS MDM enabled")
	}

	cp, err := svc.ds.GetMDMAppleConfigProfile(ctx, profileUUID)
	if err != nil {
		return ctxerr.Wrap(ctx, err)
	}

	var teamName string
	teamID := *cp.TeamID
	if teamID >= 1 {
		tm, err := svc.EnterpriseOverrides.TeamByIDOrName(ctx, &teamID, nil)
		if err != nil {
			return ctxerr.Wrap(ctx, err)
		}
		teamName = tm.Name
	}

	// now we can do a specific authz check based on team id of profile before we delete the profile
	if err := svc.authz.Authorize(ctx, &mobius.MDMConfigProfileAuthz{TeamID: cp.TeamID}, mobius.ActionWrite); err != nil {
		return ctxerr.Wrap(ctx, err)
	}

	// prevent deleting profiles that are managed by Mobius
	if _, ok := mobileconfig.MobiusPayloadIdentifiers()[cp.Identifier]; ok {
		return &mobius.BadRequestError{
			Message:     "profiles managed by Mobius can't be deleted using this endpoint.",
			InternalErr: fmt.Errorf("deleting profile %s for team %s not allowed because it's managed by Mobius", cp.Identifier, teamName),
		}
	}

	// This call will also delete host_mdm_apple_profiles references IFF the profile has not been sent to
	// the host yet.
	if err := svc.ds.DeleteMDMAppleConfigProfile(ctx, profileUUID); err != nil {
		return ctxerr.Wrap(ctx, err)
	}

	var (
		actTeamID   *uint
		actTeamName *string
	)
	if teamID > 0 {
		actTeamID = &teamID
		actTeamName = &teamName
	}
	if err := svc.NewActivity(
		ctx, authz.UserFromContext(ctx), &mobius.ActivityTypeDeletedMacosProfile{
			TeamID:            actTeamID,
			TeamName:          actTeamName,
			ProfileName:       cp.Name,
			ProfileIdentifier: cp.Identifier,
		}); err != nil {
		return ctxerr.Wrap(ctx, err, "logging activity for delete mdm apple config profile")
	}

	return nil
}

func (svc *Service) DeleteMDMAppleDeclaration(ctx context.Context, declUUID string) error {
	// first we perform a perform basic authz check
	if err := svc.authz.Authorize(ctx, &mobius.Team{}, mobius.ActionRead); err != nil {
		return ctxerr.Wrap(ctx, err)
	}

	// check that Apple MDM is enabled - the middleware of that endpoint checks
	// only that any MDM is enabled, maybe it's just Windows
	if err := svc.VerifyMDMAppleConfigured(ctx); err != nil {
		err := mobius.NewInvalidArgumentError("profile_uuid", mobius.AppleMDMNotConfiguredMessage).WithStatus(http.StatusBadRequest)
		return ctxerr.Wrap(ctx, err, "check macOS MDM enabled")
	}

	decl, err := svc.ds.GetMDMAppleDeclaration(ctx, declUUID)
	if err != nil {
		return ctxerr.Wrap(ctx, err)
	}

	// Check if the declaration contains a secret variable. If it does, this means that the declaration
	// has been provided by the user and can be deleted. We don't need to validate that it is a Mobius declaration.
	hasSecretVariable := len(mobius.ContainsPrefixVars(string(decl.RawJSON), mobius.ServerSecretPrefix)) > 0
	if !hasSecretVariable {
		if _, ok := mdm_types.MobiusReservedProfileNames()[decl.Name]; ok {
			return &mobius.BadRequestError{
				Message:     "profiles managed by Mobius can't be deleted using this endpoint.",
				InternalErr: fmt.Errorf("deleting profile %s is not allowed because it's managed by Mobius", decl.Name),
			}
		}

		// TODO: refine our approach to deleting restricted/forbidden types of declarations so that we
		// can check that Mobius-managed aren't being deleted; this can be addressed once we add support
		// for more types of declarations
		var d mobius.MDMAppleRawDeclaration
		if err := json.Unmarshal(decl.RawJSON, &d); err != nil {
			return ctxerr.Wrap(ctx, err, "unmarshalling declaration")
		}
		if err := d.ValidateUserProvided(); err != nil {
			return ctxerr.Wrap(ctx, &mobius.BadRequestError{Message: err.Error()})
		}
	}

	var teamName string
	teamID := *decl.TeamID
	if teamID >= 1 {
		tm, err := svc.EnterpriseOverrides.TeamByIDOrName(ctx, &teamID, nil)
		if err != nil {
			return ctxerr.Wrap(ctx, err)
		}
		teamName = tm.Name
	}

	// now we can do a specific authz check based on team id of profile before we delete the profile
	if err := svc.authz.Authorize(ctx, &mobius.MDMConfigProfileAuthz{TeamID: decl.TeamID}, mobius.ActionWrite); err != nil {
		return ctxerr.Wrap(ctx, err)
	}

	if err := svc.ds.DeleteMDMAppleDeclaration(ctx, declUUID); err != nil {
		return ctxerr.Wrap(ctx, err)
	}

	var (
		actTeamID   *uint
		actTeamName *string
	)
	if teamID > 0 {
		actTeamID = &teamID
		actTeamName = &teamName
	}
	if err := svc.NewActivity(
		ctx, authz.UserFromContext(ctx), &mobius.ActivityTypeDeletedDeclarationProfile{
			TeamID:      actTeamID,
			TeamName:    actTeamName,
			ProfileName: decl.Name,
			Identifier:  decl.Identifier,
		}); err != nil {
		return ctxerr.Wrap(ctx, err, "logging activity for delete mdm apple declaration")
	}

	return nil
}

type getMDMAppleFileVaultSummaryRequest struct {
	TeamID *uint `query:"team_id,optional"`
}

type getMDMAppleFileVaultSummaryResponse struct {
	*mobius.MDMAppleFileVaultSummary
	Err error `json:"error,omitempty"`
}

func (r getMDMAppleFileVaultSummaryResponse) Error() error { return r.Err }

func getMdmAppleFileVaultSummaryEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*getMDMAppleFileVaultSummaryRequest)

	fvs, err := svc.GetMDMAppleFileVaultSummary(ctx, req.TeamID)
	if err != nil {
		return &getMDMAppleFileVaultSummaryResponse{Err: err}, nil
	}

	return &getMDMAppleFileVaultSummaryResponse{
		MDMAppleFileVaultSummary: fvs,
	}, nil
}

func (svc *Service) GetMDMAppleFileVaultSummary(ctx context.Context, teamID *uint) (*mobius.MDMAppleFileVaultSummary, error) {
	if err := svc.authz.Authorize(ctx, mobius.MDMConfigProfileAuthz{TeamID: teamID}, mobius.ActionRead); err != nil {
		return nil, ctxerr.Wrap(ctx, err)
	}

	fvs, err := svc.ds.GetMDMAppleFileVaultSummary(ctx, teamID)
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err)
	}

	return fvs, nil
}

type getMDMAppleProfilesSummaryRequest struct {
	TeamID *uint `query:"team_id,optional"`
}

type getMDMAppleProfilesSummaryResponse struct {
	mobius.MDMProfilesSummary
	Err error `json:"error,omitempty"`
}

func (r getMDMAppleProfilesSummaryResponse) Error() error { return r.Err }

func getMDMAppleProfilesSummaryEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*getMDMAppleProfilesSummaryRequest)
	res := getMDMAppleProfilesSummaryResponse{}

	ps, err := svc.GetMDMAppleProfilesSummary(ctx, req.TeamID)
	if err != nil {
		return &getMDMAppleProfilesSummaryResponse{Err: err}, nil
	}

	res.Verified = ps.Verified
	res.Verifying = ps.Verifying
	res.Failed = ps.Failed
	res.Pending = ps.Pending

	return &res, nil
}

func (svc *Service) GetMDMAppleProfilesSummary(ctx context.Context, teamID *uint) (*mobius.MDMProfilesSummary, error) {
	if err := svc.authz.Authorize(ctx, mobius.MDMConfigProfileAuthz{TeamID: teamID}, mobius.ActionRead); err != nil {
		return nil, ctxerr.Wrap(ctx, err)
	}

	if err := svc.VerifyMDMAppleConfigured(ctx); err != nil {
		return &mobius.MDMProfilesSummary{}, nil
	}

	ps, err := svc.ds.GetMDMAppleProfilesSummary(ctx, teamID)
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err)
	}

	return ps, nil
}

type uploadAppleInstallerRequest struct {
	Installer *multipart.FileHeader
}

type uploadAppleInstallerResponse struct {
	ID  uint  `json:"installer_id"`
	Err error `json:"error,omitempty"`
}

// TODO(lucas): We parse the whole body before running svc.authz.Authorize.
// An authenticated but unauthorized user could abuse this.
func (uploadAppleInstallerRequest) DecodeRequest(ctx context.Context, r *http.Request) (interface{}, error) {
	err := r.ParseMultipartForm(512 * units.MiB)
	if err != nil {
		return nil, &mobius.BadRequestError{
			Message:     "failed to parse multipart form",
			InternalErr: err,
		}
	}
	installer := r.MultipartForm.File["installer"][0]
	return &uploadAppleInstallerRequest{
		Installer: installer,
	}, nil
}

func (r uploadAppleInstallerResponse) Error() error { return r.Err }

// Deprecated: Not in Use
func uploadAppleInstallerEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*uploadAppleInstallerRequest)
	ff, err := req.Installer.Open()
	if err != nil {
		return uploadAppleInstallerResponse{Err: err}, nil
	}
	defer ff.Close()
	installer, err := svc.UploadMDMAppleInstaller(ctx, req.Installer.Filename, req.Installer.Size, ff)
	if err != nil {
		return uploadAppleInstallerResponse{Err: err}, nil
	}
	return &uploadAppleInstallerResponse{
		ID: installer.ID,
	}, nil
}

func (svc *Service) UploadMDMAppleInstaller(ctx context.Context, name string, size int64, installer io.Reader) (*mobius.MDMAppleInstaller, error) {
	if err := svc.authz.Authorize(ctx, &mobius.MDMAppleInstaller{}, mobius.ActionWrite); err != nil {
		return nil, ctxerr.Wrap(ctx, err)
	}

	appConfig, err := svc.ds.AppConfig(ctx)
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err)
	}

	token := uuid.New().String()
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err)
	}

	url := svc.installerURL(token, appConfig)

	var installerBuf bytes.Buffer
	manifest, err := createManifest(size, io.TeeReader(installer, &installerBuf), url)
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err)
	}

	inst, err := svc.ds.NewMDMAppleInstaller(ctx, name, size, manifest, installerBuf.Bytes(), token)
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err)
	}

	return inst, nil
}

func (svc *Service) installerURL(token string, appConfig *mobius.AppConfig) string {
	return fmt.Sprintf("%s%s?token=%s", appConfig.ServerSettings.ServerURL, apple_mdm.InstallerPath, token)
}

func createManifest(size int64, installer io.Reader, url string) (string, error) {
	manifest, err := appmanifest.New(&readerWithSize{
		Reader: installer,
		size:   size,
	}, url)
	if err != nil {
		return "", fmt.Errorf("create manifest file: %w", err)
	}
	var buf bytes.Buffer
	enc := plist.NewEncoder(&buf)
	enc.Indent("  ")
	if err := enc.Encode(manifest); err != nil {
		return "", fmt.Errorf("encode manifest: %w", err)
	}
	return buf.String(), nil
}

type readerWithSize struct {
	io.Reader
	size int64
}

func (r *readerWithSize) Size() int64 {
	return r.size
}

type getAppleInstallerDetailsRequest struct {
	ID uint `url:"installer_id"`
}

type getAppleInstallerDetailsResponse struct {
	Installer *mobius.MDMAppleInstaller
	Err       error `json:"error,omitempty"`
}

func (r getAppleInstallerDetailsResponse) Error() error { return r.Err }

func getAppleInstallerEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*getAppleInstallerDetailsRequest)
	installer, err := svc.GetMDMAppleInstallerByID(ctx, req.ID)
	if err != nil {
		return getAppleInstallerDetailsResponse{Err: err}, nil
	}
	return &getAppleInstallerDetailsResponse{
		Installer: installer,
	}, nil
}

func (svc *Service) GetMDMAppleInstallerByID(ctx context.Context, id uint) (*mobius.MDMAppleInstaller, error) {
	if err := svc.authz.Authorize(ctx, &mobius.MDMAppleInstaller{}, mobius.ActionWrite); err != nil {
		return nil, ctxerr.Wrap(ctx, err)
	}

	inst, err := svc.ds.MDMAppleInstallerDetailsByID(ctx, id)
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err)
	}
	return inst, nil
}

type deleteAppleInstallerDetailsRequest struct {
	ID uint `url:"installer_id"`
}

type deleteAppleInstallerDetailsResponse struct {
	Err error `json:"error,omitempty"`
}

func (r deleteAppleInstallerDetailsResponse) Error() error { return r.Err }

func deleteAppleInstallerEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*deleteAppleInstallerDetailsRequest)
	if err := svc.DeleteMDMAppleInstaller(ctx, req.ID); err != nil {
		return deleteAppleInstallerDetailsResponse{Err: err}, nil
	}
	return &deleteAppleInstallerDetailsResponse{}, nil
}

func (svc *Service) DeleteMDMAppleInstaller(ctx context.Context, id uint) error {
	if err := svc.authz.Authorize(ctx, &mobius.MDMAppleInstaller{}, mobius.ActionWrite); err != nil {
		return ctxerr.Wrap(ctx, err)
	}

	if err := svc.ds.DeleteMDMAppleInstaller(ctx, id); err != nil {
		return ctxerr.Wrap(ctx, err)
	}
	return nil
}

type listMDMAppleDevicesRequest struct{}

type listMDMAppleDevicesResponse struct {
	Devices []mobius.MDMAppleDevice `json:"devices"`
	Err     error                  `json:"error,omitempty"`
}

func (r listMDMAppleDevicesResponse) Error() error { return r.Err }

func listMDMAppleDevicesEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	devices, err := svc.ListMDMAppleDevices(ctx)
	if err != nil {
		return listMDMAppleDevicesResponse{Err: err}, nil
	}
	return &listMDMAppleDevicesResponse{
		Devices: devices,
	}, nil
}

func (svc *Service) ListMDMAppleDevices(ctx context.Context) ([]mobius.MDMAppleDevice, error) {
	if err := svc.authz.Authorize(ctx, &mobius.MDMAppleDevice{}, mobius.ActionWrite); err != nil {
		return nil, ctxerr.Wrap(ctx, err)
	}

	return svc.ds.MDMAppleListDevices(ctx)
}

type newMDMAppleDEPKeyPairResponse struct {
	PublicKey  []byte `json:"public_key,omitempty"`
	PrivateKey []byte `json:"private_key,omitempty"`
	Err        error  `json:"error,omitempty"`
}

func (r newMDMAppleDEPKeyPairResponse) Error() error { return r.Err }

func newMDMAppleDEPKeyPairEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	keyPair, err := svc.NewMDMAppleDEPKeyPair(ctx)
	if err != nil {
		return newMDMAppleDEPKeyPairResponse{
			Err: err,
		}, nil
	}

	return newMDMAppleDEPKeyPairResponse{
		PublicKey:  keyPair.PublicKey,
		PrivateKey: keyPair.PrivateKey,
	}, nil
}

func (svc *Service) NewMDMAppleDEPKeyPair(ctx context.Context) (*mobius.MDMAppleDEPKeyPair, error) {
	// skipauth: Generating a new key pair does not actually make any changes to mobius, or expose any
	// information. The user must configure mobius with the new key pair and restart the server.
	svc.authz.SkipAuthorization(ctx)

	publicKeyPEM, privateKeyPEM, err := apple_mdm.NewDEPKeyPairPEM()
	if err != nil {
		return nil, fmt.Errorf("generate key pair: %w", err)
	}

	return &mobius.MDMAppleDEPKeyPair{
		PublicKey:  publicKeyPEM,
		PrivateKey: privateKeyPEM,
	}, nil
}

type enqueueMDMAppleCommandRequest struct {
	Command   string   `json:"command"`
	DeviceIDs []string `json:"device_ids"`
}

type enqueueMDMAppleCommandResponse struct {
	*mobius.CommandEnqueueResult
	Err error `json:"error,omitempty"`
}

func (r enqueueMDMAppleCommandResponse) Error() error { return r.Err }

// Deprecated: enqueueMDMAppleCommandEndpoint is now deprecated, replaced by
// the platform-agnostic runMDMCommandEndpoint. It is still supported
// indefinitely for backwards compatibility.
func enqueueMDMAppleCommandEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*enqueueMDMAppleCommandRequest)
	result, err := svc.EnqueueMDMAppleCommand(ctx, req.Command, req.DeviceIDs)
	if err != nil {
		return enqueueMDMAppleCommandResponse{Err: err}, nil
	}
	return enqueueMDMAppleCommandResponse{
		CommandEnqueueResult: result,
	}, nil
}

func (svc *Service) EnqueueMDMAppleCommand(
	ctx context.Context,
	rawBase64Cmd string,
	deviceIDs []string,
) (result *mobius.CommandEnqueueResult, err error) {
	hosts, err := svc.authorizeAllHostsTeams(ctx, deviceIDs, mobius.ActionWrite, &mobius.MDMCommandAuthz{})
	if err != nil {
		return nil, err
	}
	if len(hosts) == 0 {
		return nil, newNotFoundError()
	}

	// using a padding agnostic decoder because we released this using
	// base64.RawStdEncoding, but it was causing problems as many standard
	// libraries default to padded strings. We're now supporting both for
	// backwards compatibility.
	rawXMLCmd, err := server.Base64DecodePaddingAgnostic(rawBase64Cmd)
	if err != nil {
		err = mobius.NewInvalidArgumentError("command", "unable to decode base64 command").WithStatus(http.StatusBadRequest)

		return nil, ctxerr.Wrap(ctx, err, "decode base64 command")
	}

	return svc.enqueueAppleMDMCommand(ctx, rawXMLCmd, deviceIDs)
}

type mdmAppleEnrollRequest struct {
	// Token is expected to be a UUID string that identifies a template MDM Apple enrollment profile.
	Token string `query:"token"`
	// EnrollmentReference is expected to be a UUID string that identifies the MDM IdP account used
	// to authenticate the end user as part of the MDM IdP flow.
	EnrollmentReference string `query:"enrollment_reference,optional"`
	// DeviceInfo is expected to be a base64 encoded string extracted during MDM IdP enrollment from the
	// x-apple-aspen-deviceinfo header of the original configuration web view request and
	// persisted by the client in local storage for inclusion in a subsequent enrollment request as
	// part of the MDM IdP flow.
	// See https://developer.apple.com/documentation/devicemanagement/device_assignment/authenticating_through_web_views
	DeviceInfo string `query:"deviceinfo,optional"`
	// MachineInfo is the decoded deviceinfo URL query param for MDM IdP enrollments or the decoded
	// x-apple-aspen-deviceinfo header for non-IdP enrollments.
	MachineInfo *mobius.MDMAppleMachineInfo
}

func (mdmAppleEnrollRequest) DecodeRequest(ctx context.Context, r *http.Request) (interface{}, error) {
	decoded := mdmAppleEnrollRequest{}

	tok := r.URL.Query().Get("token")
	if tok == "" {
		return nil, &mobius.BadRequestError{
			Message: "token is required",
		}
	}
	decoded.Token = tok

	er := r.URL.Query().Get("enrollment_reference")
	decoded.EnrollmentReference = er

	// Parse the machine info from the request header or URL query param.
	di := r.Header.Get("x-apple-aspen-deviceinfo")
	if di == "" {
		vals, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil {
			return nil, &mobius.BadRequestError{
				Message:     "unable to parse query string",
				InternalErr: err,
			}
		}
		di = vals.Get("deviceinfo")
		decoded.DeviceInfo = di
	}

	if di != "" {
		// parse the base64 encoded deviceinfo
		parsed, err := apple_mdm.ParseDeviceinfo(di, false) // FIXME: use verify=true when we have better parsing for various Apple certs (https://github.com/notawar/mobius/issues/20879)
		if err != nil {
			return nil, &mobius.BadRequestError{
				Message:     "unable to parse deviceinfo header",
				InternalErr: err,
			}
		}
		decoded.MachineInfo = parsed
	}

	if decoded.MachineInfo == nil && r.Header.Get("Content-Type") == "application/pkcs7-signature" {
		defer r.Body.Close()
		// We limit the amount we read since this is an untrusted HTTP request -- a potential DoS attack from huge payloads.
		body, err := io.ReadAll(io.LimitReader(r.Body, limit10KiB))
		if err != nil {
			return nil, &mobius.BadRequestError{
				Message:     "unable to read request body",
				InternalErr: err,
			}
		}

		// FIXME: use verify=true when we have better parsing for various Apple certs (https://github.com/notawar/mobius/issues/20879)
		decoded.MachineInfo, err = apple_mdm.ParseMachineInfoFromPKCS7(body, false)
		if err != nil {
			return nil, &mobius.BadRequestError{
				Message:     "unable to parse machine info",
				InternalErr: err,
			}
		}
	}

	return &decoded, nil
}

func (r mdmAppleEnrollResponse) Error() error { return r.Err }

type mdmAppleEnrollResponse struct {
	Err error `json:"error,omitempty"`

	// Profile field is used in HijackRender for the response.
	Profile []byte

	SoftwareUpdateRequired *mobius.MDMAppleSoftwareUpdateRequired
}

func (r mdmAppleEnrollResponse) HijackRender(ctx context.Context, w http.ResponseWriter) {
	if r.SoftwareUpdateRequired != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		if err := json.NewEncoder(w).Encode(r.SoftwareUpdateRequired); err != nil {
			endpoint_utils.EncodeError(ctx, ctxerr.New(ctx, "failed to encode software update required"), w)
		}
		return
	}

	w.Header().Set("Content-Length", strconv.FormatInt(int64(len(r.Profile)), 10))
	w.Header().Set("Content-Type", "application/x-apple-aspen-config")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Disposition", "attachment;mobius-enrollment-profile.mobileconfig")

	// OK to just log the error here as writing anything on
	// `http.ResponseWriter` sets the status code to 200 (and it can't be
	// changed.) Clients should rely on matching content-length with the
	// header provided.
	if n, err := w.Write(r.Profile); err != nil {
		logging.WithExtras(ctx, "err", err, "written", n)
	}
}

func mdmAppleEnrollEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*mdmAppleEnrollRequest)

	if req.DeviceInfo == "" {
		// This is a non-IdP enrollment, so we need to check the OS version here. For IdP enrollments
		// os version checks is performed by the frontend MDM enrollment handler.
		sur, err := svc.CheckMDMAppleEnrollmentWithMinimumOSVersion(ctx, req.MachineInfo)
		if err != nil {
			return mdmAppleEnrollResponse{Err: err}, nil
		}
		if sur != nil {
			return mdmAppleEnrollResponse{
				SoftwareUpdateRequired: sur,
			}, nil
		}
	}

	legacyRef, err := svc.ReconcileMDMAppleEnrollRef(ctx, req.EnrollmentReference, req.MachineInfo)
	if err != nil {
		return mdmAppleEnrollResponse{Err: err}, nil
	}

	profile, err := svc.GetMDMAppleEnrollmentProfileByToken(ctx, req.Token, legacyRef)
	if err != nil {
		return mdmAppleEnrollResponse{Err: err}, nil
	}
	return mdmAppleEnrollResponse{
		Profile: profile,
	}, nil
}

func (svc *Service) ReconcileMDMAppleEnrollRef(ctx context.Context, enrollRef string, machineInfo *mobius.MDMAppleMachineInfo) (string, error) {
	if machineInfo == nil {
		// TODO: what to do here? We can't reconcile the enroll ref without machine info
		level.Info(svc.logger).Log("msg", "missing machine info, failing enroll ref check", "enroll_ref", enrollRef)
		return "", &mobius.BadRequestError{
			Message: "missing deviceinfo",
		}
	}

	legacyRef, err := svc.ds.ReconcileMDMAppleEnrollRef(ctx, enrollRef, machineInfo)
	if err != nil && !mobius.IsNotFound(err) {
		return "", ctxerr.Wrap(ctx, err, "check legacy enroll ref")
	}
	level.Info(svc.logger).Log("msg", "check legacy enroll ref", "host_uuid", machineInfo.UDID, "legacy_enroll_ref", legacyRef)

	return legacyRef, nil
}

func (svc *Service) GetMDMAppleEnrollmentProfileByToken(ctx context.Context, token string, ref string) (profile []byte, err error) {
	// skipauth: The enroll profile endpoint is unauthenticated.
	svc.authz.SkipAuthorization(ctx)

	_, err = svc.ds.GetMDMAppleEnrollmentProfileByToken(ctx, token)
	if err != nil {
		if mobius.IsNotFound(err) {
			return nil, mobius.NewAuthFailedError("enrollment profile not found")
		}
		return nil, ctxerr.Wrap(ctx, err, "get enrollment profile")
	}

	appConfig, err := svc.ds.AppConfig(ctx)
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err)
	}

	enrollURL, err := apple_mdm.AddEnrollmentRefToMobiusURL(appConfig.MDMUrl(), ref)
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err, "adding reference to mobius URL")
	}

	topic, err := svc.mdmPushCertTopic(ctx)
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err, "extracting topic from APNs cert")
	}

	assets, err := svc.ds.GetAllMDMConfigAssetsByName(ctx, []mobius.MDMAssetName{
		mobius.MDMAssetSCEPChallenge,
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("loading SCEP challenge from the database: %w", err)
	}
	enrollmentProf, err := apple_mdm.GenerateEnrollmentProfileMobileconfig(
		appConfig.OrgInfo.OrgName,
		enrollURL,
		string(assets[mobius.MDMAssetSCEPChallenge].Value),
		topic,
	)
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err, "generating enrollment profile")
	}

	signed, err := mdmcrypto.Sign(ctx, enrollmentProf, svc.ds)
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err, "signing profile")
	}

	return signed, nil
}

func (svc *Service) CheckMDMAppleEnrollmentWithMinimumOSVersion(ctx context.Context, m *mobius.MDMAppleMachineInfo) (*mobius.MDMAppleSoftwareUpdateRequired, error) {
	// skipauth: The enroll profile endpoint is unauthenticated.
	svc.authz.SkipAuthorization(ctx)

	if m == nil {
		level.Debug(svc.logger).Log("msg", "no machine info, skipping os version check")
		return nil, nil
	}

	level.Debug(svc.logger).Log("msg", "checking os version", "serial", m.Serial, "current_version", m.OSVersion)

	if !m.MDMCanRequestSoftwareUpdate {
		level.Debug(svc.logger).Log("msg", "mdm cannot request software update, skipping os version check", "serial", m.Serial)
		return nil, nil
	}

	needsUpdate, err := svc.needsOSUpdateForDEPEnrollment(ctx, *m)
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err, "checking os updates settings", "serial", m.Serial)
	}

	if !needsUpdate {
		level.Debug(svc.logger).Log("msg", "device is above minimum, skipping os version check", "serial", m.Serial)
		return nil, nil
	}

	sur, err := svc.getAppleSoftwareUpdateRequiredForDEPEnrollment(*m)
	if err != nil {
		// log for debugging but allow enrollment to proceed
		level.Info(svc.logger).Log("msg", "getting apple software update required", "serial", m.Serial, "err", err)
		return nil, nil
	}

	return sur, nil
}

func (svc *Service) needsOSUpdateForDEPEnrollment(ctx context.Context, m mobius.MDMAppleMachineInfo) (bool, error) {
	// NOTE: Under the hood, the datastore is joining host_dep_assignments to the hosts table to
	// look up DEP hosts by serial number. It grabs the team id and platform from the
	// hosts table. Then it uses the team id to get either the global config or team config.
	// Finally, it uses the platform to get os updates settings from the config for
	// one of ios, ipados, or darwin, as applicable. There's a lot of assumptions going on here, not
	// least of which is that the platform is correct in the hosts table. If the platform is wrong,
	// we'll end up with a meaningless comparison of unrelated versions. We could potentially add
	// some cross-check against the machine info to ensure that the platform of the host aligns with
	// what we expect from the machine info. But that would involve work to derive the platform from
	// the machine info (presumably from the product name, but that's not a 1:1 mapping).
	settings, err := svc.ds.GetMDMAppleOSUpdatesSettingsByHostSerial(ctx, m.Serial)
	if err != nil {
		if mobius.IsNotFound(err) {
			level.Info(svc.logger).Log("msg", "checking os updates settings, settings not found", "serial", m.Serial)
			return false, nil
		}
		return false, err
	}
	// TODO: confirm what this check should do
	if !settings.MinimumVersion.Set || !settings.MinimumVersion.Valid || settings.MinimumVersion.Value == "" {
		level.Info(svc.logger).Log("msg", "checking os updates settings, minimum version not set", "serial", m.Serial, "current_version", m.OSVersion, "minimum_version", settings.MinimumVersion.Value)
		return false, nil
	}

	needsUpdate, err := apple_mdm.IsLessThanVersion(m.OSVersion, settings.MinimumVersion.Value)
	if err != nil {
		level.Info(svc.logger).Log("msg", "checking os updates settings, cannot compare versions", "serial", m.Serial, "current_version", m.OSVersion, "minimum_version", settings.MinimumVersion.Value)
		return false, nil
	}

	return needsUpdate, nil
}

func (svc *Service) getAppleSoftwareUpdateRequiredForDEPEnrollment(m mobius.MDMAppleMachineInfo) (*mobius.MDMAppleSoftwareUpdateRequired, error) {
	latest, err := gdmf.GetLatestOSVersion(m)
	if err != nil {
		return nil, err
	}

	needsUpdate, err := apple_mdm.IsLessThanVersion(m.OSVersion, latest.ProductVersion)
	if err != nil {
		return nil, err
	} else if !needsUpdate {
		return nil, nil
	}

	return mobius.NewMDMAppleSoftwareUpdateRequired(mobius.MDMAppleSoftwareUpdateAsset{
		ProductVersion: latest.ProductVersion,
		Build:          latest.Build,
	}), nil
}

func (svc *Service) mdmPushCertTopic(ctx context.Context) (string, error) {
	assets, err := svc.ds.GetAllMDMConfigAssetsByName(ctx, []mobius.MDMAssetName{
		mobius.MDMAssetAPNSCert,
	}, nil)
	if err != nil {
		return "", ctxerr.Wrap(ctx, err, "loading SCEP keypair from the database")
	}

	block, _ := pem.Decode(assets[mobius.MDMAssetAPNSCert].Value)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", ctxerr.Wrap(ctx, err, "decoding PEM data")
	}

	apnsCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", ctxerr.Wrap(ctx, err, "parsing APNs certificate")
	}

	mdmPushCertTopic, err := cryptoutil.TopicFromCert(apnsCert)
	if err != nil {
		return "", ctxerr.Wrap(ctx, err, "extracting topic from APNs certificate")
	}

	return mdmPushCertTopic, nil
}

type mdmAppleCommandRemoveEnrollmentProfileRequest struct {
	HostID uint `url:"id"`
}

type mdmAppleCommandRemoveEnrollmentProfileResponse struct {
	Err error `json:"error,omitempty"`
}

func (r mdmAppleCommandRemoveEnrollmentProfileResponse) Error() error { return r.Err }

func (r mdmAppleCommandRemoveEnrollmentProfileResponse) Status() int { return http.StatusNoContent }

func mdmAppleCommandRemoveEnrollmentProfileEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*mdmAppleCommandRemoveEnrollmentProfileRequest)
	err := svc.EnqueueMDMAppleCommandRemoveEnrollmentProfile(ctx, req.HostID)
	if err != nil {
		return mdmAppleCommandRemoveEnrollmentProfileResponse{Err: err}, nil
	}
	return mdmAppleCommandRemoveEnrollmentProfileResponse{}, nil
}

func (svc *Service) EnqueueMDMAppleCommandRemoveEnrollmentProfile(ctx context.Context, hostID uint) error {
	if err := svc.authz.Authorize(ctx, &mobius.Host{}, mobius.ActionList); err != nil {
		return err
	}

	h, err := svc.ds.HostLite(ctx, hostID)
	if err != nil {
		return ctxerr.Wrap(ctx, err, "getting host info for mdm apple remove profile command")
	}

	switch h.Platform {
	case "windows":
		return &mobius.BadRequestError{
			Message: mobius.CantTurnOffMDMForWindowsHostsMessage,
		}
	default:
		// host is darwin, so continue
	}

	info, err := svc.ds.GetHostMDMCheckinInfo(ctx, h.UUID)
	if err != nil {
		return ctxerr.Wrap(ctx, err, "getting mdm checkin info for mdm apple remove profile command")
	}

	// Check authorization again based on host info for team-based permissions.
	if err := svc.authz.Authorize(ctx, mobius.MDMCommandAuthz{
		TeamID: h.TeamID,
	}, mobius.ActionWrite); err != nil {
		return err
	}

	nanoEnroll, err := svc.ds.GetNanoMDMEnrollment(ctx, h.UUID)
	if err != nil {
		return ctxerr.Wrap(ctx, err, "getting mdm enrollment status for mdm apple remove profile command")
	}
	if nanoEnroll == nil || !nanoEnroll.Enabled {
		return mobius.NewUserMessageError(ctxerr.New(ctx, fmt.Sprintf("mdm is not enabled for host %d", hostID)), http.StatusConflict)
	}

	cmdUUID := uuid.New().String()
	err = svc.mdmAppleCommander.RemoveProfile(ctx, []string{nanoEnroll.ID}, apple_mdm.MobiusPayloadIdentifier, cmdUUID)
	if err != nil {
		return ctxerr.Wrap(ctx, err, "enqueuing mdm apple remove profile command")
	}

	if err := svc.NewActivity(
		ctx, authz.UserFromContext(ctx), &mobius.ActivityTypeMDMUnenrolled{
			HostSerial:       h.HardwareSerial,
			HostDisplayName:  h.DisplayName(),
			InstalledFromDEP: info.InstalledFromDEP,
		}); err != nil {
		return ctxerr.Wrap(ctx, err, "logging activity for mdm apple remove profile command")
	}

	mdmLifecycle := mdmlifecycle.New(svc.ds, svc.logger)
	err = mdmLifecycle.Do(ctx, mdmlifecycle.HostOptions{
		Action:   mdmlifecycle.HostActionTurnOff,
		Platform: info.Platform,
		UUID:     h.UUID,
	})
	if err != nil {
		return ctxerr.Wrap(ctx, err, "running turn off action in mdm lifecycle")
	}

	return nil
}

type mdmAppleGetInstallerRequest struct {
	Token string `query:"token"`
}

func (r mdmAppleGetInstallerResponse) Error() error { return r.Err }

type mdmAppleGetInstallerResponse struct {
	Err error `json:"error,omitempty"`

	// head is used by hijackRender for the response.
	head bool
	// Name field is used in hijackRender for the response.
	name string
	// Size field is used in hijackRender for the response.
	size int64
	// Installer field is used in hijackRender for the response.
	installer []byte
}

func (r mdmAppleGetInstallerResponse) HijackRender(ctx context.Context, w http.ResponseWriter) {
	w.Header().Set("Content-Length", strconv.FormatInt(r.size, 10))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment;filename="%s"`, r.name))

	if r.head {
		w.WriteHeader(http.StatusOK)
		return
	}

	// OK to just log the error here as writing anything on
	// `http.ResponseWriter` sets the status code to 200 (and it can't be
	// changed.) Clients should rely on matching content-length with the
	// header provided
	if n, err := w.Write(r.installer); err != nil {
		logging.WithExtras(ctx, "err", err, "bytes_copied", n)
	}
}

func mdmAppleGetInstallerEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*mdmAppleGetInstallerRequest)
	installer, err := svc.GetMDMAppleInstallerByToken(ctx, req.Token)
	if err != nil {
		return mdmAppleGetInstallerResponse{Err: err}, nil
	}
	return mdmAppleGetInstallerResponse{
		head:      false,
		name:      installer.Name,
		size:      installer.Size,
		installer: installer.Installer,
	}, nil
}

func (svc *Service) GetMDMAppleInstallerByToken(ctx context.Context, token string) (*mobius.MDMAppleInstaller, error) {
	// skipauth: The installer endpoint uses token authentication.
	svc.authz.SkipAuthorization(ctx)

	installer, err := svc.ds.MDMAppleInstaller(ctx, token)
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err)
	}
	return installer, nil
}

type mdmAppleHeadInstallerRequest struct {
	Token string `query:"token"`
}

func mdmAppleHeadInstallerEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*mdmAppleHeadInstallerRequest)
	installer, err := svc.GetMDMAppleInstallerDetailsByToken(ctx, req.Token)
	if err != nil {
		return mdmAppleGetInstallerResponse{Err: err}, nil
	}
	return mdmAppleGetInstallerResponse{
		head: true,
		name: installer.Name,
		size: installer.Size,
	}, nil
}

func (svc *Service) GetMDMAppleInstallerDetailsByToken(ctx context.Context, token string) (*mobius.MDMAppleInstaller, error) {
	// skipauth: The installer endpoint uses token authentication.
	svc.authz.SkipAuthorization(ctx)

	installer, err := svc.ds.MDMAppleInstallerDetailsByToken(ctx, token)
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err)
	}
	return installer, nil
}

type listMDMAppleInstallersRequest struct{}

type listMDMAppleInstallersResponse struct {
	Installers []mobius.MDMAppleInstaller `json:"installers"`
	Err        error                     `json:"error,omitempty"`
}

func (r listMDMAppleInstallersResponse) Error() error { return r.Err }

func listMDMAppleInstallersEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	installers, err := svc.ListMDMAppleInstallers(ctx)
	if err != nil {
		return listMDMAppleInstallersResponse{
			Err: err,
		}, nil
	}
	return listMDMAppleInstallersResponse{
		Installers: installers,
	}, nil
}

func (svc *Service) ListMDMAppleInstallers(ctx context.Context) ([]mobius.MDMAppleInstaller, error) {
	if err := svc.authz.Authorize(ctx, &mobius.MDMAppleInstaller{}, mobius.ActionWrite); err != nil {
		return nil, ctxerr.Wrap(ctx, err)
	}

	appConfig, err := svc.ds.AppConfig(ctx)
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err)
	}

	installers, err := svc.ds.ListMDMAppleInstallers(ctx)
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err)
	}
	for i := range installers {
		installers[i].URL = svc.installerURL(installers[i].URLToken, appConfig)
	}
	return installers, nil
}

////////////////////////////////////////////////////////////////////////////////
// Lock a device
////////////////////////////////////////////////////////////////////////////////

type deviceLockRequest struct {
	HostID uint `url:"id"`
}

type deviceLockResponse struct {
	Err error `json:"error,omitempty"`
}

func (r deviceLockResponse) Error() error { return r.Err }

func (r deviceLockResponse) Status() int { return http.StatusNoContent }

func deviceLockEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*deviceLockRequest)
	err := svc.MDMAppleDeviceLock(ctx, req.HostID)
	if err != nil {
		return deviceLockResponse{Err: err}, nil
	}
	return deviceLockResponse{}, nil
}

func (svc *Service) MDMAppleDeviceLock(ctx context.Context, hostID uint) error {
	// skipauth: No authorization check needed due to implementation returning
	// only license error.
	svc.authz.SkipAuthorization(ctx)

	return mobius.ErrMissingLicense
}

////////////////////////////////////////////////////////////////////////////////
// Wipe a device
////////////////////////////////////////////////////////////////////////////////

type deviceWipeRequest struct {
	HostID uint `url:"id"`
}

type deviceWipeResponse struct {
	Err error `json:"error,omitempty"`
}

func (r deviceWipeResponse) Error() error { return r.Err }

func (r deviceWipeResponse) Status() int { return http.StatusNoContent }

func deviceWipeEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*deviceWipeRequest)
	err := svc.MDMAppleEraseDevice(ctx, req.HostID)
	if err != nil {
		return deviceWipeResponse{Err: err}, nil
	}
	return deviceWipeResponse{}, nil
}

func (svc *Service) MDMAppleEraseDevice(ctx context.Context, hostID uint) error {
	// skipauth: No authorization check needed due to implementation returning
	// only license error.
	svc.authz.SkipAuthorization(ctx)

	return mobius.ErrMissingLicense
}

////////////////////////////////////////////////////////////////////////////////
// Get profiles assigned to a host
////////////////////////////////////////////////////////////////////////////////

type getHostProfilesRequest struct {
	ID uint `url:"id"`
}

type getHostProfilesResponse struct {
	HostID   uint                           `json:"host_id"`
	Profiles []*mobius.MDMAppleConfigProfile `json:"profiles"`
	Err      error                          `json:"error,omitempty"`
}

func (r getHostProfilesResponse) Error() error { return r.Err }

func getHostProfilesEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*getHostProfilesRequest)
	sums, err := svc.MDMListHostConfigurationProfiles(ctx, req.ID)
	if err != nil {
		return getHostProfilesResponse{Err: err}, nil
	}
	res := getHostProfilesResponse{Profiles: sums, HostID: req.ID}
	if res.Profiles == nil {
		res.Profiles = []*mobius.MDMAppleConfigProfile{} // return empty json array instead of json null
	}
	return res, nil
}

func (svc *Service) MDMListHostConfigurationProfiles(ctx context.Context, hostID uint) ([]*mobius.MDMAppleConfigProfile, error) {
	// skipauth: No authorization check needed due to implementation returning
	// only license error.
	svc.authz.SkipAuthorization(ctx)

	return nil, mobius.ErrMissingLicense
}

////////////////////////////////////////////////////////////////////////////////
// Batch Replace MDM Apple Profiles
////////////////////////////////////////////////////////////////////////////////

type batchSetMDMAppleProfilesRequest struct {
	TeamID   *uint    `json:"-" query:"team_id,optional"`
	TeamName *string  `json:"-" query:"team_name,optional"`
	DryRun   bool     `json:"-" query:"dry_run,optional"` // if true, apply validation but do not save changes
	Profiles [][]byte `json:"profiles"`
}

type batchSetMDMAppleProfilesResponse struct {
	Err error `json:"error,omitempty"`
}

func (r batchSetMDMAppleProfilesResponse) Error() error { return r.Err }

func (r batchSetMDMAppleProfilesResponse) Status() int { return http.StatusNoContent }

func batchSetMDMAppleProfilesEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*batchSetMDMAppleProfilesRequest)
	if err := svc.BatchSetMDMAppleProfiles(ctx, req.TeamID, req.TeamName, req.Profiles, req.DryRun, false); err != nil {
		return batchSetMDMAppleProfilesResponse{Err: err}, nil
	}
	return batchSetMDMAppleProfilesResponse{}, nil
}

func (svc *Service) BatchSetMDMAppleProfiles(ctx context.Context, tmID *uint, tmName *string, profiles [][]byte, dryRun, skipBulkPending bool) error {
	var err error
	tmID, tmName, err = svc.authorizeBatchProfiles(ctx, tmID, tmName)
	if err != nil {
		return err
	}

	appCfg, err := svc.ds.AppConfig(ctx)
	if err != nil {
		return ctxerr.Wrap(ctx, err)
	}

	if !appCfg.MDM.EnabledAndConfigured {
		// NOTE: in order to prevent an error when Mobius MDM is not enabled but no
		// profile is provided, which can happen if a user runs `mobiuscli get
		// config` and tries to apply that YAML, as it will contain an empty/null
		// custom_settings key, we just return a success response in this
		// situation.
		if len(profiles) == 0 {
			return nil
		}

		return ctxerr.Wrap(ctx, mobius.NewInvalidArgumentError("mdm", "cannot set custom settings: Mobius MDM is not configured"))
	}

	// any duplicate identifier or name in the provided set results in an error
	profs := make([]*mobius.MDMAppleConfigProfile, 0, len(profiles))
	byName, byIdent := make(map[string]bool, len(profiles)), make(map[string]bool, len(profiles))
	for i, prof := range profiles {
		if len(prof) > 1024*1024 {
			return ctxerr.Wrap(ctx,
				mobius.NewInvalidArgumentError(fmt.Sprintf("profiles[%d]", i), "maximum configuration profile file size is 1 MB"),
			)
		}
		// Expand profile for validation
		expanded, secretsUpdatedAt, err := svc.ds.ExpandEmbeddedSecretsAndUpdatedAt(ctx, string(prof))
		if err != nil {
			return ctxerr.Wrap(ctx,
				mobius.NewInvalidArgumentError(fmt.Sprintf("profiles[%d]", i), err.Error()),
				"missing mobius secrets")
		}
		mdmProf, err := mobius.NewMDMAppleConfigProfile([]byte(expanded), tmID)
		if err != nil {
			return ctxerr.Wrap(ctx,
				mobius.NewInvalidArgumentError(fmt.Sprintf("profiles[%d]", i), err.Error()),
				"invalid mobileconfig profile")
		}

		if err := mdmProf.ValidateUserProvided(); err != nil {
			return ctxerr.Wrap(ctx,
				mobius.NewInvalidArgumentError(fmt.Sprintf("profiles[%d]", i), err.Error()))
		}

		// check if the profile has any mobius variable, not supported by this deprecated endpoint
		if vars := findMobiusVariablesKeepDuplicates(expanded); len(vars) > 0 {
			return ctxerr.Wrap(ctx,
				mobius.NewInvalidArgumentError(
					fmt.Sprintf("profiles[%d]", i), "profile variables are not supported by this deprecated endpoint, use POST /api/latest/mobius/mdm/profiles/batch"))
		}

		// Store original unexpanded profile
		mdmProf.Mobileconfig = prof
		mdmProf.SecretsUpdatedAt = secretsUpdatedAt

		if byName[mdmProf.Name] {
			return ctxerr.Wrap(ctx,
				mobius.NewInvalidArgumentError(fmt.Sprintf("profiles[%d]", i), fmt.Sprintf("Couldn't edit custom_settings. More than one configuration profile have the same name (PayloadDisplayName): %q", mdmProf.Name)),
				"duplicate mobileconfig profile by name")
		}
		byName[mdmProf.Name] = true

		if byIdent[mdmProf.Identifier] {
			return ctxerr.Wrap(ctx,
				mobius.NewInvalidArgumentError(fmt.Sprintf("profiles[%d]", i), fmt.Sprintf("Couldn't edit custom_settings. More than one configuration profile have the same identifier (PayloadIdentifier): %q", mdmProf.Identifier)),
				"duplicate mobileconfig profile by identifier")
		}
		byIdent[mdmProf.Identifier] = true

		profs = append(profs, mdmProf)
	}

	if !skipBulkPending {
		// check for duplicates with existing profiles, skipBulkPending signals that the caller
		// is responsible for ensuring that the profiles names are unique (e.g., MDMAppleMatchPreassignment)
		allProfs, _, err := svc.ds.ListMDMConfigProfiles(ctx, tmID, mobius.ListOptions{PerPage: 0})
		if err != nil {
			return ctxerr.Wrap(ctx, err, "list mdm config profiles")
		}
		for _, p := range allProfs {
			if byName[p.Name] {
				switch {
				case strings.HasPrefix(p.ProfileUUID, "a"):
					// do nothing, all existing mobileconfigs will be replaced and we've already checked
					// the new mobileconfigs for duplicates
					continue
				case strings.HasPrefix(p.ProfileUUID, "w"):
					err := mobius.NewInvalidArgumentError("PayloadDisplayName", fmt.Sprintf(
						"Couldn't edit custom_settings. A Windows configuration profile shares the same name as a macOS configuration profile (PayloadDisplayName): %q", p.Name))
					return ctxerr.Wrap(ctx, err, "duplicate xml and mobileconfig by name")
				default:
					err := mobius.NewInvalidArgumentError("PayloadDisplayName", fmt.Sprintf(
						"Couldn't edit custom_settings. More than one configuration profile have the same name (PayloadDisplayName): %q", p.Name))
					return ctxerr.Wrap(ctx, err, "duplicate json and mobileconfig by name")
				}
			}
			byName[p.Name] = true
		}
	}

	if dryRun {
		return nil
	}
	if err := svc.ds.BatchSetMDMAppleProfiles(ctx, tmID, profs); err != nil {
		return err
	}
	var bulkTeamID uint
	if tmID != nil {
		bulkTeamID = *tmID
	}

	if !skipBulkPending {
		if _, err := svc.ds.BulkSetPendingMDMHostProfiles(ctx, nil, []uint{bulkTeamID}, nil, nil); err != nil {
			return ctxerr.Wrap(ctx, err, "bulk set pending host profiles")
		}
	}

	if err := svc.NewActivity(
		ctx, authz.UserFromContext(ctx), &mobius.ActivityTypeEditedMacosProfile{
			TeamID:   tmID,
			TeamName: tmName,
		}); err != nil {
		return ctxerr.Wrap(ctx, err, "logging activity for edited macos profile")
	}
	return nil
}

////////////////////////////////////////////////////////////////////////////////
// Preassign a profile to a host
////////////////////////////////////////////////////////////////////////////////

type preassignMDMAppleProfileRequest struct {
	mobius.MDMApplePreassignProfilePayload
}

type preassignMDMAppleProfileResponse struct {
	Err error `json:"error,omitempty"`
}

func (r preassignMDMAppleProfileResponse) Error() error { return r.Err }

func (r preassignMDMAppleProfileResponse) Status() int { return http.StatusNoContent }

func preassignMDMAppleProfileEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*preassignMDMAppleProfileRequest)
	if err := svc.MDMApplePreassignProfile(ctx, req.MDMApplePreassignProfilePayload); err != nil {
		return preassignMDMAppleProfileResponse{Err: err}, nil
	}
	return preassignMDMAppleProfileResponse{}, nil
}

func (svc *Service) MDMApplePreassignProfile(ctx context.Context, payload mobius.MDMApplePreassignProfilePayload) error {
	// skipauth: No authorization check needed due to implementation returning
	// only license error.
	svc.authz.SkipAuthorization(ctx)

	return mobius.ErrMissingLicense
}

////////////////////////////////////////////////////////////////////////////////
// Match a set of pre-assigned profiles with a team
////////////////////////////////////////////////////////////////////////////////

type matchMDMApplePreassignmentRequest struct {
	ExternalHostIdentifier string `json:"external_host_identifier"`
}

type matchMDMApplePreassignmentResponse struct {
	Err error `json:"error,omitempty"`
}

func (r matchMDMApplePreassignmentResponse) Error() error { return r.Err }

func (r matchMDMApplePreassignmentResponse) Status() int { return http.StatusNoContent }

func matchMDMApplePreassignmentEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*matchMDMApplePreassignmentRequest)
	if err := svc.MDMAppleMatchPreassignment(ctx, req.ExternalHostIdentifier); err != nil {
		return matchMDMApplePreassignmentResponse{Err: err}, nil
	}
	return matchMDMApplePreassignmentResponse{}, nil
}

func (svc *Service) MDMAppleMatchPreassignment(ctx context.Context, ref string) error {
	// skipauth: No authorization check needed due to implementation returning
	// only license error.
	svc.authz.SkipAuthorization(ctx)

	return mobius.ErrMissingLicense
}

////////////////////////////////////////////////////////////////////////////////
// Update MDM Apple Settings
////////////////////////////////////////////////////////////////////////////////

type updateMDMAppleSettingsRequest struct {
	mobius.MDMAppleSettingsPayload
}

type updateMDMAppleSettingsResponse struct {
	Err error `json:"error,omitempty"`
}

func (r updateMDMAppleSettingsResponse) Error() error { return r.Err }

func (r updateMDMAppleSettingsResponse) Status() int { return http.StatusNoContent }

// This endpoint is required because the UI must allow maintainers (in addition
// to admins) to update some MDM Apple settings, while the update config/update
// team endpoints only allow write access to admins.
func updateMDMAppleSettingsEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*updateMDMAppleSettingsRequest)
	if err := svc.UpdateMDMDiskEncryption(ctx, req.MDMAppleSettingsPayload.TeamID, req.MDMAppleSettingsPayload.EnableDiskEncryption); err != nil {
		return updateMDMAppleSettingsResponse{Err: err}, nil
	}
	return updateMDMAppleSettingsResponse{}, nil
}

func (svc *Service) updateAppConfigMDMDiskEncryption(ctx context.Context, enabled *bool) error {
	// appconfig is only used internally, it's fine to read it unobfuscated
	// (svc.AppConfigObfuscated must not be used because the write-only users
	// such as gitops will fail to access it).
	ac, err := svc.ds.AppConfig(ctx)
	if err != nil {
		return err
	}

	var didUpdate bool
	if enabled != nil {
		if ac.MDM.EnableDiskEncryption.Value != *enabled {
			if *enabled && svc.config.Server.PrivateKey == "" {
				return ctxerr.New(ctx, "Missing required private key. Learn how to configure the private key here: https://mobiusmdm.com/learn-more-about/mobius-server-private-key")
			}

			ac.MDM.EnableDiskEncryption = optjson.SetBool(*enabled)
			didUpdate = true
		}
	}

	if didUpdate {
		if err := svc.ds.SaveAppConfig(ctx, ac); err != nil {
			return err
		}
		if ac.MDM.EnabledAndConfigured { // if macOS MDM is configured, set up FileVault escrow
			var act mobius.ActivityDetails
			if ac.MDM.EnableDiskEncryption.Value {
				act = mobius.ActivityTypeEnabledMacosDiskEncryption{}
				if err := svc.EnterpriseOverrides.MDMAppleEnableFileVaultAndEscrow(ctx, nil); err != nil {
					return ctxerr.Wrap(ctx, err, "enable no-team filevault and escrow")
				}
			} else {
				act = mobius.ActivityTypeDisabledMacosDiskEncryption{}
				if err := svc.EnterpriseOverrides.MDMAppleDisableFileVaultAndEscrow(ctx, nil); err != nil {
					return ctxerr.Wrap(ctx, err, "disable no-team filevault and escrow")
				}
			}
			if err := svc.NewActivity(ctx, authz.UserFromContext(ctx), act); err != nil {
				return ctxerr.Wrap(ctx, err, "create activity for app config macos disk encryption")
			}
		}
	}
	return nil
}

////////////////////////////////////////////////////////////////////////////////
// Upload a bootstrap package
////////////////////////////////////////////////////////////////////////////////

type uploadBootstrapPackageRequest struct {
	Package *multipart.FileHeader
	DryRun  bool `json:"-" query:"dry_run,optional"` // if true, apply validation but do not save changes
	TeamID  uint
}

type uploadBootstrapPackageResponse struct {
	Err error `json:"error,omitempty"`
}

// TODO: We parse the whole body before running svc.authz.Authorize.
// An authenticated but unauthorized user could abuse this.
func (uploadBootstrapPackageRequest) DecodeRequest(ctx context.Context, r *http.Request) (interface{}, error) {
	decoded := uploadBootstrapPackageRequest{}
	err := r.ParseMultipartForm(512 * units.MiB)
	if err != nil {
		return nil, &mobius.BadRequestError{
			Message:     "failed to parse multipart form",
			InternalErr: err,
		}
	}

	if r.MultipartForm.File["package"] == nil {
		return nil, &mobius.BadRequestError{
			Message:     "package multipart field is required",
			InternalErr: err,
		}
	}

	decoded.Package = r.MultipartForm.File["package"][0]
	if !file.IsValidMacOSName(decoded.Package.Filename) {
		return nil, &mobius.BadRequestError{
			Message:     "package name contains invalid characters",
			InternalErr: ctxerr.New(ctx, "package name contains invalid characters"),
		}
	}

	// default is no team
	decoded.TeamID = 0
	val, ok := r.MultipartForm.Value["team_id"]
	if ok && len(val) > 0 {
		teamID, err := strconv.Atoi(val[0])
		if err != nil {
			return nil, &mobius.BadRequestError{Message: fmt.Sprintf("failed to decode team_id in multipart form: %s", err.Error())}
		}
		decoded.TeamID = uint(teamID) //nolint:gosec // dismiss G115
	}

	return &decoded, nil
}

func (r uploadBootstrapPackageResponse) Error() error { return r.Err }

func uploadBootstrapPackageEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*uploadBootstrapPackageRequest)
	ff, err := req.Package.Open()
	if err != nil {
		return uploadBootstrapPackageResponse{Err: err}, nil
	}
	defer ff.Close()

	if err := svc.MDMAppleUploadBootstrapPackage(ctx, req.Package.Filename, ff, req.TeamID, req.DryRun); err != nil {
		return uploadBootstrapPackageResponse{Err: err}, nil
	}
	return &uploadBootstrapPackageResponse{}, nil
}

func (svc *Service) MDMAppleUploadBootstrapPackage(ctx context.Context, name string, pkg io.Reader, teamID uint, dryRun bool) error {
	// skipauth: No authorization check needed due to implementation returning
	// only license error.
	svc.authz.SkipAuthorization(ctx)

	return mobius.ErrMissingLicense
}

////////////////////////////////////////////////////////////////////////////////
// Download a bootstrap package
////////////////////////////////////////////////////////////////////////////////

type downloadBootstrapPackageRequest struct {
	Token string `query:"token"`
}

type downloadBootstrapPackageResponse struct {
	Err error `json:"error,omitempty"`

	// fields used by hijackRender for the response.
	pkg *mobius.MDMAppleBootstrapPackage
}

func (r downloadBootstrapPackageResponse) Error() error { return r.Err }

func (r downloadBootstrapPackageResponse) HijackRender(ctx context.Context, w http.ResponseWriter) {
	w.Header().Set("Content-Length", strconv.Itoa(len(r.pkg.Bytes)))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment;filename="%s"`, r.pkg.Name))

	// OK to just log the error here as writing anything on
	// `http.ResponseWriter` sets the status code to 200 (and it can't be
	// changed.) Clients should rely on matching content-length with the
	// header provided
	if n, err := w.Write(r.pkg.Bytes); err != nil {
		logging.WithExtras(ctx, "err", err, "bytes_copied", n)
	}
}

func downloadBootstrapPackageEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*downloadBootstrapPackageRequest)
	pkg, err := svc.GetMDMAppleBootstrapPackageBytes(ctx, req.Token)
	if err != nil {
		return downloadBootstrapPackageResponse{Err: err}, nil
	}
	return downloadBootstrapPackageResponse{pkg: pkg}, nil
}

func (svc *Service) GetMDMAppleBootstrapPackageBytes(ctx context.Context, token string) (*mobius.MDMAppleBootstrapPackage, error) {
	// skipauth: No authorization check needed due to implementation returning
	// only license error.
	svc.authz.SkipAuthorization(ctx)

	return nil, mobius.ErrMissingLicense
}

////////////////////////////////////////////////////////////////////////////////
// Get metadata about a bootstrap package
////////////////////////////////////////////////////////////////////////////////

type bootstrapPackageMetadataRequest struct {
	TeamID uint `url:"team_id"`

	// ForUpdate is used to indicate that the authorization should be for a
	// "write" instead of a "read", this is needed specifically for the gitops
	// user which is a write-only user, but needs to call this endpoint to check
	// if it needs to upload the bootstrap package (if the hashes are different).
	//
	// NOTE: this parameter is going to be removed in a future version.
	// Prefer other ways to allow gitops read access.
	// For context, see: https://github.com/notawar/mobius/issues/15337#issuecomment-1932878997
	ForUpdate bool `query:"for_update,optional"`
}

type bootstrapPackageMetadataResponse struct {
	Err                             error `json:"error,omitempty"`
	*mobius.MDMAppleBootstrapPackage `json:",omitempty"`
}

func (r bootstrapPackageMetadataResponse) Error() error { return r.Err }

func bootstrapPackageMetadataEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*bootstrapPackageMetadataRequest)
	meta, err := svc.GetMDMAppleBootstrapPackageMetadata(ctx, req.TeamID, req.ForUpdate)
	switch {
	case mobius.IsNotFound(err):
		return bootstrapPackageMetadataResponse{Err: mobius.NewInvalidArgumentError("team_id",
			"bootstrap package for this team does not exist").WithStatus(http.StatusNotFound)}, nil
	case err != nil:
		return bootstrapPackageMetadataResponse{Err: err}, nil
	}
	return bootstrapPackageMetadataResponse{MDMAppleBootstrapPackage: meta}, nil
}

func (svc *Service) GetMDMAppleBootstrapPackageMetadata(ctx context.Context, teamID uint, forUpdate bool) (*mobius.MDMAppleBootstrapPackage, error) {
	// skipauth: No authorization check needed due to implementation returning
	// only license error.
	svc.authz.SkipAuthorization(ctx)

	return nil, mobius.ErrMissingLicense
}

////////////////////////////////////////////////////////////////////////////////
// Delete a bootstrap package
////////////////////////////////////////////////////////////////////////////////

type deleteBootstrapPackageRequest struct {
	TeamID uint `url:"team_id"`
	DryRun bool `query:"dry_run,optional"` // if true, apply validation but do not delete
}

type deleteBootstrapPackageResponse struct {
	Err error `json:"error,omitempty"`
}

func (r deleteBootstrapPackageResponse) Error() error { return r.Err }

func deleteBootstrapPackageEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*deleteBootstrapPackageRequest)
	if err := svc.DeleteMDMAppleBootstrapPackage(ctx, &req.TeamID, req.DryRun); err != nil {
		return deleteBootstrapPackageResponse{Err: err}, nil
	}
	return deleteBootstrapPackageResponse{}, nil
}

func (svc *Service) DeleteMDMAppleBootstrapPackage(ctx context.Context, teamID *uint, dryRun bool) error {
	// skipauth: No authorization check needed due to implementation returning
	// only license error.
	svc.authz.SkipAuthorization(ctx)

	return mobius.ErrMissingLicense
}

////////////////////////////////////////////////////////////////////////////////
// Get aggregated summary about a team's bootstrap package
////////////////////////////////////////////////////////////////////////////////

type getMDMAppleBootstrapPackageSummaryRequest struct {
	TeamID *uint `query:"team_id,optional"`
}

type getMDMAppleBootstrapPackageSummaryResponse struct {
	mobius.MDMAppleBootstrapPackageSummary
	Err error `json:"error,omitempty"`
}

func (r getMDMAppleBootstrapPackageSummaryResponse) Error() error { return r.Err }

func getMDMAppleBootstrapPackageSummaryEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*getMDMAppleBootstrapPackageSummaryRequest)
	summary, err := svc.GetMDMAppleBootstrapPackageSummary(ctx, req.TeamID)
	if err != nil {
		return getMDMAppleBootstrapPackageSummaryResponse{Err: err}, nil
	}
	return getMDMAppleBootstrapPackageSummaryResponse{MDMAppleBootstrapPackageSummary: *summary}, nil
}

func (svc *Service) GetMDMAppleBootstrapPackageSummary(ctx context.Context, teamID *uint) (*mobius.MDMAppleBootstrapPackageSummary, error) {
	// skipauth: No authorization check needed due to implementation returning
	// only license error.
	svc.authz.SkipAuthorization(ctx)

	return &mobius.MDMAppleBootstrapPackageSummary{}, mobius.ErrMissingLicense
}

////////////////////////////////////////////////////////////////////////////////
// Create or update an MDM Apple Setup Assistant
////////////////////////////////////////////////////////////////////////////////

type createMDMAppleSetupAssistantRequest struct {
	TeamID            *uint           `json:"team_id"`
	Name              string          `json:"name"`
	EnrollmentProfile json.RawMessage `json:"enrollment_profile"`
}

type createMDMAppleSetupAssistantResponse struct {
	mobius.MDMAppleSetupAssistant
	Err error `json:"error,omitempty"`
}

func (r createMDMAppleSetupAssistantResponse) Error() error { return r.Err }

func createMDMAppleSetupAssistantEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*createMDMAppleSetupAssistantRequest)
	asst, err := svc.SetOrUpdateMDMAppleSetupAssistant(ctx, &mobius.MDMAppleSetupAssistant{
		TeamID:  req.TeamID,
		Name:    req.Name,
		Profile: req.EnrollmentProfile,
	})
	if err != nil {
		return createMDMAppleSetupAssistantResponse{Err: err}, nil
	}
	return createMDMAppleSetupAssistantResponse{MDMAppleSetupAssistant: *asst}, nil
}

func (svc *Service) SetOrUpdateMDMAppleSetupAssistant(ctx context.Context, asst *mobius.MDMAppleSetupAssistant) (*mobius.MDMAppleSetupAssistant, error) {
	// skipauth: No authorization check needed due to implementation returning
	// only license error.
	svc.authz.SkipAuthorization(ctx)

	return nil, mobius.ErrMissingLicense
}

////////////////////////////////////////////////////////////////////////////////
// Get the MDM Apple Setup Assistant
////////////////////////////////////////////////////////////////////////////////

type getMDMAppleSetupAssistantRequest struct {
	TeamID *uint `query:"team_id,optional"`
}

type getMDMAppleSetupAssistantResponse struct {
	mobius.MDMAppleSetupAssistant
	Err error `json:"error,omitempty"`
}

func (r getMDMAppleSetupAssistantResponse) Error() error { return r.Err }

func getMDMAppleSetupAssistantEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*getMDMAppleSetupAssistantRequest)
	asst, err := svc.GetMDMAppleSetupAssistant(ctx, req.TeamID)
	if err != nil {
		return getMDMAppleSetupAssistantResponse{Err: err}, nil
	}
	return getMDMAppleSetupAssistantResponse{MDMAppleSetupAssistant: *asst}, nil
}

func (svc *Service) GetMDMAppleSetupAssistant(ctx context.Context, teamID *uint) (*mobius.MDMAppleSetupAssistant, error) {
	// skipauth: No authorization check needed due to implementation returning
	// only license error.
	svc.authz.SkipAuthorization(ctx)

	return nil, mobius.ErrMissingLicense
}

////////////////////////////////////////////////////////////////////////////////
// Delete an MDM Apple Setup Assistant
////////////////////////////////////////////////////////////////////////////////

type deleteMDMAppleSetupAssistantRequest struct {
	TeamID *uint `query:"team_id,optional"`
}

type deleteMDMAppleSetupAssistantResponse struct {
	Err error `json:"error,omitempty"`
}

func (r deleteMDMAppleSetupAssistantResponse) Error() error { return r.Err }
func (r deleteMDMAppleSetupAssistantResponse) Status() int  { return http.StatusNoContent }

func deleteMDMAppleSetupAssistantEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*deleteMDMAppleSetupAssistantRequest)
	if err := svc.DeleteMDMAppleSetupAssistant(ctx, req.TeamID); err != nil {
		return deleteMDMAppleSetupAssistantResponse{Err: err}, nil
	}
	return deleteMDMAppleSetupAssistantResponse{}, nil
}

func (svc *Service) DeleteMDMAppleSetupAssistant(ctx context.Context, teamID *uint) error {
	// skipauth: No authorization check needed due to implementation returning
	// only license error.
	svc.authz.SkipAuthorization(ctx)

	return mobius.ErrMissingLicense
}

////////////////////////////////////////////////////////////////////////////////
// Update MDM Apple Setup
////////////////////////////////////////////////////////////////////////////////

type updateMDMAppleSetupRequest struct {
	mobius.MDMAppleSetupPayload
}

type updateMDMAppleSetupResponse struct {
	Err error `json:"error,omitempty"`
}

func (r updateMDMAppleSetupResponse) Error() error { return r.Err }

func (r updateMDMAppleSetupResponse) Status() int { return http.StatusNoContent }

// This endpoint is required because the UI must allow maintainers (in addition
// to admins) to update some MDM Apple settings, while the update config/update
// team endpoints only allow write access to admins.
func updateMDMAppleSetupEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*updateMDMAppleSetupRequest)
	if err := svc.UpdateMDMAppleSetup(ctx, req.MDMAppleSetupPayload); err != nil {
		return updateMDMAppleSetupResponse{Err: err}, nil
	}
	return updateMDMAppleSetupResponse{}, nil
}

func (svc *Service) UpdateMDMAppleSetup(ctx context.Context, payload mobius.MDMAppleSetupPayload) error {
	// skipauth: No authorization check needed due to implementation returning
	// only license error.
	svc.authz.SkipAuthorization(ctx)

	return mobius.ErrMissingLicense
}

////////////////////////////////////////////////////////////////////////////////
// POST /mdm/sso
////////////////////////////////////////////////////////////////////////////////

type initiateMDMAppleSSORequest struct{}

type initiateMDMAppleSSOResponse struct {
	URL string `json:"url,omitempty"`
	Err error  `json:"error,omitempty"`
}

func (r initiateMDMAppleSSOResponse) Error() error { return r.Err }

func initiateMDMAppleSSOEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	idpProviderURL, err := svc.InitiateMDMAppleSSO(ctx)
	if err != nil {
		return initiateMDMAppleSSOResponse{Err: err}, nil
	}

	return initiateMDMAppleSSOResponse{URL: idpProviderURL}, nil
}

func (svc *Service) InitiateMDMAppleSSO(ctx context.Context) (string, error) {
	// skipauth: No authorization check needed due to implementation
	// returning only license error.
	svc.authz.SkipAuthorization(ctx)

	return "", mobius.ErrMissingLicense
}

////////////////////////////////////////////////////////////////////////////////
// POST /mdm/sso/callback
////////////////////////////////////////////////////////////////////////////////

type callbackMDMAppleSSORequest struct{}

// TODO: these errors will result in JSON being returned, but we should
// redirect to the UI and let the UI display an error instead. The errors are
// rare enough (malformed data coming from the SSO provider) so they shouldn't
// affect many users.
func (callbackMDMAppleSSORequest) DecodeRequest(ctx context.Context, r *http.Request) (interface{}, error) {
	err := r.ParseForm()
	if err != nil {
		return nil, ctxerr.Wrap(ctx, &mobius.BadRequestError{
			Message:     "failed to parse form",
			InternalErr: err,
		}, "decode sso callback")
	}
	authResponse, err := sso.DecodeAuthResponse(r.FormValue("SAMLResponse"))
	if err != nil {
		return nil, ctxerr.Wrap(ctx, &mobius.BadRequestError{
			Message:     "failed to decode SAMLResponse",
			InternalErr: err,
		}, "decoding sso callback")
	}
	return authResponse, nil
}

type callbackMDMAppleSSOResponse struct {
	redirectURL string
}

func (r callbackMDMAppleSSOResponse) HijackRender(ctx context.Context, w http.ResponseWriter) {
	w.Header().Set("Location", r.redirectURL)
	w.WriteHeader(http.StatusSeeOther)
}

// Error will always be nil because errors are handled by sending a query
// parameter in the URL response, this way the UI is able to display an erorr
// message.
func (r callbackMDMAppleSSOResponse) Error() error { return nil }

func callbackMDMAppleSSOEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	auth := request.(mobius.Auth)
	redirectURL := svc.InitiateMDMAppleSSOCallback(ctx, auth)
	return callbackMDMAppleSSOResponse{redirectURL: redirectURL}, nil
}

func (svc *Service) InitiateMDMAppleSSOCallback(ctx context.Context, auth mobius.Auth) string {
	// skipauth: No authorization check needed due to implementation
	// returning only license error.
	svc.authz.SkipAuthorization(ctx)

	return apple_mdm.MobiusUISSOCallbackPath + "?error=true"
}

////////////////////////////////////////////////////////////////////////////////
// GET /mdm/manual_enrollment_profile
////////////////////////////////////////////////////////////////////////////////

type getManualEnrollmentProfileRequest struct{}

func getManualEnrollmentProfileEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	profile, err := svc.GetMDMManualEnrollmentProfile(ctx)
	if err != nil {
		return getDeviceMDMManualEnrollProfileResponse{Err: err}, nil
	}

	// Using this type to keep code DRY as it already has all the functionality we need.
	return getDeviceMDMManualEnrollProfileResponse{Profile: profile}, nil
}

func (svc *Service) GetMDMManualEnrollmentProfile(ctx context.Context) ([]byte, error) {
	// skipauth: No authorization check needed due to implementation returning
	// only license error.
	svc.authz.SkipAuthorization(ctx)

	return nil, mobius.ErrMissingLicense
}

////////////////////////////////////////////////////////////////////////////////
// FileVault-related free version implementation
////////////////////////////////////////////////////////////////////////////////

func (svc *Service) MDMAppleEnableFileVaultAndEscrow(ctx context.Context, teamID *uint) error {
	return mobius.ErrMissingLicense
}

func (svc *Service) MDMAppleDisableFileVaultAndEscrow(ctx context.Context, teamID *uint) error {
	return mobius.ErrMissingLicense
}

////////////////////////////////////////////////////////////////////////////////
// Implementation of nanomdm's CheckinAndCommandService interface
////////////////////////////////////////////////////////////////////////////////

type MDMAppleCheckinAndCommandService struct {
	ds              mobius.Datastore
	logger          kitlog.Logger
	commander       *apple_mdm.MDMAppleCommander
	mdmLifecycle    *mdmlifecycle.HostLifecycle
	commandHandlers map[string][]mobius.CommandHandler
}

func NewMDMAppleCheckinAndCommandService(ds mobius.Datastore, commander *apple_mdm.MDMAppleCommander, logger kitlog.Logger) *MDMAppleCheckinAndCommandService {
	mdmLifecycle := mdmlifecycle.New(ds, logger)
	return &MDMAppleCheckinAndCommandService{
		ds:              ds,
		commander:       commander,
		logger:          logger,
		mdmLifecycle:    mdmLifecycle,
		commandHandlers: map[string][]mobius.CommandHandler{},
	}
}

func (svc *MDMAppleCheckinAndCommandService) RegisterResultsHandler(commandType string, handler mobius.CommandHandler) {
	svc.commandHandlers[commandType] = append(svc.commandHandlers[commandType], handler)
}

// Authenticate handles MDM [Authenticate][1] requests.
//
// This method is executed after the request has been handled by nanomdm, note
// that at this point you can't send any commands to the device yet because we
// haven't received a token, nor a PushMagic.
//
// We use it to perform post-enrollment tasks such as creating a host record,
// adding activities to the log, etc.
//
// [1]: https://developer.apple.com/documentation/devicemanagement/authenticate
func (svc *MDMAppleCheckinAndCommandService) Authenticate(r *mdm.Request, m *mdm.Authenticate) error {
	var scepRenewalInProgress bool
	existingDeviceInfo, err := svc.ds.GetHostMDMCheckinInfo(r.Context, r.ID)
	if err != nil {
		var nfe mobius.NotFoundError
		if !errors.As(err, &nfe) {
			return ctxerr.Wrap(r.Context, err, "getting checkin info")
		}
	}
	if existingDeviceInfo != nil {
		scepRenewalInProgress = existingDeviceInfo.SCEPRenewalInProgress
	}

	// iPhones and iPads send ProductName but not Model/ModelName,
	// thus we use this field as the device's Model (which is required on lifecycle stages).
	platform := "darwin"
	iPhone := strings.HasPrefix(m.ProductName, "iPhone")
	iPad := strings.HasPrefix(m.ProductName, "iPad")
	if iPhone || iPad {
		m.Model = m.ProductName
		if iPhone {
			platform = "ios"
		} else {
			platform = "ipados"
		}
	}

	if err := svc.mdmLifecycle.Do(r.Context, mdmlifecycle.HostOptions{
		Action:                mdmlifecycle.HostActionReset,
		Platform:              platform,
		UUID:                  m.UDID,
		HardwareSerial:        m.SerialNumber,
		HardwareModel:         m.Model,
		SCEPRenewalInProgress: scepRenewalInProgress,
	}); err != nil {
		return err
	}

	// FIXME: We need to revisit this flow. Short-circuiting in random places means it is
	// much more difficult to reason about the state of the host. We should try instead
	// to centralize the flow control in the lifecycle methods.
	if !scepRenewalInProgress {
		// Create a new activity for the enrollment, MDM state changes after is reset, fetch the
		// checkin updatedInfo again
		updatedInfo, err := svc.ds.GetHostMDMCheckinInfo(r.Context, r.ID)
		if err != nil {
			return ctxerr.Wrap(r.Context, err, "getting checkin info in Authenticate message")
		}
		return newActivity(
			r.Context, nil, &mobius.ActivityTypeMDMEnrolled{
				HostSerial:       updatedInfo.HardwareSerial,
				HostDisplayName:  updatedInfo.DisplayName,
				InstalledFromDEP: updatedInfo.DEPAssignedToMobius,
				MDMPlatform:      mobius.MDMPlatformApple,
			}, svc.ds, svc.logger,
		)
	}

	return nil
}

// TokenUpdate handles MDM [TokenUpdate][1] requests.
//
// This method is executed after the request has been handled by nanomdm.
//
// [1]: https://developer.apple.com/documentation/devicemanagement/token_update
func (svc *MDMAppleCheckinAndCommandService) TokenUpdate(r *mdm.Request, m *mdm.TokenUpdate) error {
	svc.logger.Log("info", "received token update", "host_uuid", r.ID)
	info, err := svc.ds.GetHostMDMCheckinInfo(r.Context, r.ID)
	if err != nil {
		return ctxerr.Wrap(r.Context, err, "getting checkin info")
	}

	// FIXME: We need to revisit this flow. Short-circuiting in random places means it is
	// much more difficult to reason about the state of the host. We should try instead
	// to centralize the flow control in the lifecycle methods.
	if info.SCEPRenewalInProgress {
		svc.logger.Log("info", "token update received for a SCEP renewal in process, cleaning SCEP refs", "host_uuid", r.ID)
		if err := svc.ds.CleanSCEPRenewRefs(r.Context, r.ID); err != nil {
			return ctxerr.Wrap(r.Context, err, "cleaning SCEP refs")
		}
		svc.logger.Log("info", "cleaned SCEP refs, skipping setup experience and mdm lifecycle turn on action", "host_uuid", r.ID)
		return nil
	}

	var hasSetupExpItems bool
	if m.AwaitingConfiguration {
		// Enqueue setup experience items and mark the host as being in setup experience
		hasSetupExpItems, err = svc.ds.EnqueueSetupExperienceItems(r.Context, r.ID, info.TeamID)
		if err != nil {
			return ctxerr.Wrap(r.Context, err, "queueing setup experience tasks")
		}
	}

	var acctUUID string
	idp, err := svc.ds.GetMDMIdPAccountByHostUUID(r.Context, r.ID)
	if err != nil {
		return ctxerr.Wrap(r.Context, err, "getting idp account")
	}
	if idp != nil {
		acctUUID = idp.UUID
	}

	return svc.mdmLifecycle.Do(r.Context, mdmlifecycle.HostOptions{
		Action:                  mdmlifecycle.HostActionTurnOn,
		Platform:                info.Platform,
		UUID:                    r.ID,
		EnrollReference:         acctUUID,
		HasSetupExperienceItems: hasSetupExpItems,
	})
}

// CheckOut handles MDM [CheckOut][1] requests.
//
// This method is executed after the request has been handled by nanomdm, note
// that this message is sent on a best-effort basis, don't rely exclusively on
// it.
//
// [1]: https://developer.apple.com/documentation/devicemanagement/check_out
func (svc *MDMAppleCheckinAndCommandService) CheckOut(r *mdm.Request, m *mdm.CheckOut) error {
	info, err := svc.ds.GetHostMDMCheckinInfo(r.Context, m.Enrollment.UDID)
	if err != nil {
		return err
	}

	err = svc.mdmLifecycle.Do(r.Context, mdmlifecycle.HostOptions{
		Action:   mdmlifecycle.HostActionTurnOff,
		Platform: info.Platform,
		UUID:     r.ID,
	})
	if err != nil {
		return err
	}

	return newActivity(
		r.Context, nil, &mobius.ActivityTypeMDMUnenrolled{
			HostSerial:       info.HardwareSerial,
			HostDisplayName:  info.DisplayName,
			InstalledFromDEP: info.InstalledFromDEP,
		}, svc.ds, svc.logger,
	)
}

// SetBootstrapToken handles MDM [SetBootstrapToken][1] requests.
//
// This method is executed after the request has been handled by nanomdm.
//
// [1]: https://developer.apple.com/documentation/devicemanagement/set_bootstrap_token
func (svc *MDMAppleCheckinAndCommandService) SetBootstrapToken(*mdm.Request, *mdm.SetBootstrapToken) error {
	return nil
}

// GetBootstrapToken handles MDM [GetBootstrapToken][1] requests.
//
// This method is executed after the request has been handled by nanomdm.
//
// [1]: https://developer.apple.com/documentation/devicemanagement/get_bootstrap_token
func (svc *MDMAppleCheckinAndCommandService) GetBootstrapToken(*mdm.Request, *mdm.GetBootstrapToken) (*mdm.BootstrapToken, error) {
	return nil, nil
}

// UserAuthenticate handles MDM [UserAuthenticate][1] requests.
//
// This method is executed after the request has been handled by nanomdm.
//
// [1]: https://developer.apple.com/documentation/devicemanagement/userauthenticate
func (svc *MDMAppleCheckinAndCommandService) UserAuthenticate(*mdm.Request, *mdm.UserAuthenticate) ([]byte, error) {
	return nil, nil
}

// DeclarativeManagement handles MDM [DeclarativeManagement][1] requests.
//
// This method is executed after the request has been handled by nanomdm.
//
// [1]: https://developer.apple.com/documentation/devicemanagement/declarative_management_checkin
func (svc *MDMAppleCheckinAndCommandService) DeclarativeManagement(r *mdm.Request, dm *mdm.DeclarativeManagement) ([]byte, error) {
	// DeclarativeManagement is handled by the MDMAppleDDMService.
	return nil, nil
}

// GetToken handles MDM [GetToken][1] requests.
//
// This method is executed after the request has been handled by nanomdm.
//
// [1]: https://developer.apple.com/documentation/devicemanagement/get_token
func (svc *MDMAppleCheckinAndCommandService) GetToken(_ *mdm.Request, _ *mdm.GetToken) (*mdm.GetTokenResponse, error) {
	return nil, nil
}

// CommandAndReportResults handles MDM [Commands and Queries][1].
//
// This method is executed after the request has been handled by nanomdm.
//
// [1]: https://developer.apple.com/documentation/devicemanagement/commands_and_queries
func (svc *MDMAppleCheckinAndCommandService) CommandAndReportResults(r *mdm.Request, cmdResult *mdm.CommandResults) (*mdm.Command, error) {
	if cmdResult.Status == "Idle" {
		// NOTE: iPhone/iPad devices that are still enroled in Mobius's MDM but have
		// been deleted from Mobius (no host entry) will still send checkin
		// requests from time to time. Those should be Idle requests without a
		// CommandUUID. As stated in tickets #22941 and #22391, Mobius iDevices
		// should be re-created when they checkin with MDM.
		deletedDevice, err := svc.ds.GetMDMAppleEnrolledDeviceDeletedFromMobius(r.Context, cmdResult.UDID)
		if err != nil && !mobius.IsNotFound(err) {
			return nil, ctxerr.Wrap(r.Context, err, "lookup enrolled but deleted device info")
		}

		// only re-create iPhone/iPad devices, macOS are recreated via the mobiusdaemon checkin
		if deletedDevice != nil && (deletedDevice.Platform == "ios" || deletedDevice.Platform == "ipados") {
			msg, err := mdm.DecodeCheckin([]byte(deletedDevice.Authenticate))
			if err != nil {
				return nil, ctxerr.Wrap(r.Context, err, "decode authenticate enrollment message to re-create a deleted host")
			}
			authMsg, ok := msg.(*mdm.Authenticate)
			if !ok {
				return nil, ctxerr.Errorf(r.Context, "authenticate enrollment message to re-create a deleted host is not of the expected type: %T", msg)
			}

			err = svc.mdmLifecycle.Do(r.Context, mdmlifecycle.HostOptions{
				Action:         mdmlifecycle.HostActionReset,
				Platform:       deletedDevice.Platform,
				UUID:           deletedDevice.ID,
				HardwareSerial: deletedDevice.SerialNumber,
				HardwareModel:  authMsg.ProductName,
			})
			if err != nil {
				return nil, ctxerr.Wrap(r.Context, err, "trigger mdm reset lifecycle to re-create a deleted host")
			}

			if deletedDevice.EnrollTeamID != nil {
				host, err := svc.ds.HostLiteByIdentifier(r.Context, deletedDevice.ID)
				if err != nil {
					return nil, ctxerr.Wrap(r.Context, err, "load re-created host by identifier")
				}
				if err := svc.ds.AddHostsToTeam(r.Context, deletedDevice.EnrollTeamID, []uint{host.ID}); err != nil {
					return nil, ctxerr.Wrap(r.Context, err, "transfer re-created host to enrollment team")
				}
			}
		}

		// macOS hosts are considered unlocked if they are online any time
		// after they have been unlocked. If the host has been seen after a
		// successful unlock, take the opportunity and update the value in the
		// db as well.
		//
		// TODO: sanity check if this approach is still valid after we implement wipe

		// if there is a deleted device, it means there is no hosts entry so no need to clean the lock
		if deletedDevice == nil {
			if err := svc.ds.CleanMacOSMDMLock(r.Context, cmdResult.UDID); err != nil {
				return nil, ctxerr.Wrap(r.Context, err, "cleaning macOS host lock/wipe status")
			}
		}

		return nil, nil
	}

	// Check if this is a result of a "refetch" command sent to iPhones/iPads
	// to fetch their device information periodically.
	if strings.HasPrefix(cmdResult.CommandUUID, mobius.RefetchBaseCommandUUIDPrefix) && !strings.HasPrefix(cmdResult.CommandUUID, mobius.RefetchVPPAppInstallsCommandUUIDPrefix) {
		return svc.handleRefetch(r, cmdResult)
	}

	// We explicitly get the request type because it comes empty. There's a
	// RequestType field in the struct, but it's used when a mdm.Command is
	// issued.
	requestType, err := svc.ds.GetMDMAppleCommandRequestType(r.Context, cmdResult.CommandUUID)
	if err != nil {
		return nil, ctxerr.Wrap(r.Context, err, "command service")
	}

	switch requestType {
	case "InstallProfile":
		return nil, apple_mdm.HandleHostMDMProfileInstallResult(
			r.Context,
			svc.ds,
			cmdResult.UDID,
			cmdResult.CommandUUID,
			mdmAppleDeliveryStatusFromCommandStatus(cmdResult.Status),
			apple_mdm.FmtErrorChain(cmdResult.ErrorChain),
		)
	case "RemoveProfile":
		return nil, svc.ds.UpdateOrDeleteHostMDMAppleProfile(r.Context, &mobius.HostMDMAppleProfile{
			CommandUUID:   cmdResult.CommandUUID,
			HostUUID:      cmdResult.UDID,
			Status:        mdmAppleDeliveryStatusFromCommandStatus(cmdResult.Status),
			Detail:        apple_mdm.FmtErrorChain(cmdResult.ErrorChain),
			OperationType: mobius.MDMOperationTypeRemove,
		})
	case "DeviceLock", "EraseDevice":
		// call into our datastore to update host_mdm_actions if the status is terminal
		if cmdResult.Status == mobius.MDMAppleStatusAcknowledged ||
			cmdResult.Status == mobius.MDMAppleStatusError ||
			cmdResult.Status == mobius.MDMAppleStatusCommandFormatError {
			return nil, svc.ds.UpdateHostLockWipeStatusFromAppleMDMResult(r.Context, cmdResult.UDID, cmdResult.CommandUUID, requestType,
				cmdResult.Status == mobius.MDMAppleStatusAcknowledged)
		}
	case "DeclarativeManagement":
		// set "pending-install" profiles to "verifying" or "failed"
		// depending on the status of the DeviceManagement command
		status := mdmAppleDeliveryStatusFromCommandStatus(cmdResult.Status)
		detail := fmt.Sprintf("%s. Make sure the host is on macOS 13+, iOS 17+, iPadOS 17+.", apple_mdm.FmtErrorChain(cmdResult.ErrorChain))
		err := svc.ds.MDMAppleSetPendingDeclarationsAs(r.Context, cmdResult.UDID, status, detail)
		return nil, ctxerr.Wrap(r.Context, err, "update declaration status on DeclarativeManagement ack")
	case "InstallApplication":
		// this might be a setup experience VPP install, so we'll try to update setup experience status
		// TODO: consider limiting this to only macOS hosts
		if updated, err := maybeUpdateSetupExperienceStatus(r.Context, svc.ds, mobius.SetupExperienceVPPInstallResult{
			HostUUID:      cmdResult.UDID,
			CommandUUID:   cmdResult.CommandUUID,
			CommandStatus: cmdResult.Status,
		}, true); err != nil {
			return nil, ctxerr.Wrap(r.Context, err, "updating setup experience status from VPP install result")
		} else if updated {
			// TODO: call next step of setup experience?
			level.Debug(svc.logger).Log("msg", "setup experience script result updated", "host_uuid", cmdResult.UDID, "execution_id", cmdResult.CommandUUID)
		}

		// create an activity for installing only if we're in a terminal state
		if cmdResult.Status == mobius.MDMAppleStatusError ||
			cmdResult.Status == mobius.MDMAppleStatusCommandFormatError {
			user, act, err := svc.ds.GetPastActivityDataForVPPAppInstall(r.Context, cmdResult)
			if err != nil {
				if mobius.IsNotFound(err) {
					// Then this isn't a VPP install, so no activity generated
					return nil, nil
				}

				return nil, ctxerr.Wrap(r.Context, err, "fetching data for installed app store app activity")
			}

			if err := newActivity(r.Context, user, act, svc.ds, svc.logger); err != nil {
				return nil, ctxerr.Wrap(r.Context, err, "creating activity for installed app store app")
			}
		}

		if cmdResult.Status == mobius.MDMAppleStatusAcknowledged {
			// Only send a new InstalledApplicationList command if there's not one in flight
			ackCmds, err := svc.ds.GetAcknowledgedMDMCommandsByHost(r.Context, cmdResult.UDID, "InstalledApplicationList")
			if err != nil {
				return nil, ctxerr.Wrap(r.Context, err, "get pending mdm commands by host")
			}
			if len(ackCmds) == 0 {
				cmdUUID := uuid.NewString()
				cmdUUID = mobius.RefetchVPPAppInstallsCommandUUIDPrefix + cmdUUID
				if err := svc.commander.InstalledApplicationList(r.Context, []string{cmdResult.UDID}, cmdUUID, true); err != nil {
					return nil, ctxerr.Wrap(r.Context, err, "sending list app command to verify install")
				}

				// update the install record
				if err := svc.ds.UpdateVPPInstallVerificationCommand(r.Context, cmdResult.CommandUUID, cmdUUID); err != nil {
					return nil, ctxerr.Wrap(r.Context, err, "update install record")
				}

			}
		}
	case "DeviceConfigured":
		if err := svc.ds.SetHostAwaitingConfiguration(r.Context, r.ID, false); err != nil {
			return nil, ctxerr.Wrap(r.Context, err, "failed to mark host as non longer awaiting configuration")
		}
	case "InstalledApplicationList":
		level.Debug(svc.logger).Log("msg", "calling handlers for InstalledApplicationList")
		res, err := NewInstalledApplicationListResult(r.Context, cmdResult.Raw, cmdResult.CommandUUID, cmdResult.UDID)
		if err != nil {
			return nil, ctxerr.Wrap(r.Context, err, "new installed application list result")
		}

		for _, f := range svc.commandHandlers["InstalledApplicationList"] {
			if err := f(r.Context, res); err != nil {
				return nil, ctxerr.Wrap(r.Context, err, "InstalledApplicationList handler failed")
			}
		}
	}

	return nil, nil
}

func (svc *MDMAppleCheckinAndCommandService) handleRefetch(r *mdm.Request, cmdResult *mdm.CommandResults) (*mdm.Command, error) {
	ctx := r.Context
	host, err := svc.ds.HostByIdentifier(ctx, cmdResult.UDID)
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err, "failed to get host by identifier")
	}

	switch {
	case strings.HasPrefix(cmdResult.CommandUUID, mobius.RefetchAppsCommandUUIDPrefix):
		return svc.handleRefetchAppsResults(ctx, host, cmdResult)

	case strings.HasPrefix(cmdResult.CommandUUID, mobius.RefetchCertsCommandUUIDPrefix):
		return svc.handleRefetchCertsResults(ctx, host, cmdResult)

	case strings.HasPrefix(cmdResult.CommandUUID, mobius.RefetchDeviceCommandUUIDPrefix):
		return svc.handleRefetchDeviceResults(ctx, host, cmdResult)

	default:
		// This should never happen, but just in case we'll return an error.
		return nil, ctxerr.New(ctx, fmt.Sprintf("unknown refetch command type %s", cmdResult.CommandUUID))
	}
}

func (svc *MDMAppleCheckinAndCommandService) handleRefetchAppsResults(ctx context.Context, host *mobius.Host, cmdResult *mdm.CommandResults) (*mdm.Command, error) {
	if !strings.HasPrefix(cmdResult.CommandUUID, mobius.RefetchAppsCommandUUIDPrefix) {
		// Caller should have checked this, but just in case we'll return an error.
		return nil, ctxerr.New(ctx, fmt.Sprintf("expected REFETCH-APPS- prefix but got %s", cmdResult.CommandUUID))
	}

	// We remove pending command first in case there is an error processing the results, so that we don't prevent another refetch.
	if err := svc.ds.RemoveHostMDMCommand(ctx, mobius.HostMDMCommand{
		HostID:      host.ID,
		CommandType: mobius.RefetchAppsCommandUUIDPrefix,
	}); err != nil {
		return nil, ctxerr.Wrap(ctx, err, "remove refetch apps command")
	}

	if host.Platform != "ios" && host.Platform != "ipados" {
		return nil, ctxerr.New(ctx, "refetch apps command sent to non-iOS/non-iPadOS host")
	}
	source := "ios_apps"
	if host.Platform == "ipados" {
		source = "ipados_apps"
	}

	response := cmdResult.Raw
	software, err := unmarshalAppList(ctx, response, source)
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err, "unmarshal app list")
	}
	_, err = svc.ds.UpdateHostSoftware(ctx, host.ID, software)
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err, "update host software")
	}

	return nil, nil
}

func (svc *MDMAppleCheckinAndCommandService) handleRefetchCertsResults(ctx context.Context, host *mobius.Host, cmdResult *mdm.CommandResults) (*mdm.Command, error) {
	if !strings.HasPrefix(cmdResult.CommandUUID, mobius.RefetchCertsCommandUUIDPrefix) {
		// Caller should have checked this, but just in case we'll return an error.
		return nil, ctxerr.New(ctx, fmt.Sprintf("expected REFETCH-CERTS- prefix but got %s", cmdResult.CommandUUID))
	}

	// We remove pending command first in case there is an error processing the results, so that we don't prevent another refetch.
	if err := svc.ds.RemoveHostMDMCommand(ctx, mobius.HostMDMCommand{
		HostID:      host.ID,
		CommandType: mobius.RefetchCertsCommandUUIDPrefix,
	}); err != nil {
		return nil, ctxerr.Wrap(ctx, err, "refetch certs: remove refetch command")
	}

	// TODO(mna): when we add iOS/iPadOS support for https://github.com/notawar/mobius/issues/26913,
	// this is where we'll need to identify user-keychain certs for iPad/iPhone. For now we set
	// them all as "system" certificates.
	var listResp mobius.MDMAppleCertificateListResponse
	if err := plist.Unmarshal(cmdResult.Raw, &listResp); err != nil {
		return nil, ctxerr.Wrap(ctx, err, "refetch certs: unmarshal certificate list command result")
	}
	payload := make([]*mobius.HostCertificateRecord, 0, len(listResp.CertificateList))
	for _, cert := range listResp.CertificateList {
		parsed, err := cert.Parse(host.ID)
		if err != nil {
			return nil, ctxerr.Wrap(ctx, err, "refetch certs: parse certificate")
		}
		payload = append(payload, parsed)
	}

	if err := svc.ds.UpdateHostCertificates(ctx, host.ID, host.UUID, payload); err != nil {
		return nil, ctxerr.Wrap(ctx, err, "refetch certs: update host certificates")
	}

	return nil, nil
}

func (svc *MDMAppleCheckinAndCommandService) handleRefetchDeviceResults(ctx context.Context, host *mobius.Host, cmdResult *mdm.CommandResults) (*mdm.Command, error) {
	if !strings.HasPrefix(cmdResult.CommandUUID, mobius.RefetchDeviceCommandUUIDPrefix) {
		// Caller should have checked this, but just in case we'll return an error.
		return nil, ctxerr.New(ctx, fmt.Sprintf("expected REFETCH-DEVICE- prefix but got %s", cmdResult.CommandUUID))
	}

	// We remove pending command first in case there is an error processing the results, so that we don't prevent another refetch.
	if err := svc.ds.RemoveHostMDMCommand(ctx, mobius.HostMDMCommand{
		HostID:      host.ID,
		CommandType: mobius.RefetchDeviceCommandUUIDPrefix,
	}); err != nil {
		return nil, ctxerr.Wrap(ctx, err, "remove refetch device command")
	}

	var deviceInformationResponse struct {
		QueryResponses map[string]interface{} `plist:"QueryResponses"`
	}
	if err := plist.Unmarshal(cmdResult.Raw, &deviceInformationResponse); err != nil {
		return nil, ctxerr.Wrap(ctx, err, "failed to unmarshal device information command result")
	}
	deviceName := deviceInformationResponse.QueryResponses["DeviceName"].(string)
	deviceCapacity := deviceInformationResponse.QueryResponses["DeviceCapacity"].(float64)
	availableDeviceCapacity := deviceInformationResponse.QueryResponses["AvailableDeviceCapacity"].(float64)
	osVersion := deviceInformationResponse.QueryResponses["OSVersion"].(string)
	wifiMac := deviceInformationResponse.QueryResponses["WiFiMAC"].(string)
	productName := deviceInformationResponse.QueryResponses["ProductName"].(string)
	host.ComputerName = deviceName
	host.Hostname = deviceName
	host.GigsDiskSpaceAvailable = availableDeviceCapacity
	host.GigsTotalDiskSpace = deviceCapacity
	var (
		osVersionPrefix string
		platform        string
	)
	if strings.HasPrefix(productName, "iPhone") {
		osVersionPrefix = "iOS"
		platform = "ios"
	} else { // iPad
		osVersionPrefix = "iPadOS"
		platform = "ipados"
	}
	host.OSVersion = osVersionPrefix + " " + osVersion
	host.PrimaryMac = wifiMac
	host.HardwareModel = productName
	host.DetailUpdatedAt = time.Now()
	host.RefetchRequested = false

	if err := svc.ds.UpdateHost(ctx, host); err != nil {
		return nil, ctxerr.Wrap(ctx, err, "failed to update host")
	}
	if err := svc.ds.SetOrUpdateHostDisksSpace(ctx, host.ID, availableDeviceCapacity, 100*availableDeviceCapacity/deviceCapacity,
		deviceCapacity); err != nil {
		return nil, ctxerr.Wrap(ctx, err, "failed to update host storage")
	}
	if err := svc.ds.UpdateHostOperatingSystem(ctx, host.ID, mobius.OperatingSystem{
		Name:     osVersionPrefix,
		Version:  osVersion,
		Platform: platform,
	}); err != nil {
		return nil, ctxerr.Wrap(ctx, err, "failed to update host operating system")
	}

	if host.MDM.EnrollmentStatus != nil && *host.MDM.EnrollmentStatus == "Pending" {
		// Since the device has been refetched, we can assume it's enrolled.
		if err := svc.ds.UpdateMDMData(ctx, host.ID, true); err != nil {
			return nil, ctxerr.Wrap(ctx, err, "failed to update MDM data")
		}
	}
	return nil, nil
}

type InstalledApplicationListResult interface {
	mobius.MDMCommandResults
	AvailableApps() []mobius.Software
}

type installedApplicationListResult struct {
	raw           []byte
	availableApps []mobius.Software
	uuid          string
	hostUUID      string
}

func (i *installedApplicationListResult) Raw() []byte                     { return i.raw }
func (i *installedApplicationListResult) UUID() string                    { return i.uuid }
func (i *installedApplicationListResult) HostUUID() string                { return i.hostUUID }
func (i *installedApplicationListResult) AvailableApps() []mobius.Software { return i.availableApps }

func NewInstalledApplicationListResult(ctx context.Context, rawResult []byte, uuid, hostUUID string) (InstalledApplicationListResult, error) {
	list, err := unmarshalAppList(ctx, rawResult, "apps")
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err, "unmarshal app list for new installed application list result")
	}

	return &installedApplicationListResult{
		raw:           rawResult,
		uuid:          uuid,
		availableApps: list,
		hostUUID:      hostUUID,
	}, nil
}

func NewInstalledApplicationListResultsHandler(
	ds mobius.Datastore,
	commander *apple_mdm.MDMAppleCommander,
	logger kitlog.Logger,
	verifyTimeout, verifyRequestDelay time.Duration,
) func(ctx context.Context, commandResults mobius.MDMCommandResults) error {
	return func(ctx context.Context, commandResults mobius.MDMCommandResults) error {
		installedAppResult, ok := commandResults.(InstalledApplicationListResult)
		if !ok {
			return ctxerr.New(ctx, "unexpected results type")
		}

		// Then it's not a command sent by Mobius, so skip it
		if !strings.HasPrefix(installedAppResult.UUID(), mobius.RefetchVPPAppInstallsCommandUUIDPrefix) {
			return nil
		}

		installedApps := installedAppResult.AvailableApps()

		if len(installedApps) == 0 {
			// Nothing to do
			return nil
		}

		// Get installs that should be verified by this InstalledApplicationList command
		installs, err := ds.GetVPPInstallsByVerificationUUID(ctx, installedAppResult.UUID())
		if err != nil {
			return ctxerr.Wrap(ctx, err, "InstalledApplicationList handler: getting install record")
		}

		installsByBundleID := map[string]*mobius.HostVPPSoftwareInstall{}
		for _, install := range installs {
			installsByBundleID[install.BundleIdentifier] = install
		}

		var poll bool
		for _, a := range installedApps {
			install, ok := installsByBundleID[a.BundleIdentifier]
			if !ok {
				continue
			}

			var terminal bool
			switch {
			case a.Installed:
				if err := ds.SetVPPInstallAsVerified(ctx, install.HostID, install.InstallCommandUUID); err != nil {
					return ctxerr.Wrap(ctx, err, "InstalledApplicationList handler: set vpp install verified")
				}

				terminal = true
			case install.InstallCommandAckAt != nil && time.Since(*install.InstallCommandAckAt) > verifyTimeout:
				if err := ds.SetVPPInstallAsFailed(ctx, install.HostID, install.InstallCommandUUID); err != nil {
					return ctxerr.Wrap(ctx, err, "InstalledApplicationList handler: set vpp install failed")
				}

				terminal = true
			}

			if !terminal {
				poll = true
				continue
			}

			// this might be a setup experience VPP install, so we'll try to update setup experience status
			if updated, err := maybeUpdateSetupExperienceStatus(ctx, ds, mobius.SetupExperienceVPPInstallResult{
				HostUUID:      installedAppResult.HostUUID(),
				CommandUUID:   install.InstallCommandUUID,
				CommandStatus: install.InstallCommandStatus,
			}, true); err != nil {
				return ctxerr.Wrap(ctx, err, "updating setup experience status from VPP install result")
			} else if updated {
				level.Debug(logger).Log("msg", "setup experience script result updated", "host_uuid", installedAppResult.HostUUID(), "execution_id", install.InstallCommandUUID)
			}

			// create an activity for installing only if we're in a terminal state
			user, act, err := ds.GetPastActivityDataForVPPAppInstall(ctx, &mdm.CommandResults{CommandUUID: install.InstallCommandUUID, Status: install.InstallCommandStatus})
			if err != nil {
				if mobius.IsNotFound(err) {
					// Then this isn't a VPP install, so no activity generated
					return nil
				}

				return ctxerr.Wrap(ctx, err, "fetching data for installed app store app activity")
			}

			if err := newActivity(ctx, user, act, ds, logger); err != nil {
				return ctxerr.Wrap(ctx, err, "creating activity for installed app store app")
			}

		}

		if poll {
			err := worker.QueueVPPInstallVerificationJob(ctx, ds, logger, worker.VerifyVPPTask, verifyRequestDelay, installedAppResult.HostUUID(), installedAppResult.UUID())
			if err != nil {
				return ctxerr.Wrap(ctx, err, "InstalledApplicationList handler: queueing vpp install verification job")
			}
		}

		return nil
	}
}

func unmarshalAppList(ctx context.Context, response []byte, source string) ([]mobius.Software,
	error,
) {
	var appsResponse struct {
		InstalledApplicationList []map[string]interface{} `plist:"InstalledApplicationList"`
	}
	if err := plist.Unmarshal(response, &appsResponse); err != nil {
		return nil, ctxerr.Wrap(ctx, err, "failed to unmarshal installed application list command result")
	}

	truncateString := func(item interface{}, length int) string {
		str, ok := item.(string)
		if !ok {
			return ""
		}
		runes := []rune(str)
		if len(runes) > length {
			return string(runes[:length])
		}
		return str
	}

	var software []mobius.Software
	for _, app := range appsResponse.InstalledApplicationList {
		sw := mobius.Software{
			Name:             truncateString(app["Name"], mobius.SoftwareNameMaxLength),
			Version:          truncateString(app["ShortVersion"], mobius.SoftwareVersionMaxLength),
			BundleIdentifier: truncateString(app["Identifier"], mobius.SoftwareBundleIdentifierMaxLength),
			Source:           source,
		}
		if val, ok := app["Installing"]; ok {
			installing, ok := val.(bool)
			if !ok {
				return nil, ctxerr.New(ctx, "parsing Installing key")
			}

			sw.Installed = !installing
		}
		software = append(software, sw)
	}

	return software, nil
}

// mdmAppleDeliveryStatusFromCommandStatus converts a MDM command status to a
// mobius.MDMAppleDeliveryStatus.
//
// NOTE: this mapping does not include all
// possible delivery statuses (e.g., verified status is not included) is intended to
// only be used in the context of CommandAndReportResults in the MDMAppleCheckinAndCommandService.
// Extra care should be taken before using this function in other contexts.
func mdmAppleDeliveryStatusFromCommandStatus(cmdStatus string) *mobius.MDMDeliveryStatus {
	switch cmdStatus {
	case mobius.MDMAppleStatusAcknowledged:
		return &mobius.MDMDeliveryVerifying
	case mobius.MDMAppleStatusError, mobius.MDMAppleStatusCommandFormatError:
		return &mobius.MDMDeliveryFailed
	case mobius.MDMAppleStatusIdle, mobius.MDMAppleStatusNotNow:
		return &mobius.MDMDeliveryPending
	default:
		return nil
	}
}

// ensureMobiusProfiles ensures there's a mobiusdaemon configuration profile in
// mdm_apple_configuration_profiles for each team and for "no team"
//
// We try our best to use each team's secret but we default to creating a
// profile with the global enroll secret if the team doesn't have any enroll
// secrets.
//
// This profile will be installed to all hosts in the team (or "no team",) but it
// will only be used by hosts that have a mobiusdaemon installation without an enroll
// secret and mobius URL (mainly DEP enrolled hosts).
func ensureMobiusProfiles(ctx context.Context, ds mobius.Datastore, logger kitlog.Logger, signingCertDER []byte) error {
	appCfg, err := ds.AppConfig(ctx)
	if err != nil {
		return ctxerr.Wrap(ctx, err, "fetching app config")
	}

	var rootCAProfContents bytes.Buffer
	params := mobileconfig.MobiusCARootTemplateOptions{
		PayloadIdentifier: mobileconfig.MobiusCARootConfigPayloadIdentifier,
		PayloadName:       mdm_types.MobiusCAConfigProfileName,
		Certificate:       base64.StdEncoding.EncodeToString(signingCertDER),
	}

	if err := mobileconfig.MobiusCARootTemplate.Execute(&rootCAProfContents, params); err != nil {
		return ctxerr.Wrap(ctx, err, "executing mobius root CA config template")
	}

	b := rootCAProfContents.Bytes()

	enrollSecrets, err := ds.AggregateEnrollSecretPerTeam(ctx)
	if err != nil {
		return ctxerr.Wrap(ctx, err, "getting enroll secrets aggregates")
	}

	globalSecret := ""
	for _, es := range enrollSecrets {
		if es.TeamID == nil {
			globalSecret = es.Secret
		}
	}

	var profiles []*mobius.MDMAppleConfigProfile
	for _, es := range enrollSecrets {
		if es.Secret == "" {
			var msg string
			if es.TeamID != nil {
				msg += fmt.Sprintf("team_id %d doesn't have an enroll secret, ", *es.TeamID)
			}
			if globalSecret == "" {
				logger.Log("err", msg+"no global enroll secret found, skipping the creation of a com.mobiusmdm.mobiusdaemon.config profile")
				continue
			}
			logger.Log("err", msg+"using a global enroll secret for com.mobiusmdm.mobiusdaemon.config profile")
			es.Secret = globalSecret
		}

		var contents bytes.Buffer
		params := mobileconfig.MobiusdProfileOptions{
			EnrollSecret: es.Secret,
			ServerURL:    appCfg.ServerSettings.ServerURL, // ServerURL must be set to the Mobius URL.  Do not use appCfg.MDMUrl() here.
			PayloadType:  mobileconfig.MobiusdConfigPayloadIdentifier,
			PayloadName:  mdm_types.MobiusdConfigProfileName,
		}

		if err := mobileconfig.MobiusdProfileTemplate.Execute(&contents, params); err != nil {
			return ctxerr.Wrap(ctx, err, "executing mobiusdaemon config template")
		}

		cp, err := mobius.NewMDMAppleConfigProfile(contents.Bytes(), es.TeamID)
		if err != nil {
			return ctxerr.Wrap(ctx, err, "building mobiusdaemon configuration profile")
		}
		profiles = append(profiles, cp)

		rootCAProf, err := mobius.NewMDMAppleConfigProfile(b, es.TeamID)
		if err != nil {
			return ctxerr.Wrap(ctx, err, "building root CA configuration profile")
		}
		profiles = append(profiles, rootCAProf)
	}

	if err := ds.BulkUpsertMDMAppleConfigProfiles(ctx, profiles); err != nil {
		return ctxerr.Wrap(ctx, err, "bulk-upserting configuration profiles")
	}

	return nil
}

func SendPushesToPendingDevices(
	ctx context.Context,
	ds mobius.Datastore,
	commander *apple_mdm.MDMAppleCommander,
	logger kitlog.Logger,
) error {
	enrollmentIDs, err := ds.GetEnrollmentIDsWithPendingMDMAppleCommands(ctx)
	if err != nil {
		return ctxerr.Wrap(ctx, err, "getting host uuids with pending commands")
	}

	if len(enrollmentIDs) == 0 {
		return nil
	}

	if err := commander.SendNotifications(ctx, enrollmentIDs); err != nil {
		var apnsErr *apple_mdm.APNSDeliveryError
		if errors.As(err, &apnsErr) {
			level.Info(logger).Log("msg", "failed to send APNs notification to some hosts", "error", apnsErr.Error())
			return nil
		}

		return ctxerr.Wrap(ctx, err, "sending push notifications")

	}

	return nil
}

func ReconcileAppleDeclarations(
	ctx context.Context,
	ds mobius.Datastore,
	commander *apple_mdm.MDMAppleCommander,
	logger kitlog.Logger,
) error {
	appConfig, err := ds.AppConfig(ctx)
	if err != nil {
		return fmt.Errorf("reading app config: %w", err)
	}
	if !appConfig.MDM.EnabledAndConfigured {
		return nil
	}

	// batch set declarations as pending
	changedHosts, err := ds.MDMAppleBatchSetHostDeclarationState(ctx)
	if err != nil {
		return ctxerr.Wrap(ctx, err, "updating host declaration state")
	}

	// Find any hosts that requested a resync. This is used to cover special cases where we're not
	// 100% certain of the declarations on the device.
	resyncHosts, err := ds.MDMAppleHostDeclarationsGetAndClearResync(ctx)
	if err != nil {
		return ctxerr.Wrap(ctx, err, "getting and clearing resync hosts")
	}
	if len(resyncHosts) > 0 {
		changedHosts = append(changedHosts, resyncHosts...)
		// Deduplicate changedHosts
		uniqueHosts := make(map[string]struct{})
		deduplicatedHosts := make([]string, 0, len(changedHosts))
		for _, id := range changedHosts {
			if _, exists := uniqueHosts[id]; !exists {
				uniqueHosts[id] = struct{}{}
				deduplicatedHosts = append(deduplicatedHosts, id)
			}
		}
		changedHosts = deduplicatedHosts
	}

	if len(changedHosts) == 0 {
		level.Info(logger).Log("msg", "no hosts with changed declarations")
		return nil
	}

	// send a DeclarativeManagement command to start a sync
	if err := commander.DeclarativeManagement(ctx, changedHosts, uuid.NewString()); err != nil {
		return ctxerr.Wrap(ctx, err, "issuing DeclarativeManagement command")
	}

	level.Info(logger).Log("msg", "sent DeclarativeManagement command", "host_number", len(changedHosts))

	return nil
}

// install/removeTargets are maps from profileUUID -> command uuid and host
// UUIDs as the underlying MDM services are optimized to send one command to
// multiple hosts at the same time. Note that the same command uuid is used
// for all hosts in a given install/remove target operation.
type cmdTarget struct {
	cmdUUID       string
	profIdent     string
	enrollmentIDs []string
}

func ReconcileAppleProfiles(
	ctx context.Context,
	ds mobius.Datastore,
	commander *apple_mdm.MDMAppleCommander,
	logger kitlog.Logger,
) error {
	appConfig, err := ds.AppConfig(ctx)
	if err != nil {
		return fmt.Errorf("reading app config: %w", err)
	}
	if !appConfig.MDM.EnabledAndConfigured {
		return nil
	}

	// Map of host UUID->User Channel enrollment ID so that we can cache them per-device
	userEnrollmentMap := make(map[string]string)
	userEnrollmentsToHostUUIDsMap := make(map[string]string) // the same thing in reverse

	assets, err := ds.GetAllMDMConfigAssetsByName(ctx, []mobius.MDMAssetName{
		mobius.MDMAssetCACert,
	}, nil)
	if err != nil {
		return ctxerr.Wrap(ctx, err, "getting Apple SCEP")
	}

	block, _ := pem.Decode(assets[mobius.MDMAssetCACert].Value)
	if block == nil || block.Type != "CERTIFICATE" {
		return ctxerr.Wrap(ctx, err, "failed to decode PEM block from SCEP certificate")
	}

	if err := ensureMobiusProfiles(ctx, ds, logger, block.Bytes); err != nil {
		logger.Log("err", "unable to ensure a mobiusdaemon configuration profiles are in place", "details", err)
	}

	// retrieve the profiles to install/remove.
	toInstall, err := ds.ListMDMAppleProfilesToInstall(ctx)
	if err != nil {
		return ctxerr.Wrap(ctx, err, "getting profiles to install")
	}

	// Exclude macOS only profiles from iPhones/iPads.
	toInstall = mobius.FilterMacOSOnlyProfilesFromIOSIPadOS(toInstall)

	toRemove, err := ds.ListMDMAppleProfilesToRemove(ctx)
	if err != nil {
		return ctxerr.Wrap(ctx, err, "getting profiles to remove")
	}

	// Perform aggregations to support all the operations we need to do

	// toGetContents contains the UUIDs of all the profiles from which we
	// need to retrieve contents. Since the previous query returns one row
	// per host, it would be too expensive to retrieve the profile contents
	// there, so we make another request. Using a map to deduplicate.
	toGetContents := make(map[string]bool)

	// hostProfiles tracks each host_mdm_apple_profile we need to upsert
	// with the new status, operation_type, etc.
	hostProfiles := make([]*mobius.MDMAppleBulkUpsertHostProfilePayload, 0, len(toInstall)+len(toRemove))

	// profileIntersection tracks profilesToAdd ∩ profilesToRemove, this is used to avoid:
	//
	// - Sending a RemoveProfile followed by an InstallProfile for a
	// profile with an identifier that's already installed, which can cause
	// racy behaviors.
	// - Sending a InstallProfile command for a profile that's exactly the
	// same as the one installed. Customers have reported that sending the
	// command causes unwanted behavior.
	profileIntersection := apple_mdm.NewProfileBimap()
	profileIntersection.IntersectByIdentifierAndHostUUID(toInstall, toRemove)

	// hostProfilesToCleanup is used to track profiles that should be removed
	// from the database directly without having to issue a RemoveProfile
	// command.
	hostProfilesToCleanup := []*mobius.MDMAppleProfilePayload{}

	// Index host profiles to install by host and profile UUID, for easier bulk error processing
	hostProfilesToInstallMap := make(map[hostProfileUUID]*mobius.MDMAppleBulkUpsertHostProfilePayload, len(toInstall))

	installTargets, removeTargets := make(map[string]*cmdTarget), make(map[string]*cmdTarget)
	for _, p := range toInstall {
		if pp, ok := profileIntersection.GetMatchingProfileInCurrentState(p); ok {
			// if the profile was in any other status than `failed`
			// and the checksums match (the profiles are exactly
			// the same) we don't send another InstallProfile
			// command.
			if pp.Status != &mobius.MDMDeliveryFailed && bytes.Equal(pp.Checksum, p.Checksum) {
				hostProfile := &mobius.MDMAppleBulkUpsertHostProfilePayload{
					ProfileUUID:       p.ProfileUUID,
					HostUUID:          p.HostUUID,
					ProfileIdentifier: p.ProfileIdentifier,
					ProfileName:       p.ProfileName,
					Checksum:          p.Checksum,
					SecretsUpdatedAt:  p.SecretsUpdatedAt,
					OperationType:     pp.OperationType,
					Status:            pp.Status,
					CommandUUID:       pp.CommandUUID,
					Detail:            pp.Detail,
					Scope:             pp.Scope,
				}
				hostProfiles = append(hostProfiles, hostProfile)
				hostProfilesToInstallMap[hostProfileUUID{HostUUID: p.HostUUID, ProfileUUID: p.ProfileUUID}] = hostProfile
				continue
			}
		}
		toGetContents[p.ProfileUUID] = true

		target := installTargets[p.ProfileUUID]
		if target == nil {
			target = &cmdTarget{
				cmdUUID:   uuid.New().String(),
				profIdent: p.ProfileIdentifier,
			}
			installTargets[p.ProfileUUID] = target
		}

		sentToUserChannel := false
		if p.Scope == mobius.PayloadScopeUser {
			userEnrollment, ok := userEnrollmentMap[p.HostUUID]
			if !ok {
				userNanoEnrollment, err := ds.GetNanoMDMUserEnrollment(ctx, p.HostUUID)
				if err != nil {
					return ctxerr.Wrap(ctx, err, "getting user enrollment for host")
				}
				if userNanoEnrollment != nil {
					userEnrollment = userNanoEnrollment.ID
					userEnrollmentMap[p.HostUUID] = userEnrollment
					userEnrollmentsToHostUUIDsMap[userEnrollment] = p.HostUUID
				} else {
					level.Warn(logger).Log("msg", "host does not have a user enrollment, falling back to system enrollment for user scoped profile",
						"host_uuid", p.HostUUID, "profile_uuid", p.ProfileUUID, "profile_identifier", p.ProfileIdentifier)
				}
			}
			if userEnrollment != "" {
				sentToUserChannel = true
				target.enrollmentIDs = append(target.enrollmentIDs, userEnrollment)
			}
		}

		if !sentToUserChannel {
			p.Scope = mobius.PayloadScopeSystem
			target.enrollmentIDs = append(target.enrollmentIDs, p.HostUUID)
		}

		hostProfile := &mobius.MDMAppleBulkUpsertHostProfilePayload{
			ProfileUUID:       p.ProfileUUID,
			HostUUID:          p.HostUUID,
			OperationType:     mobius.MDMOperationTypeInstall,
			Status:            &mobius.MDMDeliveryPending,
			CommandUUID:       target.cmdUUID,
			ProfileIdentifier: p.ProfileIdentifier,
			ProfileName:       p.ProfileName,
			Checksum:          p.Checksum,
			SecretsUpdatedAt:  p.SecretsUpdatedAt,
			Scope:             p.Scope,
		}
		hostProfiles = append(hostProfiles, hostProfile)
		hostProfilesToInstallMap[hostProfileUUID{HostUUID: p.HostUUID, ProfileUUID: p.ProfileUUID}] = hostProfile
	}

	for _, p := range toRemove {
		// Exclude profiles that are also marked for installation.
		if _, ok := profileIntersection.GetMatchingProfileInDesiredState(p); ok {
			hostProfilesToCleanup = append(hostProfilesToCleanup, p)
			continue
		}

		if p.FailedInstallOnHost() {
			// then we shouldn't send an additional remove command since it failed to install on the host.
			hostProfilesToCleanup = append(hostProfilesToCleanup, p)
			continue
		}
		if p.PendingInstallOnHost() {
			// The profile most likely did not install on host. However, it is possible that the profile
			// is currently being installed. So, we clean up the profile from the database, but also send
			// a remove command to the host.
			hostProfilesToCleanup = append(hostProfilesToCleanup, p)
			// IgnoreError is set since the removal command is likely to fail.
			p.IgnoreError = true
		}

		target := removeTargets[p.ProfileUUID]
		if target == nil {
			target = &cmdTarget{
				cmdUUID:   uuid.New().String(),
				profIdent: p.ProfileIdentifier,
			}
			removeTargets[p.ProfileUUID] = target
		}

		if p.Scope == mobius.PayloadScopeUser {
			userEnrollment, ok := userEnrollmentMap[p.HostUUID]
			if !ok {
				userNanoEnrollment, err := ds.GetNanoMDMUserEnrollment(ctx, p.HostUUID)
				if err != nil {
					return ctxerr.Wrap(ctx, err, "getting user enrollment for host")
				}
				// TODO Is there a better way to handle this? This likely just means cleanups
				// haven't run yet
				if userNanoEnrollment == nil {
					// TODO(mna): should we still proceed with the device-channel removal
					// attempt, but with IgnoreError set to true? Otherwise I think the
					// profile will stay in remove pending forever (or at least until a
					// new user-enrollment is created, and then it will likely fail since
					// it's not the same)?
					level.Warn(logger).Log("msg", "host does not have a user enrollment, cannot remove user scoped profile",
						"host_uuid", p.HostUUID, "profile_uuid", p.ProfileUUID, "profile_identifier", p.ProfileIdentifier)
					continue
				}
				userEnrollment = userNanoEnrollment.ID
				userEnrollmentMap[p.HostUUID] = userEnrollment
				userEnrollmentsToHostUUIDsMap[userEnrollment] = p.HostUUID
			}
			if userEnrollment != "" {
				target.enrollmentIDs = append(target.enrollmentIDs, userEnrollment)
			}
		} else {
			target.enrollmentIDs = append(target.enrollmentIDs, p.HostUUID)
		}

		hostProfiles = append(hostProfiles, &mobius.MDMAppleBulkUpsertHostProfilePayload{
			ProfileUUID:       p.ProfileUUID,
			HostUUID:          p.HostUUID,
			OperationType:     mobius.MDMOperationTypeRemove,
			Status:            &mobius.MDMDeliveryPending,
			CommandUUID:       target.cmdUUID,
			ProfileIdentifier: p.ProfileIdentifier,
			ProfileName:       p.ProfileName,
			Checksum:          p.Checksum,
			SecretsUpdatedAt:  p.SecretsUpdatedAt,
			IgnoreError:       p.IgnoreError,
			Scope:             p.Scope,
		})
	}

	// delete all profiles that have a matching identifier to be installed.
	// This is to prevent sending both a `RemoveProfile` and an
	// `InstallProfile` for the same identifier, which can cause race
	// conditions. It's better to "update" the profile by sending a single
	// `InstallProfile` command.
	//
	// Create a map of command UUIDs to host IDs
	commandUUIDToHostIDsCleanupMap := make(map[string][]string)
	for _, hp := range hostProfilesToCleanup {
		commandUUIDToHostIDsCleanupMap[hp.CommandUUID] = append(commandUUIDToHostIDsCleanupMap[hp.CommandUUID], hp.HostUUID)
	}
	// We need to delete commands from the nano queue so they don't get sent to device.
	if err := commander.BulkDeleteHostUserCommandsWithoutResults(ctx, commandUUIDToHostIDsCleanupMap); err != nil {
		return ctxerr.Wrap(ctx, err, "deleting nano commands without results")
	}
	if err := ds.BulkDeleteMDMAppleHostsConfigProfiles(ctx, hostProfilesToCleanup); err != nil {
		return ctxerr.Wrap(ctx, err, "deleting profiles that didn't change")
	}

	// First update all the profiles in the database before sending the
	// commands, this prevents race conditions where we could get a
	// response from the device before we set its status as 'pending'
	//
	// We'll do another pass at the end to revert any changes for failed
	// deliveries.
	if err := ds.BulkUpsertMDMAppleHostProfiles(ctx, hostProfiles); err != nil {
		return ctxerr.Wrap(ctx, err, "updating host profiles")
	}

	// Grab the contents of all the profiles we need to install
	profileUUIDs := make([]string, 0, len(toGetContents))
	for pUUID := range toGetContents {
		profileUUIDs = append(profileUUIDs, pUUID)
	}
	profileContents, err := ds.GetMDMAppleProfilesContents(ctx, profileUUIDs)
	if err != nil {
		return ctxerr.Wrap(ctx, err, "get profile contents")
	}

	// Insert variables into profile contents of install targets. Variables may be host-specific.
	err = preprocessProfileContents(ctx, appConfig, ds,
		nil, // eeservice.NewSCEPConfigService(logger, nil), // Removed enterprise dependency
		nil, // digicert.NewService(digicert.WithLogger(logger)), // Removed enterprise dependency
		logger, installTargets, profileContents, hostProfilesToInstallMap, userEnrollmentsToHostUUIDsMap)
	if err != nil {
		return err
	}

	// Find the profiles containing secret variables.
	profilesWithSecrets, err := findProfilesWithSecrets(logger, installTargets, profileContents)
	if err != nil {
		return err
	}

	type remoteResult struct {
		Err     error
		CmdUUID string
	}

	// Send the install/remove commands for each profile.
	var wgProd, wgCons sync.WaitGroup
	ch := make(chan remoteResult)

	execCmd := func(profUUID string, target *cmdTarget, op mobius.MDMOperationType) {
		defer wgProd.Done()

		var err error
		switch op {
		case mobius.MDMOperationTypeInstall:
			if _, ok := profilesWithSecrets[profUUID]; ok {
				err = commander.EnqueueCommandInstallProfileWithSecrets(ctx, target.enrollmentIDs, profileContents[profUUID], target.cmdUUID)
			} else {
				err = commander.InstallProfile(ctx, target.enrollmentIDs, profileContents[profUUID], target.cmdUUID)
			}
		case mobius.MDMOperationTypeRemove:
			err = commander.RemoveProfile(ctx, target.enrollmentIDs, target.profIdent, target.cmdUUID)
		}

		var e *apple_mdm.APNSDeliveryError
		switch {
		case errors.As(err, &e):
			level.Debug(logger).Log("err", "sending push notifications, profiles still enqueued", "details", err)
		case err != nil:
			level.Error(logger).Log("err", fmt.Sprintf("enqueue command to %s profiles", op), "details", err)
			ch <- remoteResult{err, target.cmdUUID}
		}
	}
	for profUUID, target := range installTargets {
		wgProd.Add(1)
		go execCmd(profUUID, target, mobius.MDMOperationTypeInstall)
	}
	for profUUID, target := range removeTargets {
		wgProd.Add(1)
		go execCmd(profUUID, target, mobius.MDMOperationTypeRemove)
	}

	// index the host profiles by cmdUUID, for ease of error processing in the
	// consumer goroutine below.
	hostProfsByCmdUUID := make(map[string][]*mobius.MDMAppleBulkUpsertHostProfilePayload, len(installTargets)+len(removeTargets))
	for _, hp := range hostProfiles {
		hostProfsByCmdUUID[hp.CommandUUID] = append(hostProfsByCmdUUID[hp.CommandUUID], hp)
	}

	// Grab all the failed deliveries and update the status so they're picked up
	// again in the next run.
	//
	// Note that if the APNs push failed we won't try again, as the command was
	// successfully enqueued, this is only to account for internal errors like DB
	// failures.
	failed := []*mobius.MDMAppleBulkUpsertHostProfilePayload{}
	wgCons.Add(1)
	go func() {
		defer wgCons.Done()

		for resp := range ch {
			hostProfs := hostProfsByCmdUUID[resp.CmdUUID]
			for _, hp := range hostProfs {
				// clear the command as it failed to enqueue, will need to emit a new command
				hp.CommandUUID = ""
				// set status to nil so it is retried on the next cron run
				hp.Status = nil
				failed = append(failed, hp)
			}
		}
	}()

	wgProd.Wait()
	close(ch) // done sending at this point, this triggers end of for loop in consumer
	wgCons.Wait()

	if err := ds.BulkUpsertMDMAppleHostProfiles(ctx, failed); err != nil {
		return ctxerr.Wrap(ctx, err, "reverting status of failed profiles")
	}

	return nil
}

func findProfilesWithSecrets(
	logger kitlog.Logger,
	installTargets map[string]*cmdTarget,
	profileContents map[string]mobileconfig.Mobileconfig,
) (map[string]struct{}, error) {
	profilesWithSecrets := make(map[string]struct{})
	for profUUID := range installTargets {
		p, ok := profileContents[profUUID]
		if !ok { // Should never happen
			level.Error(logger).Log("msg", "profile content not found in ReconcileAppleProfiles", "profile_uuid", profUUID)
			continue
		}
		profileStr := string(p)
		vars := mobius.ContainsPrefixVars(profileStr, mobius.ServerSecretPrefix)
		if len(vars) > 0 {
			profilesWithSecrets[profUUID] = struct{}{}
		}
	}
	return profilesWithSecrets, nil
}

func preprocessProfileContents(
	ctx context.Context,
	appConfig *mobius.AppConfig,
	ds mobius.Datastore,
	scepConfig mobius.SCEPConfigService,
	digiCertService mobius.DigiCertService,
	logger kitlog.Logger,
	targets map[string]*cmdTarget,
	profileContents map[string]mobileconfig.Mobileconfig,
	hostProfilesToInstallMap map[hostProfileUUID]*mobius.MDMAppleBulkUpsertHostProfilePayload,
	userEnrollmentsToHostUUIDsMap map[string]string,
) error {
	// This method replaces Mobius variables ($MOBIUS_VAR_<NAME>) in the profile
	// contents, generating a unique profile for each host. For a 2KB profile and
	// 30K hosts, this method may generate ~60MB of profile data in memory.

	var (
		// Copy of NDES SCEP config which will contain unencrypted password, if needed
		ndesConfig    *mobius.NDESSCEPProxyIntegration
		digiCertCAs   map[string]*mobius.DigiCertIntegration
		customSCEPCAs map[string]*mobius.CustomSCEPProxyIntegration
	)

	// this is used to cache the host ID corresponding to the UUID, so we don't
	// need to look it up more than once per host.
	hostIDForUUIDCache := make(map[string]uint)

	var addedTargets map[string]*cmdTarget
	for profUUID, target := range targets {
		contents, ok := profileContents[profUUID]
		if !ok {
			// This should never happen
			continue
		}

		// Check if Mobius variables are present.
		contentsStr := string(contents)
		mobiusVars := findMobiusVariables(contentsStr)
		if len(mobiusVars) == 0 {
			continue
		}

		var variablesUpdatedAt *time.Time

		// Do common validation that applies to all hosts in the target
		valid := true
		// Check if there are any CA variables first so that if a non-CA variable causes
		// preprocessing to fail, we still set the variablesUpdatedAt timestamp so that
		// validation works as expected
		// In the future we should expand variablesUpdatedAt logic to include non-CA variables as
		// well
		for mobiusVar := range mobiusVars {
			if mobiusVar == mobius.MobiusVarNDESSCEPChallenge || mobiusVar == mobius.MobiusVarNDESSCEPProxyURL || mobiusVar == mobius.MobiusVarSCEPRenewalID ||
				strings.HasPrefix(mobiusVar, mobius.MobiusVarDigiCertPasswordPrefix) || strings.HasPrefix(mobiusVar, mobius.MobiusVarDigiCertDataPrefix) ||
				strings.HasPrefix(mobiusVar, mobius.MobiusVarCustomSCEPChallengePrefix) || strings.HasPrefix(mobiusVar, mobius.MobiusVarCustomSCEPProxyURLPrefix) {
				// Give a few minutes leeway to account for clock skew
				variablesUpdatedAt = ptr.Time(time.Now().UTC().Add(-3 * time.Minute))
				break
			}
		}

		for mobiusVar := range mobiusVars {
			switch {
			case mobiusVar == mobius.MobiusVarNDESSCEPChallenge || mobiusVar == mobius.MobiusVarNDESSCEPProxyURL:
				configured, err := isNDESSCEPConfigured(ctx, appConfig, ds, hostProfilesToInstallMap, userEnrollmentsToHostUUIDsMap, profUUID, target)
				if err != nil {
					return ctxerr.Wrap(ctx, err, "checking NDES SCEP configuration")
				}
				if !configured {
					valid = false
					break
				}

			case mobiusVar == mobius.MobiusVarHostEndUserEmailIDP || mobiusVar == mobius.MobiusVarHostHardwareSerial ||
				mobiusVar == mobius.MobiusVarHostEndUserIDPUsername || mobiusVar == mobius.MobiusVarHostEndUserIDPUsernameLocalPart ||
				mobiusVar == mobius.MobiusVarHostEndUserIDPGroups || mobiusVar == mobius.MobiusVarHostEndUserIDPDepartment || mobiusVar == mobius.MobiusVarSCEPRenewalID:
				// No extra validation needed for these variables

			case strings.HasPrefix(mobiusVar, mobius.MobiusVarDigiCertPasswordPrefix) || strings.HasPrefix(mobiusVar, mobius.MobiusVarDigiCertDataPrefix):
				var caName string
				if strings.HasPrefix(mobiusVar, mobius.MobiusVarDigiCertPasswordPrefix) {
					caName = strings.TrimPrefix(mobiusVar, mobius.MobiusVarDigiCertPasswordPrefix)
				} else {
					caName = strings.TrimPrefix(mobiusVar, mobius.MobiusVarDigiCertDataPrefix)
				}
				if digiCertCAs == nil {
					digiCertCAs = make(map[string]*mobius.DigiCertIntegration)
				}
				configured, err := isDigiCertConfigured(ctx, appConfig, ds, hostProfilesToInstallMap, userEnrollmentsToHostUUIDsMap, digiCertCAs, profUUID, target, caName, mobiusVar)
				if err != nil {
					return ctxerr.Wrap(ctx, err, "checking DigiCert configuration")
				}
				if !configured {
					valid = false
					break
				}

			case strings.HasPrefix(mobiusVar, mobius.MobiusVarCustomSCEPChallengePrefix) || strings.HasPrefix(mobiusVar, mobius.MobiusVarCustomSCEPProxyURLPrefix):
				var caName string
				if strings.HasPrefix(mobiusVar, mobius.MobiusVarCustomSCEPChallengePrefix) {
					caName = strings.TrimPrefix(mobiusVar, mobius.MobiusVarCustomSCEPChallengePrefix)
				} else {
					caName = strings.TrimPrefix(mobiusVar, mobius.MobiusVarCustomSCEPProxyURLPrefix)
				}
				if customSCEPCAs == nil {
					customSCEPCAs = make(map[string]*mobius.CustomSCEPProxyIntegration)
				}
				configured, err := isCustomSCEPConfigured(ctx, appConfig, ds, hostProfilesToInstallMap, userEnrollmentsToHostUUIDsMap, customSCEPCAs, profUUID, target, caName,
					mobiusVar)
				if err != nil {
					return ctxerr.Wrap(ctx, err, "checking custom SCEP configuration")
				}
				if !configured {
					valid = false
					break
				}

			default:
				// Otherwise, error out since this variable is unknown
				detail := fmt.Sprintf("Unknown Mobius variable $MOBIUS_VAR_%s found in profile. Please update or remove.",
					mobiusVar)
				_, err := markProfilesFailed(ctx, ds, target, hostProfilesToInstallMap, userEnrollmentsToHostUUIDsMap, profUUID, detail, variablesUpdatedAt)
				if err != nil {
					return err
				}
				valid = false
			}
		}
		if !valid {
			// We marked the profile as failed, so we will not do any additional processing on it
			delete(targets, profUUID)
			continue
		}

		// Currently, all supported Mobius variables are unique per host, so we split the profile into multiple profiles.
		// We generate a new temporary profileUUID which is currently only used to install the profile.
		// The profileUUID in host_mdm_apple_profiles is still the original profileUUID.
		// We also generate a new commandUUID which is used to install the profile via nano_commands table.
		if addedTargets == nil {
			addedTargets = make(map[string]*cmdTarget, 1)
		}
		// We store the timestamp when the challenge was retrieved to know if it has expired.
		var managedCertificatePayloads []*mobius.MDMManagedCertificate
		// We need to update the profiles of each host with the new command UUID
		profilesToUpdate := make([]*mobius.MDMAppleBulkUpsertHostProfilePayload, 0, len(target.enrollmentIDs))
		for _, enrollmentID := range target.enrollmentIDs {
			tempProfUUID := uuid.NewString()
			// Use the same UUID for command UUID, which will be the primary key for nano_commands
			tempCmdUUID := tempProfUUID
			profile, ok := getHostProfileToInstallByEnrollmentID(hostProfilesToInstallMap, userEnrollmentsToHostUUIDsMap, enrollmentID, profUUID)
			if !ok { // Should never happen
				continue
			}
			// Fetch the host UUID, which may not be the same as the Enrollment ID, from the profile
			hostUUID := profile.HostUUID
			profile.CommandUUID = tempCmdUUID
			profile.VariablesUpdatedAt = variablesUpdatedAt

			hostContents := contentsStr
			failed := false
		mobiusVarLoop:
			for mobiusVar := range mobiusVars {
				var err error
				switch {
				case mobiusVar == mobius.MobiusVarNDESSCEPChallenge:
					if ndesConfig == nil {
						// Retrieve the NDES admin password. This is done once per run.
						configAssets, err := ds.GetAllMDMConfigAssetsByName(ctx, []mobius.MDMAssetName{mobius.MDMAssetNDESPassword}, nil)
						if err != nil {
							return ctxerr.Wrap(ctx, err, "getting NDES password")
						}
						// Copy config struct by value
						configWithPassword := appConfig.Integrations.NDESSCEPProxy.Value
						configWithPassword.Password = string(configAssets[mobius.MDMAssetNDESPassword].Value)
						// Store the config with the password for later use
						ndesConfig = &configWithPassword
					}
					// Insert the SCEP challenge into the profile contents
					challenge, err := scepConfig.GetNDESSCEPChallenge(ctx, *ndesConfig)
					if err != nil {
						detail := ""
						// Enterprise error handling removed - using generic error
						detail = fmt.Sprintf("Mobius couldn't populate $MOBIUS_VAR_%s. %s", mobius.MobiusVarNDESSCEPChallenge, err.Error())
						err := ds.UpdateOrDeleteHostMDMAppleProfile(ctx, &mobius.HostMDMAppleProfile{
							CommandUUID:        target.cmdUUID,
							HostUUID:           hostUUID,
							Status:             &mobius.MDMDeliveryFailed,
							Detail:             detail,
							OperationType:      mobius.MDMOperationTypeInstall,
							VariablesUpdatedAt: variablesUpdatedAt,
						})
						if err != nil {
							return ctxerr.Wrap(ctx, err, "updating host MDM Apple profile for NDES SCEP challenge")
						}
						failed = true
						break mobiusVarLoop
					}
					payload := &mobius.MDMManagedCertificate{
						HostUUID:             hostUUID,
						ProfileUUID:          profUUID,
						ChallengeRetrievedAt: ptr.Time(time.Now()),
						Type:                 mobius.CAConfigNDES,
						CAName:               "NDES",
					}
					managedCertificatePayloads = append(managedCertificatePayloads, payload)

					hostContents = replaceMobiusVariableInXML(mobiusVarNDESSCEPChallengeRegexp, hostContents, challenge)

				case mobiusVar == mobius.MobiusVarNDESSCEPProxyURL:
					// Insert the SCEP URL into the profile contents
					proxyURL := fmt.Sprintf("%s%s%s", appConfig.MDMUrl(), apple_mdm.SCEPProxyPath,
						url.PathEscape(fmt.Sprintf("%s,%s,NDES", hostUUID, profUUID)))
					hostContents = replaceMobiusVariableInXML(mobiusVarNDESSCEPProxyURLRegexp, hostContents, proxyURL)

				case mobiusVar == mobius.MobiusVarSCEPRenewalID:
					// Insert the SCEP renewal ID into the SCEP Payload CN
					mobiusRenewalID := "mobius-" + profUUID
					hostContents = replaceMobiusVariableInXML(mobiusVarSCEPRenewalIDRegexp, hostContents, mobiusRenewalID)

				case strings.HasPrefix(mobiusVar, mobius.MobiusVarCustomSCEPChallengePrefix):
					caName := strings.TrimPrefix(mobiusVar, mobius.MobiusVarCustomSCEPChallengePrefix)
					ca, ok := customSCEPCAs[caName]
					if !ok {
						level.Error(logger).Log("msg", "Custom SCEP CA not found. "+
							"This error should never happen since we validated/populated CAs earlier", "ca_name", caName)
						continue
					}
					hostContents, err = replaceExactMobiusPrefixVariableInXML(mobius.MobiusVarCustomSCEPChallengePrefix, ca.Name, hostContents, ca.Challenge)
					if err != nil {
						return ctxerr.Wrap(ctx, err, "replacing Mobius variable for SCEP challenge")
					}

				case strings.HasPrefix(mobiusVar, mobius.MobiusVarCustomSCEPProxyURLPrefix):
					caName := strings.TrimPrefix(mobiusVar, mobius.MobiusVarCustomSCEPProxyURLPrefix)
					ca, ok := customSCEPCAs[caName]
					if !ok {
						level.Error(logger).Log("msg", "Custom SCEP CA not found. "+
							"This error should never happen since we validated/populated CAs earlier", "ca_name", caName)
						continue
					}
					// Generate a new SCEP challenge for the profile
					challenge, err := ds.NewChallenge(ctx)
					if err != nil {
						return ctxerr.Wrap(ctx, err, "generating SCEP challenge")
					}
					// Insert the SCEP URL into the profile contents
					proxyURL := fmt.Sprintf("%s%s%s", appConfig.MDMUrl(), apple_mdm.SCEPProxyPath,
						url.PathEscape(fmt.Sprintf("%s,%s,%s,%s", hostUUID, profUUID, caName, challenge)))
					hostContents, err = replaceExactMobiusPrefixVariableInXML(mobius.MobiusVarCustomSCEPProxyURLPrefix, ca.Name, hostContents, proxyURL)
					if err != nil {
						return ctxerr.Wrap(ctx, err, "replacing Mobius variable for SCEP proxy URL")
					}
					managedCertificatePayloads = append(managedCertificatePayloads, &mobius.MDMManagedCertificate{
						HostUUID:    hostUUID,
						ProfileUUID: profUUID,
						Type:        mobius.CAConfigCustomSCEPProxy,
						CAName:      caName,
					})

				case mobiusVar == mobius.MobiusVarHostEndUserEmailIDP:
					email, ok, err := getIDPEmail(ctx, ds, target, hostUUID)
					if err != nil {
						return ctxerr.Wrap(ctx, err, "getting IDP email")
					}
					if !ok {
						failed = true
						break mobiusVarLoop
					}
					hostContents = replaceMobiusVariableInXML(mobiusVarHostEndUserEmailIDPRegexp, hostContents, email)

				case mobiusVar == mobius.MobiusVarHostHardwareSerial:
					hardwareSerial, ok, err := getHostHardwareSerial(ctx, ds, target, hostUUID)
					if err != nil {
						return ctxerr.Wrap(ctx, err, "getting host hardware serial")
					}
					if !ok {
						failed = true
						break mobiusVarLoop
					}
					hostContents = replaceMobiusVariableInXML(mobiusVarHostHardwareSerialRegexp, hostContents, hardwareSerial)

				case mobiusVar == mobius.MobiusVarHostEndUserIDPUsername || mobiusVar == mobius.MobiusVarHostEndUserIDPUsernameLocalPart ||
					mobiusVar == mobius.MobiusVarHostEndUserIDPGroups || mobiusVar == mobius.MobiusVarHostEndUserIDPDepartment:
					user, ok, err := getHostEndUserIDPUser(ctx, ds, target, hostUUID, mobiusVar, hostIDForUUIDCache)
					if err != nil {
						return ctxerr.Wrap(ctx, err, "getting host end user IDP username")
					}
					if !ok {
						failed = true
						break mobiusVarLoop
					}

					var rx *regexp.Regexp
					var value string
					switch mobiusVar {
					case mobius.MobiusVarHostEndUserIDPUsername:
						rx = mobiusVarHostEndUserIDPUsernameRegexp
						value = user.IdpUserName
					case mobius.MobiusVarHostEndUserIDPUsernameLocalPart:
						rx = mobiusVarHostEndUserIDPUsernameLocalPartRegexp
						value = getEmailLocalPart(user.IdpUserName)
					case mobius.MobiusVarHostEndUserIDPGroups:
						rx = mobiusVarHostEndUserIDPGroupsRegexp
						value = strings.Join(user.IdpGroups, ",")
					case mobius.MobiusVarHostEndUserIDPDepartment:
						rx = mobiusVarHostEndUserIDPDepartmentRegexp
						value = user.Department
					}
					hostContents = replaceMobiusVariableInXML(rx, hostContents, value)

				case strings.HasPrefix(mobiusVar, mobius.MobiusVarDigiCertPasswordPrefix):
					// We will replace the password when we populate the certificate data

				case strings.HasPrefix(mobiusVar, mobius.MobiusVarDigiCertDataPrefix):
					caName := strings.TrimPrefix(mobiusVar, mobius.MobiusVarDigiCertDataPrefix)
					ca, ok := digiCertCAs[caName]
					if !ok {
						level.Error(logger).Log("msg", "Custom DigiCert CA not found. "+
							"This error should never happen since we validated/populated CAs earlier", "ca_name", caName)
						continue
					}
					caCopy := *ca

					// Populate Mobius vars in the CA fields
					caVarsCache := make(map[string]string)
					ok, err := replaceMobiusVarInItem(ctx, ds, target, hostUUID, caVarsCache, &caCopy.CertificateCommonName)
					if err != nil {
						return ctxerr.Wrap(ctx, err, "populating Mobius variables in DigiCert CA common name")
					}
					if !ok {
						failed = true
						break mobiusVarLoop
					}
					ok, err = replaceMobiusVarInItem(ctx, ds, target, hostUUID, caVarsCache, &caCopy.CertificateSeatID)
					if err != nil {
						return ctxerr.Wrap(ctx, err, "populating Mobius variables in DigiCert CA common name")
					}
					if !ok {
						failed = true
						break mobiusVarLoop
					}
					if len(caCopy.CertificateUserPrincipalNames) > 0 {
						for i := range caCopy.CertificateUserPrincipalNames {
							ok, err = replaceMobiusVarInItem(ctx, ds, target, hostUUID, caVarsCache, &caCopy.CertificateUserPrincipalNames[i])
							if err != nil {
								return ctxerr.Wrap(ctx, err, "populating Mobius variables in DigiCert CA common name")
							}
							if !ok {
								failed = true
								break mobiusVarLoop
							}
						}
					}

					cert, err := digiCertService.GetCertificate(ctx, caCopy)
					if err != nil {
						detail := fmt.Sprintf("Couldn't get certificate from DigiCert for %s. %s", caCopy.Name, err)
						err = ds.UpdateOrDeleteHostMDMAppleProfile(ctx, &mobius.HostMDMAppleProfile{
							CommandUUID:        target.cmdUUID,
							HostUUID:           hostUUID,
							Status:             &mobius.MDMDeliveryFailed,
							Detail:             detail,
							OperationType:      mobius.MDMOperationTypeInstall,
							VariablesUpdatedAt: variablesUpdatedAt,
						})
						if err != nil {
							return ctxerr.Wrap(ctx, err, "updating host MDM Apple profile for DigiCert")
						}
						failed = true
						break mobiusVarLoop
					}
					hostContents, err = replaceExactMobiusPrefixVariableInXML(mobius.MobiusVarDigiCertDataPrefix, caName, hostContents,
						base64.StdEncoding.EncodeToString(cert.PfxData))
					if err != nil {
						return ctxerr.Wrap(ctx, err, "replacing Mobius variable for DigiCert data")
					}
					hostContents, err = replaceExactMobiusPrefixVariableInXML(mobius.MobiusVarDigiCertPasswordPrefix, caName, hostContents, cert.Password)
					if err != nil {
						return ctxerr.Wrap(ctx, err, "replacing Mobius variable for DigiCert password")
					}
					managedCertificatePayloads = append(managedCertificatePayloads, &mobius.MDMManagedCertificate{
						HostUUID:       hostUUID,
						ProfileUUID:    profUUID,
						NotValidBefore: &cert.NotValidBefore,
						NotValidAfter:  &cert.NotValidAfter,
						Type:           mobius.CAConfigDigiCert,
						CAName:         caName,
						Serial:         &cert.SerialNumber,
					})

				default:
					// This was handled in the above switch statement, so we should never reach this case
				}
			}
			if !failed {
				addedTargets[tempProfUUID] = &cmdTarget{
					cmdUUID:       tempCmdUUID,
					profIdent:     target.profIdent,
					enrollmentIDs: []string{enrollmentID},
				}
				profileContents[tempProfUUID] = mobileconfig.Mobileconfig(hostContents)
				profilesToUpdate = append(profilesToUpdate, profile)
			}
		}
		// Update profiles with the new command UUID
		if len(profilesToUpdate) > 0 {
			if err := ds.BulkUpsertMDMAppleHostProfiles(ctx, profilesToUpdate); err != nil {
				return ctxerr.Wrap(ctx, err, "updating host profiles")
			}
		}
		if len(managedCertificatePayloads) != 0 {
			err := ds.BulkUpsertMDMManagedCertificates(ctx, managedCertificatePayloads)
			if err != nil {
				return ctxerr.Wrap(ctx, err, "updating managed certificates")
			}
		}
		// Remove the parent target, since we will use host-specific targets
		delete(targets, profUUID)
	}
	if len(addedTargets) > 0 {
		// Add the new host-specific targets to the original targets map
		for profUUID, target := range addedTargets {
			targets[profUUID] = target
		}
	}
	return nil
}

func replaceMobiusVarInItem(ctx context.Context, ds mobius.Datastore, target *cmdTarget, hostUUID string, caVarsCache map[string]string, item *string,
) (bool, error) {
	caMobiusVars := findMobiusVariables(*item)
	for caVar := range caMobiusVars {
		switch caVar {
		case mobius.MobiusVarHostEndUserEmailIDP:
			email, ok := caVarsCache[mobius.MobiusVarHostEndUserEmailIDP]
			if !ok {
				var err error
				email, ok, err = getIDPEmail(ctx, ds, target, hostUUID)
				if err != nil {
					return false, ctxerr.Wrap(ctx, err, "getting IDP email")
				}
				if !ok {
					return false, nil
				}
				caVarsCache[mobius.MobiusVarHostEndUserEmailIDP] = email
			}
			*item = replaceMobiusVariableInXML(mobiusVarHostEndUserEmailIDPRegexp, *item, email)
		case mobius.MobiusVarHostHardwareSerial:
			hardwareSerial, ok := caVarsCache[mobius.MobiusVarHostHardwareSerial]
			if !ok {
				var err error
				hardwareSerial, ok, err = getHostHardwareSerial(ctx, ds, target, hostUUID)
				if err != nil {
					return false, ctxerr.Wrap(ctx, err, "getting host hardware serial")
				}
				if !ok {
					return false, nil
				}
				caVarsCache[mobius.MobiusVarHostHardwareSerial] = hardwareSerial
			}
			*item = replaceMobiusVariableInXML(mobiusVarHostHardwareSerialRegexp, *item, hardwareSerial)
		default:
			// We should not reach this since we validated the variables when saving app config
		}
	}
	return true, nil
}

func getHostEndUserIDPUser(ctx context.Context, ds mobius.Datastore, target *cmdTarget,
	hostUUID, mobiusVar string, hostIDForUUIDCache map[string]uint,
) (*mobius.HostEndUser, bool, error) {
	hostID, ok := hostIDForUUIDCache[hostUUID]
	if !ok {
		filter := mobius.TeamFilter{User: &mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)}}
		ids, err := ds.HostIDsByIdentifier(ctx, filter, []string{hostUUID})
		if err != nil {
			return nil, false, ctxerr.Wrap(ctx, err, "get host id from uuid")
		}

		if len(ids) != 1 {
			// Something went wrong. Maybe host was deleted, or we have multiple
			// hosts with the same UUID. Mark the profile as failed with additional
			// detail.
			err := ds.UpdateOrDeleteHostMDMAppleProfile(ctx, &mobius.HostMDMAppleProfile{
				CommandUUID:   target.cmdUUID,
				HostUUID:      hostUUID,
				Status:        &mobius.MDMDeliveryFailed,
				Detail:        fmt.Sprintf("Unexpected number of hosts (%d) for UUID %s. ", len(ids), hostUUID),
				OperationType: mobius.MDMOperationTypeInstall,
			})
			if err != nil {
				return nil, false, ctxerr.Wrap(ctx, err, "updating host MDM Apple profile for end user IDP")
			}
			return nil, false, nil
		}
		hostID = ids[0]
		hostIDForUUIDCache[hostUUID] = hostID
	}

	users, err := getEndUsers(ctx, ds, hostID)
	if err != nil {
		return nil, false, ctxerr.Wrap(ctx, err, "get end users for host")
	}

	noGroupsErr := fmt.Sprintf("There is no IdP groups for this host. Mobius couldn’t populate $MOBIUS_VAR_%s.", mobius.MobiusVarHostEndUserIDPGroups)
	if len(users) > 0 && users[0].IdpUserName != "" {
		idpUser := users[0]

		if mobiusVar == mobius.MobiusVarHostEndUserIDPGroups && len(idpUser.IdpGroups) == 0 {
			err = ds.UpdateOrDeleteHostMDMAppleProfile(ctx, &mobius.HostMDMAppleProfile{
				CommandUUID:   target.cmdUUID,
				HostUUID:      hostUUID,
				Status:        &mobius.MDMDeliveryFailed,
				Detail:        noGroupsErr,
				OperationType: mobius.MDMOperationTypeInstall,
			})
			if err != nil {
				return nil, false, ctxerr.Wrap(ctx, err, "updating host MDM Apple profile for end user IDP")
			}
			return nil, false, nil
		}

		return &idpUser, true, nil
	}

	// otherwise there's no IdP user, mark the profile as failed with the
	// appropriate detail message.
	var detail string
	switch mobiusVar {
	case mobius.MobiusVarHostEndUserIDPUsername, mobius.MobiusVarHostEndUserIDPUsernameLocalPart:
		detail = fmt.Sprintf("There is no IdP username for this host. Mobius couldn’t populate $MOBIUS_VAR_%s.", mobiusVar)
	case mobius.MobiusVarHostEndUserIDPGroups:
		detail = noGroupsErr
	}
	err = ds.UpdateOrDeleteHostMDMAppleProfile(ctx, &mobius.HostMDMAppleProfile{
		CommandUUID:   target.cmdUUID,
		HostUUID:      hostUUID,
		Status:        &mobius.MDMDeliveryFailed,
		Detail:        detail,
		OperationType: mobius.MDMOperationTypeInstall,
	})
	if err != nil {
		return nil, false, ctxerr.Wrap(ctx, err, "updating host MDM Apple profile for end user IDP")
	}
	return nil, false, nil
}

func getEmailLocalPart(email string) string {
	// if there is a "@" in the email, return the part before that "@", otherwise
	// return the string unchanged.
	local, _, _ := strings.Cut(email, "@")
	return local
}

func getIDPEmail(ctx context.Context, ds mobius.Datastore, target *cmdTarget, hostUUID string) (string, bool, error) {
	// Insert the end user email IDP into the profile contents
	emails, err := ds.GetHostEmails(ctx, hostUUID, mobius.DeviceMappingMDMIdpAccounts)
	if err != nil {
		// This is a server error, so we exit.
		return "", false, ctxerr.Wrap(ctx, err, "getting host emails")
	}
	if len(emails) == 0 {
		// We couldn't retrieve the end user email IDP, so mark the profile as failed with additional detail.
		err := ds.UpdateOrDeleteHostMDMAppleProfile(ctx, &mobius.HostMDMAppleProfile{
			CommandUUID: target.cmdUUID,
			HostUUID:    hostUUID,
			Status:      &mobius.MDMDeliveryFailed,
			Detail: fmt.Sprintf("There is no IdP email for this host. "+
				"Mobius couldn't populate $MOBIUS_VAR_%s. "+
				"[Learn more](https://mobiusmdm.com/learn-more-about/idp-email)",
				mobius.MobiusVarHostEndUserEmailIDP),
			OperationType: mobius.MDMOperationTypeInstall,
		})
		if err != nil {
			return "", false, ctxerr.Wrap(ctx, err, "updating host MDM Apple profile for end user email IdP")
		}
		return "", false, nil
	}
	return emails[0], true, nil
}

func getHostHardwareSerial(ctx context.Context, ds mobius.Datastore, target *cmdTarget, hostUUID string) (string, bool, error) {
	hosts, err := ds.ListHostsLiteByUUIDs(ctx, mobius.TeamFilter{User: &mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)}}, []string{hostUUID})
	if err != nil {
		return "", false, ctxerr.Wrap(ctx, err, "listing hosts")
	}
	if len(hosts) != 1 {
		// Something went wrong. Maybe host was deleted, or we have multiple hosts with the same UUID.
		// Mark the profile as failed with additional detail.
		err := ds.UpdateOrDeleteHostMDMAppleProfile(ctx, &mobius.HostMDMAppleProfile{
			CommandUUID:   target.cmdUUID,
			HostUUID:      hostUUID,
			Status:        &mobius.MDMDeliveryFailed,
			Detail:        fmt.Sprintf("Unexpected number of hosts (%d) for UUID %s. ", len(hosts), hostUUID),
			OperationType: mobius.MDMOperationTypeInstall,
		})
		if err != nil {
			return "", false, ctxerr.Wrap(ctx, err, "updating host MDM Apple profile for hardware serial")
		}
		return "", false, nil
	}
	hardwareSerial := hosts[0].HardwareSerial
	return hardwareSerial, true, nil
}

type digiCertVarsFound struct {
	dataCA     map[string]struct{}
	passwordCA map[string]struct{}
}

// Ok makes sure that both DATA and PASSWORD variables are present in a DigiCert profile.
func (d *digiCertVarsFound) Ok() bool {
	if d == nil {
		return true
	}
	if len(d.dataCA) != len(d.passwordCA) {
		return false
	}
	for ca := range d.dataCA {
		if _, ok := d.passwordCA[ca]; !ok {
			return false
		}
	}
	return true
}

func (d *digiCertVarsFound) Found() bool {
	return d != nil
}

func (d *digiCertVarsFound) CAs() []string {
	if d == nil {
		return nil
	}
	keys := make([]string, 0, len(d.dataCA))
	for key := range d.dataCA {
		keys = append(keys, key)
	}
	return keys
}

func (d *digiCertVarsFound) ErrorMessage() string {
	for ca := range d.passwordCA {
		if _, ok := d.dataCA[ca]; !ok {
			return fmt.Sprintf("Missing $MOBIUS_VAR_%s%s in the profile", mobius.MobiusVarDigiCertDataPrefix, ca)
		}
	}
	for ca := range d.dataCA {
		if _, ok := d.passwordCA[ca]; !ok {
			return fmt.Sprintf("Missing $MOBIUS_VAR_%s%s in the profile", mobius.MobiusVarDigiCertPasswordPrefix, ca)
		}
	}
	return fmt.Sprintf("CA name mismatch between $MOBIUS_VAR_%s<ca_name> and $MOBIUS_VAR_%s<ca_name> in the profile.",
		mobius.MobiusVarDigiCertDataPrefix, mobius.MobiusVarDigiCertPasswordPrefix)
}

func (d *digiCertVarsFound) SetData(value string) (*digiCertVarsFound, bool) {
	if d == nil {
		d = &digiCertVarsFound{}
	}
	if d.dataCA == nil {
		d.dataCA = make(map[string]struct{})
	}
	_, alreadyPresent := d.dataCA[value]
	d.dataCA[value] = struct{}{}
	return d, !alreadyPresent
}

func (d *digiCertVarsFound) SetPassword(value string) (*digiCertVarsFound, bool) {
	if d == nil {
		d = &digiCertVarsFound{}
	}
	if d.passwordCA == nil {
		d.passwordCA = make(map[string]struct{})
	}
	_, alreadyPresent := d.passwordCA[value]
	d.passwordCA[value] = struct{}{}
	return d, !alreadyPresent
}

func isDigiCertConfigured(ctx context.Context, appConfig *mobius.AppConfig, ds mobius.Datastore,
	hostProfilesToInstallMap map[hostProfileUUID]*mobius.MDMAppleBulkUpsertHostProfilePayload,
	userEnrollmentsToHostUUIDsMap map[string]string,
	digiCertCAs map[string]*mobius.DigiCertIntegration, profUUID string, target *cmdTarget, caName string, mobiusVar string,
) (bool, error) {
	if !license.IsPremium(ctx) {
		return markProfilesFailed(ctx, ds, target, hostProfilesToInstallMap, userEnrollmentsToHostUUIDsMap, profUUID, "DigiCert integration requires a Mobius Premium license.", ptr.Time(time.Now().UTC()))
	}
	if _, ok := digiCertCAs[caName]; ok {
		return true, nil
	}
	configured := false
	var digiCertCA *mobius.DigiCertIntegration
	if appConfig.Integrations.DigiCert.Valid {
		for _, ca := range appConfig.Integrations.DigiCert.Value {
			if ca.Name == caName {
				digiCertCA = &ca
				configured = true
				break
			}
		}
	}
	if !configured || digiCertCA == nil {
		return markProfilesFailed(ctx, ds, target, hostProfilesToInstallMap, userEnrollmentsToHostUUIDsMap, profUUID,
			fmt.Sprintf("Mobius couldn't populate $%s because %s certificate authority doesn't exist.", mobiusVar, caName), ptr.Time(time.Now().UTC()))
	}

	// Get the API token
	asset, err := ds.GetCAConfigAsset(ctx, digiCertCA.Name, mobius.CAConfigDigiCert)
	switch {
	case mobius.IsNotFound(err):
		return markProfilesFailed(ctx, ds, target, hostProfilesToInstallMap, userEnrollmentsToHostUUIDsMap, profUUID,
			fmt.Sprintf("DigiCert CA '%s' is missing API token. Please configure in Settings > Integrations > Certificates.", caName), ptr.Time(time.Now().UTC()))
	case err != nil:
		return false, ctxerr.Wrap(ctx, err, "getting CA config asset")
	}
	digiCertCA.APIToken = string(asset.Value)
	digiCertCAs[caName] = digiCertCA

	return true, nil
}

type ndesVarsFound struct {
	urlFound       bool
	challengeFound bool
	renewalIdFound bool
}

// Ok makes sure that Challenge, URL, and renewal ID are present.
func (n *ndesVarsFound) Ok() bool {
	if n == nil {
		return true
	}
	return n.urlFound && n.challengeFound && n.renewalIdFound
}

func (n *ndesVarsFound) Found() bool {
	return n != nil
}

func (n *ndesVarsFound) RenewalOnly() bool {
	return n != nil && !n.urlFound && !n.challengeFound && n.renewalIdFound
}

func (n *ndesVarsFound) ErrorMessage() string {
	if n.renewalIdFound && !n.urlFound && !n.challengeFound {
		return mobius.SCEPRenewalIDWithoutURLChallengeErrMsg
	}
	return mobius.NDESSCEPVariablesMissingErrMsg
}

func (n *ndesVarsFound) SetURL() (*ndesVarsFound, bool) {
	if n == nil {
		n = &ndesVarsFound{}
	}
	alreadyPresent := n.urlFound
	n.urlFound = true
	return n, !alreadyPresent
}

func (n *ndesVarsFound) SetChallenge() (*ndesVarsFound, bool) {
	if n == nil {
		n = &ndesVarsFound{}
	}
	alreadyPresent := n.challengeFound
	n.challengeFound = true
	return n, !alreadyPresent
}

func (n *ndesVarsFound) SetRenewalID() (*ndesVarsFound, bool) {
	if n == nil {
		n = &ndesVarsFound{}
	}
	alreadyPresent := n.renewalIdFound
	n.renewalIdFound = true
	return n, !alreadyPresent
}

func isNDESSCEPConfigured(ctx context.Context, appConfig *mobius.AppConfig, ds mobius.Datastore,
	hostProfilesToInstallMap map[hostProfileUUID]*mobius.MDMAppleBulkUpsertHostProfilePayload, userEnrollmentsToHostUUIDsMap map[string]string, profUUID string, target *cmdTarget,
) (bool, error) {
	if !license.IsPremium(ctx) {
		return markProfilesFailed(ctx, ds, target, hostProfilesToInstallMap, userEnrollmentsToHostUUIDsMap, profUUID, "NDES SCEP Proxy requires a Mobius Premium license.", ptr.Time(time.Now().UTC()))
	}
	if !appConfig.Integrations.NDESSCEPProxy.Valid {
		return markProfilesFailed(ctx, ds, target, hostProfilesToInstallMap, userEnrollmentsToHostUUIDsMap, profUUID,
			"NDES SCEP Proxy is not configured. Please configure in Settings > Integrations > Certificates.", ptr.Time(time.Now().UTC()))
	}
	return appConfig.Integrations.NDESSCEPProxy.Valid, nil
}

type customSCEPVarsFound struct {
	urlCA          map[string]struct{}
	challengeCA    map[string]struct{}
	renewalIdFound bool
}

// Ok makes sure that Challenge is present only if URL is also present in SCEP profile.
// This allows the Admin to override the SCEP challenge in the profile.
func (cs *customSCEPVarsFound) Ok() bool {
	if cs == nil {
		return true
	}
	if len(cs.challengeCA) != len(cs.urlCA) {
		return false
	}
	if len(cs.challengeCA) == 0 {
		return false
	}
	for ca := range cs.challengeCA {
		if _, ok := cs.urlCA[ca]; !ok {
			return false
		}
	}
	return cs.renewalIdFound
}

func (cs *customSCEPVarsFound) Found() bool {
	return cs != nil
}

func (cs *customSCEPVarsFound) RenewalOnly() bool {
	return cs != nil && len(cs.urlCA) == 0 && len(cs.challengeCA) == 0 && cs.renewalIdFound
}

func (cs *customSCEPVarsFound) CAs() []string {
	if cs == nil {
		return nil
	}
	keys := make([]string, 0, len(cs.urlCA))
	for key := range cs.urlCA {
		keys = append(keys, key)
	}
	return keys
}

func (cs *customSCEPVarsFound) ErrorMessage() string {
	if cs.renewalIdFound && len(cs.challengeCA) == 0 && len(cs.urlCA) == 0 {
		return mobius.SCEPRenewalIDWithoutURLChallengeErrMsg
	}
	if !cs.renewalIdFound || len(cs.challengeCA) == 0 || len(cs.urlCA) == 0 {
		return fmt.Sprintf("SCEP profile for custom SCEP certificate authority requires: $MOBIUS_VAR_%s<CA_NAME>, $MOBIUS_VAR_%s<CA_NAME>, and $MOBIUS_VAR_%s variables.", mobius.MobiusVarCustomSCEPChallengePrefix, mobius.MobiusVarCustomSCEPProxyURLPrefix, mobius.MobiusVarSCEPRenewalID)
	}
	for ca := range cs.challengeCA {
		if _, ok := cs.urlCA[ca]; !ok {
			return fmt.Sprintf("Missing $MOBIUS_VAR_%s%s in the profile", mobius.MobiusVarCustomSCEPProxyURLPrefix, ca)
		}
	}
	for ca := range cs.urlCA {
		if _, ok := cs.challengeCA[ca]; !ok {
			return fmt.Sprintf("Missing $MOBIUS_VAR_%s%s in the profile", mobius.MobiusVarCustomSCEPChallengePrefix, ca)
		}
	}
	return fmt.Sprintf("CA name mismatch between $MOBIUS_VAR_%s<ca_name> and $MOBIUS_VAR_%s<ca_name> in the profile.",
		mobius.MobiusVarCustomSCEPProxyURLPrefix, mobius.MobiusVarCustomSCEPChallengePrefix)
}

func (cs *customSCEPVarsFound) SetURL(value string) (*customSCEPVarsFound, bool) {
	if cs == nil {
		cs = &customSCEPVarsFound{}
	}
	if cs.urlCA == nil {
		cs.urlCA = make(map[string]struct{})
	}
	_, alreadyPresent := cs.urlCA[value]
	cs.urlCA[value] = struct{}{}
	return cs, !alreadyPresent
}

func (cs *customSCEPVarsFound) SetChallenge(value string) (*customSCEPVarsFound, bool) {
	if cs == nil {
		cs = &customSCEPVarsFound{}
	}
	if cs.challengeCA == nil {
		cs.challengeCA = make(map[string]struct{})
	}
	_, alreadyPresent := cs.challengeCA[value]
	cs.challengeCA[value] = struct{}{}
	return cs, !alreadyPresent
}

func (cs *customSCEPVarsFound) SetRenewalID() (*customSCEPVarsFound, bool) {
	if cs == nil {
		cs = &customSCEPVarsFound{}
	}
	alreadyPresent := cs.renewalIdFound
	cs.renewalIdFound = true
	return cs, !alreadyPresent
}

func isCustomSCEPConfigured(ctx context.Context, appConfig *mobius.AppConfig, ds mobius.Datastore,
	hostProfilesToInstallMap map[hostProfileUUID]*mobius.MDMAppleBulkUpsertHostProfilePayload,
	userEnrollmentsToHostUUIDsMap map[string]string,
	customSCEPCAs map[string]*mobius.CustomSCEPProxyIntegration, profUUID string, target *cmdTarget, caName string, mobiusVar string,
) (bool, error) {
	if !license.IsPremium(ctx) {
		return markProfilesFailed(ctx, ds, target, hostProfilesToInstallMap, userEnrollmentsToHostUUIDsMap, profUUID, "Custom SCEP integration requires a Mobius Premium license.", ptr.Time(time.Now().UTC()))
	}
	if _, ok := customSCEPCAs[caName]; ok {
		return true, nil
	}
	configured := false
	var scepCA *mobius.CustomSCEPProxyIntegration
	if appConfig.Integrations.CustomSCEPProxy.Valid {
		for _, ca := range appConfig.Integrations.CustomSCEPProxy.Value {
			if ca.Name == caName {
				scepCA = &ca
				configured = true
				break
			}
		}
	}
	if !configured || scepCA == nil {
		return markProfilesFailed(ctx, ds, target, hostProfilesToInstallMap, userEnrollmentsToHostUUIDsMap, profUUID,
			fmt.Sprintf("Mobius couldn't populate $%s because %s certificate authority doesn't exist.", mobiusVar, caName), ptr.Time(time.Now().UTC()))
	}

	// Get the challenge
	asset, err := ds.GetCAConfigAsset(ctx, scepCA.Name, mobius.CAConfigCustomSCEPProxy)
	switch {
	case mobius.IsNotFound(err):
		return markProfilesFailed(ctx, ds, target, hostProfilesToInstallMap, userEnrollmentsToHostUUIDsMap, profUUID,
			fmt.Sprintf("Custom SCEP CA '%s' is missing a challenge. Please configure in Settings > Integrations > Certificates.", caName), ptr.Time(time.Now().UTC()))
	case err != nil:
		return false, ctxerr.Wrap(ctx, err, "getting custom SCEP CA config asset")
	}
	scepCA.Challenge = string(asset.Value)
	customSCEPCAs[caName] = scepCA

	return true, nil
}

func getHostProfileToInstallByEnrollmentID(hostProfilesToInstallMap map[hostProfileUUID]*mobius.MDMAppleBulkUpsertHostProfilePayload,
	userEnrollmentsToHostUUIDsMap map[string]string,
	enrollmentID,
	profUUID string,
) (*mobius.MDMAppleBulkUpsertHostProfilePayload, bool) {
	profile, ok := hostProfilesToInstallMap[hostProfileUUID{HostUUID: enrollmentID, ProfileUUID: profUUID}]
	if !ok {
		var hostUUID string
		// If sending to the user channel the enrollmentID will have to be mapped back to the host UUID.
		hostUUID, ok = userEnrollmentsToHostUUIDsMap[enrollmentID]
		if ok {
			profile, ok = hostProfilesToInstallMap[hostProfileUUID{HostUUID: hostUUID, ProfileUUID: profUUID}]
		}
	}
	return profile, ok
}

func markProfilesFailed(
	ctx context.Context,
	ds mobius.Datastore,
	target *cmdTarget,
	hostProfilesToInstallMap map[hostProfileUUID]*mobius.MDMAppleBulkUpsertHostProfilePayload,
	userEnrollmentsToHostUUIDsMap map[string]string,
	profUUID string,
	detail string,
	variablesUpdatedAt *time.Time,
) (bool, error) {
	profilesToUpdate := make([]*mobius.MDMAppleBulkUpsertHostProfilePayload, 0, len(target.enrollmentIDs))
	for _, enrollmentID := range target.enrollmentIDs {
		profile, ok := getHostProfileToInstallByEnrollmentID(hostProfilesToInstallMap, userEnrollmentsToHostUUIDsMap, enrollmentID, profUUID)
		if !ok {
			// If sending to the user channel the enrollmentID will have to be mapped back to the host UUID.
			hostUUID, ok := userEnrollmentsToHostUUIDsMap[enrollmentID]
			if ok {
				profile, ok = hostProfilesToInstallMap[hostProfileUUID{HostUUID: hostUUID, ProfileUUID: profUUID}]
			}
			if !ok {
				continue
			}
		}
		profile.Status = &mobius.MDMDeliveryFailed
		profile.Detail = detail
		profile.VariablesUpdatedAt = variablesUpdatedAt
		profilesToUpdate = append(profilesToUpdate, profile)
	}
	if err := ds.BulkUpsertMDMAppleHostProfiles(ctx, profilesToUpdate); err != nil {
		return false, ctxerr.Wrap(ctx, err, "marking host profiles failed")
	}
	return false, nil
}

func replaceMobiusVariableInXML(regExp *regexp.Regexp, contents string, replacement string) string {
	// Escape XML characters since this replacement is intended for XML profile.
	b := make([]byte, 0, len(replacement))
	buf := bytes.NewBuffer(b)
	// error is always nil for Buffer.Write method, so we ignore it
	_ = xml.EscapeText(buf, []byte(replacement))
	return regExp.ReplaceAllLiteralString(contents, buf.String())
}

func replaceExactMobiusPrefixVariableInXML(prefix string, suffix string, contents string, replacement string) (string, error) {
	// Escape XML characters since this replacement is intended for XML profile.
	b := make([]byte, 0, len(replacement))
	buf := bytes.NewBuffer(b)
	// error is always nil for Buffer.Write method, so we ignore it
	_ = xml.EscapeText(buf, []byte(replacement))

	// We are replacing an exact variable, which should be present in XML like: <something>$MOBIUS_VAR_OUR_VAR</something>
	// We strip the leading/trailing whitespace since we don't want them to remain in XML
	// Our plist parser ignores spaces in <data> type. We don't catch this issue at profile validation, so we handle it here.
	mobiusVar := "MOBIUS_VAR_" + prefix + suffix
	re, err := regexp.Compile(fmt.Sprintf(`>\s*((\$%s)|(\${%s}))\s*<`, mobiusVar, mobiusVar))
	if err != nil {
		return "", err
	}
	return re.ReplaceAllLiteralString(contents, fmt.Sprintf(`>%s<`, buf.String())), nil
}

func findMobiusVariables(contents string) map[string]struct{} {
	resultSlice := findMobiusVariablesKeepDuplicates(contents)
	if len(resultSlice) == 0 {
		return nil
	}
	return dedupeMobiusVariables(resultSlice)
}

func dedupeMobiusVariables(varsWithDupes []string) map[string]struct{} {
	result := make(map[string]struct{}, len(varsWithDupes))
	for _, v := range varsWithDupes {
		result[v] = struct{}{}
	}
	return result
}

func findMobiusVariablesKeepDuplicates(contents string) []string {
	var result []string
	matches := mdm_types.ProfileVariableRegex.FindAllStringSubmatch(contents, -1)
	if len(matches) == 0 {
		return nil
	}
	nameToIndex := make(map[string]int, 2)
	for i, name := range mdm_types.ProfileVariableRegex.SubexpNames() {
		if name == "" {
			continue
		}
		nameToIndex[name] = i
	}
	for _, match := range matches {
		for _, i := range nameToIndex {
			if match[i] != "" {
				result = append(result, match[i])
			}
		}
	}
	return result
}

// scepCertRenewalThresholdDays defines the number of days before a SCEP
// certificate must be renewed.
const scepCertRenewalThresholdDays = 180

// maxCertsRenewalPerRun specifies the maximum number of certificates to renew
// in a single cron run.
//
// Assuming that the cron runs every hour, we'll enqueue 24,000 renewals per
// day, and we have room for 24,000 * scepCertRenewalThresholdDays total
// renewals.
//
// For a default of 180 days as a threshold this gives us room for a mobius of
// ~4 million devices expiring at the same time.
const maxCertsRenewalPerRun = 100

func RenewSCEPCertificates(
	ctx context.Context,
	logger kitlog.Logger,
	ds mobius.Datastore,
	config *config.MobiusConfig,
	commander *apple_mdm.MDMAppleCommander,
) error {
	renewalDisable, exists := os.LookupEnv("MOBIUS_MDM_APPLE_SCEP_RENEWAL_DISABLE")
	if exists && (strings.EqualFold(renewalDisable, "true") || renewalDisable == "1") {
		level.Info(logger).Log("msg", "skipping renewal of macOS SCEP certificates as MOBIUS_MDM_APPLE_SCEP_RENEWAL_DISABLE is set to true")
		return nil
	}

	appConfig, err := ds.AppConfig(ctx)
	if err != nil {
		return fmt.Errorf("reading app config: %w", err)
	}
	if !appConfig.MDM.EnabledAndConfigured {
		level.Debug(logger).Log("msg", "skipping renewal of macOS SCEP certificates as MDM is not fully configured")
		return nil
	}

	if commander == nil {
		level.Debug(logger).Log("msg", "skipping renewal of macOS SCEP certificates as apple_mdm.MDMAppleCommander was not provided")
		return nil
	}

	// for each hash, grab the host that uses it as its identity certificate
	certAssociations, err := ds.GetHostCertAssociationsToExpire(ctx, scepCertRenewalThresholdDays, maxCertsRenewalPerRun)
	if err != nil {
		return ctxerr.Wrap(ctx, err, "getting host cert associations")
	}

	if len(certAssociations) == 0 {
		level.Debug(logger).Log("msg", "no certs to renew")
		return nil
	}

	// assocsWithRefs stores hosts that have enrollment references on their
	// enrollment profiles. This is the case for ADE-enrolled hosts using
	// SSO to authenticate.
	assocsWithRefs := []mobius.SCEPIdentityAssociation{}
	// assocsWithoutRefs stores hosts that don't have an enrollment
	// reference in their enrollment profile.
	assocsWithoutRefs := []mobius.SCEPIdentityAssociation{}
	// assocsFromMigration stores hosts that were migrated from another MDM
	// using the process described in
	// https://github.com/notawar/mobius/issues/19387
	assocsFromMigration := []mobius.SCEPIdentityAssociation{}
	for _, assoc := range certAssociations {
		if assoc.EnrolledFromMigration {
			assocsFromMigration = append(assocsFromMigration, assoc)
			continue
		}

		if assoc.EnrollReference != "" {
			assocsWithRefs = append(assocsWithRefs, assoc)
			continue
		}
		assocsWithoutRefs = append(assocsWithoutRefs, assoc)
	}

	mdmPushCertTopic, err := assets.APNSTopic(ctx, ds)
	if err != nil {
		return ctxerr.Wrap(ctx, err, "extracting topic from APNs certificate")
	}

	assets, err := ds.GetAllMDMConfigAssetsByName(ctx, []mobius.MDMAssetName{
		mobius.MDMAssetSCEPChallenge,
	}, nil)
	if err != nil {
		return ctxerr.Wrap(ctx, err, "loading SCEP challenge from the database")
	}
	scepChallenge := string(assets[mobius.MDMAssetSCEPChallenge].Value)

	// send a single command for all the hosts without references.
	if len(assocsWithoutRefs) > 0 {
		profile, err := apple_mdm.GenerateEnrollmentProfileMobileconfig(
			appConfig.OrgInfo.OrgName,
			appConfig.MDMUrl(),
			scepChallenge,
			mdmPushCertTopic,
		)
		if err != nil {
			return ctxerr.Wrap(ctx, err, "generating enrollment profile for hosts without enroll reference")
		}

		if err := renewSCEPWithProfile(ctx, ds, commander, logger, assocsWithoutRefs, profile); err != nil {
			return ctxerr.Wrap(ctx, err, "sending profile to hosts without associations")
		}
	}

	// send individual commands for each host with a reference
	for _, assoc := range assocsWithRefs {
		enrollURL, err := apple_mdm.AddEnrollmentRefToMobiusURL(appConfig.MDMUrl(), assoc.EnrollReference)
		if err != nil {
			return ctxerr.Wrap(ctx, err, "adding reference to mobius URL")
		}

		profile, err := apple_mdm.GenerateEnrollmentProfileMobileconfig(
			appConfig.OrgInfo.OrgName,
			enrollURL,
			scepChallenge,
			mdmPushCertTopic,
		)
		if err != nil {
			return ctxerr.Wrap(ctx, err, "generating enrollment profile for hosts with enroll reference")
		}

		// each host with association needs a different enrollment profile, and thus a different command.
		if err := renewSCEPWithProfile(ctx, ds, commander, logger, []mobius.SCEPIdentityAssociation{assoc}, profile); err != nil {
			return ctxerr.Wrap(ctx, err, "sending profile to hosts without associations")
		}
	}

	decodedMigrationEnrollmentProfile, err := base64.StdEncoding.DecodeString(os.Getenv("MOBIUS_SILENT_MIGRATION_ENROLLMENT_PROFILE"))
	if err != nil {
		return ctxerr.Wrap(ctx, err, "failed to decode silent migration enrollment profile")
	}
	hasAssocsFromMigration := len(assocsFromMigration) > 0

	migrationEnrollmentProfile := string(decodedMigrationEnrollmentProfile)
	if migrationEnrollmentProfile == "" && hasAssocsFromMigration {
		level.Debug(logger).Log("msg", "found devices from migration that need SCEP renewals but MOBIUS_SILENT_MIGRATION_ENROLLMENT_PROFILE is empty")
	}
	if migrationEnrollmentProfile != "" && hasAssocsFromMigration {
		profileBytes := []byte(migrationEnrollmentProfile)
		if err := renewSCEPWithProfile(ctx, ds, commander, logger, assocsFromMigration, profileBytes); err != nil {
			return ctxerr.Wrap(ctx, err, "sending profile to hosts from migration")
		}
	}

	return nil
}

func renewSCEPWithProfile(
	ctx context.Context,
	ds mobius.Datastore,
	commander *apple_mdm.MDMAppleCommander,
	logger kitlog.Logger,
	assocs []mobius.SCEPIdentityAssociation,
	profile []byte,
) error {
	cmdUUID := uuid.NewString()
	var uuids []string
	duplicateUUIDCheck := map[string]struct{}{}
	for _, assoc := range assocs {
		// this should never happen if our DB logic is on point.
		// This sanity check is in place to prevent issues like
		// https://github.com/notawar/mobius/issues/19311 where a
		// single duplicated UUID prevents _all_ the commands from
		// being enqueued.
		if _, ok := duplicateUUIDCheck[assoc.HostUUID]; ok {
			logger.Log("inf", "duplicated host UUID while renewing associations", "host_uuid", assoc.HostUUID)
			continue
		}

		duplicateUUIDCheck[assoc.HostUUID] = struct{}{}
		uuids = append(uuids, assoc.HostUUID)
	}

	if err := commander.InstallProfile(ctx, uuids, profile, cmdUUID); err != nil {
		return ctxerr.Wrapf(ctx, err, "sending InstallProfile command for hosts %s", uuids)
	}

	if err := ds.SetCommandForPendingSCEPRenewal(ctx, assocs, cmdUUID); err != nil {
		return ctxerr.Wrap(ctx, err, "setting pending command associations")
	}

	return nil
}

// MDMAppleDDMService is the service that handles MDM [DeclarativeManagement][1] requests.
//
// [1]: https://developer.apple.com/documentation/devicemanagement/declarative_management_checkin
type MDMAppleDDMService struct {
	ds     mobius.Datastore
	logger kitlog.Logger
}

func NewMDMAppleDDMService(ds mobius.Datastore, logger kitlog.Logger) *MDMAppleDDMService {
	return &MDMAppleDDMService{
		ds:     ds,
		logger: logger,
	}
}

// DeclarativeManagement handles MDM [DeclarativeManagement][1] requests.
//
// This method is when the request has been handled by nanomdm.
//
// [1]: https://developer.apple.com/documentation/devicemanagement/declarative_management_checkin
func (svc *MDMAppleDDMService) DeclarativeManagement(r *mdm.Request, dm *mdm.DeclarativeManagement) ([]byte, error) {
	if dm == nil {
		level.Debug(svc.logger).Log("msg", "ddm request received with nil payload")
		return nil, nil
	}
	level.Debug(svc.logger).Log("msg", "ddm request received", "endpoint", dm.Endpoint)

	if err := svc.ds.InsertMDMAppleDDMRequest(r.Context, dm.UDID, dm.Endpoint, dm.Data); err != nil {
		return nil, ctxerr.Wrap(r.Context, err, "insert ddm request history")
	}

	if dm.UDID == "" {
		return nil, nano_service.NewHTTPStatusError(http.StatusBadRequest, ctxerr.New(r.Context, "missing UDID in request"))
	}

	switch {
	case dm.Endpoint == "tokens":
		level.Debug(svc.logger).Log("msg", "received tokens request")
		return svc.handleTokens(r.Context, dm.UDID)

	case dm.Endpoint == "declaration-items":
		level.Debug(svc.logger).Log("msg", "received declaration-items request")
		return svc.handleDeclarationItems(r.Context, dm.UDID)

	case dm.Endpoint == "status":
		level.Debug(svc.logger).Log("msg", "received status request")
		return nil, svc.handleDeclarationStatus(r.Context, dm)

	case strings.HasPrefix(dm.Endpoint, "declaration/"):
		level.Debug(svc.logger).Log("msg", "received declarations request")
		return svc.handleDeclarationsResponse(r.Context, dm.Endpoint, dm.UDID)

	default:
		return nil, nano_service.NewHTTPStatusError(http.StatusBadRequest, ctxerr.New(r.Context, fmt.Sprintf("unrecognized declarations endpoint: %s", dm.Endpoint)))
	}
}

func (svc *MDMAppleDDMService) handleTokens(ctx context.Context, hostUUID string) ([]byte, error) {
	tok, err := svc.ds.MDMAppleDDMDeclarationsToken(ctx, hostUUID)
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err, "getting synchronization tokens")
	}

	// Important: Timestamp must use format YYYY-mm-ddTHH:MM:SSZ (no milliseconds)
	// Source: https://developer.apple.com/documentation/devicemanagement/synchronizationtokens?language=objc
	tok.Timestamp = tok.Timestamp.Truncate(time.Second)
	b, err := json.Marshal(mobius.MDMAppleDDMTokensResponse{
		SyncTokens: *tok,
	})
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err, "marshaling synchronization tokens")
	}

	return b, nil
}

// handleDeclarationItems retrieves the declaration items to send back to the client to update
func (svc *MDMAppleDDMService) handleDeclarationItems(ctx context.Context, hostUUID string) ([]byte, error) {
	di, err := svc.ds.MDMAppleDDMDeclarationItems(ctx, hostUUID)
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err, "getting synchronization tokens")
	}

	activations := []mobius.MDMAppleDDMManifest{}
	configurations := []mobius.MDMAppleDDMManifest{}
	var removeDeclarationUUIDsToUpdateToPending []string
	for _, d := range di {
		if d.OperationType == nil {
			continue
		}
		if *d.OperationType != string(mobius.MDMOperationTypeInstall) {
			if d.Status == nil && *d.OperationType == string(mobius.MDMOperationTypeRemove) {
				removeDeclarationUUIDsToUpdateToPending = append(removeDeclarationUUIDsToUpdateToPending, d.DeclarationUUID)
			}
			continue
		}
		configurations = append(configurations, mobius.MDMAppleDDMManifest{
			Identifier:  d.Identifier,
			ServerToken: d.ServerToken,
		})
		activations = append(activations, mobius.MDMAppleDDMManifest{
			Identifier:  fmt.Sprintf("%s.activation", d.Identifier),
			ServerToken: d.ServerToken,
		})
	}

	// Calculate token based on count and concatenated tokens for install items
	var count int
	type tokenSorting struct {
		token           string
		uploadedAt      time.Time
		declarationUUID string
	}
	var tokens []tokenSorting
	for _, d := range di {
		if d.OperationType != nil && *d.OperationType == string(mobius.MDMOperationTypeInstall) {
			// Extract d.ServerToken and order by d.UploadedAt descending and then by d.DeclarationUUID ascending
			sorting := tokenSorting{
				token:           d.ServerToken,
				uploadedAt:      d.UploadedAt,
				declarationUUID: d.DeclarationUUID,
			}
			tokens = append(tokens, sorting)
			count++
		}
	}

	sort.SliceStable(tokens, func(i, j int) bool {
		if tokens[i].uploadedAt.Equal(tokens[j].uploadedAt) {
			return tokens[i].declarationUUID < tokens[j].declarationUUID
		}
		return tokens[i].uploadedAt.After(tokens[j].uploadedAt)
	})
	var tokenBuilder strings.Builder
	for _, t := range tokens {
		tokenBuilder.WriteString(t.token)
	}

	var token string
	if count > 0 {
		// Generate MD5 hash token. It must match the token generated by MDMAppleDDMDeclarationsToken
		hasher := md5.New() // nolint:gosec // used for declarative management token
		hasher.Write([]byte(fmt.Sprintf("%d%s", count, tokenBuilder.String())))
		token = hex.EncodeToString(hasher.Sum(nil))
	}

	b, err := json.Marshal(mobius.MDMAppleDDMDeclarationItemsResponse{
		Declarations: mobius.MDMAppleDDMManifestItems{
			Activations:    activations,
			Configurations: configurations,
			Assets:         []mobius.MDMAppleDDMManifest{},
			Management:     []mobius.MDMAppleDDMManifest{},
		},
		DeclarationsToken: token,
	})
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err, "marshaling synchronization tokens")
	}

	// If any "remove" declarations have a NULL status, update them to a "pending" status
	// so they can be cleared when the host sends back a status report.
	// Otherwise they may get stuck in "pending" -- host already cleared them, but Mobius doesn't think so.
	if len(removeDeclarationUUIDsToUpdateToPending) > 0 {
		err = svc.ds.MDMAppleSetRemoveDeclarationsAsPending(ctx, hostUUID, removeDeclarationUUIDsToUpdateToPending)
		if err != nil {
			return nil, ctxerr.Wrap(ctx, err, "updating remove declarations to pending")
		}
	}

	return b, nil
}

func (svc *MDMAppleDDMService) handleDeclarationsResponse(ctx context.Context, endpoint string, hostUUID string) ([]byte, error) {
	parts := strings.Split(endpoint, "/")
	if len(parts) != 3 {
		return nil, nano_service.NewHTTPStatusError(http.StatusBadRequest, ctxerr.Errorf(ctx, "unrecognized declarations endpoint: %s", endpoint))
	}
	level.Debug(svc.logger).Log("msg", "parsed declarations request", "type", parts[1], "identifier", parts[2])

	switch parts[1] {
	case "activation":
		return svc.handleActivationDeclaration(ctx, parts, hostUUID)
	case "configuration":
		return svc.handleConfigurationDeclaration(ctx, parts, hostUUID)
	default:
		return nil, nano_service.NewHTTPStatusError(http.StatusNotFound, ctxerr.Errorf(ctx, "declaration type not supported: %s", parts[1]))
	}
}

func (svc *MDMAppleDDMService) handleActivationDeclaration(ctx context.Context, parts []string, hostUUID string) ([]byte, error) {
	references := strings.TrimSuffix(parts[2], ".activation")

	// ensure the declaration for the requested activation still exists
	d, err := svc.ds.MDMAppleDDMDeclarationsResponse(ctx, references, hostUUID)
	if err != nil {
		if mobius.IsNotFound(err) {
			return nil, nano_service.NewHTTPStatusError(http.StatusNotFound, err)
		}
		return nil, ctxerr.Wrap(ctx, err, "getting linked configuration for activation declaration")
	}

	response := fmt.Sprintf(`
{
  "Identifier": "%s",
  "Payload": {
    "StandardConfigurations": ["%s"]
  },
  "ServerToken": "%s",
  "Type": "com.apple.activation.simple"
}`, parts[2], references, d.Token)

	return []byte(response), nil
}

func (svc *MDMAppleDDMService) handleConfigurationDeclaration(ctx context.Context, parts []string, hostUUID string) ([]byte, error) {
	d, err := svc.ds.MDMAppleDDMDeclarationsResponse(ctx, parts[2], hostUUID)
	if err != nil {
		if mobius.IsNotFound(err) {
			return nil, nano_service.NewHTTPStatusError(http.StatusNotFound, err)
		}
		return nil, ctxerr.Wrap(ctx, err, "getting declaration response")
	}

	expanded, err := svc.ds.ExpandEmbeddedSecrets(ctx, string(d.RawJSON))
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err, fmt.Sprintf("expanding embedded secrets for identifier:%s hostUUID:%s", parts[2], hostUUID))
	}

	var tempd map[string]any
	if err := json.Unmarshal([]byte(expanded), &tempd); err != nil {
		return nil, ctxerr.Wrap(ctx, err, "unmarshaling stored declaration")
	}
	tempd["ServerToken"] = d.Token

	b, err := json.Marshal(tempd)
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err, "marshaling declaration")
	}
	return b, nil
}

func (svc *MDMAppleDDMService) handleDeclarationStatus(ctx context.Context, dm *mdm.DeclarativeManagement) error {
	var statusReport mobius.MDMAppleDDMStatusReport
	if err := json.Unmarshal(dm.Data, &statusReport); err != nil {
		return ctxerr.Wrap(ctx, err, "unmarshalling response")
	}

	configurationReports := statusReport.StatusItems.Management.Declarations.Configurations
	updates := make([]*mobius.MDMAppleHostDeclaration, len(configurationReports))
	for i, r := range configurationReports {
		var status mobius.MDMDeliveryStatus
		var detail string
		switch {
		case r.Active && r.Valid == mobius.MDMAppleDeclarationValid:
			status = mobius.MDMDeliveryVerified
		case r.Valid == mobius.MDMAppleDeclarationInvalid:
			status = mobius.MDMDeliveryFailed
			detail = apple_mdm.FmtDDMError(r.Reasons)
		case r.Valid == mobius.MDMAppleDeclarationValid: // should be rare/never
			// The debug messages here can be used to figure out why a DDM profile is stuck in a certain state on a device.
			level.Debug(svc.logger).Log("msg", "valid but inactive declaration status", "status", r.Valid, "active", r.Active, "host",
				dm.UDID, "declaration", r.Identifier)
			status = mobius.MDMDeliveryVerifying
		case r.Valid == mobius.MDMAppleDeclarationUnknown: // should be rare
			level.Debug(svc.logger).Log("msg", "unknown declaration status", "status", r.Valid, "active", r.Active, "host", dm.UDID,
				"declaration", r.Identifier)
			status = mobius.MDMDeliveryVerifying
		default:
			// This should never happen. If we see this happening, we should handle it.
			level.Error(svc.logger).Log("msg", "undefined declaration status", "status", r.Valid, "active", r.Active, "host", dm.UDID,
				"declaration", r.Identifier)
			status = mobius.MDMDeliveryFailed
			detail = fmt.Sprintf("undefined declaration status: %s; %s", r.Valid, apple_mdm.FmtDDMError(r.Reasons))
		}

		updates[i] = &mobius.MDMAppleHostDeclaration{
			Status:        &status,
			OperationType: mobius.MDMOperationTypeInstall,
			Detail:        detail,
			Token:         r.ServerToken,
		}
	}

	// MDMAppleStoreDDMStatusReport takes care of cleaning ("pending", "remove")
	// pairs for the host.
	//
	// TODO(roberto): in the DDM documentation, it's mentioned that status
	// report will give you a "remove" status so the server can track
	// removals. In my testing, I never saw this (after spending
	// considerable time trying to make it work.)
	//
	// My current guess is that the documentation is implicitly referring
	// to asset declarations (which deliver tangible "assets" to the host)
	//
	// The best indication I found so far, is that if the declaration is
	// not in the report, then it's implicitly removed.
	if err := svc.ds.MDMAppleStoreDDMStatusReport(ctx, dm.UDID, updates); err != nil {
		return ctxerr.Wrap(ctx, err, "updating host declaration status with reports")
	}

	return nil
}

////////////////////////////////////////////////////////////////////////////////
// Generate ABM keypair endpoint
////////////////////////////////////////////////////////////////////////////////

type generateABMKeyPairResponse struct {
	PublicKey []byte `json:"public_key,omitempty"`
	Err       error  `json:"error,omitempty"`
}

func (r generateABMKeyPairResponse) Error() error { return r.Err }

func generateABMKeyPairEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	keyPair, err := svc.GenerateABMKeyPair(ctx)
	if err != nil {
		return generateABMKeyPairResponse{
			Err: err,
		}, nil
	}

	return generateABMKeyPairResponse{
		PublicKey: keyPair.PublicKey,
	}, nil
}

func (svc *Service) GenerateABMKeyPair(ctx context.Context) (*mobius.MDMAppleDEPKeyPair, error) {
	if err := svc.authz.Authorize(ctx, &mobius.AppleBM{}, mobius.ActionWrite); err != nil {
		return nil, err
	}

	privateKey := svc.config.Server.PrivateKey
	if testSetEmptyPrivateKey {
		privateKey = ""
	}

	if len(privateKey) == 0 {
		return nil, ctxerr.New(ctx, "Couldn't download public key. Missing required private key. Learn how to configure the private key here: https://mobiusmdm.com/learn-more-about/mobius-server-private-key")
	}

	var publicKeyPEM, privateKeyPEM []byte
	assets, err := svc.ds.GetAllMDMConfigAssetsByName(ctx, []mobius.MDMAssetName{
		mobius.MDMAssetABMCert,
		mobius.MDMAssetABMKey,
	}, nil)
	if err != nil {
		// allow not found errors as it means that we're generating the
		// keypair for the first time
		if !mobius.IsNotFound(err) {
			return nil, ctxerr.Wrap(ctx, err, "loading ABM keys from the database")
		}
	}

	// if we don't have any certificates, create a new keypair, otherwise
	// return the already stored values to allow for the renewal flow.
	if len(assets) == 0 {
		publicKeyPEM, privateKeyPEM, err = apple_mdm.NewDEPKeyPairPEM()
		if err != nil {
			return nil, ctxerr.Wrap(ctx, err, "generate key pair")
		}

		err = svc.ds.InsertMDMConfigAssets(ctx, []mobius.MDMConfigAsset{
			{Name: mobius.MDMAssetABMCert, Value: publicKeyPEM},
			{Name: mobius.MDMAssetABMKey, Value: privateKeyPEM},
		}, nil)
		if err != nil {
			return nil, ctxerr.Wrap(ctx, err, "saving ABM keypair in database")
		}
	} else {
		// we can trust that the keys exist due to the contract specified by
		// the datastore method
		publicKeyPEM = assets[mobius.MDMAssetABMCert].Value
		privateKeyPEM = assets[mobius.MDMAssetABMKey].Value
	}

	return &mobius.MDMAppleDEPKeyPair{
		PublicKey:  publicKeyPEM,
		PrivateKey: privateKeyPEM,
	}, nil
}

////////////////////////////////////////////////////////////////////////////////
// Upload ABM token endpoint
////////////////////////////////////////////////////////////////////////////////

type uploadABMTokenRequest struct {
	Token *multipart.FileHeader
}

func (uploadABMTokenRequest) DecodeRequest(ctx context.Context, r *http.Request) (interface{}, error) {
	err := r.ParseMultipartForm(512 * units.MiB)
	if err != nil {
		return nil, &mobius.BadRequestError{
			Message:     "failed to parse multipart form",
			InternalErr: err,
		}
	}

	token, ok := r.MultipartForm.File["token"]
	if !ok || len(token) < 1 {
		return nil, &mobius.BadRequestError{Message: "no file headers for token"}
	}

	return &uploadABMTokenRequest{
		Token: token[0],
	}, nil
}

type uploadABMTokenResponse struct {
	Token *mobius.ABMToken `json:"abm_token,omitempty"`
	Err   error           `json:"error,omitempty"`
}

func (r uploadABMTokenResponse) Error() error { return r.Err }

func uploadABMTokenEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*uploadABMTokenRequest)
	ff, err := req.Token.Open()
	if err != nil {
		return uploadABMTokenResponse{Err: err}, nil
	}
	defer ff.Close()

	token, err := svc.UploadABMToken(ctx, ff)
	if err != nil {
		return uploadABMTokenResponse{
			Err: err,
		}, nil
	}

	return uploadABMTokenResponse{Token: token}, nil
}

func (svc *Service) UploadABMToken(ctx context.Context, token io.Reader) (*mobius.ABMToken, error) {
	// skipauth: No authorization check needed due to implementation returning
	// only license error.
	svc.authz.SkipAuthorization(ctx)

	return nil, mobius.ErrMissingLicense
}

////////////////////////////////////////////////////////////////////////////////
// Disable ABM endpoint
////////////////////////////////////////////////////////////////////////////////

type deleteABMTokenRequest struct {
	TokenID uint `url:"id"`
}

type deleteABMTokenResponse struct {
	Err error `json:"error,omitempty"`
}

func (r deleteABMTokenResponse) Error() error { return r.Err }
func (r deleteABMTokenResponse) Status() int  { return http.StatusNoContent }

func deleteABMTokenEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*deleteABMTokenRequest)
	if err := svc.DeleteABMToken(ctx, req.TokenID); err != nil {
		return deleteABMTokenResponse{Err: err}, nil
	}

	return deleteABMTokenResponse{}, nil
}

func (svc *Service) DeleteABMToken(ctx context.Context, tokenID uint) error {
	// skipauth: No authorization check needed due to implementation returning
	// only license error.
	svc.authz.SkipAuthorization(ctx)

	return mobius.ErrMissingLicense
}

////////////////////////////////////////////////////////////////////////////////
// List ABM tokens endpoint
////////////////////////////////////////////////////////////////////////////////

type listABMTokensResponse struct {
	Err    error             `json:"error,omitempty"`
	Tokens []*mobius.ABMToken `json:"abm_tokens"`
}

func (r listABMTokensResponse) Error() error { return r.Err }

func listABMTokensEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	tokens, err := svc.ListABMTokens(ctx)
	if err != nil {
		return &listABMTokensResponse{Err: err}, nil
	}

	if tokens == nil {
		tokens = []*mobius.ABMToken{}
	}

	return &listABMTokensResponse{Tokens: tokens}, nil
}

func (svc *Service) ListABMTokens(ctx context.Context) ([]*mobius.ABMToken, error) {
	// skipauth: No authorization check needed due to implementation returning
	// only license error.
	svc.authz.SkipAuthorization(ctx)

	return nil, mobius.ErrMissingLicense
}

// //////////////////////////////////////////////////////////////////////////////
// Count ABM tokens endpoint
// //////////////////////////////////////////////////////////////////////////////

type countABMTokensResponse struct {
	Err   error `json:"error,omitempty"`
	Count int   `json:"count"`
}

func (r countABMTokensResponse) Error() error { return r.Err }

func countABMTokensEndpoint(ctx context.Context, _ interface{}, svc mobius.Service) (mobius.Errorer, error) {
	tokenCount, err := svc.CountABMTokens(ctx)
	if err != nil {
		return &countABMTokensResponse{Err: err}, nil
	}

	return &countABMTokensResponse{Count: tokenCount}, nil
}

func (svc *Service) CountABMTokens(ctx context.Context) (int, error) {
	// Automatic enrollment (ABM/ADE/DEP) is a feature that requires a license.
	// skipauth: No authorization check needed due to implementation returning
	// only license error.
	svc.authz.SkipAuthorization(ctx)

	return 0, mobius.ErrMissingLicense
}

////////////////////////////////////////////////////////////////////////////////
// Update ABM token teams endpoint
////////////////////////////////////////////////////////////////////////////////

type updateABMTokenTeamsRequest struct {
	TokenID      uint  `url:"id"`
	MacOSTeamID  *uint `json:"macos_team_id"`
	IOSTeamID    *uint `json:"ios_team_id"`
	IPadOSTeamID *uint `json:"ipados_team_id"`
}

type updateABMTokenTeamsResponse struct {
	ABMToken *mobius.ABMToken `json:"abm_token,omitempty"`
	Err      error           `json:"error,omitempty"`
}

func (r updateABMTokenTeamsResponse) Error() error { return r.Err }

func updateABMTokenTeamsEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*updateABMTokenTeamsRequest)

	tok, err := svc.UpdateABMTokenTeams(ctx, req.TokenID, req.MacOSTeamID, req.IOSTeamID, req.IPadOSTeamID)
	if err != nil {
		return &updateABMTokenTeamsResponse{Err: err}, nil
	}

	return &updateABMTokenTeamsResponse{ABMToken: tok}, nil
}

func (svc *Service) UpdateABMTokenTeams(ctx context.Context, tokenID uint, macOSTeamID, iOSTeamID, iPadOSTeamID *uint) (*mobius.ABMToken, error) {
	// skipauth: No authorization check needed due to implementation returning
	// only license error.
	svc.authz.SkipAuthorization(ctx)

	return nil, mobius.ErrMissingLicense
}

////////////////////////////////////////////////////////////////////////////////
// Renew ABM token endpoint
////////////////////////////////////////////////////////////////////////////////

type renewABMTokenRequest struct {
	TokenID uint `url:"id"`
	Token   *multipart.FileHeader
}

func (renewABMTokenRequest) DecodeRequest(ctx context.Context, r *http.Request) (interface{}, error) {
	err := r.ParseMultipartForm(512 * units.MiB)
	if err != nil {
		return nil, &mobius.BadRequestError{
			Message:     "failed to parse multipart form",
			InternalErr: err,
		}
	}

	token, ok := r.MultipartForm.File["token"]
	if !ok || len(token) < 1 {
		return nil, &mobius.BadRequestError{Message: "no file headers for token"}
	}

	// because we are in this method, we know that the path has 7 parts, e.g:
	// /api/latest/mobius/abm_tokens/19/renew

	id, err := endpoint_utils.IntFromRequest(r, "id")
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err, "failed to parse abm token id")
	}

	return &renewABMTokenRequest{
		Token:   token[0],
		TokenID: uint(id), //nolint:gosec // dismiss G115
	}, nil
}

type renewABMTokenResponse struct {
	ABMToken *mobius.ABMToken `json:"abm_token,omitempty"`
	Err      error           `json:"error,omitempty"`
}

func (r renewABMTokenResponse) Error() error { return r.Err }

func renewABMTokenEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*renewABMTokenRequest)
	ff, err := req.Token.Open()
	if err != nil {
		return &renewABMTokenResponse{Err: err}, nil
	}
	defer ff.Close()

	tok, err := svc.RenewABMToken(ctx, ff, req.TokenID)
	if err != nil {
		return &renewABMTokenResponse{Err: err}, nil
	}

	return &renewABMTokenResponse{ABMToken: tok}, nil
}

func (svc *Service) RenewABMToken(ctx context.Context, token io.Reader, tokenID uint) (*mobius.ABMToken, error) {
	// skipauth: No authorization check needed due to implementation returning
	// only license error.
	svc.authz.SkipAuthorization(ctx)

	return nil, mobius.ErrMissingLicense
}

////////////////////////////////////////////////////////////////////////////////
// GET /enrollment_profiles/ota
////////////////////////////////////////////////////////////////////////////////

type getOTAProfileRequest struct {
	EnrollSecret string `query:"enroll_secret"`
}

func getOTAProfileEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*getOTAProfileRequest)
	profile, err := svc.GetOTAProfile(ctx, req.EnrollSecret)
	if err != nil {
		return &getMDMAppleConfigProfileResponse{Err: err}, err
	}

	reader := bytes.NewReader(profile)
	return &getMDMAppleConfigProfileResponse{fileReader: io.NopCloser(reader), fileLength: reader.Size(), fileName: "mobius-mdm-enrollment-profile"}, nil
}

func (svc *Service) GetOTAProfile(ctx context.Context, enrollSecret string) ([]byte, error) {
	// Skip authz as this endpoint is used by end users from their iPhones or iPads; authz is done
	// by the enroll secret verification below
	svc.authz.SkipAuthorization(ctx)

	cfg, err := svc.ds.AppConfig(ctx)
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err, "getting app config to get org name")
	}

	profBytes, err := apple_mdm.GenerateOTAEnrollmentProfileMobileconfig(cfg.OrgInfo.OrgName, cfg.MDMUrl(), enrollSecret)
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err, "generating ota mobileconfig file")
	}

	signed, err := mdmcrypto.Sign(ctx, profBytes, svc.ds)
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err, "signing profile")
	}

	return signed, nil
}

////////////////////////////////////////////////////////////////////////////////
// POST /ota_enrollment?enroll_secret=xyz
////////////////////////////////////////////////////////////////////////////////

type mdmAppleOTARequest struct {
	EnrollSecret string `query:"enroll_secret"`
	Certificates []*x509.Certificate
	RootSigner   *x509.Certificate
	DeviceInfo   mobius.MDMAppleMachineInfo
}

func (mdmAppleOTARequest) DecodeRequest(ctx context.Context, r *http.Request) (interface{}, error) {
	enrollSecret := r.URL.Query().Get("enroll_secret")
	if enrollSecret == "" {
		return nil, &mobius.OTAForbiddenError{
			InternalErr: errors.New("enroll_secret query parameter was empty"),
		}
	}

	rawData, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err, "reading body from request")
	}

	p7, err := pkcs7.Parse(rawData)
	if err != nil {
		return nil, &mobius.BadRequestError{
			Message:     "invalid request body",
			InternalErr: err,
		}
	}

	var request mdmAppleOTARequest
	err = plist.Unmarshal(p7.Content, &request.DeviceInfo)
	if err != nil {
		return nil, &mobius.BadRequestError{
			Message:     "invalid request body",
			InternalErr: err,
		}
	}

	if request.DeviceInfo.Serial == "" {
		return nil, &mobius.BadRequestError{
			Message: "SERIAL is required",
		}
	}

	request.EnrollSecret = enrollSecret
	request.Certificates = p7.Certificates
	request.RootSigner = p7.GetOnlySigner()
	return &request, nil
}

type mdmAppleOTAResponse struct {
	Err error `json:"error,omitempty"`
	xml []byte
}

func (r mdmAppleOTAResponse) Error() error { return r.Err }

func (r mdmAppleOTAResponse) HijackRender(ctx context.Context, w http.ResponseWriter) {
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(r.xml)))
	w.Header().Set("Content-Type", "application/x-apple-aspen-config")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if _, err := w.Write(r.xml); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func mdmAppleOTAEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*mdmAppleOTARequest)
	xml, err := svc.MDMAppleProcessOTAEnrollment(ctx, req.Certificates, req.RootSigner, req.EnrollSecret, req.DeviceInfo)
	if err != nil {
		return mdmAppleGetInstallerResponse{Err: err}, nil
	}
	return mdmAppleOTAResponse{xml: xml}, nil
}

// NOTE: this method and how OTA works is documented in full in the interface definition.
func (svc *Service) MDMAppleProcessOTAEnrollment(
	ctx context.Context,
	certificates []*x509.Certificate,
	rootSigner *x509.Certificate,
	enrollSecret string,
	deviceInfo mobius.MDMAppleMachineInfo,
) ([]byte, error) {
	// authorization is performed via the enroll secret and the provided certificates
	svc.authz.SkipAuthorization(ctx)

	if len(certificates) == 0 {
		return nil, authz.ForbiddenWithInternal("no certificates provided", nil, nil, nil)
	}

	// first check is for the enroll secret, we'll only let the host
	// through if it has a valid secret.
	enrollSecretInfo, err := svc.ds.VerifyEnrollSecret(ctx, enrollSecret)
	if err != nil {
		if mobius.IsNotFound(err) {
			return nil, &mobius.OTAForbiddenError{
				InternalErr: err,
			}
		}

		return nil, ctxerr.Wrap(ctx, err, "validating enroll secret")
	}

	assets, err := svc.ds.GetAllMDMConfigAssetsByName(ctx, []mobius.MDMAssetName{
		mobius.MDMAssetSCEPChallenge,
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("loading SCEP challenge from the database: %w", err)
	}
	scepChallenge := string(assets[mobius.MDMAssetSCEPChallenge].Value)

	appCfg, err := svc.ds.AppConfig(ctx)
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err, "reading app config")
	}

	mdmURL := appCfg.MDMUrl()

	// if the root signer was issued by Apple's CA, it means we're in the
	// first phase and we should return a SCEP payload.
	if err := apple_mdm.VerifyFromAppleIphoneDeviceCA(rootSigner); err == nil {
		scepURL, err := apple_mdm.ResolveAppleSCEPURL(mdmURL)
		if err != nil {
			return nil, ctxerr.Wrap(ctx, err, "resolve Apple SCEP url")
		}

		var buf bytes.Buffer
		if err := apple_mdm.OTASCEPTemplate.Execute(&buf, struct {
			SCEPURL       string
			SCEPChallenge string
		}{
			SCEPURL:       scepURL,
			SCEPChallenge: scepChallenge,
		}); err != nil {
			return nil, ctxerr.Wrap(ctx, err, "execute template")
		}
		return buf.Bytes(), nil
	}

	// otherwise we might be in the second phase, check if the signing cert
	// was issued by Mobius, only let the enrollment through if so.
	certVerifier := mdmcrypto.NewSCEPVerifier(svc.ds)
	if err := certVerifier.Verify(ctx, rootSigner); err != nil {
		return nil, authz.ForbiddenWithInternal(fmt.Sprintf("payload signed with invalid certificate: %s", err), nil, nil, nil)
	}

	topic, err := svc.mdmPushCertTopic(ctx)
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err, "extracting topic from APNs cert")
	}

	enrollmentProf, err := apple_mdm.GenerateEnrollmentProfileMobileconfig(
		appCfg.OrgInfo.OrgName,
		mdmURL,
		string(assets[mobius.MDMAssetSCEPChallenge].Value),
		topic,
	)
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err, "generating manual enrollment profile")
	}

	// before responding, create a host record, and assign the host to the
	// team that matches the enroll secret provided.
	err = svc.ds.IngestMDMAppleDeviceFromOTAEnrollment(ctx, enrollSecretInfo.TeamID, deviceInfo)
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err, "creating new host record")
	}

	// at this point we know the device can be enrolled, so we respond with
	// a signed enrollment profile
	signed, err := mdmcrypto.Sign(ctx, enrollmentProf, svc.ds)
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err, "signing profile")
	}

	return signed, nil
}
