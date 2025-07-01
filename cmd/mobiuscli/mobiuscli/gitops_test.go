package mobiuscli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/notawar/mobius/v4/cmd/mobiuscli/mobiuscli/testing_utils"
	"github.com/notawar/mobius set/v4/pkg/file"
	"github.com/notawar/mobius set/v4/pkg/optjson"
	"github.com/notawar/mobius set/v4/server/config"
	"github.com/notawar/mobius set/v4/server/datastore/mysql"
	"github.com/notawar/mobius set/v4/server/mobius"
	apple_mdm "github.com/notawar/mobius set/v4/server/mdm/apple"
	"github.com/notawar/mobius set/v4/server/mdm/apple/vpp"
	"github.com/notawar/mobius set/v4/server/mdm/nanodep/tokenpki"
	mdmtesting "github.com/notawar/mobius set/v4/server/mdm/testing_utils"
	digicert_mock "github.com/notawar/mobius set/v4/server/mock/digicert"
	mdmmock "github.com/notawar/mobius set/v4/server/mock/mdm"
	scep_mock "github.com/notawar/mobius set/v4/server/mock/scep"
	"github.com/notawar/mobius set/v4/server/ptr"
	"github.com/notawar/mobius set/v4/server/service"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	teamName       = "Team Test"
	mobiusServerURL = "https://mobius.example.com"
	orgName        = "GitOps Test"
)

func TestGitOpsFilenameValidation(t *testing.T) {
	filename := strings.Repeat("a", filenameMaxLength+1)
	_, err := RunAppNoChecks([]string{"gitops", "-f", filename})
	assert.ErrorContains(t, err, "file name must be less than")
}

func TestGitOpsBasicGlobalFree(t *testing.T) {
	// Cannot run t.Parallel() because it sets environment variables

	_, ds := testing_utils.RunServerWithMockedDS(t)

	ds.BatchSetMDMProfilesFunc = func(
		ctx context.Context, tmID *uint, macProfiles []*mobius.MDMAppleConfigProfile, winProfiles []*mobius.MDMWindowsConfigProfile,
		macDecls []*mobius.MDMAppleDeclaration, vars []mobius.MDMProfileIdentifierMobiusVariables,
	) (updates mobius.MDMProfilesUpdates, err error) {
		return mobius.MDMProfilesUpdates{}, nil
	}
	ds.BulkSetPendingMDMHostProfilesFunc = func(
		ctx context.Context, hostIDs []uint, teamIDs []uint, profileUUIDs []string, hostUUIDs []string,
	) (updates mobius.MDMProfilesUpdates, err error) {
		return mobius.MDMProfilesUpdates{}, nil
	}
	ds.BatchSetScriptsFunc = func(ctx context.Context, tmID *uint, scripts []*mobius.Script) ([]mobius.ScriptResponse, error) {
		return []mobius.ScriptResponse{}, nil
	}
	ds.NewActivityFunc = func(
		ctx context.Context, user *mobius.User, activity mobius.ActivityDetails, details []byte, createdAt time.Time,
	) error {
		return nil
	}
	ds.ListGlobalPoliciesFunc = func(ctx context.Context, opts mobius.ListOptions) ([]*mobius.Policy, error) { return nil, nil }
	ds.ListQueriesFunc = func(ctx context.Context, opts mobius.ListQueryOptions) ([]*mobius.Query, int, *mobius.PaginationMetadata, error) {
		return nil, 0, nil, nil
	}
	ds.ListTeamPoliciesFunc = func(
		ctx context.Context, teamID uint, opts mobius.ListOptions, iopts mobius.ListOptions,
	) (teamPolicies []*mobius.Policy, inheritedPolicies []*mobius.Policy, err error) {
		return nil, nil, nil
	}

	// Mock appConfig
	savedAppConfig := &mobius.AppConfig{}
	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		return &mobius.AppConfig{}, nil
	}
	ds.SaveAppConfigFunc = func(ctx context.Context, config *mobius.AppConfig) error {
		savedAppConfig = config
		return nil
	}
	ds.GetLabelSpecsFunc = func(ctx context.Context) ([]*mobius.LabelSpec, error) {
		return nil, nil
	}

	var enrolledSecrets []*mobius.EnrollSecret
	ds.ApplyEnrollSecretsFunc = func(ctx context.Context, teamID *uint, secrets []*mobius.EnrollSecret) error {
		enrolledSecrets = secrets
		return nil
	}

	ds.SaveABMTokenFunc = func(ctx context.Context, tok *mobius.ABMToken) error {
		return nil
	}

	ds.ListVPPTokensFunc = func(ctx context.Context) ([]*mobius.VPPTokenDB, error) {
		return []*mobius.VPPTokenDB{}, nil
	}

	ds.ListABMTokensFunc = func(ctx context.Context) ([]*mobius.ABMToken, error) {
		return []*mobius.ABMToken{}, nil
	}

	tmpFile, err := os.CreateTemp(t.TempDir(), "*.yml")
	require.NoError(t, err)

	const (
		mobiusServerURL = "https://mobius.example.com"
		orgName        = "GitOps Test"
	)
	t.Setenv("MOBIUS_SERVER_URL", mobiusServerURL)

	_, err = tmpFile.WriteString(
		`
controls:
queries:
policies:
agent_options:
org_settings:
  server_settings:
    server_url: $MOBIUS_SERVER_URL
  org_info:
    contact_url: https://example.com/contact
    org_logo_url: ""
    org_logo_url_light_background: ""
    org_name: ${ORG_NAME}
  secrets:
`,
	)
	require.NoError(t, err)

	// No file
	var errWriter strings.Builder
	_, err = RunAppNoChecks([]string{"gitops", tmpFile.Name()})
	require.Error(t, err)
	assert.Equal(t, `Required flag "f" not set`, err.Error())

	// Blank file
	errWriter.Reset()
	_, err = RunAppNoChecks([]string{"gitops", "-f", ""})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "file name cannot be empty")

	// Bad file
	errWriter.Reset()
	_, err = RunAppNoChecks([]string{"gitops", "-f", "fileDoesNotExist.yml"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no such file or directory")

	// Empty file
	errWriter.Reset()
	badFile, err := os.CreateTemp(t.TempDir(), "*.yml")
	require.NoError(t, err)
	_, err = RunAppNoChecks([]string{"gitops", "-f", badFile.Name()})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "errors occurred")

	// DoGitOps error
	t.Setenv("ORG_NAME", "")
	_, err = RunAppNoChecks([]string{"gitops", "-f", tmpFile.Name()})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "organization name must be present")

	// Missing controls.
	tmpFile2, err := os.CreateTemp(t.TempDir(), "*.yml")
	require.NoError(t, err)
	_, err = tmpFile2.WriteString(
		`
queries:
policies:
agent_options:
labels:
org_settings:
  server_settings:
    server_url: https://example.com
  org_info:
    contact_url: https://example.com/contact
    org_name: Foobar
  secrets:
`,
	)
	require.NoError(t, err)
	_, err = RunAppNoChecks([]string{"gitops", "-f", tmpFile2.Name()})
	require.Error(t, err)
	assert.Equal(t, `'controls' must be set on global config`, err.Error())

	// Dry run
	t.Setenv("ORG_NAME", orgName)
	_ = RunAppForTest(t, []string{"gitops", "-f", tmpFile.Name(), "--dry-run"})
	assert.Equal(t, mobius.AppConfig{}, *savedAppConfig, "AppConfig should be empty")

	// Real run
	_ = RunAppForTest(t, []string{"gitops", "-f", tmpFile.Name()})
	assert.Equal(t, orgName, savedAppConfig.OrgInfo.OrgName)
	assert.Equal(t, mobiusServerURL, savedAppConfig.ServerSettings.ServerURL)
	assert.Empty(t, enrolledSecrets)
}

func TestGitOpsBasicGlobalPremium(t *testing.T) {
	// Cannot run t.Parallel() because it sets environment variables

	license := &mobius.LicenseInfo{Tier: mobius.TierPremium, Expiration: time.Now().Add(24 * time.Hour)}
	scepConfig := &scep_mock.SCEPConfigService{}
	scepConfig.ValidateSCEPURLFunc = func(_ context.Context, _ string) error { return nil }
	scepConfig.ValidateNDESSCEPAdminURLFunc = func(_ context.Context, _ mobius.NDESSCEPProxyIntegration) error { return nil }
	digiCertService := &digicert_mock.Service{}
	digiCertService.VerifyProfileIDFunc = func(_ context.Context, _ mobius.DigiCertIntegration) error { return nil }
	_, ds := testing_utils.RunServerWithMockedDS(
		t, &service.TestServerOpts{
			License:           license,
			KeyValueStore:     testing_utils.NewMemKeyValueStore(),
			EnableSCEPProxy:   true,
			SCEPConfigService: scepConfig,
			DigiCertService:   digiCertService,
		},
	)

	ds.BatchSetMDMProfilesFunc = func(
		ctx context.Context, tmID *uint, macProfiles []*mobius.MDMAppleConfigProfile, winProfiles []*mobius.MDMWindowsConfigProfile,
		macDecls []*mobius.MDMAppleDeclaration, vars []mobius.MDMProfileIdentifierMobiusVariables,
	) (updates mobius.MDMProfilesUpdates, err error) {
		return mobius.MDMProfilesUpdates{}, nil
	}
	ds.BulkSetPendingMDMHostProfilesFunc = func(
		ctx context.Context, hostIDs []uint, teamIDs []uint, profileUUIDs []string, hostUUIDs []string,
	) (updates mobius.MDMProfilesUpdates, err error) {
		return mobius.MDMProfilesUpdates{}, nil
	}
	ds.BatchSetScriptsFunc = func(ctx context.Context, tmID *uint, scripts []*mobius.Script) ([]mobius.ScriptResponse, error) {
		return []mobius.ScriptResponse{}, nil
	}
	ds.NewActivityFunc = func(
		ctx context.Context, user *mobius.User, activity mobius.ActivityDetails, details []byte, createdAt time.Time,
	) error {
		return nil
	}
	ds.ListGlobalPoliciesFunc = func(ctx context.Context, opts mobius.ListOptions) ([]*mobius.Policy, error) { return nil, nil }
	ds.ListQueriesFunc = func(ctx context.Context, opts mobius.ListQueryOptions) ([]*mobius.Query, int, *mobius.PaginationMetadata, error) {
		return nil, 0, nil, nil
	}

	// Mock appConfig
	savedAppConfig := &mobius.AppConfig{}
	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		return &mobius.AppConfig{
			// Set a GitOps UI mode to verify that applying GitOps config won't overwrite it.
			UIGitOpsMode: mobius.UIGitOpsModeConfig{
				GitopsModeEnabled: true,
				RepositoryURL:     "https://didsomeonesaygitops.biz",
			},
		}, nil
	}
	ds.SaveAppConfigFunc = func(ctx context.Context, config *mobius.AppConfig) error {
		savedAppConfig = config
		return nil
	}
	ds.GetLabelSpecsFunc = func(ctx context.Context) ([]*mobius.LabelSpec, error) {
		return nil, nil
	}

	var enrolledSecrets []*mobius.EnrollSecret
	ds.ApplyEnrollSecretsFunc = func(ctx context.Context, teamID *uint, secrets []*mobius.EnrollSecret) error {
		enrolledSecrets = secrets
		return nil
	}
	ds.LabelIDsByNameFunc = func(ctx context.Context, labels []string) (map[string]uint, error) {
		return map[string]uint{labels[0]: 1}, nil
	}
	ds.SetOrUpdateMDMAppleDeclarationFunc = func(ctx context.Context, declaration *mobius.MDMAppleDeclaration) (*mobius.MDMAppleDeclaration, error) {
		return &mobius.MDMAppleDeclaration{}, nil
	}
	ds.NewJobFunc = func(ctx context.Context, job *mobius.Job) (*mobius.Job, error) {
		return &mobius.Job{}, nil
	}
	ds.BatchSetSoftwareInstallersFunc = func(ctx context.Context, teamID *uint, installers []*mobius.UploadSoftwareInstallerPayload) error {
		return nil
	}
	ds.GetSoftwareInstallersFunc = func(ctx context.Context, tmID uint) ([]mobius.SoftwarePackageResponse, error) {
		return nil, nil
	}

	ds.SaveABMTokenFunc = func(ctx context.Context, tok *mobius.ABMToken) error {
		return nil
	}

	ds.ListVPPTokensFunc = func(ctx context.Context) ([]*mobius.VPPTokenDB, error) {
		return []*mobius.VPPTokenDB{}, nil
	}

	ds.ListABMTokensFunc = func(ctx context.Context) ([]*mobius.ABMToken, error) {
		return []*mobius.ABMToken{}, nil
	}

	ds.GetAllCAConfigAssetsByTypeFunc = func(ctx context.Context, assetType mobius.CAConfigAssetType) (map[string]mobius.CAConfigAsset, error) {
		switch assetType {
		case mobius.CAConfigCustomSCEPProxy:
			return map[string]mobius.CAConfigAsset{
				"CustomScepProxy2": {
					Name:  "CustomScepProxy2",
					Value: []byte("challenge2"),
					Type:  mobius.CAConfigCustomSCEPProxy,
				},
			}, nil
		default:
			return nil, &notFoundError{}
		}
	}

	ds.DeleteSetupExperienceScriptFunc = func(ctx context.Context, teamID *uint) error {
		return nil
	}
	ds.ListTeamPoliciesFunc = func(
		ctx context.Context, teamID uint, opts mobius.ListOptions, iopts mobius.ListOptions,
	) (teamPolicies []*mobius.Policy, inheritedPolicies []*mobius.Policy, err error) {
		return nil, nil, nil
	}
	ds.SetTeamVPPAppsFunc = func(ctx context.Context, teamID *uint, adamIDs []mobius.VPPAppTeam) error {
		return nil
	}

	tmpFile, err := os.CreateTemp(t.TempDir(), "*.yml")
	require.NoError(t, err)

	const (
		mobiusServerURL = "https://mobius.example.com"
		orgName        = "GitOps Premium Test"
	)
	t.Setenv("MOBIUS_SERVER_URL", mobiusServerURL)

	_, err = tmpFile.WriteString(
		`
controls:
  ios_updates:
    deadline: "2022-02-02"
    minimum_version: "17.6"
  ipados_updates:
    deadline: "2023-03-03"
    minimum_version: "18.0"
queries:
policies:
labels:
agent_options:
org_settings:
  integrations:
    ndes_scep_proxy:
      url: https://ndes.example.com/scep
      admin_url: https://ndes.example.com/admin
      username: ndes_user
      password: ndes_password
    digicert:
      - name: DigiCert
        url: https://one.digicert.com
        api_token: digicert_api_token
        profile_id: digicert_profile_id
        certificate_common_name: digicert_cn
        certificate_user_principal_names: ["digicert_upn"]
        certificate_seat_id: digicert_seat_id
      - name: DigiCert2
        url: https://two.digicert.com
        api_token: digicert_api_token2
        profile_id: digicert_profile_id2
        certificate_common_name: digicert_cn2
        certificate_seat_id: digicert_seat_id2
    custom_scep_proxy:
      - name: CustomScepProxy
        url: https://custom.scep.proxy.com
        challenge: challenge
      - name: CustomScepProxy2
        url: https://custom.scep.proxy.com2
        challenge: challenge2
  server_settings:
    server_url: $MOBIUS_SERVER_URL
  org_info:
    contact_url: https://example.com/contact
    org_logo_url: ""
    org_logo_url_light_background: ""
    org_name: ${ORG_NAME}
  secrets:
software:
`,
	)
	require.NoError(t, err)

	// Dry run
	t.Setenv("ORG_NAME", orgName)
	_ = RunAppForTest(t, []string{"gitops", "-f", tmpFile.Name(), "--dry-run"})
	assert.Equal(t, mobius.AppConfig{}, *savedAppConfig, "AppConfig should be empty")

	// Real run
	_ = RunAppForTest(t, []string{"gitops", "-f", tmpFile.Name()})
	assert.Equal(t, orgName, savedAppConfig.OrgInfo.OrgName)
	assert.Equal(t, mobiusServerURL, savedAppConfig.ServerSettings.ServerURL)
	assert.Empty(t, enrolledSecrets)
	assert.True(t, savedAppConfig.Integrations.NDESSCEPProxy.Valid)
	assert.Equal(t, "https://ndes.example.com/scep", savedAppConfig.Integrations.NDESSCEPProxy.Value.URL)
	// GitOps should not overwrite GitOps UI Mode.
	assert.Equal(t, savedAppConfig.UIGitOpsMode.GitopsModeEnabled, true)
	assert.Equal(t, savedAppConfig.UIGitOpsMode.RepositoryURL, "https://didsomeonesaygitops.biz")

	assert.True(t, digiCertService.VerifyProfileIDFuncInvoked)
	require.True(t, savedAppConfig.Integrations.DigiCert.Valid)
	digicerts := savedAppConfig.Integrations.DigiCert.Value
	require.Len(t, digicerts, 2)
	assert.Equal(t, "DigiCert", digicerts[0].Name)
	assert.Equal(t, "https://one.digicert.com", digicerts[0].URL)
	assert.Equal(t, "digicert_api_token", digicerts[0].APIToken)
	assert.Equal(t, "digicert_profile_id", digicerts[0].ProfileID)
	assert.Equal(t, "digicert_cn", digicerts[0].CertificateCommonName)
	assert.Equal(t, []string{"digicert_upn"}, digicerts[0].CertificateUserPrincipalNames)
	assert.Equal(t, "digicert_seat_id", digicerts[0].CertificateSeatID)
	assert.Equal(t, "DigiCert2", digicerts[1].Name)
	assert.Equal(t, "https://two.digicert.com", digicerts[1].URL)
	assert.Equal(t, "digicert_api_token2", digicerts[1].APIToken)
	assert.Equal(t, "digicert_profile_id2", digicerts[1].ProfileID)
	assert.Equal(t, "digicert_cn2", digicerts[1].CertificateCommonName)
	assert.Empty(t, digicerts[1].CertificateUserPrincipalNames)
	assert.Equal(t, "digicert_seat_id2", digicerts[1].CertificateSeatID)

	require.True(t, savedAppConfig.Integrations.CustomSCEPProxy.Valid)
	sceps := savedAppConfig.Integrations.CustomSCEPProxy.Value
	require.Len(t, sceps, 2)
	assert.Equal(t, "CustomScepProxy", sceps[0].Name)
	assert.Equal(t, "https://custom.scep.proxy.com", sceps[0].URL)
	assert.Equal(t, "challenge", sceps[0].Challenge)
	assert.Equal(t, "CustomScepProxy2", sceps[1].Name)
	assert.Equal(t, "https://custom.scep.proxy.com2", sceps[1].URL)
	assert.Equal(t, "challenge2", sceps[1].Challenge)
}

func TestGitOpsBasicTeam(t *testing.T) {
	// Cannot run t.Parallel() because it sets environment variables
	license := &mobius.LicenseInfo{Tier: mobius.TierPremium, Expiration: time.Now().Add(24 * time.Hour)}
	_, ds := testing_utils.RunServerWithMockedDS(
		t, &service.TestServerOpts{
			License:       license,
			KeyValueStore: testing_utils.NewMemKeyValueStore(),
		},
	)

	const secret = "TestSecret"

	ds.SetTeamVPPAppsFunc = func(ctx context.Context, teamID *uint, adamIDs []mobius.VPPAppTeam) error {
		return nil
	}
	ds.BatchInsertVPPAppsFunc = func(ctx context.Context, apps []*mobius.VPPApp) error {
		return nil
	}
	ds.BatchSetScriptsFunc = func(ctx context.Context, tmID *uint, scripts []*mobius.Script) ([]mobius.ScriptResponse, error) {
		return []mobius.ScriptResponse{}, nil
	}
	ds.BatchSetMDMProfilesFunc = func(
		ctx context.Context, tmID *uint, macProfiles []*mobius.MDMAppleConfigProfile, winProfiles []*mobius.MDMWindowsConfigProfile, macDecls []*mobius.MDMAppleDeclaration, vars []mobius.MDMProfileIdentifierMobiusVariables,
	) (updates mobius.MDMProfilesUpdates, err error) {
		return mobius.MDMProfilesUpdates{}, nil
	}
	ds.BulkSetPendingMDMHostProfilesFunc = func(
		ctx context.Context, hostIDs []uint, teamIDs []uint, profileUUIDs []string, hostUUIDs []string,
	) (updates mobius.MDMProfilesUpdates, err error) {
		return mobius.MDMProfilesUpdates{}, nil
	}
	ds.NewActivityFunc = func(
		ctx context.Context, user *mobius.User, activity mobius.ActivityDetails, details []byte, createdAt time.Time,
	) error {
		return nil
	}
	ds.ListTeamPoliciesFunc = func(
		ctx context.Context, teamID uint, opts mobius.ListOptions, iopts mobius.ListOptions,
	) (teamPolicies []*mobius.Policy, inheritedPolicies []*mobius.Policy, err error) {
		return nil, nil, nil
	}
	ds.ListQueriesFunc = func(ctx context.Context, opts mobius.ListQueryOptions) ([]*mobius.Query, int, *mobius.PaginationMetadata, error) {
		return nil, 0, nil, nil
	}
	ds.GetLabelSpecsFunc = func(ctx context.Context) ([]*mobius.LabelSpec, error) {
		return nil, nil
	}

	team := &mobius.Team{
		ID:        1,
		CreatedAt: time.Now(),
		Name:      teamName,
	}
	var savedTeam *mobius.Team
	ds.TeamByNameFunc = func(ctx context.Context, name string) (*mobius.Team, error) {
		if name == teamName && savedTeam != nil {
			return savedTeam, nil
		}
		return nil, &notFoundError{}
	}
	ds.TeamByFilenameFunc = func(ctx context.Context, filename string) (*mobius.Team, error) {
		if savedTeam != nil && *savedTeam.Filename == filename {
			return savedTeam, nil
		}
		return nil, &notFoundError{}
	}
	ds.TeamFunc = func(ctx context.Context, tid uint) (*mobius.Team, error) {
		if tid == team.ID {
			return savedTeam, nil
		}
		return nil, nil
	}
	var enrolledTeamSecrets []*mobius.EnrollSecret
	ds.NewTeamFunc = func(ctx context.Context, newTeam *mobius.Team) (*mobius.Team, error) {
		newTeam.ID = team.ID
		savedTeam = newTeam
		enrolledTeamSecrets = newTeam.Secrets
		return newTeam, nil
	}
	ds.IsEnrollSecretAvailableFunc = func(ctx context.Context, secret string, isNew bool, teamID *uint) (bool, error) {
		return true, nil
	}
	ds.SaveTeamFunc = func(ctx context.Context, team *mobius.Team) (*mobius.Team, error) {
		savedTeam = team
		return team, nil
	}
	ds.LabelIDsByNameFunc = func(ctx context.Context, labels []string) (map[string]uint, error) {
		require.Len(t, labels, 1)
		switch labels[0] {
		case mobius.BuiltinLabelMacOS14Plus:
			return map[string]uint{mobius.BuiltinLabelMacOS14Plus: 1}, nil
		case mobius.BuiltinLabelIOS:
			return map[string]uint{mobius.BuiltinLabelIOS: 2}, nil
		case mobius.BuiltinLabelIPadOS:
			return map[string]uint{mobius.BuiltinLabelIPadOS: 3}, nil
		default:
			return nil, &notFoundError{}
		}
	}
	ds.DeleteMDMAppleDeclarationByNameFunc = func(ctx context.Context, teamID *uint, name string) error {
		return nil
	}
	ds.BatchSetSoftwareInstallersFunc = func(ctx context.Context, teamID *uint, installers []*mobius.UploadSoftwareInstallerPayload) error {
		return nil
	}
	ds.GetSoftwareInstallersFunc = func(ctx context.Context, tmID uint) ([]mobius.SoftwarePackageResponse, error) {
		return nil, nil
	}
	ds.ApplyEnrollSecretsFunc = func(ctx context.Context, teamID *uint, secrets []*mobius.EnrollSecret) error {
		enrolledTeamSecrets = secrets
		return nil
	}
	ds.SetOrUpdateMDMAppleDeclarationFunc = func(ctx context.Context, declaration *mobius.MDMAppleDeclaration) (*mobius.MDMAppleDeclaration, error) {
		return &mobius.MDMAppleDeclaration{}, nil
	}
	ds.NewJobFunc = func(ctx context.Context, job *mobius.Job) (*mobius.Job, error) {
		return &mobius.Job{}, nil
	}
	ds.ListSoftwareTitlesFunc = func(ctx context.Context, opt mobius.SoftwareTitleListOptions, tmFilter mobius.TeamFilter) ([]mobius.SoftwareTitleListResult, int, *mobius.PaginationMetadata, error) {
		return nil, 0, nil, nil
	}
	ds.DeleteSetupExperienceScriptFunc = func(ctx context.Context, teamID *uint) error {
		return nil
	}

	tmpFile, err := os.CreateTemp(t.TempDir(), "*.yml")
	require.NoError(t, err)

	t.Setenv("TEST_SECRET", "")

	_, err = tmpFile.WriteString(
		`
controls:
  ios_updates:
    deadline: "2024-10-10"
    minimum_version: "18.0"
  ipados_updates:
    deadline: "2025-11-11"
    minimum_version: "17.6"
queries:
policies:
agent_options:
labels:
name: ${TEST_TEAM_NAME}
team_settings:
  secrets: ${TEST_SECRET}
software:
`,
	)
	require.NoError(t, err)

	// DoGitOps error
	t.Setenv("TEST_TEAM_NAME", "")
	_, err = RunAppNoChecks([]string{"gitops", "-f", tmpFile.Name()})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "'name' is required")

	// Invalid name for "No team" file (dry and real).
	t.Setenv("TEST_TEAM_NAME", "no TEam")
	_, err = RunAppNoChecks([]string{"gitops", "-f", tmpFile.Name(), "--dry-run"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), fmt.Sprintf("file %q for 'No team' must be named 'no-team.yml'", tmpFile.Name()))
	t.Setenv("TEST_TEAM_NAME", "no TEam")
	_, err = RunAppNoChecks([]string{"gitops", "-f", tmpFile.Name()})
	require.Error(t, err)
	assert.Contains(t, err.Error(), fmt.Sprintf("file %q for 'No team' must be named 'no-team.yml'", tmpFile.Name()))

	t.Setenv("TEST_TEAM_NAME", "All teams")
	_, err = RunAppNoChecks([]string{"gitops", "-f", tmpFile.Name(), "--dry-run"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"All teams" is a reserved team name`)

	t.Setenv("TEST_TEAM_NAME", "All TEAMS")
	_, err = RunAppNoChecks([]string{"gitops", "-f", tmpFile.Name()})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"All teams" is a reserved team name`)

	// Dry run
	t.Setenv("TEST_TEAM_NAME", teamName)
	_ = RunAppForTest(t, []string{"gitops", "-f", tmpFile.Name(), "--dry-run"})
	assert.Nil(t, savedTeam)

	// Real run
	_ = RunAppForTest(t, []string{"gitops", "-f", tmpFile.Name()})
	require.NotNil(t, savedTeam)
	assert.Equal(t, teamName, savedTeam.Name)
	assert.Empty(t, enrolledTeamSecrets)

	// The previous run created the team, so let's rerun with an existing team
	_ = RunAppForTest(t, []string{"gitops", "-f", tmpFile.Name()})
	assert.Empty(t, enrolledTeamSecrets)

	// Add a secret
	t.Setenv("TEST_SECRET", fmt.Sprintf("[{\"secret\":\"%s\"}]", secret))
	_ = RunAppForTest(t, []string{"gitops", "-f", tmpFile.Name()})
	require.Len(t, enrolledTeamSecrets, 1)
	assert.Equal(t, secret, enrolledTeamSecrets[0].Secret)
}

func TestGitOpsFullGlobal(t *testing.T) {
	// Cannot run t.Parallel() because it sets environment variables
	// mdm test configuration must be set so that activating windows MDM works.
	testCert, testKey, err := apple_mdm.NewSCEPCACertKey()
	require.NoError(t, err)
	testCertPEM := tokenpki.PEMCertificate(testCert.Raw)
	testKeyPEM := tokenpki.PEMRSAPrivateKey(testKey)
	mobiusCfg := config.TestConfig()
	config.SetTestMDMConfig(t, &mobiusCfg, testCertPEM, testKeyPEM, "../../../server/service/testdata")

	// License is not needed because we are not using any premium features in our config.
	_, ds := testing_utils.RunServerWithMockedDS(
		t, &service.TestServerOpts{
			MDMStorage:  new(mdmmock.MDMAppleStore),
			MDMPusher:   testing_utils.MockPusher{},
			MobiusConfig: &mobiusCfg,
		},
	)

	var appliedScripts []*mobius.Script
	ds.BatchSetScriptsFunc = func(ctx context.Context, tmID *uint, scripts []*mobius.Script) ([]mobius.ScriptResponse, error) {
		appliedScripts = scripts
		var scriptResponses []mobius.ScriptResponse
		for _, script := range scripts {
			scriptResponses = append(scriptResponses, mobius.ScriptResponse{
				ID:     script.ID,
				Name:   script.Name,
				TeamID: script.TeamID,
			})
		}

		return scriptResponses, nil
	}
	ds.NewActivityFunc = func(
		ctx context.Context, user *mobius.User, activity mobius.ActivityDetails, details []byte, createdAt time.Time,
	) error {
		return nil
	}
	var appliedMacProfiles []*mobius.MDMAppleConfigProfile
	var appliedWinProfiles []*mobius.MDMWindowsConfigProfile
	ds.BatchSetMDMProfilesFunc = func(
		ctx context.Context, tmID *uint, macProfiles []*mobius.MDMAppleConfigProfile, winProfiles []*mobius.MDMWindowsConfigProfile, macDecls []*mobius.MDMAppleDeclaration, vars []mobius.MDMProfileIdentifierMobiusVariables,
	) (updates mobius.MDMProfilesUpdates, err error) {
		appliedMacProfiles = macProfiles
		appliedWinProfiles = winProfiles
		return mobius.MDMProfilesUpdates{}, nil
	}
	ds.BulkSetPendingMDMHostProfilesFunc = func(ctx context.Context, hostIDs, teamIDs []uint, profileUUIDs, hostUUIDs []string,
	) (updates mobius.MDMProfilesUpdates, err error) {
		return mobius.MDMProfilesUpdates{}, nil
	}
	ds.NewJobFunc = func(ctx context.Context, job *mobius.Job) (*mobius.Job, error) {
		return job, nil
	}

	// Policies
	policy := mobius.Policy{}
	policy.ID = 1
	policy.Name = "Policy to delete"
	policyDeleted := false
	ds.ListTeamPoliciesFunc = func(
		ctx context.Context, teamID uint, opts mobius.ListOptions, iopts mobius.ListOptions,
	) (teamPolicies []*mobius.Policy, inheritedPolicies []*mobius.Policy, err error) {
		return nil, nil, nil
	}
	ds.ListGlobalPoliciesFunc = func(ctx context.Context, opts mobius.ListOptions) ([]*mobius.Policy, error) {
		return []*mobius.Policy{&policy}, nil
	}
	ds.PoliciesByIDFunc = func(ctx context.Context, ids []uint) (map[uint]*mobius.Policy, error) {
		if slices.Contains(ids, 1) {
			return map[uint]*mobius.Policy{1: &policy}, nil
		}
		return nil, nil
	}
	ds.DeleteGlobalPoliciesFunc = func(ctx context.Context, ids []uint) ([]uint, error) {
		policyDeleted = true
		assert.Equal(t, []uint{policy.ID}, ids)
		return ids, nil
	}
	var appliedPolicySpecs []*mobius.PolicySpec
	ds.ApplyPolicySpecsFunc = func(ctx context.Context, authorID uint, specs []*mobius.PolicySpec) error {
		appliedPolicySpecs = specs
		return nil
	}

	// Queries
	query := mobius.Query{}
	query.ID = 1
	query.Name = "Query to delete"
	queryDeleted := false
	ds.ListQueriesFunc = func(ctx context.Context, opts mobius.ListQueryOptions) ([]*mobius.Query, int, *mobius.PaginationMetadata, error) {
		return []*mobius.Query{&query}, 1, nil, nil
	}
	ds.DeleteQueriesFunc = func(ctx context.Context, ids []uint) (uint, error) {
		queryDeleted = true
		assert.Equal(t, []uint{query.ID}, ids)
		return 1, nil
	}
	ds.QueryFunc = func(ctx context.Context, id uint) (*mobius.Query, error) {
		if id == query.ID {
			return &query, nil
		}
		return nil, nil
	}
	var appliedQueries []*mobius.Query
	ds.QueryByNameFunc = func(ctx context.Context, teamID *uint, name string) (*mobius.Query, error) {
		return nil, &notFoundError{}
	}
	ds.ApplyQueriesFunc = func(
		ctx context.Context, authorID uint, queries []*mobius.Query, queriesToDiscardResults map[uint]struct{},
	) error {
		appliedQueries = queries
		return nil
	}

	var appliedLabelSpecs []*mobius.LabelSpec
	var deletedLabels []string
	ds.GetLabelSpecsFunc = func(ctx context.Context) ([]*mobius.LabelSpec, error) {
		return []*mobius.LabelSpec{
			{
				Name:                "a",
				Description:         "A global label",
				LabelMembershipType: mobius.LabelMembershipTypeManual,
				Hosts:               []string{"host2", "host3"},
			},
			{
				Name:                "c",
				Description:         "A label that should be deleted",
				LabelMembershipType: mobius.LabelMembershipTypeDynamic,
				Query:               "SELECT 1 from osquery_info",
			},
		}, nil
	}
	ds.ApplyLabelSpecsWithAuthorFunc = func(ctx context.Context, specs []*mobius.LabelSpec, authorID *uint) (err error) {
		appliedLabelSpecs = specs
		return nil
	}

	ds.DeleteLabelFunc = func(ctx context.Context, name string) error {
		deletedLabels = append(deletedLabels, name)
		return nil
	}

	ds.LabelsByNameFunc = func(ctx context.Context, names []string) (map[string]*mobius.Label, error) {
		return map[string]*mobius.Label{
			"a": {
				ID:   1,
				Name: "a",
			},
			"b": {
				ID:   2,
				Name: "b",
			},
		}, nil
	}

	// Mock appConfig
	savedAppConfig := &mobius.AppConfig{}
	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		return &mobius.AppConfig{MDM: mobius.MDM{EnabledAndConfigured: true}}, nil
	}
	ds.SaveAppConfigFunc = func(ctx context.Context, config *mobius.AppConfig) error {
		savedAppConfig = config
		return nil
	}
	ds.IsEnrollSecretAvailableFunc = func(ctx context.Context, secret string, isNew bool, teamID *uint) (bool, error) {
		return true, nil
	}
	var enrolledSecrets []*mobius.EnrollSecret
	ds.ApplyEnrollSecretsFunc = func(ctx context.Context, teamID *uint, secrets []*mobius.EnrollSecret) error {
		enrolledSecrets = secrets
		return nil
	}

	// Needed for checking tokens
	ds.SaveABMTokenFunc = func(ctx context.Context, tok *mobius.ABMToken) error {
		return nil
	}
	ds.ListVPPTokensFunc = func(ctx context.Context) ([]*mobius.VPPTokenDB, error) {
		return []*mobius.VPPTokenDB{}, nil
	}
	ds.ListABMTokensFunc = func(ctx context.Context) ([]*mobius.ABMToken, error) {
		return []*mobius.ABMToken{}, nil
	}

	ds.ExpandEmbeddedSecretsAndUpdatedAtFunc = func(ctx context.Context, document string) (string, *time.Time, error) {
		return document, nil, nil
	}

	const (
		mobiusServerURL = "https://mobius.example.com"
		orgName        = "GitOps Test"
	)
	t.Setenv("MOBIUS_SERVER_URL", mobiusServerURL)
	t.Setenv("ORG_NAME", orgName)
	t.Setenv("SOFTWARE_INSTALLER_URL", mobiusServerURL)

	// Dry run w/ top-level labels key
	logs := RunAppForTest(t, []string{"gitops", "-f", "./testdata/gitops/global_config_no_paths.yml", "--dry-run"})
	fmt.Printf("%s", logs)
	fmt.Printf("-----------\n")
	assert.Equal(t, mobius.AppConfig{}, *savedAppConfig, "AppConfig should be empty")
	assert.Len(t, enrolledSecrets, 0)
	assert.Len(t, appliedPolicySpecs, 0)
	assert.Len(t, appliedQueries, 0)
	assert.Len(t, appliedScripts, 0)
	assert.Len(t, appliedMacProfiles, 0)
	assert.Len(t, appliedWinProfiles, 0)
	assert.Len(t, appliedLabelSpecs, 0)
	assert.Len(t, deletedLabels, 0)

	// Dry run w/out top-level labels key
	logs = RunAppForTest(t, []string{"gitops", "-f", "./testdata/gitops/global_config_no_paths_no_labels.yml", "--dry-run"})
	fmt.Printf("%s", logs)
	fmt.Printf("-----------\n")
	assert.Equal(t, mobius.AppConfig{}, *savedAppConfig, "AppConfig should be empty")
	assert.Len(t, enrolledSecrets, 0)
	assert.Len(t, appliedPolicySpecs, 0)
	assert.Len(t, appliedQueries, 0)
	assert.Len(t, appliedScripts, 0)
	assert.Len(t, appliedMacProfiles, 0)
	assert.Len(t, appliedWinProfiles, 0)
	assert.Len(t, appliedLabelSpecs, 0)
	assert.Len(t, deletedLabels, 0)

	// Real run w/ top-level labels key
	logs = RunAppForTest(t, []string{"gitops", "-f", "./testdata/gitops/global_config_no_paths.yml"})
	fmt.Printf("%s", logs)
	fmt.Printf("-----------\n")
	assert.Equal(t, orgName, savedAppConfig.OrgInfo.OrgName)
	assert.Equal(t, mobiusServerURL, savedAppConfig.ServerSettings.ServerURL)
	assert.Contains(t, string(*savedAppConfig.AgentOptions), "distributed_denylist_duration")
	assert.Equal(t, 2000, savedAppConfig.ServerSettings.QueryReportCap)
	assert.Len(t, enrolledSecrets, 2)
	assert.True(t, policyDeleted)
	assert.Len(t, appliedPolicySpecs, 5)
	assert.Len(t, appliedPolicySpecs[0].LabelsIncludeAny, 1)
	assert.Len(t, appliedPolicySpecs[0].LabelsExcludeAny, 0)
	assert.Equal(t, appliedPolicySpecs[0].LabelsIncludeAny[0], "a")
	assert.Len(t, appliedPolicySpecs[1].LabelsIncludeAny, 0)
	assert.Len(t, appliedPolicySpecs[1].LabelsExcludeAny, 1)
	assert.Equal(t, appliedPolicySpecs[1].LabelsExcludeAny[0], "b")

	assert.True(t, queryDeleted)
	assert.Len(t, appliedQueries, 3)
	assert.Len(t, appliedScripts, 1)
	assert.Len(t, appliedMacProfiles, 1)
	assert.Len(t, appliedWinProfiles, 1)
	require.Len(t, savedAppConfig.Integrations.GoogleCalendar, 1)
	assert.Equal(t, "service@example.com", savedAppConfig.Integrations.GoogleCalendar[0].ApiKey["client_email"])
	assert.True(t, savedAppConfig.ActivityExpirySettings.ActivityExpiryEnabled)
	assert.Equal(t, 60, savedAppConfig.ActivityExpirySettings.ActivityExpiryWindow)
	assert.True(t, savedAppConfig.ServerSettings.AIFeaturesDisabled)
	assert.True(t, savedAppConfig.WebhookSettings.ActivitiesWebhook.Enable)
	assert.Equal(t, "https://activities_webhook_url", savedAppConfig.WebhookSettings.ActivitiesWebhook.DestinationURL)
	assert.Len(t, appliedLabelSpecs, 2)
	assert.Len(t, deletedLabels, 1)
	assert.Len(t, appliedQueries[0].LabelsIncludeAny, 2)
	assert.Contains(t, []string{appliedQueries[0].LabelsIncludeAny[0].LabelName, appliedQueries[0].LabelsIncludeAny[1].LabelName}, "a")
	assert.Contains(t, []string{appliedQueries[0].LabelsIncludeAny[0].LabelName, appliedQueries[0].LabelsIncludeAny[1].LabelName}, "b")

	// Reset labels arrays
	deletedLabels = make([]string, 0)
	appliedLabelSpecs = make([]*mobius.LabelSpec, 0)
	// Real run w/out top-level labels key
	logs = RunAppForTest(t, []string{"gitops", "-f", "./testdata/gitops/global_config_no_paths_no_labels.yml"})
	fmt.Printf("%s", logs)
	assert.Len(t, appliedLabelSpecs, 0)
	assert.Len(t, deletedLabels, 0)
}

func TestGitOpsFullTeam(t *testing.T) {
	// Cannot run t.Parallel() because it sets environment variables
	license := &mobius.LicenseInfo{Tier: mobius.TierPremium, Expiration: time.Now().Add(24 * time.Hour)}

	// mdm test configuration must be set so that activating windows MDM works.
	testCert, testKey, err := apple_mdm.NewSCEPCACertKey()
	require.NoError(t, err)
	testCertPEM := tokenpki.PEMCertificate(testCert.Raw)
	testKeyPEM := tokenpki.PEMRSAPrivateKey(testKey)
	mobiusCfg := config.TestConfig()
	config.SetTestMDMConfig(t, &mobiusCfg, testCertPEM, testKeyPEM, "../../../server/service/testdata")

	// License is not needed because we are not using any premium features in our config.
	_, ds := testing_utils.RunServerWithMockedDS(
		t, &service.TestServerOpts{
			License:          license,
			MDMStorage:       new(mdmmock.MDMAppleStore),
			MDMPusher:        testing_utils.MockPusher{},
			MobiusConfig:      &mobiusCfg,
			NoCacheDatastore: true,
			KeyValueStore:    testing_utils.NewMemKeyValueStore(),
		},
	)

	appConfig := mobius.AppConfig{
		// During dry run, the global calendar integration setting may not be set
		MDM: mobius.MDM{
			EnabledAndConfigured:        true,
			WindowsEnabledAndConfigured: true,
		},
	}
	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		return &appConfig, nil
	}

	var appliedScripts []*mobius.Script
	ds.BatchSetScriptsFunc = func(ctx context.Context, tmID *uint, scripts []*mobius.Script) ([]mobius.ScriptResponse, error) {
		appliedScripts = scripts
		var scriptResponses []mobius.ScriptResponse
		for _, script := range scripts {
			scriptResponses = append(scriptResponses, mobius.ScriptResponse{
				ID:     script.ID,
				Name:   script.Name,
				TeamID: script.TeamID,
			})
		}

		return scriptResponses, nil
	}
	ds.NewActivityFunc = func(
		ctx context.Context, user *mobius.User, activity mobius.ActivityDetails, details []byte, createdAt time.Time,
	) error {
		return nil
	}
	var appliedMacProfiles []*mobius.MDMAppleConfigProfile
	var appliedWinProfiles []*mobius.MDMWindowsConfigProfile
	ds.BatchSetMDMProfilesFunc = func(
		ctx context.Context, tmID *uint, macProfiles []*mobius.MDMAppleConfigProfile, winProfiles []*mobius.MDMWindowsConfigProfile, macDecls []*mobius.MDMAppleDeclaration, vars []mobius.MDMProfileIdentifierMobiusVariables,
	) (updates mobius.MDMProfilesUpdates, err error) {
		appliedMacProfiles = macProfiles
		appliedWinProfiles = winProfiles
		return mobius.MDMProfilesUpdates{}, nil
	}
	ds.BulkSetPendingMDMHostProfilesFunc = func(ctx context.Context, hostIDs, teamIDs []uint, profileUUIDs, hostUUIDs []string,
	) (updates mobius.MDMProfilesUpdates, err error) {
		return mobius.MDMProfilesUpdates{}, nil
	}
	ds.NewJobFunc = func(ctx context.Context, job *mobius.Job) (*mobius.Job, error) {
		return job, nil
	}
	ds.NewMDMAppleConfigProfileFunc = func(ctx context.Context, profile mobius.MDMAppleConfigProfile, vars []string) (*mobius.MDMAppleConfigProfile, error) {
		return &profile, nil
	}
	ds.NewMDMAppleDeclarationFunc = func(ctx context.Context, declaration *mobius.MDMAppleDeclaration) (*mobius.MDMAppleDeclaration, error) {
		return declaration, nil
	}
	ds.LabelIDsByNameFunc = func(ctx context.Context, labels []string) (map[string]uint, error) {
		require.ElementsMatch(t, labels, []string{mobius.BuiltinLabelMacOS14Plus})
		return map[string]uint{mobius.BuiltinLabelMacOS14Plus: 1}, nil
	}
	ds.SetOrUpdateMDMAppleDeclarationFunc = func(ctx context.Context, declaration *mobius.MDMAppleDeclaration) (*mobius.MDMAppleDeclaration, error) {
		declaration.DeclarationUUID = uuid.NewString()
		return declaration, nil
	}
	ds.DeleteMDMAppleDeclarationByNameFunc = func(ctx context.Context, teamID *uint, name string) error {
		return nil
	}
	ds.GetMDMAppleBootstrapPackageMetaFunc = func(ctx context.Context, teamID uint) (*mobius.MDMAppleBootstrapPackage, error) {
		return &mobius.MDMAppleBootstrapPackage{}, nil
	}
	ds.DeleteMDMAppleBootstrapPackageFunc = func(ctx context.Context, teamID uint) error {
		return nil
	}
	ds.GetMDMAppleSetupAssistantFunc = func(ctx context.Context, teamID *uint) (*mobius.MDMAppleSetupAssistant, error) {
		return nil, nil
	}
	ds.DeleteMDMAppleSetupAssistantFunc = func(ctx context.Context, teamID *uint) error {
		return nil
	}
	ds.GetSoftwareCategoryIDsFunc = func(ctx context.Context, names []string) ([]uint, error) {
		return []uint{}, nil
	}

	// Team
	var savedTeam *mobius.Team
	ds.TeamByNameFunc = func(ctx context.Context, name string) (*mobius.Team, error) {
		if name == "Conflict" {
			return &mobius.Team{}, nil
		}
		if savedTeam != nil && savedTeam.Name == name {
			return savedTeam, nil
		}
		return nil, &notFoundError{}
	}
	ds.TeamByFilenameFunc = func(ctx context.Context, filename string) (*mobius.Team, error) {
		if savedTeam != nil && *savedTeam.Filename == filename {
			return savedTeam, nil
		}
		return nil, &notFoundError{}
	}
	ds.TeamFunc = func(ctx context.Context, tid uint) (*mobius.Team, error) {
		if tid == savedTeam.ID {
			return savedTeam, nil
		}
		return nil, nil
	}
	ds.IsEnrollSecretAvailableFunc = func(ctx context.Context, secret string, isNew bool, teamID *uint) (bool, error) {
		return true, nil
	}
	const teamID = uint(123)
	var enrolledSecrets []*mobius.EnrollSecret
	ds.NewTeamFunc = func(ctx context.Context, newTeam *mobius.Team) (*mobius.Team, error) {
		newTeam.ID = teamID
		savedTeam = newTeam
		enrolledSecrets = newTeam.Secrets
		return newTeam, nil
	}
	ds.SaveTeamFunc = func(ctx context.Context, team *mobius.Team) (*mobius.Team, error) {
		if team.ID == teamID {
			savedTeam = team
		} else {
			assert.Fail(t, "unexpected team ID when saving team")
		}
		return team, nil
	}

	ds.GetTeamsWithInstallerByHashFunc = func(ctx context.Context, sha256, url string) (map[uint]*mobius.ExistingSoftwareInstaller, error) {
		return map[uint]*mobius.ExistingSoftwareInstaller{}, nil
	}

	// Policies
	policy := mobius.Policy{}
	policy.ID = 1
	policy.Name = "Policy to delete"
	policy.TeamID = ptr.Uint(teamID)
	policyDeleted := false
	ds.ListTeamPoliciesFunc = func(
		ctx context.Context, teamID uint, opts mobius.ListOptions, iopts mobius.ListOptions,
	) (teamPolicies []*mobius.Policy, inheritedPolicies []*mobius.Policy, err error) {
		if teamID != 0 {
			return []*mobius.Policy{&policy}, nil, nil
		}
		return nil, nil, nil
	}
	ds.PoliciesByIDFunc = func(ctx context.Context, ids []uint) (map[uint]*mobius.Policy, error) {
		if slices.Contains(ids, 1) {
			return map[uint]*mobius.Policy{1: &policy}, nil
		}
		return nil, nil
	}
	ds.DeleteTeamPoliciesFunc = func(ctx context.Context, teamID uint, IDs []uint) ([]uint, error) {
		policyDeleted = true
		assert.Equal(t, []uint{policy.ID}, IDs)
		return []uint{policy.ID}, nil
	}
	var appliedPolicySpecs []*mobius.PolicySpec
	ds.ApplyPolicySpecsFunc = func(ctx context.Context, authorID uint, specs []*mobius.PolicySpec) error {
		appliedPolicySpecs = specs
		return nil
	}

	ds.ExpandEmbeddedSecretsAndUpdatedAtFunc = func(ctx context.Context, document string) (string, *time.Time, error) {
		return document, nil, nil
	}

	// Queries
	query := mobius.Query{}
	query.ID = 1
	query.TeamID = ptr.Uint(teamID)
	query.Name = "Query to delete"
	queryDeleted := false
	ds.ListQueriesFunc = func(ctx context.Context, opts mobius.ListQueryOptions) ([]*mobius.Query, int, *mobius.PaginationMetadata, error) {
		return []*mobius.Query{&query}, 1, nil, nil
	}
	ds.DeleteQueriesFunc = func(ctx context.Context, ids []uint) (uint, error) {
		queryDeleted = true
		assert.Equal(t, []uint{query.ID}, ids)
		return 1, nil
	}
	ds.QueryFunc = func(ctx context.Context, id uint) (*mobius.Query, error) {
		if id == query.ID {
			return &query, nil
		}
		return nil, nil
	}
	var appliedQueries []*mobius.Query
	ds.QueryByNameFunc = func(ctx context.Context, teamID *uint, name string) (*mobius.Query, error) {
		return nil, &notFoundError{}
	}
	ds.ApplyQueriesFunc = func(
		ctx context.Context, authorID uint, queries []*mobius.Query, queriesToDiscardResults map[uint]struct{},
	) error {
		appliedQueries = queries
		return nil
	}

	testing_utils.AddLabelMocks(ds)

	var appliedSoftwareInstallers []*mobius.UploadSoftwareInstallerPayload
	ds.BatchSetSoftwareInstallersFunc = func(ctx context.Context, teamID *uint, installers []*mobius.UploadSoftwareInstallerPayload) error {
		if teamID != nil && *teamID != 0 {
			appliedSoftwareInstallers = installers
		}
		return nil
	}
	ds.GetSoftwareInstallersFunc = func(ctx context.Context, tmID uint) ([]mobius.SoftwarePackageResponse, error) {
		return nil, nil
	}
	ds.SetTeamVPPAppsFunc = func(ctx context.Context, teamID *uint, adamIDs []mobius.VPPAppTeam) error {
		return nil
	}
	ds.BatchInsertVPPAppsFunc = func(ctx context.Context, apps []*mobius.VPPApp) error {
		return nil
	}
	ds.ApplyEnrollSecretsFunc = func(ctx context.Context, teamID *uint, secrets []*mobius.EnrollSecret) error {
		enrolledSecrets = secrets
		return nil
	}
	ds.ListSoftwareTitlesFunc = func(ctx context.Context, opt mobius.SoftwareTitleListOptions, tmFilter mobius.TeamFilter) ([]mobius.SoftwareTitleListResult, int, *mobius.PaginationMetadata, error) {
		return nil, 0, nil, nil
	}
	ds.DeleteSetupExperienceScriptFunc = func(ctx context.Context, teamID *uint) error {
		return nil
	}

	testing_utils.StartSoftwareInstallerServer(t)

	t.Setenv("TEST_TEAM_NAME", teamName)

	// Dry run
	const baseFilename = "team_config_no_paths.yml"
	gitopsFile := "./testdata/gitops/" + baseFilename
	_ = RunAppForTest(t, []string{"gitops", "-f", gitopsFile, "--dry-run"})
	assert.Nil(t, savedTeam)
	assert.Len(t, enrolledSecrets, 0)
	assert.Len(t, appliedPolicySpecs, 0)
	assert.Len(t, appliedQueries, 0)
	assert.Len(t, appliedScripts, 0)
	assert.Len(t, appliedMacProfiles, 0)
	assert.Len(t, appliedWinProfiles, 0)
	assert.Empty(t, appliedSoftwareInstallers)

	// Real run
	// Setting global calendar config
	appConfig.Integrations = mobius.Integrations{
		GoogleCalendar: []*mobius.GoogleCalendarIntegration{{}},
	}
	_ = RunAppForTest(t, []string{"gitops", "-f", gitopsFile})
	require.NotNil(t, savedTeam)
	assert.Equal(t, teamName, savedTeam.Name)
	assert.Contains(t, string(*savedTeam.Config.AgentOptions), "distributed_denylist_duration")
	assert.True(t, savedTeam.Config.Features.EnableHostUsers)
	assert.Equal(t, 30, savedTeam.Config.HostExpirySettings.HostExpiryWindow)
	assert.True(t, savedTeam.Config.MDM.EnableDiskEncryption)
	assert.Len(t, enrolledSecrets, 2)
	assert.True(t, policyDeleted)
	assert.Len(t, appliedPolicySpecs, 5)
	assert.True(t, queryDeleted)
	assert.Len(t, appliedQueries, 3)
	assert.Len(t, appliedScripts, 1)
	assert.Len(t, appliedMacProfiles, 1)
	assert.Len(t, appliedWinProfiles, 1)
	assert.True(t, savedTeam.Config.WebhookSettings.HostStatusWebhook.Enable)
	assert.Equal(t, "https://example.com/host_status_webhook", savedTeam.Config.WebhookSettings.HostStatusWebhook.DestinationURL)
	require.NotNil(t, savedTeam.Config.Integrations.GoogleCalendar)
	assert.True(t, savedTeam.Config.Integrations.GoogleCalendar.Enable)
	assert.Equal(t, baseFilename, *savedTeam.Filename)
	require.Len(t, appliedSoftwareInstallers, 2)
	packageID := `"ruby"`
	uninstallScriptProcessed := strings.ReplaceAll(file.GetUninstallScript("deb"), "$PACKAGE_ID", packageID)
	assert.ElementsMatch(t, []string{fmt.Sprintf("echo 'uninstall' %s\n", packageID), uninstallScriptProcessed},
		[]string{appliedSoftwareInstallers[0].UninstallScript, appliedSoftwareInstallers[1].UninstallScript})

	// Change team name
	newTeamName := "New Team Name"
	t.Setenv("TEST_TEAM_NAME", newTeamName)
	_ = RunAppForTest(t, []string{"gitops", "-f", gitopsFile, "--dry-run"})
	_ = RunAppForTest(t, []string{"gitops", "-f", gitopsFile})
	require.NotNil(t, savedTeam)
	assert.Equal(t, newTeamName, savedTeam.Name)
	assert.Equal(t, baseFilename, *savedTeam.Filename)

	// Try to change team name again, but this time the new name conflicts with an existing team
	t.Setenv("TEST_TEAM_NAME", "Conflict")
	_, err = RunAppNoChecks([]string{"gitops", "-f", gitopsFile, "--dry-run"})
	assert.ErrorContains(t, err, "team name already exists")
	_, err = RunAppNoChecks([]string{"gitops", "-f", gitopsFile})
	assert.ErrorContains(t, err, "team name already exists")

	// Now clear the settings
	t.Setenv("TEST_TEAM_NAME", newTeamName)
	tmpFile, err := os.CreateTemp(t.TempDir(), "*.yml")
	require.NoError(t, err)
	secret := "TestSecret"
	t.Setenv("TEST_SECRET", secret)

	_, err = tmpFile.WriteString(
		`
controls:
queries:
policies:
agent_options:
name: ${TEST_TEAM_NAME}
team_settings:
  secrets: [{"secret":"${TEST_SECRET}"}]
software:
`,
	)
	require.NoError(t, err)

	// Dry run
	savedTeam = nil
	_ = RunAppForTest(t, []string{"gitops", "-f", tmpFile.Name(), "--dry-run"})
	assert.Nil(t, savedTeam)

	// Real run
	_ = RunAppForTest(t, []string{"gitops", "-f", tmpFile.Name()})
	require.NotNil(t, savedTeam)
	assert.Equal(t, newTeamName, savedTeam.Name)
	require.Len(t, enrolledSecrets, 1)
	assert.Equal(t, secret, enrolledSecrets[0].Secret)
	assert.False(t, savedTeam.Config.WebhookSettings.HostStatusWebhook.Enable)
	assert.Equal(t, "", savedTeam.Config.WebhookSettings.HostStatusWebhook.DestinationURL)
	assert.NotNil(t, savedTeam.Config.Integrations.GoogleCalendar)
	assert.False(t, savedTeam.Config.Integrations.GoogleCalendar.Enable)
	assert.Empty(t, savedTeam.Config.Integrations.GoogleCalendar)
	assert.Empty(t, savedTeam.Config.MDM.MacOSSettings.CustomSettings)
	assert.Empty(t, savedTeam.Config.MDM.WindowsSettings.CustomSettings.Value)
	assert.Empty(t, savedTeam.Config.MDM.MacOSUpdates.Deadline.Value)
	assert.Empty(t, savedTeam.Config.MDM.MacOSUpdates.MinimumVersion.Value)
	assert.Empty(t, savedTeam.Config.MDM.MacOSSetup.BootstrapPackage.Value)
	assert.False(t, savedTeam.Config.MDM.EnableDiskEncryption)
	assert.Equal(t, filepath.Base(tmpFile.Name()), *savedTeam.Filename)
}

func createFakeITunesAndVPPServices(t *testing.T) {
	config := &testing_utils.AppleVPPConfigSrvConf{
		Assets: []vpp.Asset{
			{
				AdamID:         "1",
				PricingParam:   "STDQ",
				AvailableCount: 12,
			},
			{
				AdamID:         "2",
				PricingParam:   "STDQ",
				AvailableCount: 3,
			},
		},
		SerialNumbers: []string{"123", "456"},
	}
	testing_utils.StartVPPApplyServer(t, config)

	appleITunesSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// a map of apps we can respond with
		db := map[string]string{
			// macos app
			"1": `{"bundleId": "a-1", "artworkUrl512": "https://example.com/images/1", "version": "1.0.0", "trackName": "App 1", "TrackID": 1}`,
			// macos, ios, ipados app
			"2": `{"bundleId": "b-2", "artworkUrl512": "https://example.com/images/2", "version": "2.0.0", "trackName": "App 2", "TrackID": 2,
				"supportedDevices": ["MacDesktop-MacDesktop", "iPhone5s-iPhone5s", "iPadAir-iPadAir"] }`,
			// ipados app
			"3": `{"bundleId": "c-3", "artworkUrl512": "https://example.com/images/3", "version": "3.0.0", "trackName": "App 3", "TrackID": 3,
				"supportedDevices": ["iPadAir-iPadAir"] }`,
		}

		adamIDString := r.URL.Query().Get("id")
		adamIDs := strings.Split(adamIDString, ",")

		var objs []string
		for _, a := range adamIDs {
			objs = append(objs, db[a])
		}

		_, _ = w.Write([]byte(fmt.Sprintf(`{"results": [%s]}`, strings.Join(objs, ","))))
	}))
	t.Setenv("MOBIUS_DEV_ITUNES_URL", appleITunesSrv.URL)
}

func TestGitOpsBasicGlobalAndTeam(t *testing.T) {
	// Cannot run t.Parallel() because it sets environment variables
	license := &mobius.LicenseInfo{Tier: mobius.TierPremium, Expiration: time.Now().Add(24 * time.Hour)}
	_, ds := testing_utils.RunServerWithMockedDS(
		t, &service.TestServerOpts{
			License:       license,
			KeyValueStore: testing_utils.NewMemKeyValueStore(),
		},
	)

	// Mock appConfig
	savedAppConfig := &mobius.AppConfig{}
	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		appConfig := savedAppConfig.Copy()
		return appConfig, nil
	}
	ds.SaveAppConfigFunc = func(ctx context.Context, config *mobius.AppConfig) error {
		savedAppConfig = config
		return nil
	}

	ds.SetTeamVPPAppsFunc = func(ctx context.Context, teamID *uint, adamIDs []mobius.VPPAppTeam) error {
		return nil
	}
	ds.BatchInsertVPPAppsFunc = func(ctx context.Context, apps []*mobius.VPPApp) error {
		return nil
	}
	ds.GetVPPAppsFunc = func(ctx context.Context, teamID *uint) ([]mobius.VPPAppResponse, error) {
		return []mobius.VPPAppResponse{}, nil
	}

	const (
		mobiusServerURL = "https://mobius.example.com"
		orgName        = "GitOps Test"
		secret         = "TestSecret"
	)
	var enrolledSecrets []*mobius.EnrollSecret
	var enrolledTeamSecrets []*mobius.EnrollSecret
	var savedTeam *mobius.Team
	team := &mobius.Team{
		ID:        1,
		CreatedAt: time.Now(),
		Name:      teamName,
	}

	ds.IsEnrollSecretAvailableFunc = func(ctx context.Context, secret string, isNew bool, teamID *uint) (bool, error) {
		return true, nil
	}
	ds.ApplyEnrollSecretsFunc = func(ctx context.Context, teamID *uint, secrets []*mobius.EnrollSecret) error {
		if teamID == nil {
			enrolledSecrets = secrets
		} else {
			enrolledTeamSecrets = secrets
		}
		return nil
	}
	ds.BatchSetMDMProfilesFunc = func(
		ctx context.Context, tmID *uint, macProfiles []*mobius.MDMAppleConfigProfile, winProfiles []*mobius.MDMWindowsConfigProfile,
		macDecls []*mobius.MDMAppleDeclaration, vars []mobius.MDMProfileIdentifierMobiusVariables,
	) (updates mobius.MDMProfilesUpdates, err error) {
		assert.Empty(t, macProfiles)
		assert.Empty(t, winProfiles)
		return mobius.MDMProfilesUpdates{}, nil
	}
	ds.BatchSetScriptsFunc = func(ctx context.Context, tmID *uint, scripts []*mobius.Script) ([]mobius.ScriptResponse, error) {
		assert.Empty(t, scripts)
		return []mobius.ScriptResponse{}, nil
	}
	ds.BulkSetPendingMDMHostProfilesFunc = func(
		ctx context.Context, hostIDs []uint, teamIDs []uint, profileUUIDs []string, hostUUIDs []string,
	) (updates mobius.MDMProfilesUpdates, err error) {
		assert.Empty(t, profileUUIDs)
		return mobius.MDMProfilesUpdates{}, nil
	}
	ds.DeleteMDMAppleDeclarationByNameFunc = func(ctx context.Context, teamID *uint, name string) error {
		return nil
	}
	ds.LabelIDsByNameFunc = func(ctx context.Context, labels []string) (map[string]uint, error) {
		require.ElementsMatch(t, labels, []string{mobius.BuiltinLabelMacOS14Plus})
		return map[string]uint{mobius.BuiltinLabelMacOS14Plus: 1}, nil
	}
	ds.ListGlobalPoliciesFunc = func(ctx context.Context, opts mobius.ListOptions) ([]*mobius.Policy, error) { return nil, nil }
	ds.ListTeamPoliciesFunc = func(
		ctx context.Context, teamID uint, opts mobius.ListOptions, iopts mobius.ListOptions,
	) (teamPolicies []*mobius.Policy, inheritedPolicies []*mobius.Policy, err error) {
		return nil, nil, nil
	}
	ds.ListTeamsFunc = func(ctx context.Context, filter mobius.TeamFilter, opt mobius.ListOptions) ([]*mobius.Team, error) {
		if savedTeam != nil {
			return []*mobius.Team{savedTeam}, nil
		}
		return nil, nil
	}
	ds.ListQueriesFunc = func(ctx context.Context, opts mobius.ListQueryOptions) ([]*mobius.Query, int, *mobius.PaginationMetadata, error) {
		return nil, 0, nil, nil
	}

	testing_utils.AddLabelMocks(ds)

	ds.NewActivityFunc = func(
		ctx context.Context, user *mobius.User, activity mobius.ActivityDetails, details []byte, createdAt time.Time,
	) error {
		return nil
	}
	ds.NewJobFunc = func(ctx context.Context, job *mobius.Job) (*mobius.Job, error) {
		job.ID = 1
		return job, nil
	}
	ds.TeamFunc = func(ctx context.Context, tid uint) (*mobius.Team, error) {
		if tid == team.ID {
			return savedTeam, nil
		}
		return nil, nil
	}
	ds.TeamByNameFunc = func(ctx context.Context, name string) (*mobius.Team, error) {
		if name == teamName && savedTeam != nil {
			return savedTeam, nil
		}
		return nil, &notFoundError{}
	}
	ds.TeamByFilenameFunc = func(ctx context.Context, filename string) (*mobius.Team, error) {
		if savedTeam != nil && *savedTeam.Filename == filename {
			return savedTeam, nil
		}
		return nil, &notFoundError{}
	}
	ds.NewTeamFunc = func(ctx context.Context, newTeam *mobius.Team) (*mobius.Team, error) {
		newTeam.ID = team.ID
		savedTeam = newTeam
		enrolledTeamSecrets = newTeam.Secrets
		return newTeam, nil
	}
	ds.SaveTeamFunc = func(ctx context.Context, team *mobius.Team) (*mobius.Team, error) {
		savedTeam = team
		return team, nil
	}
	ds.BatchSetSoftwareInstallersFunc = func(ctx context.Context, teamID *uint, installers []*mobius.UploadSoftwareInstallerPayload) error {
		return nil
	}
	ds.GetSoftwareInstallersFunc = func(ctx context.Context, tmID uint) ([]mobius.SoftwarePackageResponse, error) {
		return nil, nil
	}
	ds.ListSoftwareTitlesFunc = func(ctx context.Context, opt mobius.SoftwareTitleListOptions, tmFilter mobius.TeamFilter) ([]mobius.SoftwareTitleListResult, int, *mobius.PaginationMetadata, error) {
		return nil, 0, nil, nil
	}

	ds.SaveABMTokenFunc = func(ctx context.Context, tok *mobius.ABMToken) error {
		return nil
	}

	vppToken := &mobius.VPPTokenDB{
		Location:  "Foobar",
		RenewDate: time.Now().Add(24 * 365 * time.Hour),
	}
	ds.ListVPPTokensFunc = func(ctx context.Context) ([]*mobius.VPPTokenDB, error) {
		return []*mobius.VPPTokenDB{vppToken}, nil
	}

	ds.ListABMTokensFunc = func(ctx context.Context) ([]*mobius.ABMToken, error) {
		return []*mobius.ABMToken{}, nil
	}
	ds.GetABMTokenCountFunc = func(ctx context.Context) (int, error) {
		return 0, nil
	}
	ds.DeleteSetupExperienceScriptFunc = func(ctx context.Context, teamID *uint) error {
		return nil
	}

	ds.TeamsSummaryFunc = func(ctx context.Context) ([]*mobius.TeamSummary, error) {
		var teamsSummary []*mobius.TeamSummary
		if savedTeam != nil {
			teamsSummary = append(teamsSummary, &mobius.TeamSummary{
				ID:          savedTeam.ID,
				Name:        savedTeam.Name,
				Description: savedTeam.Description,
			})
		}
		return teamsSummary, nil
	}

	ds.GetVPPTokenByTeamIDFunc = func(ctx context.Context, teamID *uint) (*mobius.VPPTokenDB, error) {
		if teamID != nil && *teamID == savedTeam.ID {
			return vppToken, nil
		}
		return nil, &notFoundError{}
	}

	ds.UpdateVPPTokenTeamsFunc = func(ctx context.Context, id uint, teams []uint) (*mobius.VPPTokenDB, error) {
		return vppToken, nil
	}
	ds.GetSoftwareCategoryIDsFunc = func(ctx context.Context, names []string) ([]uint, error) {
		return []uint{}, nil
	}

	createFakeITunesAndVPPServices(t)

	globalFile, err := os.CreateTemp(t.TempDir(), "*.yml")
	require.NoError(t, err)

	t.Setenv("MOBIUS_SERVER_URL", mobiusServerURL)
	t.Setenv("ORG_NAME", orgName)
	t.Setenv("TEST_TEAM_NAME", teamName)
	t.Setenv("TEST_SECRET", secret)

	_, err = globalFile.WriteString(
		`
controls:
queries:
policies:
agent_options:
org_settings:
  server_settings:
    server_url: $MOBIUS_SERVER_URL
  org_info:
    contact_url: https://example.com/contact
    org_logo_url: ""
    org_logo_url_light_background: ""
    org_name: ${ORG_NAME}
  mdm:
    volume_purchasing_program:
    - location: Foobar
      teams:
      - "${TEST_TEAM_NAME}"
  secrets: [{"secret":"globalSecret"}]
software:
`,
	)
	require.NoError(t, err)

	teamFile, err := os.CreateTemp(t.TempDir(), "*.yml")
	require.NoError(t, err)

	_, err = teamFile.WriteString(
		`
controls:
queries:
policies:
agent_options:
name: ${TEST_TEAM_NAME}
team_settings:
  secrets: [{"secret":"${TEST_SECRET}"}]
software:
  app_store_apps:
    - app_store_id: '1'
`,
	)
	require.NoError(t, err)

	teamFileDupSecret, err := os.CreateTemp(t.TempDir(), "*.yml")
	require.NoError(t, err)
	_, err = teamFileDupSecret.WriteString(
		`
controls:
queries:
policies:
agent_options:
name: ${TEST_TEAM_NAME}
team_settings:
  secrets: [{"secret":"${TEST_SECRET}"},{"secret":"globalSecret"}]
software:
`,
	)
	require.NoError(t, err)

	// Files out of order
	_, err = RunAppNoChecks([]string{"gitops", "-f", teamFile.Name(), "-f", globalFile.Name(), "--dry-run"})
	require.NoError(t, err)

	// No global file, only team file
	_, err = RunAppNoChecks([]string{"gitops", "-f", teamFile.Name(), "--dry-run"})
	require.NoError(t, err)

	// Global file specified multiple times
	_, err = RunAppNoChecks([]string{"gitops", "-f", globalFile.Name(), "-f", teamFile.Name(), "-f", globalFile.Name(), "--dry-run"})
	require.Error(t, err)
	fmt.Printf("err.Error(): %v\n", err.Error())
	assert.Contains(t, err.Error(), "only one global config file may be provided")

	// Duplicate secret
	_, err = RunAppNoChecks([]string{"gitops", "-f", globalFile.Name(), "-f", teamFileDupSecret.Name(), "--dry-run"})
	require.Error(t, err)
	assert.ErrorContains(t, err, "duplicate enroll secret found")

	ds.GetVPPTokenByTeamIDFuncInvoked = false

	// Dry run
	_ = RunAppForTest(t, []string{"gitops", "-f", globalFile.Name(), "-f", teamFile.Name(), "--dry-run"})
	assert.Equal(t, mobius.AppConfig{}, *savedAppConfig, "AppConfig should be empty")

	// Dry run should not attempt to get the VPP token when applying VPP apps (it may not exist).
	require.False(t, ds.GetVPPTokenByTeamIDFuncInvoked)
	ds.ListTeamsFuncInvoked = false

	// Dry run, deleting other teams
	savedAppConfig = &mobius.AppConfig{}
	_ = RunAppForTest(t, []string{"gitops", "-f", globalFile.Name(), "-f", teamFile.Name(), "--dry-run", "--delete-other-teams"})
	assert.Equal(t, mobius.AppConfig{}, *savedAppConfig, "AppConfig should be empty")
	assert.True(t, ds.ListTeamsFuncInvoked)

	// Real run
	_ = RunAppForTest(t, []string{"gitops", "-f", globalFile.Name(), "-f", teamFile.Name()})
	assert.Equal(t, orgName, savedAppConfig.OrgInfo.OrgName)
	assert.Equal(t, mobiusServerURL, savedAppConfig.ServerSettings.ServerURL)
	assert.Len(t, enrolledSecrets, 1)
	require.NotNil(t, savedTeam)
	assert.Equal(t, teamName, savedTeam.Name)
	require.Len(t, enrolledTeamSecrets, 1)
	assert.Equal(t, secret, enrolledTeamSecrets[0].Secret)

	// Dry run again (after team was created by real run)
	ds.GetVPPTokenByTeamIDFuncInvoked = false
	_ = RunAppForTest(t, []string{"gitops", "-f", globalFile.Name(), "-f", teamFile.Name(), "--dry-run"})
	// Dry run should not attempt to get the VPP token when applying VPP apps (it may not exist).
	require.False(t, ds.GetVPPTokenByTeamIDFuncInvoked)

	// Now, set  up a team to delete
	teamToDeleteID := uint(999)
	teamToDelete := &mobius.Team{
		ID:        teamToDeleteID,
		CreatedAt: time.Now(),
		Name:      "Team to delete",
	}
	ds.ListTeamsFuncInvoked = false
	ds.ListTeamsFunc = func(ctx context.Context, filter mobius.TeamFilter, opt mobius.ListOptions) ([]*mobius.Team, error) {
		return []*mobius.Team{teamToDelete, team}, nil
	}
	ds.TeamFunc = func(ctx context.Context, tid uint) (*mobius.Team, error) {
		switch tid {
		case team.ID:
			return team, nil
		case teamToDeleteID:
			return teamToDelete, nil
		}
		assert.Fail(t, fmt.Sprintf("unexpected team ID %d", tid))
		return teamToDelete, nil
	}
	ds.DeleteTeamFunc = func(ctx context.Context, tid uint) error {
		assert.Equal(t, teamToDeleteID, tid)
		return nil
	}
	ds.ListHostsFunc = func(ctx context.Context, filter mobius.TeamFilter, opt mobius.HostListOptions) ([]*mobius.Host, error) {
		return nil, nil
	}

	// Real run, deleting other teams
	_ = RunAppForTest(t, []string{"gitops", "-f", globalFile.Name(), "-f", teamFile.Name(), "--delete-other-teams"})
	assert.True(t, ds.ListTeamsFuncInvoked)
	assert.True(t, ds.DeleteTeamFuncInvoked)
}

func TestGitOpsBasicGlobalAndNoTeam(t *testing.T) {
	// Cannot run t.Parallel() because runServerWithMockedDS sets the MOBIUS_SERVER_ADDRESS
	// environment variable.

	license := &mobius.LicenseInfo{Tier: mobius.TierPremium, Expiration: time.Now().Add(24 * time.Hour)}
	_, ds := testing_utils.RunServerWithMockedDS(
		t, &service.TestServerOpts{
			License:       license,
			KeyValueStore: testing_utils.NewMemKeyValueStore(),
		},
	)
	// Mock appConfig
	savedAppConfig := &mobius.AppConfig{}
	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		return &mobius.AppConfig{}, nil
	}
	ds.SaveAppConfigFunc = func(ctx context.Context, config *mobius.AppConfig) error {
		savedAppConfig = config
		return nil
	}
	ds.SetTeamVPPAppsFunc = func(ctx context.Context, teamID *uint, adamIDs []mobius.VPPAppTeam) error {
		return nil
	}
	ds.BatchInsertVPPAppsFunc = func(ctx context.Context, apps []*mobius.VPPApp) error {
		return nil
	}

	const (
		mobiusServerURL = "https://mobius.example.com"
		orgName        = "GitOps Test"
		secret         = "TestSecret"
	)
	var enrolledSecrets []*mobius.EnrollSecret
	var enrolledTeamSecrets []*mobius.EnrollSecret
	var savedTeam *mobius.Team
	team := &mobius.Team{
		ID:        1,
		CreatedAt: time.Now(),
		Name:      teamName,
	}

	ds.IsEnrollSecretAvailableFunc = func(ctx context.Context, secret string, isNew bool, teamID *uint) (bool, error) {
		return true, nil
	}
	ds.ApplyEnrollSecretsFunc = func(ctx context.Context, teamID *uint, secrets []*mobius.EnrollSecret) error {
		if teamID == nil {
			enrolledSecrets = secrets
		} else {
			enrolledTeamSecrets = secrets
		}
		return nil
	}
	ds.BatchSetMDMProfilesFunc = func(
		ctx context.Context, tmID *uint, macProfiles []*mobius.MDMAppleConfigProfile, winProfiles []*mobius.MDMWindowsConfigProfile,
		macDecls []*mobius.MDMAppleDeclaration, vars []mobius.MDMProfileIdentifierMobiusVariables,
	) (updates mobius.MDMProfilesUpdates, err error) {
		assert.Empty(t, macProfiles)
		assert.Empty(t, winProfiles)
		return mobius.MDMProfilesUpdates{}, nil
	}
	ds.BatchSetScriptsFunc = func(ctx context.Context, tmID *uint, scripts []*mobius.Script) ([]mobius.ScriptResponse, error) {
		assert.Empty(t, scripts)
		return []mobius.ScriptResponse{}, nil
	}
	ds.BulkSetPendingMDMHostProfilesFunc = func(
		ctx context.Context, hostIDs []uint, teamIDs []uint, profileUUIDs []string, hostUUIDs []string,
	) (updates mobius.MDMProfilesUpdates, err error) {
		assert.Empty(t, profileUUIDs)
		return mobius.MDMProfilesUpdates{}, nil
	}
	ds.DeleteMDMAppleDeclarationByNameFunc = func(ctx context.Context, teamID *uint, name string) error {
		return nil
	}
	ds.LabelIDsByNameFunc = func(ctx context.Context, labels []string) (map[string]uint, error) {
		require.ElementsMatch(t, labels, []string{mobius.BuiltinLabelMacOS14Plus})
		return map[string]uint{mobius.BuiltinLabelMacOS14Plus: 1}, nil
	}
	ds.ListGlobalPoliciesFunc = func(ctx context.Context, opts mobius.ListOptions) ([]*mobius.Policy, error) { return nil, nil }
	ds.ListTeamPoliciesFunc = func(
		ctx context.Context, teamID uint, opts mobius.ListOptions, iopts mobius.ListOptions,
	) (teamPolicies []*mobius.Policy, inheritedPolicies []*mobius.Policy, err error) {
		return nil, nil, nil
	}
	ds.ListTeamsFunc = func(ctx context.Context, filter mobius.TeamFilter, opt mobius.ListOptions) ([]*mobius.Team, error) {
		return nil, nil
	}
	ds.ListQueriesFunc = func(ctx context.Context, opts mobius.ListQueryOptions) ([]*mobius.Query, int, *mobius.PaginationMetadata, error) {
		return nil, 0, nil, nil
	}
	testing_utils.AddLabelMocks(ds)

	ds.NewActivityFunc = func(
		ctx context.Context, user *mobius.User, activity mobius.ActivityDetails, details []byte, createdAt time.Time,
	) error {
		return nil
	}
	ds.NewJobFunc = func(ctx context.Context, job *mobius.Job) (*mobius.Job, error) {
		job.ID = 1
		return job, nil
	}
	ds.TeamFunc = func(ctx context.Context, tid uint) (*mobius.Team, error) {
		if tid == team.ID {
			return savedTeam, nil
		}
		return nil, nil
	}
	ds.TeamByNameFunc = func(ctx context.Context, name string) (*mobius.Team, error) {
		if name == teamName && savedTeam != nil {
			return savedTeam, nil
		}
		return nil, &notFoundError{}
	}
	ds.TeamByFilenameFunc = func(ctx context.Context, filename string) (*mobius.Team, error) {
		if savedTeam != nil && *savedTeam.Filename == filename {
			return savedTeam, nil
		}
		return nil, &notFoundError{}
	}
	ds.NewTeamFunc = func(ctx context.Context, newTeam *mobius.Team) (*mobius.Team, error) {
		newTeam.ID = team.ID
		savedTeam = newTeam
		enrolledTeamSecrets = newTeam.Secrets
		return newTeam, nil
	}
	ds.SaveTeamFunc = func(ctx context.Context, team *mobius.Team) (*mobius.Team, error) {
		savedTeam = team
		return team, nil
	}
	ds.BatchSetSoftwareInstallersFunc = func(ctx context.Context, teamID *uint, installers []*mobius.UploadSoftwareInstallerPayload) error {
		return nil
	}
	ds.GetSoftwareInstallersFunc = func(ctx context.Context, tmID uint) ([]mobius.SoftwarePackageResponse, error) {
		return nil, nil
	}
	ds.ListSoftwareTitlesFunc = func(ctx context.Context, opt mobius.SoftwareTitleListOptions, tmFilter mobius.TeamFilter) ([]mobius.SoftwareTitleListResult, int, *mobius.PaginationMetadata, error) {
		return nil, 0, nil, nil
	}

	ds.SaveABMTokenFunc = func(ctx context.Context, tok *mobius.ABMToken) error {
		return nil
	}

	ds.ListVPPTokensFunc = func(ctx context.Context) ([]*mobius.VPPTokenDB, error) {
		return []*mobius.VPPTokenDB{}, nil
	}

	ds.ListABMTokensFunc = func(ctx context.Context) ([]*mobius.ABMToken, error) {
		return []*mobius.ABMToken{}, nil
	}
	ds.DeleteSetupExperienceScriptFunc = func(ctx context.Context, teamID *uint) error {
		return nil
	}

	globalFileBasic := createGlobalFileBasic(t, mobiusServerURL, orgName)

	teamFileBasic := createTeamFileBasic(t, secret)

	// We cannot use os.CreateTemp because the filename must be exactly "no-team.yml"
	noTeamFilePath := filepath.Join(t.TempDir(), "no-team.yml")
	noTeamFileBasic, err := os.Create(noTeamFilePath)
	require.NoError(t, err)
	_, err = noTeamFileBasic.WriteString(`
controls:
policies:
name: No team
software:
`)
	require.NoError(t, err)

	t.Run("global defines software -- should fail", func(t *testing.T) {
		globalFileWithSoftware, err := os.CreateTemp(t.TempDir(), "*.yml")
		require.NoError(t, err)
		_, err = globalFileWithSoftware.WriteString(fmt.Sprintf(
			`
controls:
queries:
policies:
agent_options:
org_settings:
  server_settings:
    server_url: %s
  org_info:
    contact_url: https://example.com/contact
    org_logo_url: ""
    org_logo_url_light_background: ""
    org_name: %s
  secrets: [{"secret":"globalSecret"}]
software:
  packages:
    - url: https://example.com
`, mobiusServerURL, orgName),
		)
		require.NoError(t, err)

		// Dry run, global defines software, should fail.
		_, err = RunAppNoChecks([]string{
			"gitops", "-f", globalFileWithSoftware.Name(), "-f", teamFileBasic.Name(), "-f",
			noTeamFileBasic.Name(),
			"--dry-run",
		})
		require.Error(t, err)
		assert.ErrorContains(t, err, "'software' cannot be set on global file")
		// Real run, global defines software, should fail.
		_, err = RunAppNoChecks([]string{
			"gitops", "-f", globalFileWithSoftware.Name(), "-f", teamFileBasic.Name(), "-f",
			noTeamFileBasic.Name(),
		})
		require.Error(t, err)
		assert.ErrorContains(t, err, "'software' cannot be set on global file")
	})

	t.Run("both global and no-team.yml define controls -- should fail", func(t *testing.T) {
		globalFileWithControls := createGlobalFileWithControls(t, mobiusServerURL, orgName)

		noTeamFilePathWithControls := filepath.Join(t.TempDir(), "no-team.yml")
		noTeamFileWithControls, err := os.Create(noTeamFilePathWithControls)
		require.NoError(t, err)
		_, err = noTeamFileWithControls.WriteString(`
controls:
  ipados_updates:
    deadline: "2023-03-03"
    minimum_version: "18.0"
policies:
name: No team
software:
`)
		require.NoError(t, err)

		// Dry run, both global and no-team.yml define controls.
		_, err = RunAppNoChecks([]string{
			"gitops", "-f", globalFileWithControls.Name(), "-f", teamFileBasic.Name(), "-f",
			noTeamFileWithControls.Name(), "--dry-run",
		})
		require.Error(t, err)
		assert.True(t, strings.Contains(err.Error(), "'controls' cannot be set on both global config and on no-team.yml"))
		// Real run, both global and no-team.yml define controls.
		_, err = RunAppNoChecks([]string{
			"gitops", "-f", globalFileWithControls.Name(), "-f", teamFileBasic.Name(), "-f",
			noTeamFileWithControls.Name(),
		})
		require.Error(t, err)
		assert.True(t, strings.Contains(err.Error(), "'controls' cannot be set on both global config and on no-team.yml"))
	})

	t.Run("no-team.yml defines policy with calendar events enabled -- should fail", func(t *testing.T) {
		globalFileWithControls := createGlobalFileWithControls(t, mobiusServerURL, orgName)

		noTeamFilePathPoliciesCalendarPath := filepath.Join(t.TempDir(), "no-team.yml")
		noTeamFilePathPoliciesCalendar, err := os.Create(noTeamFilePathPoliciesCalendarPath)
		require.NoError(t, err)
		_, err = noTeamFilePathPoliciesCalendar.WriteString(`
controls:
policies:
  - name: Foobar
    query: SELECT 1 FROM osquery_info WHERE start_time < 0;
    calendar_events_enabled: true
name: No team
software:
`)
		require.NoError(t, err)

		// Dry run, both global and no-team.yml defines policy with calendar events enabled.
		_, err = RunAppNoChecks([]string{
			"gitops", "-f", globalFileWithControls.Name(), "-f", teamFileBasic.Name(), "-f",
			noTeamFilePathPoliciesCalendar.Name(), "--dry-run",
		})
		require.Error(t, err)
		assert.True(t, strings.Contains(err.Error(), "calendar events are not supported on \"No team\" policies: \"Foobar\""), err.Error())
		// Real run, both global and no-team.yml define controls.
		_, err = RunAppNoChecks([]string{
			"gitops", "-f", globalFileWithControls.Name(), "-f", teamFileBasic.Name(), "-f",
			noTeamFilePathPoliciesCalendar.Name(),
		})
		require.Error(t, err)
		assert.True(t, strings.Contains(err.Error(), "calendar events are not supported on \"No team\" policies: \"Foobar\""), err.Error())
	})

	t.Run("global and no-team.yml DO NOT define controls -- should fail", func(t *testing.T) {
		globalFileWithoutControlsAndSoftwareKeys := createGlobalFileWithoutControlsAndSoftwareKeys(t, mobiusServerURL, orgName)

		noTeamFilePathWithoutControls := filepath.Join(t.TempDir(), "no-team.yml")
		noTeamFileWithoutControls, err := os.Create(noTeamFilePathWithoutControls)
		require.NoError(t, err)
		_, err = noTeamFileWithoutControls.WriteString(`
policies:
name: No team
software:
`)
		require.NoError(t, err)

		// Dry run, controls should be defined somewhere, either in no-team.yml or global.
		_, err = RunAppNoChecks([]string{
			"gitops", "-f", globalFileWithoutControlsAndSoftwareKeys.Name(), "-f", teamFileBasic.Name(), "-f",
			noTeamFileWithoutControls.Name(), "--dry-run",
		})
		require.Error(t, err)
		assert.True(t, strings.Contains(err.Error(), "'controls' must be set on global config or no-team.yml"))
		// Real run
		_, err = RunAppNoChecks([]string{
			"gitops", "-f", globalFileWithoutControlsAndSoftwareKeys.Name(), "-f", teamFileBasic.Name(), "-f",
			noTeamFileWithoutControls.Name(),
		})
		require.Error(t, err)
		assert.True(t, strings.Contains(err.Error(), "'controls' must be set on global config or no-team.yml"))
	})

	t.Run("controls only defined in no-team.yml", func(t *testing.T) {
		savedAppConfig = &mobius.AppConfig{}

		globalFileWithoutControlsAndSoftwareKeys := createGlobalFileWithoutControlsAndSoftwareKeys(t, mobiusServerURL, orgName)

		// Dry run, global file without controls and software keys.
		_ = RunAppForTest(t,
			[]string{
				"gitops", "-f", globalFileWithoutControlsAndSoftwareKeys.Name(), "-f", teamFileBasic.Name(), "-f",
				noTeamFileBasic.Name(),
				"--dry-run",
			})
		assert.Equal(t, mobius.AppConfig{}, *savedAppConfig, "AppConfig should be empty")

		// Real run, global file without controls and software keys.
		_ = RunAppForTest(t,
			[]string{
				"gitops", "-f", globalFileWithoutControlsAndSoftwareKeys.Name(), "-f", teamFileBasic.Name(), "-f",
				noTeamFileBasic.Name(),
			})
		assert.Equal(t, orgName, savedAppConfig.OrgInfo.OrgName)
		assert.Equal(t, mobiusServerURL, savedAppConfig.ServerSettings.ServerURL)
		assert.Len(t, enrolledSecrets, 1)
		require.NotNil(t, savedTeam)
		assert.Equal(t, teamName, savedTeam.Name)
		require.Len(t, enrolledTeamSecrets, 1)
		assert.Equal(t, secret, enrolledTeamSecrets[0].Secret)
	})

	t.Run("basic global and no-team.yml", func(t *testing.T) {
		savedAppConfig = &mobius.AppConfig{}
		// Dry run
		_ = RunAppForTest(t,
			[]string{"gitops", "-f", globalFileBasic.Name(), "-f", teamFileBasic.Name(), "-f", noTeamFileBasic.Name(), "--dry-run"})
		assert.Equal(t, mobius.AppConfig{}, *savedAppConfig, "AppConfig should be empty")
		// Real run
		_ = RunAppForTest(t, []string{"gitops", "-f", globalFileBasic.Name(), "-f", teamFileBasic.Name(), "-f", noTeamFileBasic.Name()})
		assert.Equal(t, orgName, savedAppConfig.OrgInfo.OrgName)
		assert.Equal(t, mobiusServerURL, savedAppConfig.ServerSettings.ServerURL)
		assert.Len(t, enrolledSecrets, 1)
		require.NotNil(t, savedTeam)
		assert.Equal(t, teamName, savedTeam.Name)
		require.Len(t, enrolledTeamSecrets, 1)
		assert.Equal(t, secret, enrolledTeamSecrets[0].Secret)
	})
}

func createTeamFileBasic(t *testing.T, secret string) *os.File {
	teamFileBasic, err := os.CreateTemp(t.TempDir(), "*.yml")
	require.NoError(t, err)
	_, err = teamFileBasic.WriteString(fmt.Sprintf(`
controls:
queries:
policies:
agent_options:
name: %s
team_settings:
  secrets: [{"secret":"%s"}]
software:
`, teamName, secret),
	)
	require.NoError(t, err)
	return teamFileBasic
}

func createGlobalFileBasic(t *testing.T, mobiusServerURL string, orgName string) *os.File {
	globalFileBasic, err := os.CreateTemp(t.TempDir(), "*.yml")
	require.NoError(t, err)
	_, err = globalFileBasic.WriteString(fmt.Sprintf(
		`
controls:
queries:
policies:
agent_options:
org_settings:
  server_settings:
    server_url: %s
  org_info:
    contact_url: https://example.com/contact
    org_logo_url: ""
    org_logo_url_light_background: ""
    org_name: %s
  secrets: [{"secret":"globalSecret"}]
software:
`, mobiusServerURL, orgName),
	)
	require.NoError(t, err)
	return globalFileBasic
}

func createGlobalFileWithoutControlsAndSoftwareKeys(t *testing.T, mobiusServerURL string, orgName string) *os.File {
	globalFileWithoutControlsAndSoftwareKeys, err := os.CreateTemp(t.TempDir(), "*.yml")
	require.NoError(t, err)
	_, err = globalFileWithoutControlsAndSoftwareKeys.WriteString(fmt.Sprintf(
		`
queries:
policies:
agent_options:
org_settings:
  server_settings:
    server_url: %s
  org_info:
    contact_url: https://example.com/contact
    org_logo_url: ""
    org_logo_url_light_background: ""
    org_name: %s
  secrets: [{"secret":"globalSecret"}]
`, mobiusServerURL, orgName),
	)
	require.NoError(t, err)
	return globalFileWithoutControlsAndSoftwareKeys
}

func createGlobalFileWithControls(t *testing.T, mobiusServerURL string, orgName string) *os.File {
	globalFileWithControls, err := os.CreateTemp(t.TempDir(), "*.yml")
	require.NoError(t, err)
	_, err = globalFileWithControls.WriteString(fmt.Sprintf(
		`
controls:
  ios_updates:
    deadline: "2022-02-02"
    minimum_version: "17.6"
queries:
policies:
agent_options:
org_settings:
  server_settings:
    server_url: %s
  org_info:
    contact_url: https://example.com/contact
    org_logo_url: ""
    org_logo_url_light_background: ""
    org_name: %s
  secrets: [{"secret":"globalSecret"}]
software:
`, mobiusServerURL, orgName),
	)
	require.NoError(t, err)
	return globalFileWithControls
}

func TestGitOpsFullGlobalAndTeam(t *testing.T) {
	// Cannot run t.Parallel() because it sets environment variables
	// mdm test configuration must be set so that activating windows MDM works.
	ds, savedAppConfigPtr, savedTeams := testing_utils.SetupFullGitOpsPremiumServer(t)
	testing_utils.StartSoftwareInstallerServer(t)

	var enrolledSecrets []*mobius.EnrollSecret
	var enrolledTeamSecrets []*mobius.EnrollSecret
	var appliedPolicySpecs []*mobius.PolicySpec
	var appliedQueries []*mobius.Query

	ds.ApplyEnrollSecretsFunc = func(ctx context.Context, teamID *uint, secrets []*mobius.EnrollSecret) error {
		if teamID == nil {
			enrolledSecrets = secrets
		} else {
			enrolledTeamSecrets = secrets
		}
		return nil
	}
	ds.ApplyPolicySpecsFunc = func(ctx context.Context, authorID uint, specs []*mobius.PolicySpec) error {
		appliedPolicySpecs = specs
		return nil
	}
	ds.ApplyQueriesFunc = func(
		ctx context.Context, authorID uint, queries []*mobius.Query, queriesToDiscardResults map[uint]struct{},
	) error {
		appliedQueries = queries
		return nil
	}
	ds.NewTeamFunc = func(ctx context.Context, team *mobius.Team) (*mobius.Team, error) {
		team.ID = 1
		enrolledTeamSecrets = team.Secrets
		savedTeams[team.Name] = &team
		return team, nil
	}

	ds.SaveABMTokenFunc = func(ctx context.Context, tok *mobius.ABMToken) error {
		return nil
	}

	ds.ListVPPTokensFunc = func(ctx context.Context) ([]*mobius.VPPTokenDB, error) {
		return []*mobius.VPPTokenDB{}, nil
	}

	ds.ListABMTokensFunc = func(ctx context.Context) ([]*mobius.ABMToken, error) {
		return []*mobius.ABMToken{}, nil
	}
	ds.GetABMTokenCountFunc = func(ctx context.Context) (int, error) {
		return 0, nil
	}
	ds.GetTeamsWithInstallerByHashFunc = func(ctx context.Context, sha256, url string) (map[uint]*mobius.ExistingSoftwareInstaller, error) {
		return map[uint]*mobius.ExistingSoftwareInstaller{}, nil
	}
	ds.GetSoftwareCategoryIDsFunc = func(ctx context.Context, names []string) ([]uint, error) {
		return []uint{}, nil
	}

	apnsCert, apnsKey, err := mysql.GenerateTestCertBytes(mdmtesting.NewTestMDMAppleCertTemplate())
	require.NoError(t, err)
	crt, key, err := apple_mdm.NewSCEPCACertKey()
	require.NoError(t, err)
	scepCert := tokenpki.PEMCertificate(crt.Raw)
	scepKey := tokenpki.PEMRSAPrivateKey(key)

	ds.GetAllMDMConfigAssetsByNameFunc = func(ctx context.Context, assetNames []mobius.MDMAssetName,
		_ sqlx.QueryerContext,
	) (map[mobius.MDMAssetName]mobius.MDMConfigAsset, error) {
		return map[mobius.MDMAssetName]mobius.MDMConfigAsset{
			mobius.MDMAssetCACert:   {Value: scepCert},
			mobius.MDMAssetCAKey:    {Value: scepKey},
			mobius.MDMAssetAPNSKey:  {Value: apnsKey},
			mobius.MDMAssetAPNSCert: {Value: apnsCert},
		}, nil
	}

	ds.SetTeamVPPAppsFunc = func(ctx context.Context, teamID *uint, adamIDs []mobius.VPPAppTeam) error {
		return nil
	}
	ds.BatchInsertVPPAppsFunc = func(ctx context.Context, apps []*mobius.VPPApp) error {
		return nil
	}

	ds.LabelsByNameFunc = func(ctx context.Context, names []string) (map[string]*mobius.Label, error) {
		return map[string]*mobius.Label{
			"a": {
				ID:   1,
				Name: "a",
			},
			"b": {
				ID:   2,
				Name: "b",
			},
		}, nil
	}

	globalFile := "./testdata/gitops/global_config_no_paths.yml"
	teamFile := "./testdata/gitops/team_config_no_paths.yml"

	// Dry run
	_ = RunAppForTest(t, []string{"gitops", "-f", globalFile, "-f", teamFile, "--dry-run", "--delete-other-teams"})
	assert.False(t, ds.SaveAppConfigFuncInvoked)
	assert.Len(t, enrolledSecrets, 0)
	assert.Len(t, enrolledTeamSecrets, 0)
	assert.Len(t, appliedPolicySpecs, 0)
	assert.Len(t, appliedQueries, 0)

	// Real run
	_ = RunAppForTest(t, []string{"gitops", "-f", globalFile, "-f", teamFile, "--delete-other-teams"})
	assert.Equal(t, orgName, (*savedAppConfigPtr).OrgInfo.OrgName)
	assert.Equal(t, mobiusServerURL, (*savedAppConfigPtr).ServerSettings.ServerURL)
	assert.Len(t, enrolledSecrets, 2)
	require.NotNil(t, *savedTeams[teamName])
	assert.Equal(t, teamName, (*savedTeams[teamName]).Name)
	require.Len(t, enrolledTeamSecrets, 2)

	t.Run("no-team.yml using relative paths", func(t *testing.T) {
		globalFileBasic := createGlobalFileBasic(t, mobiusServerURL, orgName)
		teamFileBasic := createTeamFileBasic(t, teamName)

		noTeamDir := t.TempDir()
		noTeamFile, err := os.Create(filepath.Join(noTeamDir, "no-team.yml"))
		require.NoError(t, err)
		_, err = noTeamFile.WriteString(`
controls:
  scripts:
    - path: ./script.sh
  windows_enabled_and_configured: true
  macos_settings:
    custom_settings:
    - path: ./config.json
  windows_settings:
    custom_settings:
    - path: ./config2.xml
policies:
name: No team
software:
`)
		require.NoError(t, err)

		ddmFile, err := os.Create(filepath.Join(noTeamDir, "config.json"))
		require.NoError(t, err)
		_, err = ddmFile.WriteString(`
{
    "Type": "com.apple.configuration.passcode.settings",
    "Identifier": "com.mobiusmdm.config.passcode.settings",
    "Payload": {
        "RequireAlphanumericPasscode": true
    }
}
		`)
		require.NoError(t, err)

		cspFile, err := os.Create(filepath.Join(noTeamDir, "config2.xml"))
		require.NoError(t, err)
		_, err = cspFile.WriteString(`<Replace>bozo</Replace>`)
		require.NoError(t, err)

		scriptFile, err := os.Create(filepath.Join(noTeamDir, "script.sh"))
		require.NoError(t, err)
		_, err = scriptFile.WriteString(`echo "Hello, world!"`)
		require.NoError(t, err)

		// Dry run
		ds.SaveAppConfigFuncInvoked = false
		ds.BatchSetScriptsFuncInvoked = false
		_ = RunAppForTest(t,
			[]string{"gitops", "-f", globalFileBasic.Name(), "-f", teamFileBasic.Name(), "-f", noTeamFile.Name(), "--dry-run"})
		assert.False(t, ds.SaveAppConfigFuncInvoked)
		assert.False(t, ds.BatchSetScriptsFuncInvoked)

		// Real run
		_ = RunAppForTest(t, []string{"gitops", "-f", globalFileBasic.Name(), "-f", teamFileBasic.Name(), "-f", noTeamFile.Name()})
		assert.Equal(t, orgName, (*savedAppConfigPtr).OrgInfo.OrgName)
		assert.Equal(t, mobiusServerURL, (*savedAppConfigPtr).ServerSettings.ServerURL)
		require.Len(t, (*savedAppConfigPtr).MDM.MacOSSettings.CustomSettings, 1)
		assert.Equal(t, filepath.Base(ddmFile.Name()), filepath.Base((*savedAppConfigPtr).MDM.MacOSSettings.CustomSettings[0].Path))
		require.Len(t, (*savedAppConfigPtr).MDM.WindowsSettings.CustomSettings.Value, 1)
		assert.Equal(t, filepath.Base(cspFile.Name()), filepath.Base((*savedAppConfigPtr).MDM.WindowsSettings.CustomSettings.Value[0].Path))
		assert.True(t, ds.BatchSetScriptsFuncInvoked)

		// Get applied policies for the team
		teamAppliedPoliceSpecs := make([]*mobius.PolicySpec, 0)
		for _, appliedPolicySpec := range appliedPolicySpecs {
			if appliedPolicySpec.Team == teamName {
				teamAppliedPoliceSpecs = append(teamAppliedPoliceSpecs, appliedPolicySpec)
			}
		}
		assert.Len(t, teamAppliedPoliceSpecs, 5)
		assert.Len(t, teamAppliedPoliceSpecs[0].LabelsIncludeAny, 0)
		assert.Len(t, teamAppliedPoliceSpecs[0].LabelsExcludeAny, 1)
		assert.Equal(t, teamAppliedPoliceSpecs[0].LabelsExcludeAny[0], "a")
		assert.Len(t, teamAppliedPoliceSpecs[1].LabelsIncludeAny, 1)
		assert.Len(t, teamAppliedPoliceSpecs[1].LabelsExcludeAny, 0)
		assert.Equal(t, teamAppliedPoliceSpecs[1].LabelsIncludeAny[0], "b")
	})
}

func TestGitOpsCustomSettings(t *testing.T) {
	cases := []struct {
		file    string
		wantErr string
	}{
		{"testdata/gitops/global_macos_windows_custom_settings_valid.yml", ""},
		{"testdata/gitops/global_macos_custom_settings_valid_deprecated.yml", ""},
		{"testdata/gitops/global_windows_custom_settings_invalid_label_mix.yml", "please choose one of `labels_include_any`, `labels_include_all` or `labels_exclude_any`"},
		{"testdata/gitops/global_windows_custom_settings_invalid_label_mix_2.yml", "please choose one of `labels_include_any`, `labels_include_all` or `labels_exclude_any`"},
		{"testdata/gitops/global_windows_custom_settings_unknown_label.yml", `Please create the missing labels, or update your settings to not refer to these labels.`},
		{"testdata/gitops/team_macos_windows_custom_settings_valid.yml", ""},
		{"testdata/gitops/team_macos_custom_settings_valid_deprecated.yml", ""},
		{"testdata/gitops/team_macos_windows_custom_settings_invalid_labels_mix.yml", "please choose one of `labels_include_any`, `labels_include_all` or `labels_exclude_any`"},
		{"testdata/gitops/team_macos_windows_custom_settings_invalid_labels_mix_2.yml", "please choose one of `labels_include_any`, `labels_include_all` or `labels_exclude_any`"},
		{"testdata/gitops/team_macos_windows_custom_settings_unknown_label.yml", `Please create the missing labels, or update your settings to not refer to these labels.`},
	}
	for _, c := range cases {
		t.Run(filepath.Base(c.file), func(t *testing.T) {
			ds, appCfgPtr, _ := testing_utils.SetupFullGitOpsPremiumServer(t)
			(*appCfgPtr).MDM.EnabledAndConfigured = true
			(*appCfgPtr).MDM.WindowsEnabledAndConfigured = true
			ds.GetLabelSpecsFunc = func(ctx context.Context) ([]*mobius.LabelSpec, error) {
				return []*mobius.LabelSpec{
					{
						Name:                "A",
						Description:         "A global label",
						LabelMembershipType: mobius.LabelMembershipTypeManual,
						Hosts:               []string{"host2", "host3"},
					},
					{
						Name:                "B",
						Description:         "Another label",
						LabelMembershipType: mobius.LabelMembershipTypeDynamic,
						Query:               "SELECT 1 from osquery_info",
					},
					{
						Name:                "C",
						Description:         "Another nother label",
						LabelMembershipType: mobius.LabelMembershipTypeDynamic,
						Query:               "SELECT 1 from osquery_info",
					},
				}, nil
			}
			labelToIDs := map[string]uint{
				mobius.BuiltinLabelMacOS14Plus: 1,
				"A":                           2,
				"B":                           3,
				"C":                           4,
			}

			ds.LabelIDsByNameFunc = func(ctx context.Context, labels []string) (map[string]uint, error) {
				// for this test, recognize labels A, B and C (as well as the built-in macos 14+ one)
				ret := make(map[string]uint)
				for _, lbl := range labels {
					id, ok := labelToIDs[lbl]
					if ok {
						ret[lbl] = id
					}
				}
				return ret, nil
			}
			ds.SetTeamVPPAppsFunc = func(ctx context.Context, teamID *uint, adamIDs []mobius.VPPAppTeam) error {
				return nil
			}
			ds.BatchInsertVPPAppsFunc = func(ctx context.Context, apps []*mobius.VPPApp) error {
				return nil
			}

			_, err := RunAppNoChecks([]string{"gitops", "-f", c.file})
			if c.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, c.wantErr)
			}
		})
	}
}

func TestGitOpsABM(t *testing.T) {
	global := func(mdm string) string {
		return fmt.Sprintf(`
controls:
queries:
policies:
agent_options:
software:
org_settings:
  server_settings:
    server_url: "https://foo.example.com"
  org_info:
    org_name: GitOps Test
  secrets:
    - secret: "global"
  mdm:
    %s
 `, mdm)
	}

	team := func(name string) string {
		return fmt.Sprintf(`
name: %s
team_settings:
  secrets:
    - secret: "%s-secret"
agent_options:
controls:
policies:
queries:
software:
`, name, name)
	}

	workstations := team("💻 Workstations")
	iosTeam := team("📱🏢 Company-owned iPhones")
	ipadTeam := team("🔳🏢 Company-owned iPads")

	cases := []struct {
		name             string
		cfgs             []string
		dryRunAssertion  func(t *testing.T, appCfg *mobius.AppConfig, ds mobius.Datastore, out string, err error)
		realRunAssertion func(t *testing.T, appCfg *mobius.AppConfig, ds mobius.Datastore, out string, err error)
		tokens           []*mobius.ABMToken
	}{
		{
			name: "backwards compat",
			cfgs: []string{
				global("apple_bm_default_team: 💻 Workstations"),
				workstations,
			},
			tokens: []*mobius.ABMToken{{OrganizationName: "Mobius Device Management Inc."}},
			dryRunAssertion: func(t *testing.T, appCfg *mobius.AppConfig, ds mobius.Datastore, out string, err error) {
				assert.NoError(t, err)
				assert.Empty(t, appCfg.MDM.AppleBusinessManager.Value)
				assert.Empty(t, appCfg.MDM.DeprecatedAppleBMDefaultTeam)
				assert.Contains(t, out, "[!] gitops dry run succeeded")
			},
			realRunAssertion: func(t *testing.T, appCfg *mobius.AppConfig, ds mobius.Datastore, out string, err error) {
				assert.NoError(t, err)
				assert.Empty(t, appCfg.MDM.AppleBusinessManager.Value)
				assert.Equal(t, appCfg.MDM.DeprecatedAppleBMDefaultTeam, "💻 Workstations")
				assert.Contains(t, out, "[!] gitops succeeded")
			},
		},
		{
			name: "deprecated config with two tokens in the db fails",
			cfgs: []string{
				global("apple_bm_default_team: 💻 Workstations"),
				workstations,
			},
			tokens: []*mobius.ABMToken{{OrganizationName: "Mobius Device Management Inc."}, {OrganizationName: "Second Token LLC"}},
			dryRunAssertion: func(t *testing.T, appCfg *mobius.AppConfig, ds mobius.Datastore, out string, err error) {
				t.Logf("got: %s", out)
				require.ErrorContains(t, err, "mdm.apple_bm_default_team has been deprecated")
				assert.Empty(t, appCfg.MDM.AppleBusinessManager.Value)
				assert.Empty(t, appCfg.MDM.DeprecatedAppleBMDefaultTeam)
				assert.NotContains(t, out, "[!] gitops dry run succeeded")
			},
			realRunAssertion: func(t *testing.T, appCfg *mobius.AppConfig, ds mobius.Datastore, out string, err error) {
				require.ErrorContains(t, err, "mdm.apple_bm_default_team has been deprecated")
				assert.Empty(t, appCfg.MDM.AppleBusinessManager.Value)
				assert.Empty(t, appCfg.MDM.DeprecatedAppleBMDefaultTeam)
				assert.NotContains(t, out, "[!] gitops succeeded")
			},
		},
		{
			name: "new key all valid",
			cfgs: []string{
				global(`
                                  apple_business_manager:
                                    - organization_name: Mobius Device Management Inc.
                                      macos_team: "💻 Workstations"
                                      ios_team: "📱🏢 Company-owned iPhones"
                                      ipados_team: "🔳🏢 Company-owned iPads"`),
				workstations,
				iosTeam,
				ipadTeam,
			},
			dryRunAssertion: func(t *testing.T, appCfg *mobius.AppConfig, ds mobius.Datastore, out string, err error) {
				assert.NoError(t, err)
				assert.Empty(t, appCfg.MDM.AppleBusinessManager.Value)
				assert.Empty(t, appCfg.MDM.DeprecatedAppleBMDefaultTeam)
				assert.Contains(t, out, "[!] gitops dry run succeeded")
			},
			realRunAssertion: func(t *testing.T, appCfg *mobius.AppConfig, ds mobius.Datastore, out string, err error) {
				assert.NoError(t, err)
				assert.Empty(t, appCfg.MDM.DeprecatedAppleBMDefaultTeam)
				assert.ElementsMatch(
					t,
					appCfg.MDM.AppleBusinessManager.Value,
					[]mobius.MDMAppleABMAssignmentInfo{
						{
							OrganizationName: "Mobius Device Management Inc.",
							MacOSTeam:        "💻 Workstations",
							IOSTeam:          "📱🏢 Company-owned iPhones",
							IpadOSTeam:       "🔳🏢 Company-owned iPads",
						},
					},
				)
				assert.Contains(t, out, "[!] gitops succeeded")
			},
		},
		{
			name: "new key multiple elements",
			cfgs: []string{
				global(`
                                  apple_business_manager:
                                    - organization_name: Foo Inc.
                                      macos_team: "💻 Workstations"
                                      ios_team: "📱🏢 Company-owned iPhones"
                                      ipados_team: "🔳🏢 Company-owned iPads"
                                    - organization_name: Mobius Device Management Inc.
                                      macos_team: "💻 Workstations"
                                      ios_team: "📱🏢 Company-owned iPhones"
                                      ipados_team: "🔳🏢 Company-owned iPads"`),
				workstations,
				iosTeam,
				ipadTeam,
			},
			dryRunAssertion: func(t *testing.T, appCfg *mobius.AppConfig, ds mobius.Datastore, out string, err error) {
				assert.NoError(t, err)
				assert.Empty(t, appCfg.MDM.AppleBusinessManager.Value)
				assert.Empty(t, appCfg.MDM.DeprecatedAppleBMDefaultTeam)
				assert.Contains(t, out, "[!] gitops dry run succeeded")
			},
			realRunAssertion: func(t *testing.T, appCfg *mobius.AppConfig, ds mobius.Datastore, out string, err error) {
				assert.NoError(t, err)
				assert.Empty(t, appCfg.MDM.DeprecatedAppleBMDefaultTeam)
				assert.ElementsMatch(
					t,
					appCfg.MDM.AppleBusinessManager.Value,
					[]mobius.MDMAppleABMAssignmentInfo{
						{
							OrganizationName: "Mobius Device Management Inc.",
							MacOSTeam:        "💻 Workstations",
							IOSTeam:          "📱🏢 Company-owned iPhones",
							IpadOSTeam:       "🔳🏢 Company-owned iPads",
						},
						{
							OrganizationName: "Foo Inc.",
							MacOSTeam:        "💻 Workstations",
							IOSTeam:          "📱🏢 Company-owned iPhones",
							IpadOSTeam:       "🔳🏢 Company-owned iPads",
						},
					},
				)
				assert.Contains(t, out, "[!] gitops succeeded")
			},
		},
		{
			name: "both keys errors",
			cfgs: []string{
				global(`
                                  apple_bm_default_team: "💻 Workstations"
                                  apple_business_manager:
                                    - organization_name: Mobius Device Management Inc.
                                      macos_team: "💻 Workstations"
                                      ios_team: "📱🏢 Company-owned iPhones"
                                      ipados_team: "🔳🏢 Company-owned iPads"`),
				workstations,
				iosTeam,
				ipadTeam,
			},
			dryRunAssertion: func(t *testing.T, appCfg *mobius.AppConfig, ds mobius.Datastore, out string, err error) {
				require.ErrorContains(t, err, "mdm.apple_bm_default_team has been deprecated")
				assert.NotContains(t, out, "[!] gitops dry run succeeded")
			},
			realRunAssertion: func(t *testing.T, appCfg *mobius.AppConfig, ds mobius.Datastore, out string, err error) {
				require.ErrorContains(t, err, "mdm.apple_bm_default_team has been deprecated")
				assert.NotContains(t, out, "[!] gitops succeeded")
			},
		},
		{
			name: "using an undefined team errors",
			cfgs: []string{
				global(`
                                  apple_business_manager:
                                    - organization_name: Mobius Device Management Inc.
                                      macos_team: "💻 Workstations"
                                      ios_team: "📱🏢 Company-owned iPhones"
                                      ipados_team: "🔳🏢 Company-owned iPads"`),
				workstations,
			},
			dryRunAssertion: func(t *testing.T, appCfg *mobius.AppConfig, ds mobius.Datastore, out string, err error) {
				assert.ErrorContains(t, err, "apple_business_manager team \"📱🏢 Company-owned iPhones\" not found in team configs")
			},
			realRunAssertion: func(t *testing.T, appCfg *mobius.AppConfig, ds mobius.Datastore, out string, err error) {
				assert.ErrorContains(t, err, "apple_business_manager team \"📱🏢 Company-owned iPhones\" not found in team configs")
			},
		},
		{
			name: "no team is supported",
			cfgs: []string{
				global(`
                                  apple_business_manager:
                                    - organization_name: Mobius Device Management Inc.
                                      macos_team: "No team"
                                      ios_team: "No team"
                                      ipados_team: "No team"`),
			},
			dryRunAssertion: func(t *testing.T, appCfg *mobius.AppConfig, ds mobius.Datastore, out string, err error) {
				assert.NoError(t, err)
				assert.Empty(t, appCfg.MDM.AppleBusinessManager.Value)
				assert.Empty(t, appCfg.MDM.DeprecatedAppleBMDefaultTeam)
				assert.Contains(t, out, "[!] gitops dry run succeeded")
			},
			realRunAssertion: func(t *testing.T, appCfg *mobius.AppConfig, ds mobius.Datastore, out string, err error) {
				assert.NoError(t, err)
				assert.Empty(t, appCfg.MDM.DeprecatedAppleBMDefaultTeam)
				assert.ElementsMatch(
					t,
					appCfg.MDM.AppleBusinessManager.Value,
					[]mobius.MDMAppleABMAssignmentInfo{
						{
							OrganizationName: "Mobius Device Management Inc.",
							MacOSTeam:        "No team",
							IOSTeam:          "No team",
							IpadOSTeam:       "No team",
						},
					},
				)
				assert.Contains(t, out, "[!] gitops succeeded")
			},
		},
		{
			name: "not provided teams defaults to no team",
			cfgs: []string{
				global(`
                                  apple_business_manager:
                                    - organization_name: Mobius Device Management Inc.
                                      macos_team: "No team"
                                      ios_team: ""`),
			},
			dryRunAssertion: func(t *testing.T, appCfg *mobius.AppConfig, ds mobius.Datastore, out string, err error) {
				assert.NoError(t, err)
				assert.Empty(t, appCfg.MDM.AppleBusinessManager.Value)
				assert.Empty(t, appCfg.MDM.DeprecatedAppleBMDefaultTeam)
				assert.Contains(t, out, "[!] gitops dry run succeeded")
			},
			realRunAssertion: func(t *testing.T, appCfg *mobius.AppConfig, ds mobius.Datastore, out string, err error) {
				assert.NoError(t, err)
				assert.Empty(t, appCfg.MDM.DeprecatedAppleBMDefaultTeam)
				assert.ElementsMatch(
					t,
					appCfg.MDM.AppleBusinessManager.Value,
					[]mobius.MDMAppleABMAssignmentInfo{
						{
							OrganizationName: "Mobius Device Management Inc.",
							MacOSTeam:        "No team",
							IOSTeam:          "",
							IpadOSTeam:       "",
						},
					},
				)
				assert.Contains(t, out, "[!] gitops succeeded")
			},
		},
		{
			name: "non existent org name fails",
			cfgs: []string{
				global(`
                                  apple_business_manager:
                                    - organization_name: Does not exist
                                      macos_team: "No team"`),
			},
			tokens: []*mobius.ABMToken{{OrganizationName: "Mobius Device Management Inc."}},
			dryRunAssertion: func(t *testing.T, appCfg *mobius.AppConfig, ds mobius.Datastore, out string, err error) {
				assert.ErrorContains(t, err, "token with organization name Does not exist doesn't exist")
				assert.Empty(t, appCfg.MDM.AppleBusinessManager.Value)
				assert.Empty(t, appCfg.MDM.DeprecatedAppleBMDefaultTeam)
				assert.NotContains(t, out, "[!] gitops dry run succeeded")
			},
			realRunAssertion: func(t *testing.T, appCfg *mobius.AppConfig, ds mobius.Datastore, out string, err error) {
				assert.ErrorContains(t, err, "token with organization name Does not exist doesn't exist")
				assert.Empty(t, appCfg.MDM.AppleBusinessManager.Value)
				assert.Empty(t, appCfg.MDM.DeprecatedAppleBMDefaultTeam)
				assert.NotContains(t, out, "[!] gitops dry run succeeded")
			},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			ds, savedAppConfigPtr, savedTeams := testing_utils.SetupFullGitOpsPremiumServer(t)

			ds.ListABMTokensFunc = func(ctx context.Context) ([]*mobius.ABMToken, error) {
				if len(tt.tokens) > 0 {
					return tt.tokens, nil
				}
				return []*mobius.ABMToken{{OrganizationName: "Mobius Device Management Inc."}, {OrganizationName: "Foo Inc."}}, nil
			}
			ds.GetABMTokenCountFunc = func(ctx context.Context) (int, error) {
				return len(tt.tokens), nil
			}

			ds.TeamsSummaryFunc = func(ctx context.Context) ([]*mobius.TeamSummary, error) {
				var res []*mobius.TeamSummary
				for _, tm := range savedTeams {
					res = append(res, &mobius.TeamSummary{Name: (*tm).Name, ID: (*tm).ID})
				}
				return res, nil
			}

			ds.SaveABMTokenFunc = func(ctx context.Context, tok *mobius.ABMToken) error {
				return nil
			}

			args := []string{"gitops"}
			for _, cfg := range tt.cfgs {
				if cfg != "" {
					tmpFile, err := os.CreateTemp(t.TempDir(), "*.yml")
					require.NoError(t, err)
					_, err = tmpFile.WriteString(cfg)
					require.NoError(t, err)
					args = append(args, "-f", tmpFile.Name())
				}
			}

			// Dry run
			out, err := RunAppNoChecks(append(args, "--dry-run"))
			tt.dryRunAssertion(t, *savedAppConfigPtr, ds, out.String(), err)
			if t.Failed() {
				t.FailNow()
			}

			// Real run
			out, err = RunAppNoChecks(args)
			tt.realRunAssertion(t, *savedAppConfigPtr, ds, out.String(), err)

			// Second real run, now that all the teams are saved
			out, err = RunAppNoChecks(args)
			tt.realRunAssertion(t, *savedAppConfigPtr, ds, out.String(), err)
		})
	}
}

func TestGitOpsWindowsMigration(t *testing.T) {
	cases := []struct {
		file    string
		wantErr string
	}{
		// booleans are Windows MDM enabled and Windows migration enabled
		{"testdata/gitops/global_config_windows_migration_true_true.yml", ""},
		{"testdata/gitops/global_config_windows_migration_false_true.yml", "Windows MDM is not enabled"},
		{"testdata/gitops/global_config_windows_migration_true_false.yml", ""},
		{"testdata/gitops/global_config_windows_migration_false_false.yml", ""},
	}
	for _, c := range cases {
		t.Run(filepath.Base(c.file), func(t *testing.T) {
			testing_utils.SetupFullGitOpsPremiumServer(t)

			_, err := RunAppNoChecks([]string{"gitops", "-f", c.file})
			if c.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, c.wantErr)
			}
		})
	}
}

func TestGitOpsGlobalWebhooksDisable(t *testing.T) {
	_, appConfig, _ := testing_utils.SetupFullGitOpsPremiumServer(t)

	webhook := &(*appConfig).WebhookSettings
	webhook.ActivitiesWebhook.Enable = true
	webhook.FailingPoliciesWebhook.Enable = true
	webhook.HostStatusWebhook.Enable = true
	webhook.VulnerabilitiesWebhook.Enable = true

	// Run config with no webooks settings
	_, err := RunAppNoChecks([]string{"gitops", "-f", "testdata/gitops/global_config_windows_migration_true_true.yml"})
	require.NoError(t, err)

	webhook = &(*appConfig).WebhookSettings
	require.False(t, webhook.ActivitiesWebhook.Enable)
	require.False(t, webhook.FailingPoliciesWebhook.Enable)
	require.False(t, webhook.HostStatusWebhook.Enable)
	require.False(t, webhook.VulnerabilitiesWebhook.Enable)
}

func TestGitOpsTeamWebhooks(t *testing.T) {
	teamName := "TestTeamWebhooks"

	ds, _, savedTeams := testing_utils.SetupFullGitOpsPremiumServer(t)

	// Create a new team.
	_, err := ds.NewTeam(context.Background(), &mobius.Team{Name: teamName, Config: mobius.TeamConfig{WebhookSettings: mobius.TeamWebhookSettings{
		FailingPoliciesWebhook: mobius.FailingPoliciesWebhookSettings{Enable: true, DestinationURL: "http://saybye.by"},
		HostStatusWebhook:      &mobius.HostStatusWebhookSettings{Enable: true},
	}}})
	require.NoError(t, err)
	require.NotNil(t, *savedTeams[teamName])

	// Do a GitOps run with no webhook settings.
	t.Setenv("TEST_TEAM_NAME", teamName)
	_, err = RunAppNoChecks([]string{"gitops", "-f", "testdata/gitops/team_config_webhook.yml"})
	require.NoError(t, err)

	team, err := ds.TeamByName(context.Background(), teamName)
	require.NoError(t, err)
	require.NotNil(t, team)
	require.NotNil(t, team.Config.WebhookSettings)

	// Check that the team's failing policy webhook settings are disabled and cleared, since the GitOps
	// config doesn't include them.
	require.False(t, team.Config.WebhookSettings.FailingPoliciesWebhook.Enable)
	require.Equal(t, "", team.Config.WebhookSettings.FailingPoliciesWebhook.DestinationURL)
	// Check that the team's host status webhook settings are enabled and set to the new values.
	require.True(t, team.Config.WebhookSettings.HostStatusWebhook.Enable)
	require.Equal(t, "http://coolwebhook.biz", team.Config.WebhookSettings.HostStatusWebhook.DestinationURL)
}

func TestGitOpsFeatures(t *testing.T) {
	globalFileBasic := createGlobalFileBasic(t, mobiusServerURL, orgName)
	ds, _, _ := testing_utils.SetupFullGitOpsPremiumServer(t)

	appConfig := mobius.AppConfig{
		Features: mobius.Features{
			EnableHostUsers:         true,
			EnableSoftwareInventory: true,
			AdditionalQueries:       ptr.RawMessage(json.RawMessage(`{"query_a": "SELECT 1", "query_b": "SELECT 2"}`)),
			DetailQueryOverrides: map[string]*string{
				"detail_query_a": ptr.String("SELECT a"),
				"detail_query_b": nil,
			},
		},
	}

	globalFileUpdatedFeatures, err := os.CreateTemp(t.TempDir(), "*.yml")
	require.NoError(t, err)
	_, err = globalFileUpdatedFeatures.WriteString(fmt.Sprintf(
		`
controls:
queries:
policies:
agent_options:
org_settings:
  features:
    enable_host_users: false
    enable_software_inventory: true
    additional_queries:
      query_a: "SELECT 1"
    detail_query_overrides:
      detail_query_a: "SELECT it_works"
  server_settings:
    server_url: %s
  org_info:
    contact_url: https://example.com/contact
    org_logo_url: ""
    org_logo_url_light_background: ""
    org_name: %s
  secrets: [{"secret":"globalSecret"}]
software:
`, mobiusServerURL, orgName),
	)
	require.NoError(t, err)

	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		return &appConfig, nil
	}

	ds.SaveAppConfigFunc = func(ctx context.Context, config *mobius.AppConfig) error {
		appConfig = *config
		return nil
	}

	// Do a GitOps run with updated feature settings.
	_, err = RunAppNoChecks([]string{"gitops", "-f", globalFileUpdatedFeatures.Name()})
	require.NoError(t, err)
	require.False(t, appConfig.Features.EnableHostUsers)
	require.True(t, appConfig.Features.EnableSoftwareInventory)

	// Parse the additional queries into a map.
	var additionalQueries map[string]string
	err = json.Unmarshal(*appConfig.Features.AdditionalQueries, &additionalQueries)
	require.NoError(t, err)
	require.Equal(t, 1, len(additionalQueries))
	require.Equal(t, "SELECT 1", additionalQueries["query_a"])
	require.Equal(t, 1, len(appConfig.Features.DetailQueryOverrides))
	require.Equal(t, "SELECT it_works", *appConfig.Features.DetailQueryOverrides["detail_query_a"])

	// Do a GitOps run with no feature settings.
	_, err = RunAppNoChecks([]string{"gitops", "-f", globalFileBasic.Name()})
	require.NoError(t, err)

	require.False(t, appConfig.Features.EnableHostUsers)
	require.False(t, appConfig.Features.EnableSoftwareInventory)
	require.Nil(t, appConfig.Features.AdditionalQueries)
	require.Nil(t, appConfig.Features.DetailQueryOverrides)
}

func TestGitOpsSSOSettings(t *testing.T) {
	globalFileBasic := createGlobalFileBasic(t, mobiusServerURL, orgName)
	ds, _, _ := testing_utils.SetupFullGitOpsPremiumServer(t)

	appConfig := mobius.AppConfig{
		SSOSettings: &mobius.SSOSettings{
			SSOProviderSettings: mobius.SSOProviderSettings{
				EntityID:  "some-entity-id",
				IssuerURI: "https://example.com/saml",
				Metadata:  "some-metadata",
				IDPName:   "some-idp-name",
			},
			IDPImageURL:           "https://example.com/logo.png",
			EnableSSO:             true,
			EnableSSOIdPLogin:     true,
			EnableJITProvisioning: true,
			EnableJITRoleSync:     true,
		},
	}

	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		return &appConfig, nil
	}

	ds.SaveAppConfigFunc = func(ctx context.Context, config *mobius.AppConfig) error {
		appConfig = *config
		return nil
	}

	// Do a GitOps run with no sso settings.
	_, err := RunAppNoChecks([]string{"gitops", "-f", globalFileBasic.Name()})
	require.NoError(t, err)

	require.Nil(t, appConfig.SSOSettings)
}

func TestGitOpsSMTPSettings(t *testing.T) {
	globalFileBasic := createGlobalFileBasic(t, mobiusServerURL, orgName)
	ds, _, _ := testing_utils.SetupFullGitOpsPremiumServer(t)

	appConfig := mobius.AppConfig{
		SMTPSettings: &mobius.SMTPSettings{
			SMTPEnabled:              true,
			SMTPConfigured:           true,
			SMTPSenderAddress:        "http://example.com",
			SMTPServer:               "server.example.com",
			SMTPPort:                 587,
			SMTPAuthenticationType:   "smoooth",
			SMTPUserName:             "uzer",
			SMTPPassword:             "pazzword",
			SMTPEnableTLS:            true,
			SMTPAuthenticationMethod: "crunchy",
			SMTPDomain:               "smtp.example.com",
			SMTPVerifySSLCerts:       true,
			SMTPEnableStartTLS:       true,
		},
	}

	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		return &appConfig, nil
	}

	ds.SaveAppConfigFunc = func(ctx context.Context, config *mobius.AppConfig) error {
		appConfig = *config
		return nil
	}

	// Do a GitOps run with no smtp settings.
	_, err := RunAppNoChecks([]string{"gitops", "-f", globalFileBasic.Name()})
	require.NoError(t, err)

	// Currently we do NOT clear the SMTP settings if they are not in the config,
	// because the smtp_settings key is not documented in the GitOps config.
	// TODO - update this test if we change this behavior.
	require.Equal(t, &mobius.SMTPSettings{
		SMTPEnabled:              true,
		SMTPConfigured:           true,
		SMTPSenderAddress:        "http://example.com",
		SMTPServer:               "server.example.com",
		SMTPPort:                 587,
		SMTPAuthenticationType:   "smoooth",
		SMTPUserName:             "uzer",
		SMTPPassword:             "********",
		SMTPEnableTLS:            true,
		SMTPAuthenticationMethod: "crunchy",
		SMTPDomain:               "smtp.example.com",
		SMTPVerifySSLCerts:       true,
		SMTPEnableStartTLS:       true,
	}, appConfig.SMTPSettings)
}

func TestGitOpsMDMAuthSettings(t *testing.T) {
	globalFileBasic := createGlobalFileBasic(t, mobiusServerURL, orgName)
	ds, _, _ := testing_utils.SetupFullGitOpsPremiumServer(t)

	appConfig := mobius.AppConfig{
		MDM: mobius.MDM{
			EndUserAuthentication: mobius.MDMEndUserAuthentication{
				SSOProviderSettings: mobius.SSOProviderSettings{
					EntityID:  "some-entity-id",
					IssuerURI: "https://example.com/saml",
					Metadata:  "some-metadata",
					IDPName:   "some-idp-name",
				},
			},
		},
	}

	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		return &appConfig, nil
	}

	ds.SaveAppConfigFunc = func(ctx context.Context, config *mobius.AppConfig) error {
		appConfig = *config
		return nil
	}

	// Do a GitOps run with no mdm end user auth settings.
	_, err := RunAppNoChecks([]string{"gitops", "-f", globalFileBasic.Name()})
	require.NoError(t, err)

	require.NotNil(t, appConfig.MDM.EndUserAuthentication)
	require.Empty(t, appConfig.MDM.EndUserAuthentication.SSOProviderSettings.EntityID)
	require.Empty(t, appConfig.MDM.EndUserAuthentication.SSOProviderSettings.IssuerURI)
	require.Empty(t, appConfig.MDM.EndUserAuthentication.SSOProviderSettings.Metadata)
	require.Empty(t, appConfig.MDM.EndUserAuthentication.SSOProviderSettings.MetadataURL)
	require.Empty(t, appConfig.MDM.EndUserAuthentication.SSOProviderSettings.IDPName)
}

func TestGitOpsTeamConditionalAccess(t *testing.T) {
	teamName := "TestTeamConditionalAccess"

	ds, _, savedTeams := testing_utils.SetupFullGitOpsPremiumServer(t)

	ds.ConditionalAccessMicrosoftGetFunc = func(ctx context.Context) (*mobius.ConditionalAccessMicrosoftIntegration, error) {
		return &mobius.ConditionalAccessMicrosoftIntegration{}, nil
	}

	// Create integration with conditional access enabled.
	_, err := ds.NewTeam(context.Background(), &mobius.Team{Name: teamName, Config: mobius.TeamConfig{
		Integrations: mobius.TeamIntegrations{
			ConditionalAccessEnabled: optjson.SetBool(true),
		},
	}})
	require.NoError(t, err)
	require.NotNil(t, *savedTeams[teamName])

	// Do a GitOps run with conditional access not set.
	t.Setenv("TEST_TEAM_NAME", teamName)
	_, err = RunAppNoChecks([]string{"gitops", "-f", "testdata/gitops/team_config_webhook.yml"})
	require.NoError(t, err)

	team, err := ds.TeamByName(context.Background(), teamName)
	require.NoError(t, err)
	require.NotNil(t, team)
	require.True(t, team.Config.Integrations.ConditionalAccessEnabled.Set)
	require.False(t, team.Config.Integrations.ConditionalAccessEnabled.Value)
}

func TestGitOpsNoTeamConditionalAccess(t *testing.T) {
	globalFileBasic := createGlobalFileBasic(t, mobiusServerURL, orgName)
	ds, _, _ := testing_utils.SetupFullGitOpsPremiumServer(t)

	ds.ConditionalAccessMicrosoftGetFunc = func(ctx context.Context) (*mobius.ConditionalAccessMicrosoftIntegration, error) {
		return &mobius.ConditionalAccessMicrosoftIntegration{}, nil
	}

	appConfig := mobius.AppConfig{
		Integrations: mobius.Integrations{
			ConditionalAccessEnabled: optjson.SetBool(true),
		},
	}

	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		return &appConfig, nil
	}

	ds.SaveAppConfigFunc = func(ctx context.Context, config *mobius.AppConfig) error {
		appConfig = *config
		return nil
	}

	// Do a GitOps run with conditional access not set.
	_, err := RunAppNoChecks([]string{"gitops", "-f", globalFileBasic.Name()})
	require.NoError(t, err)
	require.True(t, appConfig.Integrations.ConditionalAccessEnabled.Set)
	require.False(t, appConfig.Integrations.ConditionalAccessEnabled.Value)
}
