package gitops

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/notawar/mobius/cmd/mobiuscli/mobiuscli"
	"github.com/notawar/mobius/cmd/mobiuscli/mobiuscli/testing_utils"
	"github.com/notawar/mobius/cmd/mobiuscli/integrationtest"
	eeservice "github.com/notawar/mobius/ee/server/service"
	"github.com/notawar/mobius/ee/server/service/digicert"
	"github.com/notawar/mobius/server/config"
	"github.com/notawar/mobius/server/datastore/mysql"
	"github.com/notawar/mobius/server/datastore/redis/redistest"
	"github.com/notawar/mobius/server/mobius"
	appleMdm "github.com/notawar/mobius/server/mdm/apple"
	"github.com/notawar/mobius/server/mdm/nanodep/tokenpki"
	"github.com/notawar/mobius/server/ptr"
	"github.com/notawar/mobius/server/service"
	"github.com/notawar/mobius/server/service/integrationtest/scep_server"
	"github.com/notawar/mobius/server/test"
	"github.com/go-git/go-git/v5"
	"github.com/go-json-experiment/json/v1"
	kitlog "github.com/go-kit/log"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

func TestIntegrationsEnterpriseGitops(t *testing.T) {
	testingSuite := new(enterpriseIntegrationGitopsTestSuite)
	testingSuite.WithServer.Suite = &testingSuite.Suite
	suite.Run(t, testingSuite)
}

type enterpriseIntegrationGitopsTestSuite struct {
	suite.Suite
	integrationtest.WithServer
	mobiusCfg config.MobiusConfig
}

func (s *enterpriseIntegrationGitopsTestSuite) SetupSuite() {
	s.WithDS.SetupSuite("enterpriseIntegrationGitopsTestSuite")

	appConf, err := s.DS.AppConfig(context.Background())
	require.NoError(s.T(), err)
	appConf.MDM.EnabledAndConfigured = true
	appConf.MDM.AppleBMEnabledAndConfigured = true
	err = s.DS.SaveAppConfig(context.Background(), appConf)
	require.NoError(s.T(), err)

	testCert, testKey, err := appleMdm.NewSCEPCACertKey()
	require.NoError(s.T(), err)
	testCertPEM := tokenpki.PEMCertificate(testCert.Raw)
	testKeyPEM := tokenpki.PEMRSAPrivateKey(testKey)

	mobiusCfg := config.TestConfig()
	config.SetTestMDMConfig(s.T(), &mobiusCfg, testCertPEM, testKeyPEM, "../../../../server/service/testdata")
	mobiusCfg.Osquery.EnrollCooldown = 0

	err = s.DS.InsertMDMConfigAssets(context.Background(), []mobius.MDMConfigAsset{
		{Name: mobius.MDMAssetAPNSCert, Value: testCertPEM},
		{Name: mobius.MDMAssetAPNSKey, Value: testKeyPEM},
		{Name: mobius.MDMAssetCACert, Value: testCertPEM},
		{Name: mobius.MDMAssetCAKey, Value: testKeyPEM},
	}, nil)
	require.NoError(s.T(), err)

	mdmStorage, err := s.DS.NewMDMAppleMDMStorage()
	require.NoError(s.T(), err)
	depStorage, err := s.DS.NewMDMAppleDEPStorage()
	require.NoError(s.T(), err)
	scepStorage, err := s.DS.NewSCEPDepot()
	require.NoError(s.T(), err)
	redisPool := redistest.SetupRedis(s.T(), "zz", false, false, false)

	serverConfig := service.TestServerOpts{
		License: &mobius.LicenseInfo{
			Tier: mobius.TierPremium,
		},
		MobiusConfig:       &mobiusCfg,
		MDMStorage:        mdmStorage,
		DEPStorage:        depStorage,
		SCEPStorage:       scepStorage,
		Pool:              redisPool,
		APNSTopic:         "com.apple.mgmt.External.10ac3ce5-4668-4e58-b69a-b2b5ce667589",
		SCEPConfigService: eeservice.NewSCEPConfigService(kitlog.NewLogfmtLogger(os.Stdout), nil),
		DigiCertService:   digicert.NewService(),
	}
	err = s.DS.InsertMDMConfigAssets(context.Background(), []mobius.MDMConfigAsset{
		{Name: mobius.MDMAssetSCEPChallenge, Value: []byte("scepchallenge")},
	}, nil)
	require.NoError(s.T(), err)
	users, server := service.RunServerForTestsWithDS(s.T(), s.DS, &serverConfig)
	s.T().Setenv("MOBIUS_SERVER_ADDRESS", server.URL) // mobiuscli always uses this env var in tests
	s.Server = server
	s.Users = users
	s.mobiusCfg = mobiusCfg

	appConf, err = s.DS.AppConfig(context.Background())
	require.NoError(s.T(), err)
	appConf.ServerSettings.ServerURL = server.URL
	err = s.DS.SaveAppConfig(context.Background(), appConf)
	require.NoError(s.T(), err)
}

func (s *enterpriseIntegrationGitopsTestSuite) TearDownSuite() {
	appConf, err := s.DS.AppConfig(context.Background())
	require.NoError(s.T(), err)
	appConf.MDM.EnabledAndConfigured = false
	err = s.DS.SaveAppConfig(context.Background(), appConf)
	require.NoError(s.T(), err)
}

func (s *enterpriseIntegrationGitopsTestSuite) TearDownTest() {
	t := s.T()
	ctx := context.Background()

	teams, err := s.DS.ListTeams(ctx, mobius.TeamFilter{User: test.UserAdmin}, mobius.ListOptions{})
	require.NoError(t, err)
	for _, tm := range teams {
		err := s.DS.DeleteTeam(ctx, tm.ID)
		require.NoError(t, err)
	}

	// Clean software installers in "No team" (the others are deleted in ts.DS.DeleteTeam above).
	mysql.ExecAdhocSQL(t, s.DS, func(q sqlx.ExtContext) error {
		_, err := q.ExecContext(ctx, `DELETE FROM software_installers WHERE global_or_team_id = 0;`)
		return err
	})
	mysql.ExecAdhocSQL(t, s.DS, func(tx sqlx.ExtContext) error {
		_, err := tx.ExecContext(ctx, "DELETE FROM vpp_apps;")
		return err
	})

	lbls, err := s.DS.ListLabels(ctx, mobius.TeamFilter{User: test.UserAdmin}, mobius.ListOptions{})
	require.NoError(t, err)
	for _, lbl := range lbls {
		if lbl.LabelType != mobius.LabelTypeBuiltIn {
			err := s.DS.DeleteLabel(ctx, lbl.Name)
			require.NoError(t, err)
		}
	}
}

// TestMobiusGitops runs `mobiuscli gitops` command on configs in https://github.com/notawar/mobius-gitops repo.
// Changes to that repo may cause this test to fail.
func (s *enterpriseIntegrationGitopsTestSuite) TestMobiusGitops() {
	t := s.T()
	const mobiusGitopsRepo = "https://github.com/notawar/mobius-gitops"

	user := s.createGitOpsUser(t)
	mobiuscliConfig := s.createMobiusctlConfig(t, user)

	// Clone git repo
	repoDir := t.TempDir()
	_, err := git.PlainClone(
		repoDir, false, &git.CloneOptions{
			ReferenceName: "main",
			SingleBranch:  true,
			Depth:         1,
			URL:           mobiusGitopsRepo,
			Progress:      os.Stdout,
		},
	)
	require.NoError(t, err)

	// Set the required environment variables
	t.Setenv("MOBIUS_URL", s.Server.URL)
	t.Setenv("MOBIUS_GLOBAL_ENROLL_SECRET", "global_enroll_secret")
	t.Setenv("MOBIUS_WORKSTATIONS_ENROLL_SECRET", "workstations_enroll_secret")
	t.Setenv("MOBIUS_WORKSTATIONS_CANARY_ENROLL_SECRET", "workstations_canary_enroll_secret")
	globalFile := path.Join(repoDir, "default.yml")
	teamsDir := path.Join(repoDir, "teams")
	teamFiles, err := os.ReadDir(teamsDir)
	require.NoError(t, err)
	teamFileNames := make([]string, 0, len(teamFiles))
	for _, file := range teamFiles {
		if filepath.Ext(file.Name()) == ".yml" {
			teamFileNames = append(teamFileNames, path.Join(teamsDir, file.Name()))
		}
	}

	// Create a team to be deleted.
	deletedTeamFile, err := os.CreateTemp(t.TempDir(), "*.yml")
	require.NoError(t, err)
	const deletedTeamName = "team_to_be_deleted"

	_, err = deletedTeamFile.WriteString(
		fmt.Sprintf(
			`
controls:
software:
queries:
policies:
agent_options:
name: %s
team_settings:
  secrets: [{"secret":"deleted_team_secret"}]
`, deletedTeamName,
		),
	)
	require.NoError(t, err)

	test.CreateInsertGlobalVPPToken(t, s.DS)

	// Apply the team to be deleted
	_ = mobiuscli.RunAppForTest(t, []string{"gitops", "--config", mobiuscliConfig.Name(), "-f", deletedTeamFile.Name()})

	// Dry run
	_ = mobiuscli.RunAppForTest(t, []string{"gitops", "--config", mobiuscliConfig.Name(), "-f", globalFile, "--dry-run"})
	for _, fileName := range teamFileNames {
		_ = mobiuscli.RunAppForTest(t, []string{"gitops", "--config", mobiuscliConfig.Name(), "-f", fileName, "--dry-run"})
	}

	// Dry run with all the files
	args := []string{"gitops", "--config", mobiuscliConfig.Name(), "--dry-run", "--delete-other-teams", "-f", globalFile}
	for _, fileName := range teamFileNames {
		args = append(args, "-f", fileName)
	}
	_ = mobiuscli.RunAppForTest(t, args)

	// Real run with all the files, but don't delete other teams
	args = []string{"gitops", "--config", mobiuscliConfig.Name(), "-f", globalFile}
	for _, fileName := range teamFileNames {
		args = append(args, "-f", fileName)
	}
	_ = mobiuscli.RunAppForTest(t, args)

	// Check that all the teams exist
	teamsJSON := mobiuscli.RunAppForTest(t, []string{"get", "teams", "--config", mobiuscliConfig.Name(), "--json"})
	assert.Equal(t, 3, strings.Count(teamsJSON, "team_id"))

	// Real run with all the files, and delete other teams
	args = []string{"gitops", "--config", mobiuscliConfig.Name(), "--delete-other-teams", "-f", globalFile}
	for _, fileName := range teamFileNames {
		args = append(args, "-f", fileName)
	}
	_ = mobiuscli.RunAppForTest(t, args)

	// Check that only the right teams exist
	teamsJSON = mobiuscli.RunAppForTest(t, []string{"get", "teams", "--config", mobiuscliConfig.Name(), "--json"})
	assert.Equal(t, 2, strings.Count(teamsJSON, "team_id"))
	assert.NotContains(t, teamsJSON, deletedTeamName)

	// Real run with one file at a time
	_ = mobiuscli.RunAppForTest(t, []string{"gitops", "--config", mobiuscliConfig.Name(), "-f", globalFile})
	for _, fileName := range teamFileNames {
		_ = mobiuscli.RunAppForTest(t, []string{"gitops", "--config", mobiuscliConfig.Name(), "-f", fileName})
	}
}

func (s *enterpriseIntegrationGitopsTestSuite) createMobiusctlConfig(t *testing.T, user mobius.User) *os.File {
	mobiuscliConfig, err := os.CreateTemp(t.TempDir(), "*.yml")
	require.NoError(t, err)
	token := s.GetTestToken(user.Email, test.GoodPassword)
	configStr := fmt.Sprintf(
		`
contexts:
  default:
    address: %s
    tls-skip-verify: true
    token: %s
`, s.Server.URL, token,
	)
	_, err = mobiuscliConfig.WriteString(configStr)
	require.NoError(t, err)
	return mobiuscliConfig
}

func (s *enterpriseIntegrationGitopsTestSuite) createGitOpsUser(t *testing.T) mobius.User {
	user := mobius.User{
		Name:       "GitOps User",
		Email:      uuid.NewString() + "@example.com",
		GlobalRole: ptr.String(mobius.RoleGitOps),
	}
	require.NoError(t, user.SetPassword(test.GoodPassword, 10, 10))
	_, err := s.DS.NewUser(context.Background(), &user)
	require.NoError(t, err)
	return user
}

// TestDeleteMacOSSetup tests the deletion of macOS setup assets by `mobiuscli gitops` command.
func (s *enterpriseIntegrationGitopsTestSuite) TestDeleteMacOSSetup() {
	t := s.T()

	user := s.createGitOpsUser(t)
	mobiuscliConfig := s.createMobiusctlConfig(t, user)

	globalFile, err := os.CreateTemp(t.TempDir(), "*.yml")
	require.NoError(t, err)
	_, err = globalFile.WriteString(`
agent_options:
controls:
org_settings:
  server_settings:
    server_url: $MOBIUS_URL
  org_info:
    org_name: Mobius
  secrets:
policies:
queries:
`)
	require.NoError(t, err)

	teamName := uuid.NewString()
	teamFile, err := os.CreateTemp(t.TempDir(), "*.yml")
	require.NoError(t, err)
	_, err = teamFile.WriteString(
		fmt.Sprintf(
			`
controls:
software:
queries:
policies:
agent_options:
name: %s
team_settings:
  secrets: [{"secret":"enroll_secret"}]
`, teamName,
		),
	)
	require.NoError(t, err)

	// Set the required environment variables
	t.Setenv("MOBIUS_URL", s.Server.URL)

	// Apply configs
	_ = mobiuscli.RunAppForTest(t,
		[]string{"gitops", "--config", mobiuscliConfig.Name(), "-f", globalFile.Name(), "-f", teamFile.Name(), "--dry-run"})
	_ = mobiuscli.RunAppForTest(t, []string{"gitops", "--config", mobiuscliConfig.Name(), "-f", globalFile.Name(), "-f", teamFile.Name()})

	// Add bootstrap packages
	require.NoError(t, s.DS.InsertMDMAppleBootstrapPackage(context.Background(), &mobius.MDMAppleBootstrapPackage{
		Name:   "bootstrap.pkg",
		TeamID: 0,
		Bytes:  []byte("bootstrap package"),
		Token:  uuid.NewString(),
		Sha256: []byte("sha256"),
	}, nil))
	team, err := s.DS.TeamByName(context.Background(), teamName)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = s.DS.DeleteTeam(context.Background(), team.ID)
	})
	require.NoError(t, s.DS.InsertMDMAppleBootstrapPackage(context.Background(), &mobius.MDMAppleBootstrapPackage{
		Name:   "bootstrap.pkg",
		TeamID: team.ID,
		Bytes:  []byte("bootstrap package"),
		Token:  uuid.NewString(),
		Sha256: []byte("sha256"),
	}, nil))
	mysql.ExecAdhocSQL(t, s.DS, func(q sqlx.ExtContext) error {
		stmt := "SELECT COUNT(*) FROM mdm_apple_bootstrap_packages WHERE team_id IN (?, ?)"
		var result int
		require.NoError(t, sqlx.GetContext(context.Background(), q, &result, stmt, 0, team.ID))
		assert.Equal(t, 2, result)
		return nil
	})

	// Add enrollment profiles
	_, err = s.DS.SetOrUpdateMDMAppleSetupAssistant(context.Background(), &mobius.MDMAppleSetupAssistant{
		TeamID:  nil,
		Name:    "enrollment_profile.json",
		Profile: []byte(`{"foo":"bar"}`),
	})
	require.NoError(t, err)
	_, err = s.DS.SetOrUpdateMDMAppleSetupAssistant(context.Background(), &mobius.MDMAppleSetupAssistant{
		TeamID:  &team.ID,
		Name:    "enrollment_profile.json",
		Profile: []byte(`{"foo":"bar"}`),
	})
	require.NoError(t, err)
	mysql.ExecAdhocSQL(t, s.DS, func(q sqlx.ExtContext) error {
		stmt := "SELECT COUNT(*) FROM mdm_apple_setup_assistants WHERE global_or_team_id IN (?, ?)"
		var result int
		require.NoError(t, sqlx.GetContext(context.Background(), q, &result, stmt, 0, team.ID))
		assert.Equal(t, 2, result)
		return nil
	})

	// Re-apply configs and expect the macOS setup assets to be cleared
	_ = mobiuscli.RunAppForTest(t,
		[]string{"gitops", "--config", mobiuscliConfig.Name(), "-f", globalFile.Name(), "-f", teamFile.Name(), "--dry-run"})
	_ = mobiuscli.RunAppForTest(t, []string{"gitops", "--config", mobiuscliConfig.Name(), "-f", globalFile.Name(), "-f", teamFile.Name()})

	mysql.ExecAdhocSQL(t, s.DS, func(q sqlx.ExtContext) error {
		stmt := "SELECT COUNT(*) FROM mdm_apple_bootstrap_packages WHERE team_id IN (?, ?)"
		var result int
		require.NoError(t, sqlx.GetContext(context.Background(), q, &result, stmt, 0, team.ID))
		assert.Equal(t, 0, result)
		return nil
	})
	mysql.ExecAdhocSQL(t, s.DS, func(q sqlx.ExtContext) error {
		stmt := "SELECT COUNT(*) FROM mdm_apple_setup_assistants WHERE global_or_team_id IN (?, ?)"
		var result int
		require.NoError(t, sqlx.GetContext(context.Background(), q, &result, stmt, 0, team.ID))
		assert.Equal(t, 0, result)
		return nil
	})
}

// TestCAIntegrations enables DigiCert and Custom SCEP CAs via GitOps.
// At the same time, GitOps uploads Apple profiles that use the newly configured CAs.
func (s *enterpriseIntegrationGitopsTestSuite) TestCAIntegrations() {
	t := s.T()
	user := s.createGitOpsUser(t)
	mobiuscliConfig := s.createMobiusctlConfig(t, user)

	var (
		gotProfileMu sync.Mutex
		gotProfile   bool
	)
	digiCertServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			matches := regexp.MustCompile(`^/mpki/api/v2/profile/([a-zA-Z0-9_-]+)$`).FindStringSubmatch(r.URL.Path)
			if len(matches) != 2 {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			profileID := matches[1]

			resp := map[string]string{
				"id":     profileID,
				"name":   "DigiCert",
				"status": "Active",
			}
			err := json.NewEncoder(w).Encode(resp)
			require.NoError(t, err)
			gotProfileMu.Lock()
			gotProfile = profileID == "digicert_profile_id"
			defer gotProfileMu.Unlock()
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	t.Cleanup(digiCertServer.Close)

	scepServer := scep_server.StartTestSCEPServer(t)

	// Get the path to the directory of this test file
	_, currentFile, _, ok := runtime.Caller(0)
	require.True(t, ok, "failed to get runtime caller info")
	dirPath := filepath.Dir(currentFile)
	// Resolve ../../mobiuscli relative to the source file directory
	dirPath = filepath.Join(dirPath, "../../mobiuscli")
	// Clean and convert to absolute path
	dirPath, err := filepath.Abs(filepath.Clean(dirPath))
	require.NoError(t, err)

	globalFile, err := os.CreateTemp(t.TempDir(), "*.yml")
	require.NoError(t, err)
	_, err = globalFile.WriteString(fmt.Sprintf(`
agent_options:
controls:
  macos_settings:
    custom_settings:
      - path: %s/testdata/gitops/lib/scep-and-digicert.mobileconfig
org_settings:
  server_settings:
    server_url: $MOBIUS_URL
  org_info:
    org_name: Mobius
  secrets:
  integrations:
    digicert:
      - name: DigiCert
        url: %s
        api_token: digicert_api_token
        profile_id: digicert_profile_id
        certificate_common_name: digicert_cn
        certificate_user_principal_names: ["digicert_upn"]
        certificate_seat_id: digicert_seat_id
    custom_scep_proxy:
      - name: CustomScepProxy
        url: %s
        challenge: challenge
policies:
queries:
`, dirPath, digiCertServer.URL, scepServer.URL+"/scep"))
	require.NoError(t, err)

	// Set the required environment variables
	t.Setenv("MOBIUS_URL", s.Server.URL)

	// Apply configs
	_ = mobiuscli.RunAppForTest(t, []string{"gitops", "--config", mobiuscliConfig.Name(), "-f", globalFile.Name(), "--dry-run"})
	_ = mobiuscli.RunAppForTest(t, []string{"gitops", "--config", mobiuscliConfig.Name(), "-f", globalFile.Name()})

	appConfig, err := s.DS.AppConfig(context.Background())
	require.NoError(t, err)
	require.True(t, appConfig.Integrations.DigiCert.Valid)
	require.Len(t, appConfig.Integrations.DigiCert.Value, 1)
	digicertCA := appConfig.Integrations.DigiCert.Value[0]
	require.Equal(t, "DigiCert", digicertCA.Name)
	require.Equal(t, digiCertServer.URL, digicertCA.URL)
	require.Equal(t, mobius.MaskedPassword, digicertCA.APIToken)
	require.Equal(t, "digicert_profile_id", digicertCA.ProfileID)
	require.Equal(t, "digicert_cn", digicertCA.CertificateCommonName)
	require.Equal(t, []string{"digicert_upn"}, digicertCA.CertificateUserPrincipalNames)
	require.Equal(t, "digicert_seat_id", digicertCA.CertificateSeatID)
	gotProfileMu.Lock()
	require.True(t, gotProfile)
	gotProfileMu.Unlock()

	require.True(t, appConfig.Integrations.CustomSCEPProxy.Valid)
	require.Len(t, appConfig.Integrations.CustomSCEPProxy.Value, 1)
	customSCEPProxyCA := appConfig.Integrations.CustomSCEPProxy.Value[0]
	require.Equal(t, "CustomScepProxy", customSCEPProxyCA.Name)
	require.Equal(t, scepServer.URL+"/scep", customSCEPProxyCA.URL)
	require.Equal(t, mobius.MaskedPassword, customSCEPProxyCA.Challenge)

	profiles, _, err := s.DS.ListMDMConfigProfiles(context.Background(), nil, mobius.ListOptions{})
	require.NoError(t, err)
	assert.Len(t, profiles, 1)

	// Now test that we can clear the configs
	_, err = globalFile.WriteString(`
agent_options:
controls:
  macos_settings:
    custom_settings:
org_settings:
  server_settings:
    server_url: $MOBIUS_URL
  org_info:
    org_name: Mobius
  secrets:
policies:
queries:
`)
	require.NoError(t, err)

	_ = mobiuscli.RunAppForTest(t, []string{"gitops", "--config", mobiuscliConfig.Name(), "-f", globalFile.Name(), "--dry-run"})
	_ = mobiuscli.RunAppForTest(t, []string{"gitops", "--config", mobiuscliConfig.Name(), "-f", globalFile.Name()})
	appConfig, err = s.DS.AppConfig(context.Background())
	require.NoError(t, err)
	assert.Empty(t, appConfig.Integrations.DigiCert.Value)
	assert.Empty(t, appConfig.Integrations.CustomSCEPProxy.Value)
}

// TestUnsetConfigurationProfileLabels tests the removal of labels associated with a
// configuration profile via gitops.
func (s *enterpriseIntegrationGitopsTestSuite) TestUnsetConfigurationProfileLabels() {
	t := s.T()
	ctx := context.Background()

	user := s.createGitOpsUser(t)
	mobiuscliConfig := s.createMobiusctlConfig(t, user)
	lbl, err := s.DS.NewLabel(ctx, &mobius.Label{Name: "Label1", Query: "SELECT 1"})
	require.NoError(t, err)
	require.NotZero(t, lbl.ID)

	profileFile, err := os.CreateTemp(t.TempDir(), "*.mobileconfig")
	require.NoError(t, err)
	_, err = profileFile.WriteString(test.GenerateMDMAppleProfile("test", "test", uuid.NewString()))
	require.NoError(t, err)
	err = profileFile.Close()
	require.NoError(t, err)

	const (
		globalTemplate = `
agent_options:
controls:
  macos_settings:
    custom_settings:
      - path: %s
%s
org_settings:
  server_settings:
    server_url: $MOBIUS_URL
  org_info:
    org_name: Mobius
  secrets:
policies:
queries:
`
		withLabelsIncludeAny = `
        labels_include_any:
          - Label1
`
		emptyLabelsIncludeAny = `
        labels_include_any:
`
		teamTemplate = `
controls:
  macos_settings:
    custom_settings:
      - path: %s
%s
software:
queries:
policies:
agent_options:
name: %s
team_settings:
  secrets: [{"secret":"enroll_secret"}]
`
		withLabelsIncludeAll = `
        labels_include_all:
          - Label1
`
	)

	globalFile, err := os.CreateTemp(t.TempDir(), "*.yml")
	require.NoError(t, err)
	_, err = globalFile.WriteString(fmt.Sprintf(globalTemplate, profileFile.Name(), withLabelsIncludeAny))
	require.NoError(t, err)
	err = globalFile.Close()
	require.NoError(t, err)

	teamName := uuid.NewString()
	teamFile, err := os.CreateTemp(t.TempDir(), "*.yml")
	require.NoError(t, err)
	_, err = teamFile.WriteString(fmt.Sprintf(teamTemplate, profileFile.Name(), withLabelsIncludeAll, teamName))
	require.NoError(t, err)
	err = teamFile.Close()
	require.NoError(t, err)

	// Set the required environment variables
	t.Setenv("MOBIUS_URL", s.Server.URL)

	// Apply configs
	_ = mobiuscli.RunAppForTest(t,
		[]string{"gitops", "--config", mobiuscliConfig.Name(), "-f", globalFile.Name(), "-f", teamFile.Name(), "--dry-run"})
	_ = mobiuscli.RunAppForTest(t, []string{"gitops", "--config", mobiuscliConfig.Name(), "-f", globalFile.Name(), "-f", teamFile.Name()})

	// get the team ID
	team, err := s.DS.TeamByName(ctx, teamName)
	require.NoError(t, err)

	// the custom setting is scoped by the label for no team
	profs, _, err := s.DS.ListMDMConfigProfiles(ctx, nil, mobius.ListOptions{})
	require.NoError(t, err)
	require.Len(t, profs, 1)
	require.Len(t, profs[0].LabelsIncludeAny, 1)
	require.Equal(t, "Label1", profs[0].LabelsIncludeAny[0].LabelName)

	// the custom setting is scoped by the label for team
	profs, _, err = s.DS.ListMDMConfigProfiles(ctx, &team.ID, mobius.ListOptions{})
	require.NoError(t, err)
	require.Len(t, profs, 1)
	require.Len(t, profs[0].LabelsIncludeAll, 1)
	require.Equal(t, "Label1", profs[0].LabelsIncludeAll[0].LabelName)

	// remove the label conditions
	err = os.WriteFile(globalFile.Name(), []byte(fmt.Sprintf(globalTemplate, profileFile.Name(), emptyLabelsIncludeAny)), 0o644)
	require.NoError(t, err)
	err = os.WriteFile(teamFile.Name(), []byte(fmt.Sprintf(teamTemplate, profileFile.Name(), "", teamName)), 0o644)
	require.NoError(t, err)

	// Apply configs
	_ = mobiuscli.RunAppForTest(t,
		[]string{"gitops", "--config", mobiuscliConfig.Name(), "-f", globalFile.Name(), "-f", teamFile.Name(), "--dry-run"})
	_ = mobiuscli.RunAppForTest(t, []string{"gitops", "--config", mobiuscliConfig.Name(), "-f", globalFile.Name(), "-f", teamFile.Name()})

	// the custom setting is not scoped by label anymore
	profs, _, err = s.DS.ListMDMConfigProfiles(ctx, nil, mobius.ListOptions{})
	require.NoError(t, err)
	require.Len(t, profs, 1)
	require.Len(t, profs[0].LabelsIncludeAny, 0)

	profs, _, err = s.DS.ListMDMConfigProfiles(ctx, &team.ID, mobius.ListOptions{})
	require.NoError(t, err)
	require.Len(t, profs, 1)
	require.Len(t, profs[0].LabelsIncludeAll, 0)
}

// TestUnsetSoftwareInstallerLabels tests the removal of labels associated with a
// software installer via gitops.
func (s *enterpriseIntegrationGitopsTestSuite) TestUnsetSoftwareInstallerLabels() {
	t := s.T()
	ctx := context.Background()

	user := s.createGitOpsUser(t)
	mobiuscliConfig := s.createMobiusctlConfig(t, user)
	lbl, err := s.DS.NewLabel(ctx, &mobius.Label{Name: "Label1", Query: "SELECT 1"})
	require.NoError(t, err)
	require.NotZero(t, lbl.ID)

	const (
		globalTemplate = `
agent_options:
controls:
org_settings:
  server_settings:
    server_url: $MOBIUS_URL
  org_info:
    org_name: Mobius
  secrets:
policies:
queries:
`

		noTeamTemplate = `name: No team
controls:
policies:
software:
  packages:
    - url: ${SOFTWARE_INSTALLER_URL}/ruby.deb
%s
`
		withLabelsIncludeAny = `
      labels_include_any:
        - Label1
`
		emptyLabelsIncludeAny = `
      labels_include_any:
`
		teamTemplate = `
controls:
software:
  packages:
    - url: ${SOFTWARE_INSTALLER_URL}/ruby.deb
%s
queries:
policies:
agent_options:
name: %s
team_settings:
  secrets: [{"secret":"enroll_secret"}]
`
		withLabelsExcludeAny = `
      labels_exclude_any:
        - Label1
`
	)

	globalFile, err := os.CreateTemp(t.TempDir(), "*.yml")
	require.NoError(t, err)
	_, err = globalFile.WriteString(globalTemplate)
	require.NoError(t, err)
	err = globalFile.Close()
	require.NoError(t, err)

	noTeamFile, err := os.CreateTemp(t.TempDir(), "*.yml")
	require.NoError(t, err)
	_, err = noTeamFile.WriteString(fmt.Sprintf(noTeamTemplate, withLabelsIncludeAny))
	require.NoError(t, err)
	err = noTeamFile.Close()
	require.NoError(t, err)
	noTeamFilePath := filepath.Join(filepath.Dir(noTeamFile.Name()), "no-team.yml")
	err = os.Rename(noTeamFile.Name(), noTeamFilePath)
	require.NoError(t, err)

	teamName := uuid.NewString()
	teamFile, err := os.CreateTemp(t.TempDir(), "*.yml")
	require.NoError(t, err)
	_, err = teamFile.WriteString(fmt.Sprintf(teamTemplate, withLabelsExcludeAny, teamName))
	require.NoError(t, err)
	err = teamFile.Close()
	require.NoError(t, err)

	// Set the required environment variables
	t.Setenv("MOBIUS_URL", s.Server.URL)
	testing_utils.StartSoftwareInstallerServer(t)

	// Apply configs
	_ = mobiuscli.RunAppForTest(t,
		[]string{"gitops", "--config", mobiuscliConfig.Name(), "-f", globalFile.Name(), "-f", noTeamFilePath, "-f", teamFile.Name(), "--dry-run"})
	_ = mobiuscli.RunAppForTest(t,
		[]string{"gitops", "--config", mobiuscliConfig.Name(), "-f", globalFile.Name(), "-f", noTeamFilePath, "-f", teamFile.Name()})

	// get the team ID
	team, err := s.DS.TeamByName(ctx, teamName)
	require.NoError(t, err)

	// the installer is scoped by the label for no team
	titles, _, _, err := s.DS.ListSoftwareTitles(ctx, mobius.SoftwareTitleListOptions{AvailableForInstall: true, TeamID: ptr.Uint(0)},
		mobius.TeamFilter{User: test.UserAdmin})
	require.NoError(t, err)
	require.Len(t, titles, 1)
	require.NotNil(t, titles[0].SoftwarePackage)
	noTeamTitleID := titles[0].ID
	meta, err := s.DS.GetSoftwareInstallerMetadataByTeamAndTitleID(ctx, nil, noTeamTitleID, false)
	require.NoError(t, err)
	require.Len(t, meta.LabelsIncludeAny, 1)
	require.Equal(t, "Label1", meta.LabelsIncludeAny[0].LabelName)

	// the installer is scoped by the label for team
	titles, _, _, err = s.DS.ListSoftwareTitles(ctx, mobius.SoftwareTitleListOptions{TeamID: &team.ID}, mobius.TeamFilter{User: test.UserAdmin})
	require.NoError(t, err)
	require.Len(t, titles, 1)
	require.NotNil(t, titles[0].SoftwarePackage)
	teamTitleID := titles[0].ID
	meta, err = s.DS.GetSoftwareInstallerMetadataByTeamAndTitleID(ctx, &team.ID, teamTitleID, false)
	require.NoError(t, err)
	require.Len(t, meta.LabelsExcludeAny, 1)
	require.Equal(t, "Label1", meta.LabelsExcludeAny[0].LabelName)

	// remove the label conditions
	err = os.WriteFile(noTeamFilePath, []byte(fmt.Sprintf(noTeamTemplate, emptyLabelsIncludeAny)), 0o644)
	require.NoError(t, err)
	err = os.WriteFile(teamFile.Name(), []byte(fmt.Sprintf(teamTemplate, "", teamName)), 0o644)
	require.NoError(t, err)

	// Apply configs
	_ = mobiuscli.RunAppForTest(t,
		[]string{"gitops", "--config", mobiuscliConfig.Name(), "-f", globalFile.Name(), "-f", noTeamFilePath, "-f", teamFile.Name(), "--dry-run"})
	_ = mobiuscli.RunAppForTest(t,
		[]string{"gitops", "--config", mobiuscliConfig.Name(), "-f", globalFile.Name(), "-f", noTeamFilePath, "-f", teamFile.Name()})

	// the installer is not scoped by label anymore
	meta, err = s.DS.GetSoftwareInstallerMetadataByTeamAndTitleID(ctx, nil, noTeamTitleID, false)
	require.NoError(t, err)
	require.NotNil(t, meta.TitleID)
	require.Equal(t, noTeamTitleID, *meta.TitleID)
	require.Len(t, meta.LabelsExcludeAny, 0)
	require.Len(t, meta.LabelsIncludeAny, 0)

	meta, err = s.DS.GetSoftwareInstallerMetadataByTeamAndTitleID(ctx, &team.ID, teamTitleID, false)
	require.NoError(t, err)
	require.NotNil(t, meta.TitleID)
	require.Equal(t, teamTitleID, *meta.TitleID)
	require.Len(t, meta.LabelsExcludeAny, 0)
	require.Len(t, meta.LabelsIncludeAny, 0)
}

func (s *enterpriseIntegrationGitopsTestSuite) TestDeletingNoTeamYAML() {
	t := s.T()
	ctx := context.Background()

	user := s.createGitOpsUser(t)
	mobiuscliConfig := s.createMobiusctlConfig(t, user)

	// Set the required environment variables
	t.Setenv("MOBIUS_URL", s.Server.URL)

	// global file setup
	const (
		globalTemplate = `
agent_options:
controls:
org_settings:
  server_settings:
    server_url: $MOBIUS_URL
  org_info:
    org_name: Mobius
  secrets:
policies:
queries:
`
	)

	globalFile, err := os.CreateTemp(t.TempDir(), "*.yml")
	require.NoError(t, err)
	_, err = globalFile.WriteString(globalTemplate)
	require.NoError(t, err)
	err = globalFile.Close()
	require.NoError(t, err)

	// setup script
	const testScriptTemplate = `echo "Hello, world!"`

	scriptFile, err := os.CreateTemp(t.TempDir(), "*.sh")
	require.NoError(t, err)
	_, err = scriptFile.WriteString(testScriptTemplate)
	require.NoError(t, err)
	err = scriptFile.Close()
	require.NoError(t, err)

	// no team file setup
	const (
		noTeamTemplate = `name: No team
policies:
controls:
  macos_setup:
    script: %s
software:
`
	)

	noTeamFile, err := os.CreateTemp(t.TempDir(), "*.yml")
	require.NoError(t, err)
	_, err = noTeamFile.WriteString(fmt.Sprintf(noTeamTemplate, scriptFile.Name()))
	require.NoError(t, err)
	err = noTeamFile.Close()
	require.NoError(t, err)
	noTeamFilePath := filepath.Join(filepath.Dir(noTeamFile.Name()), "no-team.yml")
	err = os.Rename(noTeamFile.Name(), noTeamFilePath)
	require.NoError(t, err)

	_ = mobiuscli.RunAppForTest(t,
		[]string{"gitops", "--config", mobiuscliConfig.Name(), "-f", globalFile.Name(), "-f", noTeamFilePath, "--dry-run"})
	_ = mobiuscli.RunAppForTest(t, []string{"gitops", "--config", mobiuscliConfig.Name(), "-f", globalFile.Name(), "-f", noTeamFilePath})

	// Check script existance
	_, err = s.DS.GetSetupExperienceScript(ctx, nil)
	require.NoError(t, err)

	_ = mobiuscli.RunAppForTest(t, []string{"gitops", "--config", mobiuscliConfig.Name(), "-f", globalFile.Name(), "--dry-run"})
	_ = mobiuscli.RunAppForTest(t, []string{"gitops", "--config", mobiuscliConfig.Name(), "-f", globalFile.Name()})

	// Check script does not exist
	_, err = s.DS.GetSetupExperienceScript(ctx, nil)
	var nfe mobius.NotFoundError
	require.ErrorAs(t, err, &nfe)
}

func (s *enterpriseIntegrationGitopsTestSuite) TestRemoveCustomSettingsFromDefaultYAML() {
	t := s.T()
	ctx := context.Background()

	user := s.createGitOpsUser(t)
	mobiuscliConfig := s.createMobiusctlConfig(t, user)

	// Set the required environment variables
	t.Setenv("MOBIUS_URL", s.Server.URL)

	// setup custom settings profile
	profileFile, err := os.CreateTemp(t.TempDir(), "*.mobileconfig")
	require.NoError(t, err)
	_, err = profileFile.WriteString(test.GenerateMDMAppleProfile("test", "test", uuid.NewString()))
	require.NoError(t, err)
	err = profileFile.Close()
	require.NoError(t, err)

	// global file setup with custom settings
	const (
		globalTemplateWithCustomSettings = `
agent_options:
controls:
  macos_settings:
    custom_settings:
      - path: %s
org_settings:
  server_settings:
    server_url: $MOBIUS_URL
  org_info:
    org_name: Mobius
  secrets:
policies:
queries:
`
	)

	globalFile, err := os.CreateTemp(t.TempDir(), "*.yml")
	require.NoError(t, err)
	_, err = globalFile.WriteString(fmt.Sprintf(globalTemplateWithCustomSettings, profileFile.Name()))
	require.NoError(t, err)
	err = globalFile.Close()
	require.NoError(t, err)

	_ = mobiuscli.RunAppForTest(t, []string{"gitops", "--config", mobiuscliConfig.Name(), "-f", globalFile.Name(), "--dry-run"})
	_ = mobiuscli.RunAppForTest(t, []string{"gitops", "--config", mobiuscliConfig.Name(), "-f", globalFile.Name()})

	profiles, err := s.DS.ListMDMAppleConfigProfiles(ctx, nil)
	require.NoError(t, err)
	require.Equal(t, 1, len(profiles))

	// global file setup without custom settings
	const (
		globalTemplateWithoutCustomSettings = `
agent_options:
controls:
org_settings:
  server_settings:
    server_url: $MOBIUS_URL
  org_info:
    org_name: Mobius
  secrets:
policies:
queries:
`
	)

	globalFile, err = os.CreateTemp(t.TempDir(), "*.yml")
	require.NoError(t, err)
	_, err = globalFile.WriteString(globalTemplateWithoutCustomSettings)
	require.NoError(t, err)
	err = globalFile.Close()
	require.NoError(t, err)

	_ = mobiuscli.RunAppForTest(t, []string{"gitops", "--config", mobiuscliConfig.Name(), "-f", globalFile.Name(), "--dry-run"})
	_ = mobiuscli.RunAppForTest(t, []string{"gitops", "--config", mobiuscliConfig.Name(), "-f", globalFile.Name()})

	// Check profile does not exist
	profiles, err = s.DS.ListMDMAppleConfigProfiles(ctx, nil)
	require.NoError(t, err)
	require.Equal(t, 0, len(profiles))
}

func (s *enterpriseIntegrationGitopsTestSuite) TestMacOSSetup() {
	t := s.T()
	ctx := context.Background()

	user := s.createGitOpsUser(t)
	mobiuscliConfig := s.createMobiusctlConfig(t, user)

	const (
		globalConfig = `
agent_options:
org_settings:
  server_settings:
    server_url: $MOBIUS_URL
  org_info:
    org_name: Mobius
  secrets:
policies:
queries:
`

		globalConfigOnly = `
agent_options:
controls:
  macos_setup:
    manual_agent_install: %t
org_settings:
  server_settings:
    server_url: $MOBIUS_URL
  org_info:
    org_name: Mobius
  secrets:
policies:
queries:
`

		noTeamConfig = `name: No team
controls:
  macos_setup:
    manual_agent_install: true
policies:
software:
`

		teamConfig = `
controls:
  macos_setup:
    manual_agent_install: %t
software:
queries:
policies:
agent_options:
name: %s
team_settings:
  secrets: [{"secret":"enroll_secret"}]
`
	)

	globalFile, err := os.CreateTemp(t.TempDir(), "*.yml")
	require.NoError(t, err)
	_, err = globalFile.WriteString(globalConfig)
	require.NoError(t, err)
	err = globalFile.Close()
	require.NoError(t, err)

	noTeamFile, err := os.CreateTemp(t.TempDir(), "*.yml")
	require.NoError(t, err)
	_, err = noTeamFile.WriteString(noTeamConfig)
	require.NoError(t, err)
	err = noTeamFile.Close()
	require.NoError(t, err)
	noTeamFilePath := filepath.Join(filepath.Dir(noTeamFile.Name()), "no-team.yml")
	err = os.Rename(noTeamFile.Name(), noTeamFilePath)
	require.NoError(t, err)

	teamName := uuid.NewString()
	teamFile, err := os.CreateTemp(t.TempDir(), "*.yml")
	require.NoError(t, err)
	_, err = teamFile.WriteString(fmt.Sprintf(teamConfig, true, teamName))
	require.NoError(t, err)
	err = teamFile.Close()
	require.NoError(t, err)
	teamFileClear, err := os.CreateTemp(t.TempDir(), "*.yml")
	require.NoError(t, err)
	_, err = teamFileClear.WriteString(fmt.Sprintf(teamConfig, false, teamName))
	require.NoError(t, err)
	err = teamFileClear.Close()
	require.NoError(t, err)

	globalFileOnlySet, err := os.CreateTemp(t.TempDir(), "*.yml")
	require.NoError(t, err)
	_, err = globalFileOnlySet.WriteString(fmt.Sprintf(globalConfigOnly, true))
	require.NoError(t, err)
	err = globalFileOnlySet.Close()
	require.NoError(t, err)
	globalFileOnlyClear, err := os.CreateTemp(t.TempDir(), "*.yml")
	require.NoError(t, err)
	_, err = globalFileOnlyClear.WriteString(fmt.Sprintf(globalConfigOnly, false))
	require.NoError(t, err)
	err = globalFileOnlyClear.Close()
	require.NoError(t, err)

	// Set the required environment variables
	t.Setenv("MOBIUS_URL", s.Server.URL)

	// Apply configs
	_ = mobiuscli.RunAppForTest(t,
		[]string{"gitops", "--config", mobiuscliConfig.Name(), "-f", globalFile.Name(), "-f", noTeamFilePath, "-f", teamFile.Name(), "--dry-run"})
	_ = mobiuscli.RunAppForTest(t,
		[]string{"gitops", "--config", mobiuscliConfig.Name(), "-f", globalFile.Name(), "-f", noTeamFilePath, "-f", teamFile.Name()})

	appConfig, err := s.DS.AppConfig(ctx)
	require.NoError(t, err)
	assert.True(t, appConfig.MDM.MacOSSetup.ManualAgentInstall.Value)

	team, err := s.DS.TeamByName(ctx, teamName)
	require.NoError(t, err)
	assert.True(t, team.Config.MDM.MacOSSetup.ManualAgentInstall.Value)

	// Apply global configs without no-team
	_ = mobiuscli.RunAppForTest(t,
		[]string{"gitops", "--config", mobiuscliConfig.Name(), "-f", globalFileOnlyClear.Name(), "-f", teamFileClear.Name(), "--dry-run"})
	_ = mobiuscli.RunAppForTest(t,
		[]string{"gitops", "--config", mobiuscliConfig.Name(), "-f", globalFileOnlyClear.Name(), "-f", teamFileClear.Name()})
	appConfig, err = s.DS.AppConfig(ctx)
	require.NoError(t, err)
	assert.False(t, appConfig.MDM.MacOSSetup.ManualAgentInstall.Value)
	team, err = s.DS.TeamByName(ctx, teamName)
	require.NoError(t, err)
	assert.False(t, team.Config.MDM.MacOSSetup.ManualAgentInstall.Value)

	// Apply global configs only
	_ = mobiuscli.RunAppForTest(t,
		[]string{"gitops", "--config", mobiuscliConfig.Name(), "-f", globalFileOnlySet.Name(), "--dry-run"})
	_ = mobiuscli.RunAppForTest(t, []string{"gitops", "--config", mobiuscliConfig.Name(), "-f", globalFileOnlySet.Name()})
	appConfig, err = s.DS.AppConfig(ctx)
	require.NoError(t, err)
	assert.True(t, appConfig.MDM.MacOSSetup.ManualAgentInstall.Value)
}

func (s *enterpriseIntegrationGitopsTestSuite) TestMobiusGitOpsDeletesNonManagedLabels() {
	t := s.T()
	ctx := context.Background()

	// Set the required environment variables
	t.Setenv("MOBIUS_SERVER_URL", s.Server.URL)
	t.Setenv("ORG_NAME", "Around the block")

	user := s.createGitOpsUser(t)
	mobiuscliConfig := s.createMobiusctlConfig(t, user)

	var someUser mobius.User
	for _, u := range s.Users {
		someUser = u
		break
	}

	// 'nonManagedLabel' is associated with a software installer and is
	// not managed in the ops file so it should be deleted.
	nonManagedLabel, err := s.DS.NewLabel(ctx, &mobius.Label{
		Name:  t.Name(),
		Query: "bye bye label",
	})
	require.NoError(t, err)

	installer, err := mobius.NewTempFileReader(strings.NewReader("echo"), t.TempDir)
	require.NoError(t, err)

	_, _, err = s.DS.MatchOrCreateSoftwareInstaller(ctx, &mobius.UploadSoftwareInstallerPayload{
		InstallScript: "install zoo",
		InstallerFile: installer,
		StorageID:     uuid.NewString(),
		Filename:      "zoo.pkg",
		Title:         "zoo",
		Source:        "apps",
		Version:       "0.0.1",
		UserID:        someUser.ID,
		ValidatedLabels: &mobius.LabelIdentsWithScope{
			LabelScope: mobius.LabelScopeIncludeAny,
			ByName: map[string]mobius.LabelIdent{nonManagedLabel.Name: {
				LabelID:   nonManagedLabel.ID,
				LabelName: nonManagedLabel.Name,
			}},
		},
	})
	require.NoError(t, err)

	opsFile := path.Join("..", "..", "mobiuscli", "testdata", "gitops", "global_config_no_paths.yml")
	_ = mobiuscli.RunAppForTest(t, []string{"gitops", "--config", mobiuscliConfig.Name(), "-f", opsFile})

	// Check label was removed successfully
	result, err := s.DS.LabelIDsByName(ctx, []string{nonManagedLabel.Name})
	require.NoError(t, err)
	require.Empty(t, result)
}

func (s *enterpriseIntegrationGitopsTestSuite) TestMacOSSetupScriptWithMobiusSecret() {
	t := s.T()
	ctx := context.Background()

	user := s.createGitOpsUser(t)
	mobiuscliConfig := s.createMobiusctlConfig(t, user)

	const secretName = "MY_SECRET"
	const secretValue = "my-secret-value"

	// Set the required environment variables
	t.Setenv("MOBIUS_URL", s.Server.URL)
	t.Setenv("MOBIUS_SECRET_"+secretName, secretValue)

	// Create a script file that uses the mobius secret
	scriptFile, err := os.CreateTemp(t.TempDir(), "*.sh")
	require.NoError(t, err)
	_, err = scriptFile.WriteString(`echo "Using secret: $MOBIUS_SECRET_` + secretName)
	require.NoError(t, err)
	err = scriptFile.Close()
	require.NoError(t, err)

	// Create a no-team file with the script
	const noTeamTemplate = `name: No team
policies:
controls:
  macos_setup:
    script: %s
software:
`
	noTeamFile, err := os.CreateTemp(t.TempDir(), "*.yml")
	require.NoError(t, err)
	_, err = noTeamFile.WriteString(fmt.Sprintf(noTeamTemplate, scriptFile.Name()))
	require.NoError(t, err)
	err = noTeamFile.Close()
	require.NoError(t, err)
	noTeamFilePath := filepath.Join(filepath.Dir(noTeamFile.Name()), "no-team.yml")
	err = os.Rename(noTeamFile.Name(), noTeamFilePath)
	require.NoError(t, err)

	// Create a global file
	globalFile, err := os.CreateTemp(t.TempDir(), "*.yml")
	require.NoError(t, err)
	_, err = globalFile.WriteString(`
agent_options:
controls:
org_settings:
  server_settings:
    server_url: $MOBIUS_URL
  org_info:
    org_name: Mobius
  secrets:
policies:
queries:
`)
	require.NoError(t, err)

	// Apply the configs
	_ = mobiuscli.RunAppForTest(t, []string{"gitops", "--config", mobiuscliConfig.Name(), "-f", globalFile.Name(), "-f", noTeamFilePath, "--dry-run"})
	_ = mobiuscli.RunAppForTest(t, []string{"gitops", "--config", mobiuscliConfig.Name(), "-f", globalFile.Name(), "-f", noTeamFilePath})

	// Verify the script was saved
	_, err = s.DS.GetSetupExperienceScript(ctx, nil)
	require.NoError(t, err)

	// Verify the secret was saved
	secretVariables, err := s.DS.GetSecretVariables(ctx, []string{secretName})
	require.NoError(t, err)
	require.Equal(t, secretVariables[0].Name, secretName)
	require.Equal(t, secretVariables[0].Value, secretValue)
}
