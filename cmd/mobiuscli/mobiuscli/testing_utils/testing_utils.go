package testing_utils

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/notawar/mobius/v4/server/config"
	"github.com/notawar/mobius set/v4/server/datastore/cached_mysql"
	"github.com/notawar/mobius set/v4/server/datastore/mysql"
	"github.com/notawar/mobius set/v4/server/mobius"
	apple_mdm "github.com/notawar/mobius set/v4/server/mdm/apple"
	"github.com/notawar/mobius set/v4/server/mdm/apple/vpp"
	"github.com/notawar/mobius set/v4/server/mdm/nanodep/tokenpki"
	"github.com/notawar/mobius set/v4/server/mdm/nanomdm/push"
	mdmtesting "github.com/notawar/mobius set/v4/server/mdm/testing_utils"
	"github.com/notawar/mobius set/v4/server/mock"
	mock2 "github.com/notawar/mobius set/v4/server/mock/mdm"
	"github.com/notawar/mobius set/v4/server/service"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/require"
)

const (
	teamName       = "Team Test"
	mobiusServerURL = "https://mobius.example.com"
	orgName        = "GitOps Test"
)

// RunServerWithMockedDS runs the mobius server with several mocked DS methods.
//
// NOTE: Assumes the current session is always from the admin user (see ds.SessionByKeyFunc below).
func RunServerWithMockedDS(t *testing.T, opts ...*service.TestServerOpts) (*httptest.Server, *mock.Store) {
	ds := new(mock.Store)
	var users []*mobius.User
	var admin *mobius.User
	ds.NewUserFunc = func(ctx context.Context, user *mobius.User) (*mobius.User, error) {
		if user.GlobalRole != nil && *user.GlobalRole == mobius.RoleAdmin {
			admin = user
		}
		users = append(users, user)
		return user, nil
	}
	ds.SessionByKeyFunc = func(ctx context.Context, key string) (*mobius.Session, error) {
		return &mobius.Session{
			CreateTimestamp: mobius.CreateTimestamp{CreatedAt: time.Now()},
			ID:              1,
			AccessedAt:      time.Now(),
			UserID:          admin.ID,
			Key:             key,
		}, nil
	}
	ds.MarkSessionAccessedFunc = func(ctx context.Context, session *mobius.Session) error {
		return nil
	}
	ds.UserByIDFunc = func(ctx context.Context, id uint) (*mobius.User, error) {
		return admin, nil
	}
	ds.ListUsersFunc = func(ctx context.Context, opt mobius.UserListOptions) ([]*mobius.User, error) {
		return users, nil
	}
	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		return &mobius.AppConfig{}, nil
	}
	apnsCert, apnsKey, err := mysql.GenerateTestCertBytes(mdmtesting.NewTestMDMAppleCertTemplate())
	require.NoError(t, err)
	certPEM, keyPEM, tokenBytes, err := mysql.GenerateTestABMAssets(t)
	require.NoError(t, err)
	ds.GetAllMDMConfigAssetsHashesFunc = func(ctx context.Context, assetNames []mobius.MDMAssetName) (map[mobius.MDMAssetName]string, error) {
		return map[mobius.MDMAssetName]string{
			mobius.MDMAssetABMCert:            "abmcert",
			mobius.MDMAssetABMKey:             "abmkey",
			mobius.MDMAssetABMTokenDeprecated: "abmtoken",
			mobius.MDMAssetAPNSCert:           "apnscert",
			mobius.MDMAssetAPNSKey:            "apnskey",
			mobius.MDMAssetCACert:             "scepcert",
			mobius.MDMAssetCAKey:              "scepkey",
		}, nil
	}
	ds.GetAllMDMConfigAssetsByNameFunc = func(ctx context.Context, assetNames []mobius.MDMAssetName,
		_ sqlx.QueryerContext,
	) (map[mobius.MDMAssetName]mobius.MDMConfigAsset, error) {
		return map[mobius.MDMAssetName]mobius.MDMConfigAsset{
			mobius.MDMAssetABMCert:            {Name: mobius.MDMAssetABMCert, Value: certPEM},
			mobius.MDMAssetABMKey:             {Name: mobius.MDMAssetABMKey, Value: keyPEM},
			mobius.MDMAssetABMTokenDeprecated: {Name: mobius.MDMAssetABMTokenDeprecated, Value: tokenBytes},
			mobius.MDMAssetAPNSCert:           {Name: mobius.MDMAssetAPNSCert, Value: apnsCert},
			mobius.MDMAssetAPNSKey:            {Name: mobius.MDMAssetAPNSKey, Value: apnsKey},
			mobius.MDMAssetCACert:             {Name: mobius.MDMAssetCACert, Value: certPEM},
			mobius.MDMAssetCAKey:              {Name: mobius.MDMAssetCAKey, Value: keyPEM},
		}, nil
	}

	ds.ApplyYaraRulesFunc = func(context.Context, []mobius.YaraRule) error {
		return nil
	}
	ds.ValidateEmbeddedSecretsFunc = func(ctx context.Context, documents []string) error {
		return nil
	}
	ds.ScimUserByHostIDFunc = func(ctx context.Context, hostID uint) (*mobius.ScimUser, error) {
		return nil, nil
	}
	ds.ListHostDeviceMappingFunc = func(ctx context.Context, id uint) ([]*mobius.HostDeviceMapping, error) {
		return nil, nil
	}
	var cachedDS mobius.Datastore
	if len(opts) > 0 && opts[0].NoCacheDatastore {
		cachedDS = ds
	} else {
		cachedDS = cached_mysql.New(ds)
	}
	_, server := service.RunServerForTestsWithDS(t, cachedDS, opts...)
	os.Setenv("MOBIUS_SERVER_ADDRESS", server.URL)

	return server, ds
}

func getPathRelative(relativePath string) string {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		panic("failed to get runtime caller info")
	}
	sourceDir := filepath.Dir(currentFile)
	return filepath.Join(sourceDir, relativePath)
}

func ServeMDMBootstrapPackage(t *testing.T, pkgPath, pkgName string) (*httptest.Server, int) {
	pkgBytes, err := os.ReadFile(pkgPath)
	require.NoError(t, err)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(len(pkgBytes)))
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment;filename="%s"`, pkgName))
		if n, err := w.Write(pkgBytes); err != nil {
			require.NoError(t, err)
			require.Equal(t, len(pkgBytes), n)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, len(pkgBytes)
}

func StartSoftwareInstallerServer(t *testing.T) {
	// start the web server that will serve the installer
	b, err := os.ReadFile(getPathRelative("../../../../server/service/testdata/software-installers/ruby.deb"))
	require.NoError(t, err)

	srv := httptest.NewServer(
		http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.Contains(r.URL.Path, "notfound"):
					w.WriteHeader(http.StatusNotFound)
					return
				case strings.HasSuffix(r.URL.Path, ".txt"):
					w.Header().Set("Content-Type", "text/plain")
					_, _ = w.Write([]byte(`a simple text file`))
					return
				case strings.Contains(r.URL.Path, "toolarge"):
					w.Header().Set("Content-Type", "application/vnd.debian.binary-package")
					var sz int
					for sz < 3000*1024*1024 {
						n, _ := w.Write(b)
						sz += n
					}
				default:
					w.Header().Set("Content-Type", "application/vnd.debian.binary-package")
					_, _ = w.Write(b)
				}
			},
		),
	)
	t.Cleanup(srv.Close)
	t.Setenv("SOFTWARE_INSTALLER_URL", srv.URL)
}

func SetupFullGitOpsPremiumServer(t *testing.T) (*mock.Store, **mobius.AppConfig, map[string]**mobius.Team) {
	testCert, testKey, err := apple_mdm.NewSCEPCACertKey()
	require.NoError(t, err)
	testCertPEM := tokenpki.PEMCertificate(testCert.Raw)
	testKeyPEM := tokenpki.PEMRSAPrivateKey(testKey)
	mobiusCfg := config.TestConfig()
	config.SetTestMDMConfig(t, &mobiusCfg, testCertPEM, testKeyPEM, getPathRelative("../../../../server/service/testdata"))

	license := &mobius.LicenseInfo{Tier: mobius.TierPremium, Expiration: time.Now().Add(24 * time.Hour)}
	_, ds := RunServerWithMockedDS(
		t, &service.TestServerOpts{
			MDMStorage:       new(mock2.MDMAppleStore),
			MDMPusher:        MockPusher{},
			MobiusConfig:      &mobiusCfg,
			License:          license,
			NoCacheDatastore: true,
			KeyValueStore:    NewMemKeyValueStore(),
		},
	)

	// Mock appConfig
	savedAppConfig := &mobius.AppConfig{
		MDM: mobius.MDM{
			EnabledAndConfigured: true,
		},
	}
	AddLabelMocks(ds)

	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		appConfigCopy := *savedAppConfig
		return &appConfigCopy, nil
	}
	ds.SaveAppConfigFunc = func(ctx context.Context, config *mobius.AppConfig) error {
		appConfigCopy := *config
		savedAppConfig = &appConfigCopy
		return nil
	}
	ds.SetTeamVPPAppsFunc = func(ctx context.Context, teamID *uint, adamIDs []mobius.VPPAppTeam) error {
		return nil
	}
	ds.BatchInsertVPPAppsFunc = func(ctx context.Context, apps []*mobius.VPPApp) error {
		return nil
	}

	savedTeams := map[string]**mobius.Team{}

	ds.ApplyEnrollSecretsFunc = func(ctx context.Context, teamID *uint, secrets []*mobius.EnrollSecret) error {
		return nil
	}
	ds.ApplyPolicySpecsFunc = func(ctx context.Context, authorID uint, specs []*mobius.PolicySpec) error {
		return nil
	}
	ds.ApplyQueriesFunc = func(
		ctx context.Context, authorID uint, queries []*mobius.Query, queriesToDiscardResults map[uint]struct{},
	) error {
		return nil
	}
	ds.BatchSetMDMProfilesFunc = func(
		ctx context.Context, tmID *uint, macProfiles []*mobius.MDMAppleConfigProfile, winProfiles []*mobius.MDMWindowsConfigProfile,
		macDecls []*mobius.MDMAppleDeclaration, vars []mobius.MDMProfileIdentifierMobiusVariables,
	) (updates mobius.MDMProfilesUpdates, err error) {
		return mobius.MDMProfilesUpdates{}, nil
	}
	ds.BatchSetScriptsFunc = func(ctx context.Context, tmID *uint, scripts []*mobius.Script) ([]mobius.ScriptResponse, error) {
		return []mobius.ScriptResponse{}, nil
	}
	ds.BulkSetPendingMDMHostProfilesFunc = func(
		ctx context.Context, hostIDs []uint, teamIDs []uint, profileUUIDs []string, hostUUIDs []string,
	) (updates mobius.MDMProfilesUpdates, err error) {
		return mobius.MDMProfilesUpdates{}, nil
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
	ds.IsEnrollSecretAvailableFunc = func(ctx context.Context, secret string, isNew bool, teamID *uint) (bool, error) {
		return true, nil
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
		if savedTeams != nil {
			var result []*mobius.Team
			for _, t := range savedTeams {
				result = append(result, *t)
			}
			return result, nil
		}
		return nil, nil
	}
	ds.TeamsSummaryFunc = func(ctx context.Context) ([]*mobius.TeamSummary, error) {
		summary := make([]*mobius.TeamSummary, 0, len(savedTeams))
		for _, team := range savedTeams {
			summary = append(summary, &mobius.TeamSummary{
				ID:          (*team).ID,
				Name:        (*team).Name,
				Description: (*team).Description,
			})
		}
		return summary, nil
	}
	ds.ListQueriesFunc = func(ctx context.Context, opts mobius.ListQueryOptions) ([]*mobius.Query, int, *mobius.PaginationMetadata, error) {
		return nil, 0, nil, nil
	}
	ds.NewActivityFunc = func(
		ctx context.Context, user *mobius.User, activity mobius.ActivityDetails, details []byte, createdAt time.Time,
	) error {
		return nil
	}
	ds.NewMDMAppleConfigProfileFunc = func(ctx context.Context, p mobius.MDMAppleConfigProfile, vars []string) (*mobius.MDMAppleConfigProfile, error) {
		return nil, nil
	}
	ds.NewJobFunc = func(ctx context.Context, job *mobius.Job) (*mobius.Job, error) {
		job.ID = 1
		return job, nil
	}
	ds.NewTeamFunc = func(ctx context.Context, team *mobius.Team) (*mobius.Team, error) {
		team.ID = uint(len(savedTeams) + 1) //nolint:gosec // dismiss G115
		savedTeams[team.Name] = &team
		return team, nil
	}
	ds.QueryByNameFunc = func(ctx context.Context, teamID *uint, name string) (*mobius.Query, error) {
		return nil, &notFoundError{}
	}
	ds.TeamFunc = func(ctx context.Context, tid uint) (*mobius.Team, error) {
		for _, tm := range savedTeams {
			if (*tm).ID == tid {
				return *tm, nil
			}
		}
		return nil, &notFoundError{}
	}
	ds.TeamByNameFunc = func(ctx context.Context, name string) (*mobius.Team, error) {
		for _, tm := range savedTeams {
			if (*tm).Name == name {
				return *tm, nil
			}
		}
		return nil, &notFoundError{}
	}
	ds.TeamByFilenameFunc = func(ctx context.Context, filename string) (*mobius.Team, error) {
		for _, tm := range savedTeams {
			if (*tm).Filename != nil && *(*tm).Filename == filename {
				return *tm, nil
			}
		}
		return nil, &notFoundError{}
	}
	ds.SaveTeamFunc = func(ctx context.Context, team *mobius.Team) (*mobius.Team, error) {
		savedTeams[team.Name] = &team
		return team, nil
	}
	ds.SetOrUpdateMDMAppleDeclarationFunc = func(ctx context.Context, declaration *mobius.MDMAppleDeclaration) (
		*mobius.MDMAppleDeclaration, error,
	) {
		declaration.DeclarationUUID = uuid.NewString()
		return declaration, nil
	}
	ds.BatchSetSoftwareInstallersFunc = func(ctx context.Context, teamID *uint, installers []*mobius.UploadSoftwareInstallerPayload) error {
		return nil
	}
	ds.GetSoftwareInstallersFunc = func(ctx context.Context, tmID uint) ([]mobius.SoftwarePackageResponse, error) {
		return nil, nil
	}

	ds.InsertVPPTokenFunc = func(ctx context.Context, tok *mobius.VPPTokenData) (*mobius.VPPTokenDB, error) {
		return &mobius.VPPTokenDB{}, nil
	}
	ds.GetVPPTokenFunc = func(ctx context.Context, tokenID uint) (*mobius.VPPTokenDB, error) {
		return &mobius.VPPTokenDB{}, err
	}
	ds.GetVPPTokenByTeamIDFunc = func(ctx context.Context, teamID *uint) (*mobius.VPPTokenDB, error) {
		return &mobius.VPPTokenDB{}, nil
	}
	ds.ListVPPTokensFunc = func(ctx context.Context) ([]*mobius.VPPTokenDB, error) {
		return nil, nil
	}
	ds.UpdateVPPTokenTeamsFunc = func(ctx context.Context, id uint, teams []uint) (*mobius.VPPTokenDB, error) {
		return &mobius.VPPTokenDB{}, nil
	}
	ds.ListABMTokensFunc = func(ctx context.Context) ([]*mobius.ABMToken, error) {
		return []*mobius.ABMToken{{OrganizationName: "Mobius Device Management Inc."}}, nil
	}
	ds.ListSoftwareTitlesFunc = func(ctx context.Context, opt mobius.SoftwareTitleListOptions,
		tmFilter mobius.TeamFilter,
	) ([]mobius.SoftwareTitleListResult, int, *mobius.PaginationMetadata, error) {
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
	ds.SetSetupExperienceScriptFunc = func(ctx context.Context, script *mobius.Script) error {
		return nil
	}
	ds.ExpandEmbeddedSecretsAndUpdatedAtFunc = func(ctx context.Context, document string) (string, *time.Time, error) {
		return document, nil, nil
	}

	t.Setenv("MOBIUS_SERVER_URL", mobiusServerURL)
	t.Setenv("ORG_NAME", orgName)
	t.Setenv("TEST_TEAM_NAME", teamName)
	t.Setenv("APPLE_BM_DEFAULT_TEAM", teamName)

	return ds, &savedAppConfig, savedTeams
}

type AppleVPPConfigSrvConf struct {
	Assets        []vpp.Asset
	SerialNumbers []string
}

func StartVPPApplyServer(t *testing.T, config *AppleVPPConfigSrvConf) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "associate") {
			var associations vpp.AssociateAssetsRequest

			decoder := json.NewDecoder(r.Body)
			if err := decoder.Decode(&associations); err != nil {
				http.Error(w, "invalid request", http.StatusBadRequest)
				return
			}

			if len(associations.Assets) == 0 {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				res := vpp.ErrorResponse{
					ErrorNumber:  9718,
					ErrorMessage: "This request doesn't contain an asset, which is a required argument. Change the request to provide an asset.",
				}
				if err := json.NewEncoder(w).Encode(res); err != nil {
					panic(err)
				}
				return
			}

			if len(associations.SerialNumbers) == 0 {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				res := vpp.ErrorResponse{
					ErrorNumber:  9719,
					ErrorMessage: "Either clientUserIds or serialNumbers are required arguments. Change the request to provide assignable users and devices.",
				}
				if err := json.NewEncoder(w).Encode(res); err != nil {
					panic(err)
				}
				return
			}

			var badAssets []vpp.Asset
			for _, reqAsset := range associations.Assets {
				var found bool
				for _, goodAsset := range config.Assets {
					if reqAsset == goodAsset {
						found = true
					}
				}
				if !found {
					badAssets = append(badAssets, reqAsset)
				}
			}

			var badSerials []string
			for _, reqSerial := range associations.SerialNumbers {
				var found bool
				for _, goodSerial := range config.SerialNumbers {
					if reqSerial == goodSerial {
						found = true
					}
				}
				if !found {
					badSerials = append(badSerials, reqSerial)
				}
			}

			if len(badAssets) != 0 || len(badSerials) != 0 {
				errMsg := "error associating assets."
				if len(badAssets) > 0 {
					var badAdamIds []string
					for _, asset := range badAssets {
						badAdamIds = append(badAdamIds, asset.AdamID)
					}
					errMsg += fmt.Sprintf(" assets don't exist on account: %s.", strings.Join(badAdamIds, ", "))
				}
				if len(badSerials) > 0 {
					errMsg += fmt.Sprintf(" bad serials: %s.", strings.Join(badSerials, ", "))
				}
				res := vpp.ErrorResponse{
					ErrorInfo: vpp.ResponseErrorInfo{
						Assets:        badAssets,
						ClientUserIds: []string{"something"},
						SerialNumbers: badSerials,
					},
					// Not sure what error should be returned on each
					// error type
					ErrorNumber:  1,
					ErrorMessage: errMsg,
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				if err := json.NewEncoder(w).Encode(res); err != nil {
					panic(err)
				}
			}
			return
		}

		if strings.Contains(r.URL.Path, "assets") {
			// Then we're responding to GetAssets
			w.Header().Set("Content-Type", "application/json")
			encoder := json.NewEncoder(w)
			err := encoder.Encode(map[string][]vpp.Asset{"assets": config.Assets})
			if err != nil {
				panic(err)
			}
			return
		}

		resp := []byte(`{"locationName": "Mobius Location One"}`)
		if strings.Contains(r.URL.RawQuery, "invalidToken") {
			// This replicates the response sent back from Apple's VPP endpoints when an invalid
			// token is passed. For more details see:
			// https://developer.apple.com/documentation/devicemanagement/app_and_book_management/app_and_book_management_legacy/interpreting_error_codes
			// https://developer.apple.com/documentation/devicemanagement/client_config
			// https://developer.apple.com/documentation/devicemanagement/errorresponse
			// Note that the Apple server returns 200 in this case.
			resp = []byte(`{"errorNumber": 9622,"errorMessage": "Invalid authentication token"}`)
		}

		if strings.Contains(r.URL.RawQuery, "serverError") {
			resp = []byte(`{"errorNumber": 9603,"errorMessage": "Internal server error"}`)
			w.WriteHeader(http.StatusInternalServerError)
		}

		_, _ = w.Write(resp)
	}))

	t.Setenv("MOBIUS_DEV_VPP_URL", srv.URL)
	t.Cleanup(srv.Close)
}

func StartAndServeVPPServer(t *testing.T) {
	config := &AppleVPPConfigSrvConf{
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

	StartVPPApplyServer(t, config)

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

type MockPusher struct{}

func (MockPusher) Push(ctx context.Context, ids []string) (map[string]*push.Response, error) {
	m := make(map[string]*push.Response, len(ids))
	for _, id := range ids {
		m[id] = &push.Response{Id: id}
	}
	return m, nil
}

type MemKeyValueStore struct {
	m sync.Map
}

func NewMemKeyValueStore() *MemKeyValueStore {
	return &MemKeyValueStore{}
}

func (m *MemKeyValueStore) Set(ctx context.Context, key string, value string, expireTime time.Duration) error {
	m.m.Store(key, value)
	return nil
}

func (m *MemKeyValueStore) Get(ctx context.Context, key string) (*string, error) {
	v, ok := m.m.Load(key)
	if !ok {
		return nil, nil
	}
	vAsString := v.(string)
	return &vAsString, nil
}

func AddLabelMocks(ds *mock.Store) {
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
				Name:                "b",
				Description:         "Another global label",
				LabelMembershipType: mobius.LabelMembershipTypeDynamic,
				Query:               "SELECT 1 from osquery_info",
			},
		}, nil
	}
	ds.ApplyLabelSpecsWithAuthorFunc = func(ctx context.Context, specs []*mobius.LabelSpec, authorID *uint) (err error) {
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
}

type notFoundError struct{}

var _ mobius.NotFoundError = (*notFoundError)(nil)

func (e *notFoundError) IsNotFound() bool {
	return true
}

func (e *notFoundError) Error() string {
	return ""
}
