package service

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	_ "embed"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	eeservice "github.com/notawar/mobius/ee/server/service"
	"github.com/notawar/mobius/ee/server/service/digicert"
	"github.com/notawar/mobius/pkg/optjson"
	"github.com/notawar/mobius/server/authz"
	"github.com/notawar/mobius/server/config"
	"github.com/notawar/mobius/server/contexts/license"
	"github.com/notawar/mobius/server/contexts/viewer"
	"github.com/notawar/mobius/server/datastore/mysql"
	"github.com/notawar/mobius/server/mobius"
	mobiusmdm "github.com/notawar/mobius/server/mdm"
	apple_mdm "github.com/notawar/mobius/server/mdm/apple"
	"github.com/notawar/mobius/server/mdm/apple/mobileconfig"
	mdmlifecycle "github.com/notawar/mobius/server/mdm/lifecycle"
	nanodep_client "github.com/notawar/mobius/server/mdm/nanodep/client"
	"github.com/notawar/mobius/server/mdm/nanodep/tokenpki"
	"github.com/notawar/mobius/server/mdm/nanomdm/mdm"
	nanomdm_pushsvc "github.com/notawar/mobius/server/mdm/nanomdm/push/service"
	"github.com/notawar/mobius/server/mock"
	mdmmock "github.com/notawar/mobius/server/mock/mdm"
	nanodep_mock "github.com/notawar/mobius/server/mock/nanodep"
	scep_mock "github.com/notawar/mobius/server/mock/scep"
	"github.com/notawar/mobius/server/ptr"
	"github.com/notawar/mobius/server/test"
	kitlog "github.com/go-kit/log"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	micromdm "github.com/micromdm/micromdm/mdm/mdm"
	"github.com/micromdm/nanolib/log/stdlogfmt"
	"github.com/micromdm/plist"
	"github.com/smallstep/pkcs7"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	mdmtesting "github.com/notawar/mobius/server/mdm/testing_utils"
)

type nopProfileMatcher struct{}

func (nopProfileMatcher) PreassignProfile(ctx context.Context, pld mobius.MDMApplePreassignProfilePayload) error {
	return nil
}

func (nopProfileMatcher) RetrieveProfiles(ctx context.Context, extHostID string) (mobius.MDMApplePreassignHostProfiles, error) {
	return mobius.MDMApplePreassignHostProfiles{}, nil
}

func setupAppleMDMService(t *testing.T, license *mobius.LicenseInfo) (mobius.Service, context.Context, *mock.Store) {
	ds := new(mock.Store)
	cfg := config.TestConfig()
	testCertPEM, testKeyPEM, err := generateCertWithAPNsTopic()
	require.NoError(t, err)
	config.SetTestMDMConfig(t, &cfg, testCertPEM, testKeyPEM, "../../server/service/testdata")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/server/devices"):
			_, err := w.Write([]byte("{}"))
			require.NoError(t, err)
			return
		case strings.Contains(r.URL.Path, "/session"):
			_, err := w.Write([]byte(`{"auth_session_token": "yoo"}`))
			require.NoError(t, err)
			return
		case strings.Contains(r.URL.Path, "/profile"):
			_, err := w.Write([]byte(`{"profile_uuid": "profile123"}`))
			require.NoError(t, err)
		}
	}))

	mdmStorage := &mdmmock.MDMAppleStore{}
	depStorage := &nanodep_mock.Storage{}
	pushFactory, _ := newMockAPNSPushProviderFactory()
	pusher := nanomdm_pushsvc.New(
		mdmStorage,
		mdmStorage,
		pushFactory,
		NewNanoMDMLogger(kitlog.NewJSONLogger(os.Stdout)),
	)

	opts := &TestServerOpts{
		MobiusConfig:    &cfg,
		MDMStorage:     mdmStorage,
		DEPStorage:     depStorage,
		MDMPusher:      pusher,
		License:        license,
		ProfileMatcher: nopProfileMatcher{},
	}
	svc, ctx := newTestServiceWithConfig(t, ds, cfg, nil, nil, opts)

	mdmStorage.EnqueueCommandFunc = func(ctx context.Context, id []string, cmd *mdm.CommandWithSubtype) (map[string]error, error) {
		return nil, nil
	}
	mdmStorage.RetrievePushInfoFunc = func(ctx context.Context, tokens []string) (map[string]*mdm.Push, error) {
		res := make(map[string]*mdm.Push, len(tokens))
		for _, t := range tokens {
			res[t] = &mdm.Push{
				PushMagic: "",
				Token:     []byte(t),
				Topic:     "",
			}
		}
		return res, nil
	}
	mdmStorage.RetrievePushCertFunc = func(ctx context.Context, topic string) (*tls.Certificate, string, error) {
		cert, err := tls.LoadX509KeyPair("testdata/server.pem", "testdata/server.key")
		return &cert, "", err
	}
	mdmStorage.IsPushCertStaleFunc = func(ctx context.Context, topic string, staleToken string) (bool, error) {
		return false, nil
	}

	depStorage.RetrieveAuthTokensFunc = func(ctx context.Context, name string) (*nanodep_client.OAuth1Tokens, error) {
		return &nanodep_client.OAuth1Tokens{}, nil
	}
	depStorage.RetrieveConfigFunc = func(context.Context, string) (*nanodep_client.Config, error) {
		return &nanodep_client.Config{
			BaseURL: ts.URL,
		}, nil
	}

	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		return &mobius.AppConfig{
			OrgInfo: mobius.OrgInfo{
				OrgName: "Foo Inc.",
			},
			ServerSettings: mobius.ServerSettings{
				ServerURL: "https://foo.example.com",
			},
			MDM: mobius.MDM{
				EnabledAndConfigured: true,
			},
		}, nil
	}
	ds.GetMDMAppleEnrollmentProfileByTokenFunc = func(ctx context.Context, token string) (*mobius.MDMAppleEnrollmentProfile, error) {
		return nil, nil
	}
	ds.NewMDMAppleEnrollmentProfileFunc = func(ctx context.Context, enrollmentPayload mobius.MDMAppleEnrollmentProfilePayload) (*mobius.MDMAppleEnrollmentProfile, error) {
		return &mobius.MDMAppleEnrollmentProfile{
			ID:            1,
			Token:         "foo",
			Type:          mobius.MDMAppleEnrollmentTypeManual,
			EnrollmentURL: "https://foo.example.com?token=foo",
		}, nil
	}
	ds.GetMDMAppleEnrollmentProfileByTokenFunc = func(ctx context.Context, token string) (*mobius.MDMAppleEnrollmentProfile, error) {
		return nil, nil
	}
	ds.ListMDMAppleEnrollmentProfilesFunc = func(ctx context.Context) ([]*mobius.MDMAppleEnrollmentProfile, error) {
		return nil, nil
	}
	ds.NewMDMAppleInstallerFunc = func(ctx context.Context, name string, size int64, manifest string, installer []byte, urlToken string) (*mobius.MDMAppleInstaller, error) {
		return nil, nil
	}
	ds.MDMAppleInstallerFunc = func(ctx context.Context, token string) (*mobius.MDMAppleInstaller, error) {
		return nil, nil
	}
	ds.MDMAppleInstallerDetailsByIDFunc = func(ctx context.Context, id uint) (*mobius.MDMAppleInstaller, error) {
		return nil, nil
	}
	ds.DeleteMDMAppleInstallerFunc = func(ctx context.Context, id uint) error {
		return nil
	}
	ds.MDMAppleInstallerDetailsByTokenFunc = func(ctx context.Context, token string) (*mobius.MDMAppleInstaller, error) {
		return nil, nil
	}
	ds.ListMDMAppleInstallersFunc = func(ctx context.Context) ([]mobius.MDMAppleInstaller, error) {
		return nil, nil
	}
	ds.MDMAppleListDevicesFunc = func(ctx context.Context) ([]mobius.MDMAppleDevice, error) {
		return nil, nil
	}
	ds.GetNanoMDMEnrollmentFunc = func(ctx context.Context, hostUUID string) (*mobius.NanoEnrollment, error) {
		return &mobius.NanoEnrollment{Enabled: false}, nil
	}
	ds.GetNanoMDMEnrollmentTimesFunc = func(ctx context.Context, hostUUID string) (*time.Time, *time.Time, error) {
		return nil, nil, nil
	}
	ds.GetMDMAppleCommandRequestTypeFunc = func(ctx context.Context, commandUUID string) (string, error) {
		return "", nil
	}
	ds.MDMGetEULAMetadataFunc = func(ctx context.Context) (*mobius.MDMEULA, error) {
		return &mobius.MDMEULA{}, nil
	}
	ds.MDMGetEULABytesFunc = func(ctx context.Context, token string) (*mobius.MDMEULA, error) {
		return &mobius.MDMEULA{}, nil
	}
	ds.MDMInsertEULAFunc = func(ctx context.Context, eula *mobius.MDMEULA) error {
		return nil
	}
	ds.MDMDeleteEULAFunc = func(ctx context.Context, token string) error {
		return nil
	}
	ds.ValidateEmbeddedSecretsFunc = func(ctx context.Context, documents []string) error {
		return nil
	}
	ds.ExpandEmbeddedSecretsFunc = func(ctx context.Context, document string) (string, error) {
		return document, nil
	}
	ds.ExpandEmbeddedSecretsAndUpdatedAtFunc = func(ctx context.Context, document string) (string, *time.Time, error) {
		return document, nil, nil
	}
	apnsCert, apnsKey, err := mysql.GenerateTestCertBytes(mdmtesting.NewTestMDMAppleCertTemplate())
	require.NoError(t, err)
	crt, key, err := apple_mdm.NewSCEPCACertKey()
	require.NoError(t, err)
	certPEM := tokenpki.PEMCertificate(crt.Raw)
	keyPEM := tokenpki.PEMRSAPrivateKey(key)
	ds.GetAllMDMConfigAssetsByNameFunc = func(ctx context.Context, assetNames []mobius.MDMAssetName,
		_ sqlx.QueryerContext,
	) (map[mobius.MDMAssetName]mobius.MDMConfigAsset, error) {
		return map[mobius.MDMAssetName]mobius.MDMConfigAsset{
			mobius.MDMAssetAPNSCert: {Value: apnsCert},
			mobius.MDMAssetAPNSKey:  {Value: apnsKey},
			mobius.MDMAssetCACert:   {Value: certPEM},
			mobius.MDMAssetCAKey:    {Value: keyPEM},
		}, nil
	}

	ds.GetABMTokenOrgNamesAssociatedWithTeamFunc = func(ctx context.Context, teamID *uint) ([]string, error) {
		return []string{"foobar"}, nil
	}
	ds.ListABMTokensFunc = func(ctx context.Context) ([]*mobius.ABMToken, error) {
		return []*mobius.ABMToken{{ID: 1}}, nil
	}

	return svc, ctx, ds
}

func TestAppleMDMAuthorization(t *testing.T) {
	svc, ctx, ds := setupAppleMDMService(t, &mobius.LicenseInfo{Tier: mobius.TierPremium})

	ds.GetEnrollSecretsFunc = func(ctx context.Context, teamID *uint) ([]*mobius.EnrollSecret, error) {
		return []*mobius.EnrollSecret{
			{
				Secret: "abcd",
				TeamID: nil,
			},
			{
				Secret: "efgh",
				TeamID: nil,
			},
		}, nil
	}

	checkAuthErr := func(t *testing.T, err error, shouldFailWithAuth bool) {
		t.Helper()

		if shouldFailWithAuth {
			require.Error(t, err)
			require.Contains(t, err.Error(), authz.ForbiddenErrorMessage)
		} else {
			require.NoError(t, err)
		}
	}

	testAuthdMethods := func(t *testing.T, user *mobius.User, shouldFailWithAuth bool) {
		ctx := test.UserContext(ctx, user)
		_, err := svc.UploadMDMAppleInstaller(ctx, "foo", 3, bytes.NewReader([]byte("foo")))
		checkAuthErr(t, err, shouldFailWithAuth)
		_, err = svc.GetMDMAppleInstallerByID(ctx, 42)
		checkAuthErr(t, err, shouldFailWithAuth)
		err = svc.DeleteMDMAppleInstaller(ctx, 42)
		checkAuthErr(t, err, shouldFailWithAuth)
		_, err = svc.ListMDMAppleInstallers(ctx)
		checkAuthErr(t, err, shouldFailWithAuth)
		_, err = svc.ListMDMAppleDevices(ctx)
		checkAuthErr(t, err, shouldFailWithAuth)

		// check EULA routes
		_, err = svc.MDMGetEULAMetadata(ctx)
		checkAuthErr(t, err, shouldFailWithAuth)
		err = svc.MDMCreateEULA(ctx, "eula.pdf", bytes.NewReader([]byte("%PDF-")))
		checkAuthErr(t, err, shouldFailWithAuth)
		err = svc.MDMDeleteEULA(ctx, "foo")
		checkAuthErr(t, err, shouldFailWithAuth)
	}

	// Only global admins can access the endpoints.
	testAuthdMethods(t, test.UserAdmin, false)

	// All other users should not have access to the endpoints.
	for _, user := range []*mobius.User{
		test.UserNoRoles,
		test.UserMaintainer,
		test.UserObserver,
		test.UserObserverPlus,
		test.UserTeamAdminTeam1,
	} {
		testAuthdMethods(t, user, true)
	}
	// Token authenticated endpoints can be accessed by anyone.
	ctx = test.UserContext(ctx, test.UserNoRoles)
	_, err := svc.GetMDMAppleInstallerByToken(ctx, "foo")
	require.NoError(t, err)
	_, err = svc.GetMDMAppleEnrollmentProfileByToken(ctx, "foo", "")
	require.NoError(t, err)
	_, err = svc.GetMDMAppleInstallerDetailsByToken(ctx, "foo")
	require.NoError(t, err)
	_, err = svc.MDMGetEULABytes(ctx, "foo")
	require.NoError(t, err)
	// Generating a new key pair does not actually make any changes to mobius, or expose any
	// information. The user must configure mobius with the new key pair and restart the server.
	_, err = svc.NewMDMAppleDEPKeyPair(ctx)
	require.NoError(t, err)

	// Should work for all user types
	for _, user := range []*mobius.User{
		test.UserAdmin,
		test.UserMaintainer,
		test.UserObserver,
		test.UserObserverPlus,
		test.UserTeamAdminTeam1,
		test.UserTeamGitOpsTeam1,
		test.UserGitOps,
		test.UserTeamMaintainerTeam1,
		test.UserTeamObserverTeam1,
		test.UserTeamObserverPlusTeam1,
	} {
		usrctx := test.UserContext(ctx, user)
		_, err = svc.GetMDMManualEnrollmentProfile(usrctx)
		require.NoError(t, err)
	}

	// Must be device-authenticated, should fail
	_, err = svc.GetDeviceMDMAppleEnrollmentProfile(ctx)
	checkAuthErr(t, err, true)
	// works with device-authenticated context
	hostCtx := test.HostContext(context.Background(), &mobius.Host{})
	_, err = svc.GetDeviceMDMAppleEnrollmentProfile(hostCtx)
	require.NoError(t, err)

	hostUUIDsToTeamID := map[string]uint{
		"host1": 1,
		"host2": 1,
		"host3": 2,
		"host4": 0,
	}
	ds.ListHostsLiteByUUIDsFunc = func(ctx context.Context, filter mobius.TeamFilter, uuids []string) ([]*mobius.Host, error) {
		hosts := make([]*mobius.Host, 0, len(uuids))
		for _, uuid := range uuids {
			tmID := hostUUIDsToTeamID[uuid]
			if tmID == 0 {
				hosts = append(hosts, &mobius.Host{UUID: uuid, TeamID: nil})
			} else {
				hosts = append(hosts, &mobius.Host{UUID: uuid, TeamID: &tmID})
			}
		}
		return hosts, nil
	}

	rawB64FreeCmd := base64.RawStdEncoding.EncodeToString([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Command</key>
    <dict>
        <key>RequestType</key>
        <string>FooBar</string>
    </dict>
    <key>CommandUUID</key>
    <string>uuid</string>
</dict>
</plist>`))

	t.Run("EnqueueMDMAppleCommand", func(t *testing.T) {
		enqueueCmdCases := []struct {
			desc              string
			user              *mobius.User
			uuids             []string
			shoudFailWithAuth bool
		}{
			{"no role", test.UserNoRoles, []string{"host1", "host2", "host3", "host4"}, true},
			{"maintainer can run", test.UserMaintainer, []string{"host1", "host2", "host3", "host4"}, false},
			{"admin can run", test.UserAdmin, []string{"host1", "host2", "host3", "host4"}, false},
			{"observer cannot run", test.UserObserver, []string{"host1", "host2", "host3", "host4"}, true},
			{"team 1 admin can run team 1", test.UserTeamAdminTeam1, []string{"host1", "host2"}, false},
			{"team 2 admin can run team 2", test.UserTeamAdminTeam2, []string{"host3"}, false},
			{"team 1 maintainer can run team 1", test.UserTeamMaintainerTeam1, []string{"host1", "host2"}, false},
			{"team 1 observer cannot run team 1", test.UserTeamObserverTeam1, []string{"host1", "host2"}, true},
			{"team 1 admin cannot run team 2", test.UserTeamAdminTeam1, []string{"host3"}, true},
			{"team 1 admin cannot run no team", test.UserTeamAdminTeam1, []string{"host4"}, true},
			{"team 1 admin cannot run mix of team 1 and 2", test.UserTeamAdminTeam1, []string{"host1", "host3"}, true},
		}
		for _, c := range enqueueCmdCases {
			t.Run(c.desc, func(t *testing.T) {
				ctx = test.UserContext(ctx, c.user)
				_, err = svc.EnqueueMDMAppleCommand(ctx, rawB64FreeCmd, c.uuids)
				checkAuthErr(t, err, c.shoudFailWithAuth)
			})
		}

		// test with a command that requires a premium license
		ctx = test.UserContext(ctx, test.UserAdmin)
		ctx = license.NewContext(ctx, &mobius.LicenseInfo{Tier: mobius.TierFree})
		rawB64PremiumCmd := base64.RawStdEncoding.EncodeToString([]byte(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Command</key>
    <dict>
        <key>RequestType</key>
        <string>%s</string>
    </dict>
    <key>CommandUUID</key>
    <string>uuid</string>
</dict>
</plist>`, "DeviceLock")))
		_, err = svc.EnqueueMDMAppleCommand(ctx, rawB64PremiumCmd, []string{"host1"})
		require.Error(t, err)
		require.ErrorContains(t, err, mobius.ErrMissingLicense.Error())
	})

	cmdUUIDToHostUUIDs := map[string][]string{
		"uuidTm1":       {"host1", "host2"},
		"uuidTm2":       {"host3"},
		"uuidNoTm":      {"host4"},
		"uuidMixTm1Tm2": {"host1", "host3"},
	}
	getResults := func(commandUUID string) ([]*mobius.MDMCommandResult, error) {
		hosts := cmdUUIDToHostUUIDs[commandUUID]
		res := make([]*mobius.MDMCommandResult, 0, len(hosts))
		for _, h := range hosts {
			res = append(res, &mobius.MDMCommandResult{
				HostUUID: h,
			})
		}
		return res, nil
	}

	ds.GetMDMAppleCommandResultsFunc = func(ctx context.Context, commandUUID string) ([]*mobius.MDMCommandResult, error) {
		return getResults(commandUUID)
	}

	ds.GetMDMCommandPlatformFunc = func(ctx context.Context, commandUUID string) (string, error) {
		return "darwin", nil
	}

	t.Run("GetMDMAppleCommandResults", func(t *testing.T) {
		cmdResultsCases := []struct {
			desc              string
			user              *mobius.User
			cmdUUID           string
			shoudFailWithAuth bool
		}{
			{"no role", test.UserNoRoles, "uuidTm1", true},
			{"maintainer can view", test.UserMaintainer, "uuidTm1", false},
			{"maintainer can view", test.UserMaintainer, "uuidTm2", false},
			{"maintainer can view", test.UserMaintainer, "uuidNoTm", false},
			{"maintainer can view", test.UserMaintainer, "uuidMixTm1Tm2", false},
			{"observer can view", test.UserObserver, "uuidTm1", false},
			{"observer can view", test.UserObserver, "uuidTm2", false},
			{"observer can view", test.UserObserver, "uuidNoTm", false},
			{"observer can view", test.UserObserver, "uuidMixTm1Tm2", false},
			{"observer+ can view", test.UserObserverPlus, "uuidTm1", false},
			{"observer+ can view", test.UserObserverPlus, "uuidTm2", false},
			{"observer+ can view", test.UserObserverPlus, "uuidNoTm", false},
			{"observer+ can view", test.UserObserverPlus, "uuidMixTm1Tm2", false},
			{"admin can view", test.UserAdmin, "uuidTm1", false},
			{"admin can view", test.UserAdmin, "uuidTm2", false},
			{"admin can view", test.UserAdmin, "uuidNoTm", false},
			{"admin can view", test.UserAdmin, "uuidMixTm1Tm2", false},
			{"tm1 maintainer can view tm1", test.UserTeamMaintainerTeam1, "uuidTm1", false},
			{"tm1 maintainer cannot view tm2", test.UserTeamMaintainerTeam1, "uuidTm2", true},
			{"tm1 maintainer cannot view no team", test.UserTeamMaintainerTeam1, "uuidNoTm", true},
			{"tm1 maintainer cannot view mix", test.UserTeamMaintainerTeam1, "uuidMixTm1Tm2", true},
			{"tm1 observer can view tm1", test.UserTeamObserverTeam1, "uuidTm1", false},
			{"tm1 observer cannot view tm2", test.UserTeamObserverTeam1, "uuidTm2", true},
			{"tm1 observer cannot view no team", test.UserTeamObserverTeam1, "uuidNoTm", true},
			{"tm1 observer cannot view mix", test.UserTeamObserverTeam1, "uuidMixTm1Tm2", true},
			{"tm1 observer+ can view tm1", test.UserTeamObserverPlusTeam1, "uuidTm1", false},
			{"tm1 observer+ cannot view tm2", test.UserTeamObserverPlusTeam1, "uuidTm2", true},
			{"tm1 observer+ cannot view no team", test.UserTeamObserverPlusTeam1, "uuidNoTm", true},
			{"tm1 observer+ cannot view mix", test.UserTeamObserverPlusTeam1, "uuidMixTm1Tm2", true},
			{"tm1 admin can view tm1", test.UserTeamAdminTeam1, "uuidTm1", false},
			{"tm1 admin cannot view tm2", test.UserTeamAdminTeam1, "uuidTm2", true},
			{"tm1 admin cannot view no team", test.UserTeamAdminTeam1, "uuidNoTm", true},
			{"tm1 admin cannot view mix", test.UserTeamAdminTeam1, "uuidMixTm1Tm2", true},
		}
		for _, c := range cmdResultsCases {
			t.Run(c.desc, func(t *testing.T) {
				ctx = test.UserContext(ctx, c.user)
				_, err = svc.GetMDMAppleCommandResults(ctx, c.cmdUUID)
				checkAuthErr(t, err, c.shoudFailWithAuth)

				// TODO(sarah): move test to shared file
				_, err = svc.GetMDMCommandResults(ctx, c.cmdUUID)
				checkAuthErr(t, err, c.shoudFailWithAuth)
			})
		}
	})

	t.Run("ListMDMAppleCommands", func(t *testing.T) {
		ds.ListMDMAppleCommandsFunc = func(ctx context.Context, tmFilter mobius.TeamFilter, opt *mobius.MDMCommandListOptions) ([]*mobius.MDMAppleCommand, error) {
			return []*mobius.MDMAppleCommand{
				{DeviceID: "no team", TeamID: nil},
				{DeviceID: "tm1", TeamID: ptr.Uint(1)},
				{DeviceID: "tm2", TeamID: ptr.Uint(2)},
			}, nil
		}

		listCmdsCases := []struct {
			desc       string
			user       *mobius.User
			want       []string // the expected device ids in the results
			shouldFail bool     // with forbidden error
		}{
			{"no role", test.UserNoRoles, []string{}, true},
			{"maintainer can view", test.UserMaintainer, []string{"no team", "tm1", "tm2"}, false},
			{"observer can view", test.UserObserver, []string{"no team", "tm1", "tm2"}, false},
			{"observer+ can view", test.UserObserverPlus, []string{"no team", "tm1", "tm2"}, false},
			{"admin can view", test.UserAdmin, []string{"no team", "tm1", "tm2"}, false},
			{"tm1 maintainer can view tm1", test.UserTeamMaintainerTeam1, []string{"tm1"}, false},
			{"tm1 observer can view tm1", test.UserTeamObserverTeam1, []string{"tm1"}, false},
			{"tm1 observer+ can view tm1", test.UserTeamObserverPlusTeam1, []string{"tm1"}, false},
			{"tm1 admin can view tm1", test.UserTeamAdminTeam1, []string{"tm1"}, false},
		}
		for _, c := range listCmdsCases {
			t.Run(c.desc, func(t *testing.T) {
				ctx = test.UserContext(ctx, c.user)
				res, err := svc.ListMDMAppleCommands(ctx, &mobius.MDMCommandListOptions{})
				checkAuthErr(t, err, c.shouldFail)
				if c.shouldFail {
					return
				}

				got := make([]string, len(res))
				for i, r := range res {
					got[i] = r.DeviceID
				}
				require.Equal(t, c.want, got)
			})
		}
	})
}

func TestMDMAppleConfigProfileAuthz(t *testing.T) {
	svc, ctx, ds := setupAppleMDMService(t, &mobius.LicenseInfo{Tier: mobius.TierPremium})

	profUUID := "a" + uuid.NewString()
	testCases := []struct {
		name             string
		user             *mobius.User
		shouldFailGlobal bool
		shouldFailTeam   bool
	}{
		{
			"global admin",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)},
			false,
			false,
		},
		{
			"global maintainer",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleMaintainer)},
			false,
			false,
		},
		{
			"global observer",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleObserver)},
			true,
			true,
		},
		{
			"team admin, belongs to team",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleAdmin}}},
			true,
			false,
		},
		{
			"team admin, DOES NOT belong to team",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 2}, Role: mobius.RoleAdmin}}},
			true,
			true,
		},
		{
			"team maintainer, belongs to team",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleMaintainer}}},
			true,
			false,
		},
		{
			"team maintainer, DOES NOT belong to team",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 2}, Role: mobius.RoleMaintainer}}},
			true,
			true,
		},
		{
			"team observer, belongs to team",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleObserver}}},
			true,
			true,
		},
		{
			"team observer, DOES NOT belong to team",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 2}, Role: mobius.RoleObserver}}},
			true,
			true,
		},
		{
			"user no roles",
			&mobius.User{ID: 1337},
			true,
			true,
		},
	}

	ds.NewMDMAppleConfigProfileFunc = func(ctx context.Context, cp mobius.MDMAppleConfigProfile, usesVars []string) (*mobius.MDMAppleConfigProfile, error) {
		return &cp, nil
	}
	ds.ListMDMAppleConfigProfilesFunc = func(ctx context.Context, teamID *uint) ([]*mobius.MDMAppleConfigProfile, error) {
		return nil, nil
	}
	ds.NewActivityFunc = func(context.Context, *mobius.User, mobius.ActivityDetails, []byte, time.Time) error {
		return nil
	}
	ds.GetMDMAppleProfilesSummaryFunc = func(context.Context, *uint) (*mobius.MDMProfilesSummary, error) {
		return nil, nil
	}
	ds.BulkSetPendingMDMHostProfilesFunc = func(ctx context.Context, hids, tids []uint, puuids, uuids []string,
	) (updates mobius.MDMProfilesUpdates, err error) {
		return mobius.MDMProfilesUpdates{}, nil
	}
	mockGetFuncWithTeamID := func(teamID uint) mock.GetMDMAppleConfigProfileFunc {
		return func(ctx context.Context, puid string) (*mobius.MDMAppleConfigProfile, error) {
			require.Equal(t, profUUID, puid)
			return &mobius.MDMAppleConfigProfile{TeamID: &teamID}, nil
		}
	}
	mockDeleteFuncWithTeamID := func(teamID uint) mock.DeleteMDMAppleConfigProfileFunc {
		return func(ctx context.Context, puid string) error {
			require.Equal(t, profUUID, puid)
			return nil
		}
	}
	mockTeamFuncWithUser := func(u *mobius.User) mock.TeamFunc {
		return func(ctx context.Context, teamID uint) (*mobius.Team, error) {
			if len(u.Teams) > 0 {
				for _, t := range u.Teams {
					if t.ID == teamID {
						return &mobius.Team{ID: teamID, Users: []mobius.TeamUser{{User: *u, Role: t.Role}}}, nil
					}
				}
			}
			return &mobius.Team{}, nil
		}
	}

	checkShouldFail := func(err error, shouldFail bool) {
		if !shouldFail {
			require.NoError(t, err)
		} else {
			require.Error(t, err)
			require.Contains(t, err.Error(), authz.ForbiddenErrorMessage)
		}
	}

	mcBytes := mcBytesForTest("Foo", "Bar", "UUID")

	for _, tt := range testCases {
		ctx := viewer.NewContext(ctx, viewer.Viewer{User: tt.user})
		ds.TeamFunc = mockTeamFuncWithUser(tt.user)

		t.Run(tt.name, func(t *testing.T) {
			// test authz create new profile (no team)
			_, err := svc.NewMDMAppleConfigProfile(ctx, 0, bytes.NewReader(mcBytes), nil, mobius.LabelsIncludeAll)
			checkShouldFail(err, tt.shouldFailGlobal)

			// test authz create new profile (team 1)
			_, err = svc.NewMDMAppleConfigProfile(ctx, 1, bytes.NewReader(mcBytes), nil, mobius.LabelsIncludeAll)
			checkShouldFail(err, tt.shouldFailTeam)

			// test authz list profiles (no team)
			_, err = svc.ListMDMAppleConfigProfiles(ctx, 0)
			checkShouldFail(err, tt.shouldFailGlobal)

			// test authz list profiles (team 1)
			_, err = svc.ListMDMAppleConfigProfiles(ctx, 1)
			checkShouldFail(err, tt.shouldFailTeam)

			// test authz get config profile (no team)
			ds.GetMDMAppleConfigProfileFunc = mockGetFuncWithTeamID(0)
			_, err = svc.GetMDMAppleConfigProfile(ctx, profUUID)
			checkShouldFail(err, tt.shouldFailGlobal)

			// test authz delete config profile (no team)
			ds.DeleteMDMAppleConfigProfileFunc = mockDeleteFuncWithTeamID(0)
			err = svc.DeleteMDMAppleConfigProfile(ctx, profUUID)
			checkShouldFail(err, tt.shouldFailGlobal)

			// test authz get config profile (team 1)
			ds.GetMDMAppleConfigProfileFunc = mockGetFuncWithTeamID(1)
			_, err = svc.GetMDMAppleConfigProfile(ctx, profUUID)
			checkShouldFail(err, tt.shouldFailTeam)

			// test authz delete config profile (team 1)
			ds.DeleteMDMAppleConfigProfileFunc = mockDeleteFuncWithTeamID(1)
			err = svc.DeleteMDMAppleConfigProfile(ctx, profUUID)
			checkShouldFail(err, tt.shouldFailTeam)

			// test authz get profiles summary (no team)
			_, err = svc.GetMDMAppleProfilesSummary(ctx, nil)
			checkShouldFail(err, tt.shouldFailGlobal)

			// test authz get profiles summary (no team)
			_, err = svc.GetMDMAppleProfilesSummary(ctx, ptr.Uint(1))
			checkShouldFail(err, tt.shouldFailTeam)
		})
	}
}

func TestNewMDMAppleConfigProfile(t *testing.T) {
	svc, ctx, ds := setupAppleMDMService(t, &mobius.LicenseInfo{Tier: mobius.TierPremium})
	ctx = viewer.NewContext(ctx, viewer.Viewer{User: &mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)}})

	identifier := "Bar.$MOBIUS_VAR_HOST_END_USER_EMAIL_IDP"
	mcBytes := mcBytesForTest("Foo", identifier, "UUID")
	r := bytes.NewReader(mcBytes)

	ds.NewMDMAppleConfigProfileFunc = func(ctx context.Context, cp mobius.MDMAppleConfigProfile, usesVars []string) (*mobius.MDMAppleConfigProfile, error) {
		require.Equal(t, "Foo", cp.Name)
		assert.Equal(t, identifier, cp.Identifier)
		require.Equal(t, mcBytes, []byte(cp.Mobileconfig))
		return &cp, nil
	}
	ds.NewActivityFunc = func(context.Context, *mobius.User, mobius.ActivityDetails, []byte, time.Time) error {
		return nil
	}
	ds.BulkSetPendingMDMHostProfilesFunc = func(ctx context.Context, hids, tids []uint, puuids, uuids []string,
	) (updates mobius.MDMProfilesUpdates, err error) {
		return mobius.MDMProfilesUpdates{}, nil
	}

	cp, err := svc.NewMDMAppleConfigProfile(ctx, 0, r, nil, mobius.LabelsIncludeAll)
	require.NoError(t, err)
	require.Equal(t, "Foo", cp.Name)
	assert.Equal(t, identifier, cp.Identifier)
	require.Equal(t, mcBytes, []byte(cp.Mobileconfig))

	// Unsupported Mobius variable
	mcBytes = mcBytesForTest("Foo", identifier, "UUID${MOBIUS_VAR_BOZO}")
	r = bytes.NewReader(mcBytes)
	_, err = svc.NewMDMAppleConfigProfile(ctx, 0, r, nil, mobius.LabelsIncludeAll)
	assert.ErrorContains(t, err, "Mobius variable")
}

func mcBytesForTest(name, identifier, uuid string) []byte {
	return []byte(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array/>
	<key>PayloadDisplayName</key>
	<string>%s</string>
	<key>PayloadIdentifier</key>
	<string>%s</string>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadUUID</key>
	<string>%s</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
</dict>
</plist>
`, name, identifier, uuid))
}

func TestNewMDMAppleDeclaration(t *testing.T) {
	svc, ctx, ds := setupAppleMDMService(t, &mobius.LicenseInfo{Tier: mobius.TierPremium})
	ctx = viewer.NewContext(ctx, viewer.Viewer{User: &mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)}})

	// Unsupported Mobius variable
	b := declBytesForTest("D1", "d1content $MOBIUS_VAR_BOZO")
	_, err := svc.NewMDMAppleDeclaration(ctx, 0, bytes.NewReader(b), nil, "name", mobius.LabelsIncludeAll)
	assert.ErrorContains(t, err, "Mobius variable")

	ds.NewMDMAppleDeclarationFunc = func(ctx context.Context, d *mobius.MDMAppleDeclaration) (*mobius.MDMAppleDeclaration, error) {
		return d, nil
	}
	ds.NewActivityFunc = func(context.Context, *mobius.User, mobius.ActivityDetails, []byte, time.Time) error {
		return nil
	}
	ds.BulkSetPendingMDMHostProfilesFunc = func(ctx context.Context, hids, tids []uint, puuids, uuids []string,
	) (updates mobius.MDMProfilesUpdates, err error) {
		return mobius.MDMProfilesUpdates{}, nil
	}

	// Good declaration
	b = declBytesForTest("D1", "d1content")
	d, err := svc.NewMDMAppleDeclaration(ctx, 0, bytes.NewReader(b), nil, "name", mobius.LabelsIncludeAll)
	require.NoError(t, err)
	assert.NotNil(t, d)
}

// Fragile test: This test is fragile because of the large reliance on Datastore mocks. Consider refactoring test/logic or removing the test. It may be slowing us down more than helping us.
func TestHostDetailsMDMProfiles(t *testing.T) {
	svc, ctx, ds := setupAppleMDMService(t, &mobius.LicenseInfo{Tier: mobius.TierPremium})
	ctx = viewer.NewContext(ctx, viewer.Viewer{User: &mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)}})

	expected := []mobius.HostMDMAppleProfile{
		{HostUUID: "H057-UU1D-1337", Name: "NAME-5", ProfileUUID: "a" + uuid.NewString(), CommandUUID: "CMD-UU1D-5", Status: &mobius.MDMDeliveryPending, OperationType: mobius.MDMOperationTypeInstall, Detail: ""},
		{HostUUID: "H057-UU1D-1337", Name: "NAME-9", ProfileUUID: "a" + uuid.NewString(), CommandUUID: "CMD-UU1D-8", Status: &mobius.MDMDeliveryVerifying, OperationType: mobius.MDMOperationTypeInstall, Detail: ""},
		{HostUUID: "H057-UU1D-1337", Name: "NAME-13", ProfileUUID: "a" + uuid.NewString(), CommandUUID: "CMD-UU1D-13", Status: &mobius.MDMDeliveryFailed, OperationType: mobius.MDMOperationTypeRemove, Detail: "Error removing profile"},
	}

	ds.GetHostMDMAppleProfilesFunc = func(ctx context.Context, hostUUID string) ([]mobius.HostMDMAppleProfile, error) {
		if hostUUID == "H057-UU1D-1337" {
			return expected, nil
		}
		return []mobius.HostMDMAppleProfile{}, nil
	}
	ds.HostFunc = func(ctx context.Context, hostID uint) (*mobius.Host, error) {
		if hostID == uint(42) {
			return &mobius.Host{ID: uint(42), UUID: "H057-UU1D-1337", Platform: "darwin"}, nil
		}
		return &mobius.Host{ID: hostID, UUID: "WR0N6-UU1D", Platform: "darwin"}, nil
	}
	ds.HostByIdentifierFunc = func(ctx context.Context, identifier string) (*mobius.Host, error) {
		if identifier == "h0571d3n71f13r" {
			return &mobius.Host{ID: uint(42), UUID: "H057-UU1D-1337", Platform: "darwin"}, nil
		}
		return &mobius.Host{ID: uint(21), UUID: "WR0N6-UU1D", Platform: "darwin"}, nil
	}
	ds.LoadHostSoftwareFunc = func(ctx context.Context, host *mobius.Host, includeCVEScores bool) error {
		return nil
	}
	ds.ListLabelsForHostFunc = func(ctx context.Context, hid uint) ([]*mobius.Label, error) {
		return nil, nil
	}
	ds.ListPacksForHostFunc = func(ctx context.Context, hid uint) (packs []*mobius.Pack, err error) {
		return nil, nil
	}
	ds.ListHostBatteriesFunc = func(ctx context.Context, id uint) ([]*mobius.HostBattery, error) {
		return nil, nil
	}
	ds.ListUpcomingHostMaintenanceWindowsFunc = func(ctx context.Context, hid uint) ([]*mobius.HostMaintenanceWindow, error) {
		return nil, nil
	}
	ds.ListPoliciesForHostFunc = func(ctx context.Context, host *mobius.Host) ([]*mobius.HostPolicy, error) {
		return nil, nil
	}
	ds.GetHostMDMMacOSSetupFunc = func(ctx context.Context, hostID uint) (*mobius.HostMDMMacOSSetup, error) {
		return nil, nil
	}
	ds.GetHostLockWipeStatusFunc = func(ctx context.Context, host *mobius.Host) (*mobius.HostLockWipeStatus, error) {
		return &mobius.HostLockWipeStatus{}, nil
	}
	ds.ScimUserByHostIDFunc = func(ctx context.Context, hostID uint) (*mobius.ScimUser, error) {
		return nil, nil
	}
	ds.ListHostDeviceMappingFunc = func(ctx context.Context, id uint) ([]*mobius.HostDeviceMapping, error) {
		return nil, nil
	}
	ds.GetHostIssuesLastUpdatedFunc = func(ctx context.Context, hostId uint) (time.Time, error) {
		return time.Time{}, nil
	}
	ds.UpdateHostIssuesFailingPoliciesFunc = func(ctx context.Context, hostIDs []uint) error {
		return nil
	}

	expectedNilSlice := []mobius.HostMDMAppleProfile(nil)
	expectedEmptySlice := []mobius.HostMDMAppleProfile{}

	cases := []struct {
		name           string
		mdmEnabled     bool
		hostID         *uint
		hostIdentifier *string
		expected       *[]mobius.HostMDMAppleProfile
	}{
		{
			name:           "TestGetHostMDMProfilesOK",
			mdmEnabled:     true,
			hostID:         ptr.Uint(42),
			hostIdentifier: nil,
			expected:       &expected,
		},
		{
			name:           "TestGetHostMDMProfilesEmpty",
			mdmEnabled:     true,
			hostID:         ptr.Uint(21),
			hostIdentifier: nil,
			expected:       &expectedEmptySlice,
		},
		{
			name:           "TestGetHostMDMProfilesNil",
			mdmEnabled:     false,
			hostID:         ptr.Uint(42),
			hostIdentifier: nil,
			expected:       &expectedNilSlice,
		},
		{
			name:           "TestHostByIdentifierMDMProfilesOK",
			mdmEnabled:     true,
			hostID:         nil,
			hostIdentifier: ptr.String("h0571d3n71f13r"),
			expected:       &expected,
		},
		{
			name:           "TestHostByIdentifierMDMProfilesNil",
			mdmEnabled:     false,
			hostID:         nil,
			hostIdentifier: ptr.String("h0571d3n71f13r"),
			expected:       &expectedNilSlice,
		},
		{
			name:           "TestHostByIdentifierMDMProfilesEmpty",
			mdmEnabled:     true,
			hostID:         nil,
			hostIdentifier: ptr.String("4n07h3r1d3n71f13r"),
			expected:       &expectedEmptySlice,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ds.AppConfigFunc = func(context.Context) (*mobius.AppConfig, error) {
				return &mobius.AppConfig{MDM: mobius.MDM{EnabledAndConfigured: c.mdmEnabled}}, nil
			}
			ds.AppConfigFuncInvoked = false
			ds.HostFuncInvoked = false
			ds.HostByIdentifierFuncInvoked = false
			ds.GetHostMDMAppleProfilesFuncInvoked = false

			var gotHost *mobius.HostDetail
			if c.hostID != nil {
				h, err := svc.GetHost(ctx, *c.hostID, mobius.HostDetailOptions{})
				require.NoError(t, err)
				require.True(t, ds.HostFuncInvoked)
				gotHost = h
			}
			if c.hostIdentifier != nil {
				h, err := svc.HostByIdentifier(ctx, *c.hostIdentifier, mobius.HostDetailOptions{})
				require.NoError(t, err)
				require.True(t, ds.HostByIdentifierFuncInvoked)
				gotHost = h
			}
			require.NotNil(t, gotHost)
			require.True(t, ds.AppConfigFuncInvoked)

			if !c.mdmEnabled {
				var ep []mobius.HostMDMProfile
				switch c.expected {
				case &expectedNilSlice:
					ns := []mobius.HostMDMProfile(nil)
					ep = ns
				case &expectedEmptySlice:
					ep = []mobius.HostMDMProfile{}
				default:
					for _, p := range *c.expected {
						ep = append(ep, p.ToHostMDMProfile(gotHost.Platform))
					}
				}
				require.Equal(t, gotHost.MDM.Profiles, &ep)
				return
			}

			require.True(t, ds.GetHostMDMAppleProfilesFuncInvoked)
			require.NotNil(t, gotHost.MDM.Profiles)
			ep := make([]mobius.HostMDMProfile, 0, len(*gotHost.MDM.Profiles))
			for _, p := range *c.expected {
				ep = append(ep, p.ToHostMDMProfile(gotHost.Platform))
			}
			require.ElementsMatch(t, ep, *gotHost.MDM.Profiles)
		})
	}
}

func TestMDMCommandAuthz(t *testing.T) {
	svc, ctx, ds := setupAppleMDMService(t, &mobius.LicenseInfo{Tier: mobius.TierPremium})

	ds.HostLiteFunc = func(ctx context.Context, hostID uint) (*mobius.Host, error) {
		switch hostID {
		case 1:
			return &mobius.Host{UUID: "test-host-team-1", TeamID: ptr.Uint(1)}, nil
		default:
			return &mobius.Host{UUID: "test-host-no-team"}, nil
		}
	}

	ds.GetHostMDMCheckinInfoFunc = func(ctx context.Context, hostUUID string) (*mobius.HostMDMCheckinInfo, error) {
		return &mobius.HostMDMCheckinInfo{Platform: "darwin"}, nil
	}

	ds.NewActivityFunc = func(context.Context, *mobius.User, mobius.ActivityDetails, []byte, time.Time) error {
		return nil
	}
	ds.MDMTurnOffFunc = func(ctx context.Context, uuid string) error {
		return nil
	}

	var mdmEnabled atomic.Bool
	ds.GetNanoMDMEnrollmentFunc = func(ctx context.Context, hostUUID string) (*mobius.NanoEnrollment, error) {
		// This function is called twice during EnqueueMDMAppleCommandRemoveEnrollmentProfile.
		// It first is called to check that the device is enrolled as a pre-condition to enqueueing the
		// command. It is called second time after the command has been enqueued to check whether
		// the device was successfully unenrolled.
		//
		// For each test run, the bool should be initialized to true to simulate an existing device
		// that is initially enrolled to Mobius's MDM.
		enroll := mobius.NanoEnrollment{
			Enabled: mdmEnabled.Swap(!mdmEnabled.Load()),
		}
		return &enroll, nil
	}

	testCases := []struct {
		name             string
		user             *mobius.User
		shouldFailGlobal bool
		shouldFailTeam   bool
	}{
		{
			"global admin",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)},
			false,
			false,
		},
		{
			"global maintainer",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleMaintainer)},
			false,
			false,
		},
		{
			"global observer",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleObserver)},
			true,
			true,
		},
		{
			"team admin, belongs to team",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleAdmin}}},
			true,
			false,
		},
		{
			"team admin, DOES NOT belong to team",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 2}, Role: mobius.RoleAdmin}}},
			true,
			true,
		},
		{
			"team maintainer, belongs to team",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleMaintainer}}},
			true,
			false,
		},
		{
			"team maintainer, DOES NOT belong to team",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 2}, Role: mobius.RoleMaintainer}}},
			true,
			true,
		},
		{
			"team observer, belongs to team",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleObserver}}},
			true,
			true,
		},
		{
			"team observer, DOES NOT belong to team",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 2}, Role: mobius.RoleObserver}}},
			true,
			true,
		},
		{
			"user no roles",
			&mobius.User{ID: 1337},
			true,
			true,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			ctx := viewer.NewContext(ctx, viewer.Viewer{User: tt.user})

			mdmEnabled.Store(true)
			err := svc.EnqueueMDMAppleCommandRemoveEnrollmentProfile(ctx, 42) // global host
			if !tt.shouldFailGlobal {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				require.Contains(t, err.Error(), authz.ForbiddenErrorMessage)
			}

			mdmEnabled.Store(true)
			err = svc.EnqueueMDMAppleCommandRemoveEnrollmentProfile(ctx, 1) // host belongs to team 1
			if !tt.shouldFailTeam {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				require.Contains(t, err.Error(), authz.ForbiddenErrorMessage)
			}
		})
	}
}

func TestMDMAuthenticateManualEnrollment(t *testing.T) {
	ds := new(mock.Store)
	mdmLifecycle := mdmlifecycle.New(ds, kitlog.NewNopLogger())
	svc := MDMAppleCheckinAndCommandService{
		ds:           ds,
		mdmLifecycle: mdmLifecycle,
	}
	ctx := context.Background()
	uuid, serial, model := "ABC-DEF-GHI", "XYZABC", "MacBookPro 16,1"

	ds.MDMAppleUpsertHostFunc = func(ctx context.Context, mdmHost *mobius.Host) error {
		require.Equal(t, uuid, mdmHost.UUID)
		require.Equal(t, serial, mdmHost.HardwareSerial)
		require.Equal(t, model, mdmHost.HardwareModel)
		return nil
	}

	ds.GetHostMDMCheckinInfoFunc = func(ct context.Context, hostUUID string) (*mobius.HostMDMCheckinInfo, error) {
		require.Equal(t, uuid, hostUUID)
		return &mobius.HostMDMCheckinInfo{
			HardwareSerial:   serial,
			DisplayName:      fmt.Sprintf("%s (%s)", model, serial),
			InstalledFromDEP: false,
		}, nil
	}

	ds.AppConfigFunc = func(context.Context) (*mobius.AppConfig, error) {
		return &mobius.AppConfig{}, nil
	}
	ds.NewActivityFunc = func(
		ctx context.Context, user *mobius.User, activity mobius.ActivityDetails, details []byte, createdAt time.Time,
	) error {
		a, ok := activity.(*mobius.ActivityTypeMDMEnrolled)
		require.True(t, ok)
		require.Nil(t, user)
		require.Equal(t, "mdm_enrolled", activity.ActivityName())
		require.Equal(t, serial, a.HostSerial)
		require.Equal(t, a.HostDisplayName, fmt.Sprintf("%s (%s)", model, serial))
		require.False(t, a.InstalledFromDEP)
		require.Equal(t, mobius.MDMPlatformApple, a.MDMPlatform)
		return nil
	}

	ds.MDMResetEnrollmentFunc = func(ctx context.Context, hostUUID string, scepRenewalInProgress bool) error {
		require.Equal(t, uuid, hostUUID)
		return nil
	}

	err := svc.Authenticate(
		&mdm.Request{Context: ctx, EnrollID: &mdm.EnrollID{ID: uuid}},
		&mdm.Authenticate{
			Enrollment: mdm.Enrollment{
				UDID: uuid,
			},
			SerialNumber: serial,
			Model:        model,
		},
	)
	require.NoError(t, err)
	require.True(t, ds.MDMAppleUpsertHostFuncInvoked)
	require.True(t, ds.GetHostMDMCheckinInfoFuncInvoked)
	require.True(t, ds.NewActivityFuncInvoked)
	require.True(t, ds.MDMResetEnrollmentFuncInvoked)
}

func TestMDMAuthenticateADE(t *testing.T) {
	ds := new(mock.Store)
	mdmLifecycle := mdmlifecycle.New(ds, kitlog.NewNopLogger())
	svc := MDMAppleCheckinAndCommandService{
		ds:           ds,
		mdmLifecycle: mdmLifecycle,
	}
	ctx := context.Background()
	uuid, serial, model := "ABC-DEF-GHI", "XYZABC", "MacBookPro 16,1"

	ds.MDMAppleUpsertHostFunc = func(ctx context.Context, mdmHost *mobius.Host) error {
		require.Equal(t, uuid, mdmHost.UUID)
		require.Equal(t, serial, mdmHost.HardwareSerial)
		require.Equal(t, model, mdmHost.HardwareModel)
		return nil
	}

	ds.GetHostMDMCheckinInfoFunc = func(ct context.Context, hostUUID string) (*mobius.HostMDMCheckinInfo, error) {
		require.Equal(t, uuid, hostUUID)
		return &mobius.HostMDMCheckinInfo{
			HardwareSerial:     serial,
			DisplayName:        fmt.Sprintf("%s (%s)", model, serial),
			DEPAssignedToMobius: true,
		}, nil
	}

	ds.AppConfigFunc = func(context.Context) (*mobius.AppConfig, error) {
		return &mobius.AppConfig{}, nil
	}
	ds.NewActivityFunc = func(
		ctx context.Context, user *mobius.User, activity mobius.ActivityDetails, details []byte, createdAt time.Time,
	) error {
		a, ok := activity.(*mobius.ActivityTypeMDMEnrolled)
		require.True(t, ok)
		require.Nil(t, user)
		require.Equal(t, "mdm_enrolled", activity.ActivityName())
		require.Equal(t, serial, a.HostSerial)
		require.Equal(t, a.HostDisplayName, fmt.Sprintf("%s (%s)", model, serial))
		require.True(t, a.InstalledFromDEP)
		require.Equal(t, mobius.MDMPlatformApple, a.MDMPlatform)
		return nil
	}

	ds.MDMResetEnrollmentFunc = func(ctx context.Context, hostUUID string, scepRenewalInProgress bool) error {
		require.Equal(t, uuid, hostUUID)
		return nil
	}

	err := svc.Authenticate(
		&mdm.Request{Context: ctx, EnrollID: &mdm.EnrollID{ID: uuid}},
		&mdm.Authenticate{
			Enrollment: mdm.Enrollment{
				UDID: uuid,
			},
			SerialNumber: serial,
			Model:        model,
		},
	)
	require.NoError(t, err)
	require.True(t, ds.MDMAppleUpsertHostFuncInvoked)
	require.True(t, ds.GetHostMDMCheckinInfoFuncInvoked)
	require.True(t, ds.NewActivityFuncInvoked)
	require.True(t, ds.MDMResetEnrollmentFuncInvoked)
}

func TestMDMAuthenticateSCEPRenewal(t *testing.T) {
	ds := new(mock.Store)
	mdmLifecycle := mdmlifecycle.New(ds, kitlog.NewNopLogger())
	svc := MDMAppleCheckinAndCommandService{
		ds:           ds,
		mdmLifecycle: mdmLifecycle,
		logger:       kitlog.NewNopLogger(),
	}
	ctx := context.Background()
	uuid, serial, model := "ABC-DEF-GHI", "XYZABC", "MacBookPro 16,1"

	ds.GetHostMDMCheckinInfoFunc = func(ct context.Context, hostUUID string) (*mobius.HostMDMCheckinInfo, error) {
		require.Equal(t, uuid, hostUUID)
		return &mobius.HostMDMCheckinInfo{
			HardwareSerial:        serial,
			DisplayName:           fmt.Sprintf("%s (%s)", model, serial),
			SCEPRenewalInProgress: true,
		}, nil
	}

	ds.NewActivityFunc = func(
		ctx context.Context, user *mobius.User, activity mobius.ActivityDetails, details []byte, createdAt time.Time,
	) error {
		return nil
	}
	ds.MDMResetEnrollmentFunc = func(ctx context.Context, hostUUID string, scepRenewalInProgress bool) error {
		require.Equal(t, uuid, hostUUID)
		require.True(t, scepRenewalInProgress)
		return nil
	}
	ds.MDMAppleUpsertHostFunc = func(ctx context.Context, mdmHost *mobius.Host) error {
		return nil
	}

	err := svc.Authenticate(
		&mdm.Request{Context: ctx, EnrollID: &mdm.EnrollID{ID: uuid}},
		&mdm.Authenticate{
			Enrollment: mdm.Enrollment{
				UDID: uuid,
			},
			SerialNumber: serial,
			Model:        model,
		},
	)
	require.NoError(t, err)
	require.False(t, ds.MDMAppleUpsertHostFuncInvoked)
	require.True(t, ds.GetHostMDMCheckinInfoFuncInvoked)
	require.False(t, ds.NewActivityFuncInvoked)
	require.True(t, ds.MDMResetEnrollmentFuncInvoked)
}

func TestMDMTokenUpdate(t *testing.T) {
	ctx := context.Background()
	ds := new(mock.Store)
	mdmStorage := &mdmmock.MDMAppleStore{}
	pushFactory, _ := newMockAPNSPushProviderFactory()
	pusher := nanomdm_pushsvc.New(
		mdmStorage,
		mdmStorage,
		pushFactory,
		NewNanoMDMLogger(kitlog.NewJSONLogger(os.Stdout)),
	)
	cmdr := apple_mdm.NewMDMAppleCommander(mdmStorage, pusher)
	mdmLifecycle := mdmlifecycle.New(ds, kitlog.NewNopLogger())
	svc := MDMAppleCheckinAndCommandService{
		ds:           ds,
		mdmLifecycle: mdmLifecycle,
		commander:    cmdr,
		logger:       kitlog.NewNopLogger(),
	}
	uuid, serial, model, wantTeamID := "ABC-DEF-GHI", "XYZABC", "MacBookPro 16,1", uint(12)

	ds.GetNanoMDMEnrollmentFunc = func(ctx context.Context, hostUUID string) (*mobius.NanoEnrollment, error) {
		return &mobius.NanoEnrollment{Enabled: true, Type: "Device", TokenUpdateTally: 1}, nil
	}

	ds.GetHostMDMCheckinInfoFunc = func(ct context.Context, hostUUID string) (*mobius.HostMDMCheckinInfo, error) {
		require.Equal(t, uuid, hostUUID)
		return &mobius.HostMDMCheckinInfo{
			HardwareSerial:     serial,
			DisplayName:        model,
			InstalledFromDEP:   true,
			TeamID:             wantTeamID,
			DEPAssignedToMobius: true,
			Platform:           "darwin",
		}, nil
	}

	ds.GetMDMIdPAccountByHostUUIDFunc = func(ctx context.Context, hostUUID string) (*mobius.MDMIdPAccount, error) {
		require.Equal(t, uuid, hostUUID)
		return &mobius.MDMIdPAccount{
			UUID:     "some-uuid",
			Username: "some-user",
			Email:    "some-user@example.com",
			Fullname: "Some User",
		}, nil
	}

	ds.NewJobFunc = func(ctx context.Context, j *mobius.Job) (*mobius.Job, error) {
		return j, nil
	}

	err := svc.TokenUpdate(
		&mdm.Request{Context: ctx, EnrollID: &mdm.EnrollID{ID: uuid}},
		&mdm.TokenUpdate{
			Enrollment: mdm.Enrollment{
				UDID: uuid,
			},
		},
	)
	require.NoError(t, err)
	require.True(t, ds.GetHostMDMCheckinInfoFuncInvoked)
	require.True(t, ds.NewJobFuncInvoked)
	ds.GetHostMDMCheckinInfoFuncInvoked = false
	ds.NewJobFuncInvoked = false

	// with enrollment reference
	err = svc.TokenUpdate(
		&mdm.Request{
			Context:  ctx,
			EnrollID: &mdm.EnrollID{ID: uuid},
			Params:   map[string]string{"enroll_reference": "abcd"},
		},
		&mdm.TokenUpdate{
			Enrollment: mdm.Enrollment{
				UDID: uuid,
			},
		},
	)
	require.NoError(t, err)
	require.True(t, ds.GetHostMDMCheckinInfoFuncInvoked)
	require.True(t, ds.NewJobFuncInvoked)
}

func TestMDMCheckout(t *testing.T) {
	ds := new(mock.Store)
	mdmLifecycle := mdmlifecycle.New(ds, kitlog.NewNopLogger())
	svc := MDMAppleCheckinAndCommandService{
		ds:           ds,
		mdmLifecycle: mdmLifecycle,
		logger:       kitlog.NewNopLogger(),
	}
	ctx := context.Background()
	uuid, serial, installedFromDEP, displayName := "ABC-DEF-GHI", "XYZABC", true, "Test's MacBook"

	ds.MDMTurnOffFunc = func(ctx context.Context, hostUUID string) error {
		require.Equal(t, uuid, hostUUID)
		return nil
	}

	ds.GetHostMDMCheckinInfoFunc = func(ct context.Context, hostUUID string) (*mobius.HostMDMCheckinInfo, error) {
		require.Equal(t, uuid, hostUUID)
		return &mobius.HostMDMCheckinInfo{
			HardwareSerial:   serial,
			DisplayName:      displayName,
			InstalledFromDEP: installedFromDEP,
			Platform:         "darwin",
		}, nil
	}

	ds.AppConfigFunc = func(context.Context) (*mobius.AppConfig, error) {
		return &mobius.AppConfig{}, nil
	}
	ds.NewActivityFunc = func(
		ctx context.Context, user *mobius.User, activity mobius.ActivityDetails, details []byte, createdAt time.Time,
	) error {
		a, ok := activity.(*mobius.ActivityTypeMDMUnenrolled)
		require.True(t, ok)
		require.Nil(t, user)
		require.Equal(t, "mdm_unenrolled", activity.ActivityName())
		require.Equal(t, serial, a.HostSerial)
		require.Equal(t, displayName, a.HostDisplayName)
		require.True(t, a.InstalledFromDEP)
		return nil
	}

	err := svc.CheckOut(
		&mdm.Request{
			Context:  ctx,
			EnrollID: &mdm.EnrollID{ID: uuid},
		},
		&mdm.CheckOut{
			Enrollment: mdm.Enrollment{
				UDID: uuid,
			},
		},
	)
	require.NoError(t, err)
	require.True(t, ds.MDMTurnOffFuncInvoked)
	require.True(t, ds.GetHostMDMCheckinInfoFuncInvoked)
	require.True(t, ds.NewActivityFuncInvoked)
}

func TestMDMCommandAndReportResultsProfileHandling(t *testing.T) {
	ctx := context.Background()
	hostUUID := "ABC-DEF-GHI"
	commandUUID := "COMMAND-UUID"
	profileIdentifier := "PROFILE-IDENTIFIER"

	cases := []struct {
		status      string
		requestType string
		errors      []mdm.ErrorChain
		want        *mobius.HostMDMAppleProfile
		prevRetries uint
	}{
		{
			status:      "Acknowledged",
			requestType: "InstallProfile",
			errors:      nil,
			want: &mobius.HostMDMAppleProfile{
				Status:        &mobius.MDMDeliveryVerifying,
				Detail:        "",
				OperationType: mobius.MDMOperationTypeInstall,
			},
		},
		{
			status:      "Acknowledged",
			requestType: "RemoveProfile",
			errors:      nil,
			want: &mobius.HostMDMAppleProfile{
				Status:        &mobius.MDMDeliveryVerifying,
				Detail:        "",
				OperationType: mobius.MDMOperationTypeRemove,
			},
		},
		{
			status:      "Error",
			requestType: "InstallProfile",
			errors: []mdm.ErrorChain{
				{ErrorCode: 123, ErrorDomain: "testDomain", USEnglishDescription: "testMessage"},
			},
			prevRetries: 0, // expect to retry
			want: &mobius.HostMDMAppleProfile{
				Status:        &mobius.MDMDeliveryPending,
				Detail:        "",
				OperationType: mobius.MDMOperationTypeInstall,
			},
		},
		{
			status:      "Error",
			requestType: "InstallProfile",
			errors: []mdm.ErrorChain{
				{ErrorCode: 123, ErrorDomain: "testDomain", USEnglishDescription: "testMessage"},
			},
			prevRetries: 1, // expect to fail
			want: &mobius.HostMDMAppleProfile{
				Status:        &mobius.MDMDeliveryFailed,
				Detail:        "testDomain (123): testMessage\n",
				OperationType: mobius.MDMOperationTypeInstall,
			},
		},
		{
			status:      "Error",
			requestType: "RemoveProfile",
			errors: []mdm.ErrorChain{
				{ErrorCode: 123, ErrorDomain: "testDomain", USEnglishDescription: "testMessage"},
				{ErrorCode: 321, ErrorDomain: "domainTest", USEnglishDescription: "messageTest"},
			},
			want: &mobius.HostMDMAppleProfile{
				Status:        &mobius.MDMDeliveryFailed,
				Detail:        "testDomain (123): testMessage\ndomainTest (321): messageTest\n",
				OperationType: mobius.MDMOperationTypeRemove,
			},
		},
		{
			status:      "Error",
			requestType: "RemoveProfile",
			errors:      nil,
			want: &mobius.HostMDMAppleProfile{
				Status:        &mobius.MDMDeliveryFailed,
				Detail:        "",
				OperationType: mobius.MDMOperationTypeRemove,
			},
		},
	}

	for i, c := range cases {
		t.Run(fmt.Sprintf("%s%s-%d", c.requestType, c.status, i), func(t *testing.T) {
			ds := new(mock.Store)
			svc := MDMAppleCheckinAndCommandService{ds: ds}
			ds.GetMDMAppleCommandRequestTypeFunc = func(ctx context.Context, targetCmd string) (string, error) {
				require.Equal(t, commandUUID, targetCmd)
				return c.requestType, nil
			}
			ds.UpdateOrDeleteHostMDMAppleProfileFunc = func(ctx context.Context, profile *mobius.HostMDMAppleProfile) error {
				c.want.CommandUUID = commandUUID
				c.want.HostUUID = hostUUID
				require.Equal(t, c.want, profile)
				return nil
			}
			ds.GetHostMDMProfileRetryCountByCommandUUIDFunc = func(ctx context.Context, host *mobius.Host, cmdUUID string) (mobius.HostMDMProfileRetryCount, error) {
				require.Equal(t, hostUUID, host.UUID)
				require.Equal(t, commandUUID, cmdUUID)
				return mobius.HostMDMProfileRetryCount{ProfileIdentifier: profileIdentifier, Retries: c.prevRetries}, nil
			}
			ds.UpdateHostMDMProfilesVerificationFunc = func(ctx context.Context, host *mobius.Host, toVerify, toFail, toRetry []string) error {
				require.Equal(t, hostUUID, host.UUID)
				require.Nil(t, toVerify)
				require.Nil(t, toFail)
				require.ElementsMatch(t, toRetry, []string{profileIdentifier})
				return nil
			}

			_, err := svc.CommandAndReportResults(
				&mdm.Request{Context: ctx},
				&mdm.CommandResults{
					Enrollment:  mdm.Enrollment{UDID: hostUUID},
					CommandUUID: commandUUID,
					Status:      c.status,
					ErrorChain:  c.errors,
				},
			)
			require.NoError(t, err)
			require.True(t, ds.GetMDMAppleCommandRequestTypeFuncInvoked)
			var shouldCheckCount, shouldRetry, shouldUpdateOrDelete bool
			if c.requestType == "InstallProfile" && c.status == "Error" {
				shouldCheckCount = true
			}
			if shouldCheckCount && c.prevRetries == uint(0) {
				shouldRetry = true
			}
			if c.requestType == "RemoveProfile" || (c.requestType == "InstallProfile" && !shouldRetry) {
				shouldUpdateOrDelete = true
			}
			require.Equal(t, shouldCheckCount, ds.GetHostMDMProfileRetryCountByCommandUUIDFuncInvoked)
			require.Equal(t, shouldRetry, ds.UpdateHostMDMProfilesVerificationFuncInvoked)
			require.Equal(t, shouldUpdateOrDelete, ds.UpdateOrDeleteHostMDMAppleProfileFuncInvoked)
		})
	}
}

func TestMDMBatchSetAppleProfiles(t *testing.T) {
	svc, ctx, ds := setupAppleMDMService(t, &mobius.LicenseInfo{Tier: mobius.TierPremium})

	ds.TeamByNameFunc = func(ctx context.Context, name string) (*mobius.Team, error) {
		return &mobius.Team{ID: 1, Name: name}, nil
	}
	ds.TeamFunc = func(ctx context.Context, id uint) (*mobius.Team, error) {
		return &mobius.Team{ID: id, Name: "team"}, nil
	}
	ds.BatchSetMDMAppleProfilesFunc = func(ctx context.Context, teamID *uint, profiles []*mobius.MDMAppleConfigProfile) error {
		return nil
	}
	ds.NewActivityFunc = func(
		ctx context.Context, user *mobius.User, activity mobius.ActivityDetails, details []byte, createdAt time.Time,
	) error {
		return nil
	}
	ds.BulkSetPendingMDMHostProfilesFunc = func(ctx context.Context, hids, tids []uint, puuids, uuids []string,
	) (updates mobius.MDMProfilesUpdates, err error) {
		return mobius.MDMProfilesUpdates{}, nil
	}
	ds.ListMDMConfigProfilesFunc = func(ctx context.Context, tid *uint, opt mobius.ListOptions) ([]*mobius.MDMConfigProfilePayload, *mobius.PaginationMetadata, error) {
		return nil, nil, nil
	}

	type testCase struct {
		name     string
		user     *mobius.User
		premium  bool
		teamID   *uint
		teamName *string
		profiles [][]byte
		wantErr  string
	}

	testCases := []testCase{
		{
			"global admin",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)},
			false,
			nil,
			nil,
			nil,
			"",
		},
		{
			"global admin, team",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)},
			true,
			ptr.Uint(1),
			nil,
			nil,
			"",
		},
		{
			"global maintainer",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleMaintainer)},
			false,
			nil,
			nil,
			nil,
			"",
		},
		{
			"global maintainer, team",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleMaintainer)},
			true,
			ptr.Uint(1),
			nil,
			nil,
			"",
		},
		{
			"global observer",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleObserver)},
			false,
			nil,
			nil,
			nil,
			authz.ForbiddenErrorMessage,
		},
		{
			"team admin, DOES belong to team",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleAdmin}}},
			true,
			ptr.Uint(1),
			nil,
			nil,
			"",
		},
		{
			"team admin, DOES belong to team by name",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleAdmin}}},
			true,
			nil,
			ptr.String("team"),
			nil,
			"",
		},
		{
			"team admin, DOES NOT belong to team",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 2}, Role: mobius.RoleAdmin}}},
			true,
			ptr.Uint(1),
			nil,
			nil,
			authz.ForbiddenErrorMessage,
		},
		{
			"team admin, DOES NOT belong to team by name",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 2}, Role: mobius.RoleAdmin}}},
			true,
			nil,
			ptr.String("team"),
			nil,
			authz.ForbiddenErrorMessage,
		},
		{
			"team maintainer, DOES belong to team",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleMaintainer}}},
			true,
			ptr.Uint(1),
			nil,
			nil,
			"",
		},
		{
			"team maintainer, DOES NOT belong to team",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 2}, Role: mobius.RoleMaintainer}}},
			true,
			ptr.Uint(1),
			nil,
			nil,
			authz.ForbiddenErrorMessage,
		},
		{
			"team observer, DOES belong to team",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleObserver}}},
			true,
			ptr.Uint(1),
			nil,
			nil,
			authz.ForbiddenErrorMessage,
		},
		{
			"team observer, DOES NOT belong to team",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 2}, Role: mobius.RoleObserver}}},
			true,
			ptr.Uint(1),
			nil,
			nil,
			authz.ForbiddenErrorMessage,
		},
		{
			"user no roles",
			&mobius.User{ID: 1337},
			false,
			nil,
			nil,
			nil,
			authz.ForbiddenErrorMessage,
		},
		{
			"team id with free license",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)},
			false,
			ptr.Uint(1),
			nil,
			nil,
			ErrMissingLicense.Error(),
		},
		{
			"team name with free license",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)},
			false,
			nil,
			ptr.String("team"),
			nil,
			ErrMissingLicense.Error(),
		},
		{
			"team id and name specified",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)},
			true,
			ptr.Uint(1),
			ptr.String("team"),
			nil,
			"cannot specify both team_id and team_name",
		},
		{
			"duplicate profile name",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)},
			true,
			ptr.Uint(1),
			nil,
			[][]byte{
				mobileconfigForTest("N1", "I1"),
				mobileconfigForTest("N1", "I2"),
			},
			`More than one configuration profile have the same name (PayloadDisplayName): "N1"`,
		},
		{
			"duplicate profile identifier",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)},
			true,
			ptr.Uint(1),
			nil,
			[][]byte{
				mobileconfigForTest("N1", "I1"),
				mobileconfigForTest("N2", "I2"),
				mobileconfigForTest("N3", "I1"),
			},
			`More than one configuration profile have the same identifier (PayloadIdentifier): "I1"`,
		},
		{
			"no duplicates",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)},
			false,
			nil,
			nil,
			[][]byte{
				mobileconfigForTest("N1", "I1"),
				mobileconfigForTest("N2", "I2"),
				mobileconfigForTest("N3", "I3"),
			},
			``,
		},
		{
			"unsupported payload type",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)},
			false,
			nil,
			nil,
			[][]byte{[]byte(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
			<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
			<plist version="1.0">
			<dict>
				<key>PayloadContent</key>
				<array>
					<dict>
						<key>Enable</key>
						<string>On</string>
						<key>PayloadDisplayName</key>
						<string>FileVault 2</string>
						<key>PayloadIdentifier</key>
						<string>com.apple.MCX.FileVault2.A5874654-D6BA-4649-84B5-43847953B369</string>
						<key>PayloadType</key>
						<string>%s</string>
						<key>PayloadUUID</key>
						<string>A5874654-D6BA-4649-84B5-43847953B369</string>
						<key>PayloadVersion</key>
						<integer>1</integer>
					</dict>
				</array>
				<key>PayloadDisplayName</key>
				<string>Config Profile Name</string>
				<key>PayloadIdentifier</key>
				<string>com.example.config.FE42D0A2-DBA9-4B72-BC67-9288665B8D59</string>
				<key>PayloadType</key>
				<string>Configuration</string>
				<key>PayloadUUID</key>
				<string>FE42D0A2-DBA9-4B72-BC67-9288665B8D59</string>
				<key>PayloadVersion</key>
				<integer>1</integer>
			</dict>
			</plist>`, mobileconfig.MobiusFileVaultPayloadType))},
			mobileconfig.DiskEncryptionProfileRestrictionErrMsg,
		},
		{
			"uses a Mobius Variable",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)},
			false,
			nil,
			nil,
			[][]byte{[]byte(`<?xml version="1.0" encoding="UTF-8"?>
			<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
			<plist version="1.0">
			<dict>
				<key>PayloadContent</key>
				<array>
					<dict>
						<key>Username</key>
						<string>$MOBIUS_VAR_HOST_END_USER_IDP_USERNAME</string>
					</dict>
				</array>
				<key>PayloadDisplayName</key>
				<string>Config Profile Name</string>
				<key>PayloadIdentifier</key>
				<string>com.example.config.FE42D0A2-DBA9-4B72-BC67-9288665B8D59</string>
				<key>PayloadType</key>
				<string>Configuration</string>
				<key>PayloadUUID</key>
				<string>FE42D0A2-DBA9-4B72-BC67-9288665B8D59</string>
				<key>PayloadVersion</key>
				<integer>1</integer>
			</dict>
			</plist>`)},
			`profile variables are not supported by this deprecated endpoint`,
		},
	}
	for name := range mobiusmdm.MobiusReservedProfileNames() {
		testCases = append(testCases,
			testCase{
				"reserved payload outer name " + name,
				&mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)},
				true,
				nil,
				nil,
				[][]byte{mobileconfigForTest(name, "I1")},
				name,
			},
			testCase{
				"reserved payload inner name " + name,
				&mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)},
				true,
				nil,
				nil,
				[][]byte{mobileconfigForTestWithContent("N1", "I1", "I1", "PayloadType", name)},
				name,
			},
		)
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			defer func() { ds.BatchSetMDMAppleProfilesFuncInvoked = false }()

			// prepare the context with the user and license
			ctx := viewer.NewContext(ctx, viewer.Viewer{User: tt.user})
			tier := mobius.TierFree
			if tt.premium {
				tier = mobius.TierPremium
			}
			ctx = license.NewContext(ctx, &mobius.LicenseInfo{Tier: tier})

			err := svc.BatchSetMDMAppleProfiles(ctx, tt.teamID, tt.teamName, tt.profiles, false, false)
			if tt.wantErr == "" {
				require.NoError(t, err)
				require.True(t, ds.BatchSetMDMAppleProfilesFuncInvoked)
				return
			}
			require.Error(t, err)
			require.ErrorContains(t, err, tt.wantErr)
			require.False(t, ds.BatchSetMDMAppleProfilesFuncInvoked)
		})
	}
}

func TestMDMBatchSetAppleProfilesBoolArgs(t *testing.T) {
	svc, ctx, ds := setupAppleMDMService(t, &mobius.LicenseInfo{Tier: mobius.TierPremium})

	ds.TeamByNameFunc = func(ctx context.Context, name string) (*mobius.Team, error) {
		return &mobius.Team{ID: 1, Name: name}, nil
	}
	ds.TeamFunc = func(ctx context.Context, id uint) (*mobius.Team, error) {
		return &mobius.Team{ID: id, Name: "team"}, nil
	}
	ds.BatchSetMDMAppleProfilesFunc = func(ctx context.Context, teamID *uint, profiles []*mobius.MDMAppleConfigProfile) error {
		return nil
	}
	ds.NewActivityFunc = func(
		ctx context.Context, user *mobius.User, activity mobius.ActivityDetails, details []byte, createdAt time.Time,
	) error {
		return nil
	}
	ds.BulkSetPendingMDMHostProfilesFunc = func(ctx context.Context, hids, tids []uint, profileUUIDs, uuids []string,
	) (updates mobius.MDMProfilesUpdates, err error) {
		return mobius.MDMProfilesUpdates{}, nil
	}
	ds.ListMDMConfigProfilesFunc = func(ctx context.Context, tid *uint, opt mobius.ListOptions) ([]*mobius.MDMConfigProfilePayload, *mobius.PaginationMetadata, error) {
		return nil, nil, nil
	}

	ctx = viewer.NewContext(ctx, viewer.Viewer{User: &mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)}})
	ctx = license.NewContext(ctx, &mobius.LicenseInfo{Tier: mobius.TierPremium})

	// dry run doesn't call methods that save stuff in the db
	err := svc.BatchSetMDMAppleProfiles(ctx, nil, nil, [][]byte{}, true, false)
	require.NoError(t, err)
	require.False(t, ds.BatchSetMDMAppleProfilesFuncInvoked)
	require.False(t, ds.BulkSetPendingMDMHostProfilesFuncInvoked)
	require.False(t, ds.NewActivityFuncInvoked)

	// skipping bulk set only skips that method
	err = svc.BatchSetMDMAppleProfiles(ctx, nil, nil, [][]byte{}, false, true)
	require.NoError(t, err)
	require.True(t, ds.BatchSetMDMAppleProfilesFuncInvoked)
	require.False(t, ds.BulkSetPendingMDMHostProfilesFuncInvoked)
	require.True(t, ds.NewActivityFuncInvoked)
}

func TestUpdateMDMAppleSettings(t *testing.T) {
	svc, ctx, ds := setupAppleMDMService(t, &mobius.LicenseInfo{Tier: mobius.TierPremium})

	ds.TeamFunc = func(ctx context.Context, id uint) (*mobius.Team, error) {
		return &mobius.Team{ID: id, Name: "team"}, nil
	}
	ds.SaveTeamFunc = func(ctx context.Context, team *mobius.Team) (*mobius.Team, error) {
		return team, nil
	}
	ds.NewActivityFunc = func(
		ctx context.Context, user *mobius.User, activity mobius.ActivityDetails, details []byte, createdAt time.Time,
	) error {
		return nil
	}
	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		return &mobius.AppConfig{}, nil
	}
	ds.SaveAppConfigFunc = func(ctx context.Context, appConfig *mobius.AppConfig) error {
		return nil
	}

	testCases := []struct {
		name    string
		user    *mobius.User
		premium bool
		teamID  *uint
		wantErr string
	}{
		{
			"global admin",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)},
			false,
			nil,
			mobius.ErrMissingLicense.Error(),
		},
		{
			"global admin premium",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)},
			true,
			nil,
			"",
		},
		{
			"global admin, team",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)},
			true,
			ptr.Uint(1),
			"",
		},
		{
			"global maintainer",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleMaintainer)},
			false,
			nil,
			mobius.ErrMissingLicense.Error(),
		},
		{
			"global maintainer premium",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleMaintainer)},
			true,
			nil,
			"",
		},
		{
			"global maintainer, team",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleMaintainer)},
			true,
			ptr.Uint(1),
			"",
		},
		{
			"global observer",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleObserver)},
			true,
			nil,
			authz.ForbiddenErrorMessage,
		},
		{
			"team admin, DOES belong to team",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleAdmin}}},
			true,
			ptr.Uint(1),
			"",
		},
		{
			"team admin, DOES NOT belong to team",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 2}, Role: mobius.RoleAdmin}}},
			true,
			ptr.Uint(1),
			authz.ForbiddenErrorMessage,
		},
		{
			"team maintainer, DOES belong to team",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleMaintainer}}},
			true,
			ptr.Uint(1),
			"",
		},
		{
			"team maintainer, DOES NOT belong to team",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 2}, Role: mobius.RoleMaintainer}}},
			true,
			ptr.Uint(1),
			authz.ForbiddenErrorMessage,
		},
		{
			"team observer, DOES belong to team",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleObserver}}},
			true,
			ptr.Uint(1),
			authz.ForbiddenErrorMessage,
		},
		{
			"team observer, DOES NOT belong to team",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 2}, Role: mobius.RoleObserver}}},
			true,
			ptr.Uint(1),
			authz.ForbiddenErrorMessage,
		},
		{
			"user no roles",
			&mobius.User{ID: 1337},
			true,
			nil,
			authz.ForbiddenErrorMessage,
		},
		{
			"team id with free license",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)},
			false,
			ptr.Uint(1),
			mobius.ErrMissingLicense.Error(),
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			// prepare the context with the user and license
			ctx := viewer.NewContext(ctx, viewer.Viewer{User: tt.user})
			tier := mobius.TierFree
			if tt.premium {
				tier = mobius.TierPremium
			}
			ctx = license.NewContext(ctx, &mobius.LicenseInfo{Tier: tier})

			err := svc.UpdateMDMDiskEncryption(ctx, tt.teamID, nil)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestUpdateMDMAppleSetup(t *testing.T) {
	setupTest := func(tier string) (mobius.Service, context.Context, *mock.Store) {
		svc, ctx, ds := setupAppleMDMService(t, &mobius.LicenseInfo{Tier: tier})
		ds.TeamFunc = func(ctx context.Context, id uint) (*mobius.Team, error) {
			return &mobius.Team{ID: id, Name: "team"}, nil
		}
		ds.SaveTeamFunc = func(ctx context.Context, team *mobius.Team) (*mobius.Team, error) {
			return team, nil
		}
		ds.NewActivityFunc = func(
			ctx context.Context, user *mobius.User, activity mobius.ActivityDetails, details []byte, createdAt time.Time,
		) error {
			return nil
		}
		ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
			return &mobius.AppConfig{MDM: mobius.MDM{EnabledAndConfigured: true}}, nil
		}
		ds.SaveAppConfigFunc = func(ctx context.Context, appConfig *mobius.AppConfig) error {
			return nil
		}
		return svc, ctx, ds
	}

	type testCase struct {
		name    string
		user    *mobius.User
		teamID  *uint
		wantErr string
	}
	// TODO: Add tests for gitops and observer plus roles? (Settings endpoint test above may also need to be updated)

	t.Run("FreeTier", func(t *testing.T) {
		freeTestCases := []testCase{
			{
				"global admin",
				&mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)},
				nil,
				"Requires Mobius Premium license",
			},
			{
				"global maintainer",
				&mobius.User{GlobalRole: ptr.String(mobius.RoleMaintainer)},
				nil,
				"Requires Mobius Premium license",
			},
			{
				"team id with free license",
				&mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)},
				ptr.Uint(1),
				"Requires Mobius Premium license",
			},
		}
		svc, ctx, _ := setupTest(mobius.TierFree)
		for _, tt := range freeTestCases {
			t.Run(tt.name, func(t *testing.T) {
				// prepare the context with the user and license
				ctx := viewer.NewContext(ctx, viewer.Viewer{User: tt.user})
				err := svc.UpdateMDMAppleSetup(ctx, mobius.MDMAppleSetupPayload{TeamID: tt.teamID})
				if tt.wantErr == "" {
					require.NoError(t, err)
					return
				}
				require.Error(t, err)
				require.ErrorContains(t, err, tt.wantErr)
			})
		}
	})
	t.Run("PremiumTier", func(t *testing.T) {
		premiumTestCases := []testCase{
			{
				"global admin premium",
				&mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)},
				nil,
				"",
			},
			{
				"global admin, team",
				&mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)},
				ptr.Uint(1),
				"",
			},
			{
				"global maintainer premium",
				&mobius.User{GlobalRole: ptr.String(mobius.RoleMaintainer)},
				nil,
				"",
			},
			{
				"global maintainer, team",
				&mobius.User{GlobalRole: ptr.String(mobius.RoleMaintainer)},
				ptr.Uint(1),
				"",
			},
			{
				"global observer",
				&mobius.User{GlobalRole: ptr.String(mobius.RoleObserver)},
				nil,
				authz.ForbiddenErrorMessage,
			},
			{
				"team admin, DOES belong to team",
				&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleAdmin}}},
				ptr.Uint(1),
				"",
			},
			{
				"team admin, DOES NOT belong to team",
				&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 2}, Role: mobius.RoleAdmin}}},
				ptr.Uint(1),
				authz.ForbiddenErrorMessage,
			},
			{
				"team maintainer, DOES belong to team",
				&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleMaintainer}}},
				ptr.Uint(1),
				"",
			},
			{
				"team maintainer, DOES NOT belong to team",
				&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 2}, Role: mobius.RoleMaintainer}}},
				ptr.Uint(1),
				authz.ForbiddenErrorMessage,
			},
			{
				"team observer, DOES belong to team",
				&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleObserver}}},
				ptr.Uint(1),
				authz.ForbiddenErrorMessage,
			},
			{
				"team observer, DOES NOT belong to team",
				&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 2}, Role: mobius.RoleObserver}}},
				ptr.Uint(1),
				authz.ForbiddenErrorMessage,
			},
			{
				"user no roles",
				&mobius.User{ID: 1337},
				nil,
				authz.ForbiddenErrorMessage,
			},
		}
		svc, ctx, _ := setupTest(mobius.TierPremium)
		for _, tt := range premiumTestCases {
			t.Run(tt.name, func(t *testing.T) {
				// prepare the context with the user and license
				ctx := viewer.NewContext(ctx, viewer.Viewer{User: tt.user})
				err := svc.UpdateMDMAppleSetup(ctx, mobius.MDMAppleSetupPayload{TeamID: tt.teamID})
				if tt.wantErr == "" {
					require.NoError(t, err)
					return
				}
				require.Error(t, err)
				require.ErrorContains(t, err, tt.wantErr)
			})
		}
	})
}

func TestMDMAppleReconcileAppleProfiles(t *testing.T) {
	ctx := context.Background()
	mdmStorage := &mdmmock.MDMAppleStore{}
	ds := new(mock.Store)
	pushFactory, _ := newMockAPNSPushProviderFactory()
	pusher := nanomdm_pushsvc.New(
		mdmStorage,
		mdmStorage,
		pushFactory,
		NewNanoMDMLogger(kitlog.NewNopLogger()),
	)
	mdmConfig := config.MDMConfig{
		AppleSCEPCert: "./testdata/server.pem",
		AppleSCEPKey:  "./testdata/server.key",
	}
	ds.GetAllMDMConfigAssetsByNameFunc = func(ctx context.Context, assetNames []mobius.MDMAssetName,
		_ sqlx.QueryerContext,
	) (map[mobius.MDMAssetName]mobius.MDMConfigAsset, error) {
		_, pemCert, pemKey, err := mdmConfig.AppleSCEP()
		require.NoError(t, err)
		return map[mobius.MDMAssetName]mobius.MDMConfigAsset{
			mobius.MDMAssetCACert: {Value: pemCert},
			mobius.MDMAssetCAKey:  {Value: pemKey},
		}, nil
	}

	cmdr := apple_mdm.NewMDMAppleCommander(mdmStorage, pusher)
	hostUUID1, hostUUID2 := "ABC-DEF", "GHI-JKL"
	hostUUID1UserEnrollment := hostUUID1 + ":user"
	contents1 := []byte("test-content-1")
	expectedContents1 := []byte("test-content-1") // used for Mobius variable substitution
	contents2 := []byte("test-content-2")
	contents4 := []byte("test-content-4")
	contents5 := []byte("test-contents-5")

	p1, p2, p3, p4, p5, p6 := "a"+uuid.NewString(), "a"+uuid.NewString(), "a"+uuid.NewString(), "a"+uuid.NewString(), "a"+uuid.NewString(), "a"+uuid.NewString()
	ds.ListMDMAppleProfilesToInstallFunc = func(ctx context.Context) ([]*mobius.MDMAppleProfilePayload, error) {
		return []*mobius.MDMAppleProfilePayload{
			{ProfileUUID: p1, ProfileIdentifier: "com.add.profile", HostUUID: hostUUID1, Scope: mobius.PayloadScopeSystem},
			{ProfileUUID: p2, ProfileIdentifier: "com.add.profile.two", HostUUID: hostUUID1, Scope: mobius.PayloadScopeSystem},
			{ProfileUUID: p2, ProfileIdentifier: "com.add.profile.two", HostUUID: hostUUID2, Scope: mobius.PayloadScopeSystem},
			{ProfileUUID: p4, ProfileIdentifier: "com.add.profile.four", HostUUID: hostUUID2, Scope: mobius.PayloadScopeSystem},
			{ProfileUUID: p5, ProfileIdentifier: "com.add.profile.five", HostUUID: hostUUID1, Scope: mobius.PayloadScopeUser},
			{ProfileUUID: p5, ProfileIdentifier: "com.add.profile.five", HostUUID: hostUUID2, Scope: mobius.PayloadScopeUser},
		}, nil
	}

	ds.ListMDMAppleProfilesToRemoveFunc = func(ctx context.Context) ([]*mobius.MDMAppleProfilePayload, error) {
		return []*mobius.MDMAppleProfilePayload{
			{ProfileUUID: p3, ProfileIdentifier: "com.remove.profile", HostUUID: hostUUID1, Scope: mobius.PayloadScopeSystem},
			{ProfileUUID: p3, ProfileIdentifier: "com.remove.profile", HostUUID: hostUUID2, Scope: mobius.PayloadScopeSystem},
			{ProfileUUID: p6, ProfileIdentifier: "com.remove.profile.six", HostUUID: hostUUID1, Scope: mobius.PayloadScopeUser},
			{ProfileUUID: p6, ProfileIdentifier: "com.remove.profile.six", HostUUID: hostUUID2, Scope: mobius.PayloadScopeUser},
		}, nil
	}

	ds.GetMDMAppleProfilesContentsFunc = func(ctx context.Context, profileUUIDs []string) (map[string]mobileconfig.Mobileconfig, error) {
		require.ElementsMatch(t, []string{p1, p2, p4, p5}, profileUUIDs)
		// only those profiles that are to be installed
		return map[string]mobileconfig.Mobileconfig{
			p1: contents1,
			p2: contents2,
			p4: contents4,
			p5: contents5,
		}, nil
	}

	ds.BulkDeleteMDMAppleHostsConfigProfilesFunc = func(ctx context.Context, payload []*mobius.MDMAppleProfilePayload) error {
		require.Empty(t, payload)
		return nil
	}

	ds.GetNanoMDMUserEnrollmentFunc = func(ctx context.Context, hostUUID string) (*mobius.NanoEnrollment, error) {
		if hostUUID == hostUUID1 {
			return &mobius.NanoEnrollment{
				ID:               hostUUID1UserEnrollment,
				DeviceID:         hostUUID1,
				Type:             "User",
				Enabled:          true,
				TokenUpdateTally: 1,
			}, nil
		}
		// hostUUID2 has no user enrollment
		assert.Equal(t, hostUUID2, hostUUID)
		return nil, nil
	}

	mdmStorage.BulkDeleteHostUserCommandsWithoutResultsFunc = func(ctx context.Context, commandToIDs map[string][]string) error {
		require.Empty(t, commandToIDs)
		return nil
	}

	var enqueueFailForOp mobius.MDMOperationType
	var mu sync.Mutex
	mdmStorage.EnqueueCommandFunc = func(ctx context.Context, id []string, cmd *mdm.CommandWithSubtype) (map[string]error, error) {
		require.NotNil(t, cmd)
		require.NotEmpty(t, cmd.CommandUUID)

		switch cmd.Command.Command.RequestType {
		case "InstallProfile":

			var fullCmd micromdm.CommandPayload
			require.NoError(t, plist.Unmarshal(cmd.Raw, &fullCmd))
			// the p7 library doesn't support concurrent calls to Parse
			mu.Lock()
			p7, err := pkcs7.Parse(fullCmd.Command.InstallProfile.Payload)
			mu.Unlock()
			require.NoError(t, err)

			if !bytes.Equal(p7.Content, expectedContents1) && !bytes.Equal(p7.Content, contents2) &&
				!bytes.Equal(p7.Content, contents4) && !bytes.Equal(p7.Content, contents5) {
				require.Failf(t, "profile contents don't match", "expected to contain %s, %s or %s but got %s",
					expectedContents1, contents2, contents4, p7.Content)
			}

			// may be called for a single host or both
			if len(id) == 2 {
				if bytes.Equal(p7.Content, contents5) {
					require.ElementsMatch(t, []string{hostUUID1UserEnrollment, hostUUID2}, id)
				} else {
					require.ElementsMatch(t, []string{hostUUID1, hostUUID2}, id)
				}
			} else {
				require.Len(t, id, 1)
			}

		case "RemoveProfile":
			if len(id) == 1 {
				require.Equal(t, hostUUID1UserEnrollment, id[0])
			} else {
				require.ElementsMatch(t, []string{hostUUID1, hostUUID2}, id)
			}
			require.Contains(t, string(cmd.Raw), "com.remove.profile")
		}
		switch {
		case enqueueFailForOp == mobius.MDMOperationTypeInstall && cmd.Command.Command.RequestType == "InstallProfile":
			return nil, errors.New("enqueue error")
		case enqueueFailForOp == mobius.MDMOperationTypeRemove && cmd.Command.Command.RequestType == "RemoveProfile":
			return nil, errors.New("enqueue error")
		}
		return nil, nil
	}

	mdmStorage.RetrievePushInfoFunc = func(ctx context.Context, tokens []string) (map[string]*mdm.Push, error) {
		res := make(map[string]*mdm.Push, len(tokens))
		for _, t := range tokens {
			res[t] = &mdm.Push{
				PushMagic: "",
				Token:     []byte(t),
				Topic:     "",
			}
		}
		return res, nil
	}
	mdmStorage.RetrievePushCertFunc = func(ctx context.Context, topic string) (*tls.Certificate, string, error) {
		cert, err := tls.LoadX509KeyPair("testdata/server.pem", "testdata/server.key")
		return &cert, "", err
	}
	mdmStorage.IsPushCertStaleFunc = func(ctx context.Context, topic string, staleToken string) (bool, error) {
		return false, nil
	}
	mdmStorage.GetAllMDMConfigAssetsByNameFunc = func(ctx context.Context, assetNames []mobius.MDMAssetName,
		_ sqlx.QueryerContext,
	) (map[mobius.MDMAssetName]mobius.MDMConfigAsset, error) {
		certPEM, err := os.ReadFile("./testdata/server.pem")
		require.NoError(t, err)
		keyPEM, err := os.ReadFile("./testdata/server.key")
		require.NoError(t, err)
		return map[mobius.MDMAssetName]mobius.MDMConfigAsset{
			mobius.MDMAssetCACert: {Value: certPEM},
			mobius.MDMAssetCAKey:  {Value: keyPEM},
		}, nil
	}

	var failedCall bool
	var failedCheck func([]*mobius.MDMAppleBulkUpsertHostProfilePayload)
	ds.BulkUpsertMDMAppleHostProfilesFunc = func(ctx context.Context, payload []*mobius.MDMAppleBulkUpsertHostProfilePayload) error {
		if failedCall {
			failedCheck(payload)
			return nil
		}

		// next call will be failed call, until reset
		failedCall = true

		// first time it is called, it is to set the status to pending and all
		// host profiles have a command uuid
		cmdUUIDByProfileUUIDInstall := make(map[string]string)
		cmdUUIDByProfileUUIDRemove := make(map[string]string)
		copies := make([]*mobius.MDMAppleBulkUpsertHostProfilePayload, len(payload))
		for i, p := range payload {
			if p.OperationType == mobius.MDMOperationTypeInstall {
				existing, ok := cmdUUIDByProfileUUIDInstall[p.ProfileUUID]
				if ok {
					require.Equal(t, existing, p.CommandUUID)
				} else {
					cmdUUIDByProfileUUIDInstall[p.ProfileUUID] = p.CommandUUID
				}
			} else {
				require.Equal(t, mobius.MDMOperationTypeRemove, p.OperationType)
				existing, ok := cmdUUIDByProfileUUIDRemove[p.ProfileUUID]
				if ok {
					require.Equal(t, existing, p.CommandUUID)
				} else {
					cmdUUIDByProfileUUIDRemove[p.ProfileUUID] = p.CommandUUID
				}
			}

			// clear the command UUID (in a copy so that it does not affect the
			// pointed-to struct) from the payload for the subsequent checks
			copyp := *p
			copyp.CommandUUID = ""
			copies[i] = &copyp
		}

		require.ElementsMatch(t, []*mobius.MDMAppleBulkUpsertHostProfilePayload{
			{
				ProfileUUID:       p1,
				ProfileIdentifier: "com.add.profile",
				HostUUID:          hostUUID1,
				OperationType:     mobius.MDMOperationTypeInstall,
				Status:            &mobius.MDMDeliveryPending,
				Scope:             mobius.PayloadScopeSystem,
			},
			{
				ProfileUUID:       p2,
				ProfileIdentifier: "com.add.profile.two",
				HostUUID:          hostUUID1,
				OperationType:     mobius.MDMOperationTypeInstall,
				Status:            &mobius.MDMDeliveryPending,
				Scope:             mobius.PayloadScopeSystem,
			},
			{
				ProfileUUID:       p2,
				ProfileIdentifier: "com.add.profile.two",
				HostUUID:          hostUUID2,
				OperationType:     mobius.MDMOperationTypeInstall,
				Status:            &mobius.MDMDeliveryPending,
				Scope:             mobius.PayloadScopeSystem,
			},
			{
				ProfileUUID:       p3,
				ProfileIdentifier: "com.remove.profile",
				HostUUID:          hostUUID1,
				OperationType:     mobius.MDMOperationTypeRemove,
				Status:            &mobius.MDMDeliveryPending,
				Scope:             mobius.PayloadScopeSystem,
			},
			{
				ProfileUUID:       p3,
				ProfileIdentifier: "com.remove.profile",
				HostUUID:          hostUUID2,
				OperationType:     mobius.MDMOperationTypeRemove,
				Status:            &mobius.MDMDeliveryPending,
				Scope:             mobius.PayloadScopeSystem,
			},
			{
				ProfileUUID:       p4,
				ProfileIdentifier: "com.add.profile.four",
				HostUUID:          hostUUID2,
				OperationType:     mobius.MDMOperationTypeInstall,
				Status:            &mobius.MDMDeliveryPending,
				Scope:             mobius.PayloadScopeSystem,
			},
			// This host has a user enrollment so the profile is sent to it
			{
				ProfileUUID:       p5,
				ProfileIdentifier: "com.add.profile.five",
				HostUUID:          hostUUID1,
				OperationType:     mobius.MDMOperationTypeInstall,
				Status:            &mobius.MDMDeliveryPending,
				Scope:             mobius.PayloadScopeUser,
			},
			// This host has no user enrollment so the profile is sent to the device enrollment
			{
				ProfileUUID:       p5,
				ProfileIdentifier: "com.add.profile.five",
				HostUUID:          hostUUID2,
				OperationType:     mobius.MDMOperationTypeInstall,
				Status:            &mobius.MDMDeliveryPending,
				Scope:             mobius.PayloadScopeSystem,
			},
			// This host has a user enrollment so the profile is removed from it
			{
				ProfileUUID:       p6,
				ProfileIdentifier: "com.remove.profile.six",
				HostUUID:          hostUUID1,
				OperationType:     mobius.MDMOperationTypeRemove,
				Status:            &mobius.MDMDeliveryPending,
				Scope:             mobius.PayloadScopeUser,
			},
		}, copies)
		return nil
	}

	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		appCfg := &mobius.AppConfig{}
		appCfg.ServerSettings.ServerURL = "https://test.example.com"
		appCfg.MDM.EnabledAndConfigured = true
		return appCfg, nil
	}

	ds.BulkUpsertMDMAppleConfigProfilesFunc = func(ctx context.Context, p []*mobius.MDMAppleConfigProfile) error {
		return nil
	}

	ds.AggregateEnrollSecretPerTeamFunc = func(ctx context.Context) ([]*mobius.EnrollSecret, error) {
		return []*mobius.EnrollSecret{}, nil
	}

	checkAndReset := func(t *testing.T, want bool, invoked *bool) {
		if want {
			assert.True(t, *invoked)
		} else {
			assert.False(t, *invoked)
		}
		*invoked = false
	}

	t.Run("success", func(t *testing.T) {
		var failedCount int
		failedCall = false
		failedCheck = func(payload []*mobius.MDMAppleBulkUpsertHostProfilePayload) {
			failedCount++
			require.Len(t, payload, 0)
		}
		err := ReconcileAppleProfiles(ctx, ds, cmdr, kitlog.NewNopLogger())
		require.NoError(t, err)
		require.Equal(t, 1, failedCount)
		checkAndReset(t, true, &ds.ListMDMAppleProfilesToInstallFuncInvoked)
		checkAndReset(t, true, &ds.ListMDMAppleProfilesToRemoveFuncInvoked)
		checkAndReset(t, true, &ds.GetMDMAppleProfilesContentsFuncInvoked)
		checkAndReset(t, true, &ds.BulkUpsertMDMAppleHostProfilesFuncInvoked)
		checkAndReset(t, true, &ds.GetNanoMDMUserEnrollmentFuncInvoked)
	})

	t.Run("fail enqueue remove ops", func(t *testing.T) {
		var failedCount int
		failedCall = false
		failedCheck = func(payload []*mobius.MDMAppleBulkUpsertHostProfilePayload) {
			failedCount++
			require.Len(t, payload, 3) // the 3 remove ops
			require.ElementsMatch(t, []*mobius.MDMAppleBulkUpsertHostProfilePayload{
				{
					ProfileUUID:       p3,
					ProfileIdentifier: "com.remove.profile",
					HostUUID:          hostUUID1,
					OperationType:     mobius.MDMOperationTypeRemove,
					Status:            nil,
					CommandUUID:       "",
					Scope:             mobius.PayloadScopeSystem,
				},
				{
					ProfileUUID:       p3,
					ProfileIdentifier: "com.remove.profile",
					HostUUID:          hostUUID2,
					OperationType:     mobius.MDMOperationTypeRemove,
					Status:            nil,
					CommandUUID:       "",
					Scope:             mobius.PayloadScopeSystem,
				},
				{
					ProfileUUID:       p6,
					ProfileIdentifier: "com.remove.profile.six",
					HostUUID:          hostUUID1,
					OperationType:     mobius.MDMOperationTypeRemove,
					Status:            nil,
					CommandUUID:       "",
					Scope:             mobius.PayloadScopeUser,
				},
			}, payload)
		}

		enqueueFailForOp = mobius.MDMOperationTypeRemove
		err := ReconcileAppleProfiles(ctx, ds, cmdr, kitlog.NewNopLogger())
		require.NoError(t, err)
		require.Equal(t, 1, failedCount)
		checkAndReset(t, true, &ds.ListMDMAppleProfilesToInstallFuncInvoked)
		checkAndReset(t, true, &ds.ListMDMAppleProfilesToRemoveFuncInvoked)
		checkAndReset(t, true, &ds.GetMDMAppleProfilesContentsFuncInvoked)
		checkAndReset(t, true, &ds.BulkUpsertMDMAppleHostProfilesFuncInvoked)
		checkAndReset(t, true, &ds.GetNanoMDMUserEnrollmentFuncInvoked)
	})

	t.Run("fail enqueue install ops", func(t *testing.T) {
		var failedCount int
		failedCall = false
		failedCheck = func(payload []*mobius.MDMAppleBulkUpsertHostProfilePayload) {
			failedCount++

			require.Len(t, payload, 6) // the 6 install ops
			require.ElementsMatch(t, []*mobius.MDMAppleBulkUpsertHostProfilePayload{
				{
					ProfileUUID:       p1,
					ProfileIdentifier: "com.add.profile",
					HostUUID:          hostUUID1, OperationType: mobius.MDMOperationTypeInstall,
					Status:      nil,
					CommandUUID: "",
					Scope:       mobius.PayloadScopeSystem,
				},
				{
					ProfileUUID:       p2,
					ProfileIdentifier: "com.add.profile.two",
					HostUUID:          hostUUID1, OperationType: mobius.MDMOperationTypeInstall,
					Status:      nil,
					CommandUUID: "",
					Scope:       mobius.PayloadScopeSystem,
				},
				{
					ProfileUUID:       p2,
					ProfileIdentifier: "com.add.profile.two",
					HostUUID:          hostUUID2,
					OperationType:     mobius.MDMOperationTypeInstall,
					Status:            nil,
					CommandUUID:       "",
					Scope:             mobius.PayloadScopeSystem,
				},
				{
					ProfileUUID:       p4,
					ProfileIdentifier: "com.add.profile.four",
					HostUUID:          hostUUID2,
					OperationType:     mobius.MDMOperationTypeInstall,
					Status:            nil,
					CommandUUID:       "",
					Scope:             mobius.PayloadScopeSystem,
				},
				{
					ProfileUUID:       p5,
					ProfileIdentifier: "com.add.profile.five",
					HostUUID:          hostUUID1,
					OperationType:     mobius.MDMOperationTypeInstall,
					Status:            nil,
					CommandUUID:       "",
					Scope:             mobius.PayloadScopeUser,
				},
				{
					ProfileUUID:       p5,
					ProfileIdentifier: "com.add.profile.five",
					HostUUID:          hostUUID2,
					OperationType:     mobius.MDMOperationTypeInstall,
					Status:            nil,
					CommandUUID:       "",
					Scope:             mobius.PayloadScopeSystem,
				},
			}, payload)
		}

		enqueueFailForOp = mobius.MDMOperationTypeInstall
		err := ReconcileAppleProfiles(ctx, ds, cmdr, kitlog.NewNopLogger())
		require.NoError(t, err)
		require.Equal(t, 1, failedCount)
		checkAndReset(t, true, &ds.ListMDMAppleProfilesToInstallFuncInvoked)
		checkAndReset(t, true, &ds.ListMDMAppleProfilesToRemoveFuncInvoked)
		checkAndReset(t, true, &ds.GetMDMAppleProfilesContentsFuncInvoked)
		checkAndReset(t, true, &ds.BulkUpsertMDMAppleHostProfilesFuncInvoked)
		checkAndReset(t, true, &ds.GetNanoMDMUserEnrollmentFuncInvoked)
	})

	// Zero profiles to remove
	ds.ListMDMAppleProfilesToRemoveFunc = func(ctx context.Context) ([]*mobius.MDMAppleProfilePayload, error) {
		return nil, nil
	}
	ds.BulkUpsertMDMAppleHostProfilesFunc = func(ctx context.Context, payload []*mobius.MDMAppleBulkUpsertHostProfilePayload) error {
		if failedCall {
			failedCheck(payload)
			return nil
		}

		// next call will be failed call, until reset
		failedCall = true

		// first time it is called, it is to set the status to pending and all
		// host profiles have a command uuid
		cmdUUIDByProfileUUIDInstall := make(map[string]string)
		cmdUUIDByProfileUUIDRemove := make(map[string]string)
		copies := make([]*mobius.MDMAppleBulkUpsertHostProfilePayload, len(payload))
		for i, p := range payload {
			if p.OperationType == mobius.MDMOperationTypeInstall {
				existing, ok := cmdUUIDByProfileUUIDInstall[p.ProfileUUID]
				if ok {
					require.Equal(t, existing, p.CommandUUID)
				} else {
					cmdUUIDByProfileUUIDInstall[p.ProfileUUID] = p.CommandUUID
				}
			} else {
				require.Equal(t, mobius.MDMOperationTypeRemove, p.OperationType)
				existing, ok := cmdUUIDByProfileUUIDRemove[p.ProfileUUID]
				if ok {
					require.Equal(t, existing, p.CommandUUID)
				} else {
					cmdUUIDByProfileUUIDRemove[p.ProfileUUID] = p.CommandUUID
				}
			}

			// clear the command UUID (in a copy so that it does not affect the
			// pointed-to struct) from the payload for the subsequent checks
			copyp := *p
			copyp.CommandUUID = ""
			copies[i] = &copyp
		}

		require.ElementsMatch(t, []*mobius.MDMAppleBulkUpsertHostProfilePayload{
			{
				ProfileUUID:       p1,
				ProfileIdentifier: "com.add.profile",
				HostUUID:          hostUUID1,
				OperationType:     mobius.MDMOperationTypeInstall,
				Status:            &mobius.MDMDeliveryPending,
				Scope:             mobius.PayloadScopeSystem,
			},
			{
				ProfileUUID:       p2,
				ProfileIdentifier: "com.add.profile.two",
				HostUUID:          hostUUID1,
				OperationType:     mobius.MDMOperationTypeInstall,
				Status:            &mobius.MDMDeliveryPending,
				Scope:             mobius.PayloadScopeSystem,
			},
			{
				ProfileUUID:       p2,
				ProfileIdentifier: "com.add.profile.two",
				HostUUID:          hostUUID2,
				OperationType:     mobius.MDMOperationTypeInstall,
				Status:            &mobius.MDMDeliveryPending,
				Scope:             mobius.PayloadScopeSystem,
			},
			{
				ProfileUUID:       p4,
				ProfileIdentifier: "com.add.profile.four",
				HostUUID:          hostUUID2,
				OperationType:     mobius.MDMOperationTypeInstall,
				Status:            &mobius.MDMDeliveryPending,
				Scope:             mobius.PayloadScopeSystem,
			},
			{
				ProfileUUID:       p5,
				ProfileIdentifier: "com.add.profile.five",
				HostUUID:          hostUUID1,
				OperationType:     mobius.MDMOperationTypeInstall,
				Status:            &mobius.MDMDeliveryPending,
				Scope:             mobius.PayloadScopeUser,
			},
			// This host has no user enrollment so the profile is sent to the device enrollment
			{
				ProfileUUID:       p5,
				ProfileIdentifier: "com.add.profile.five",
				HostUUID:          hostUUID2,
				OperationType:     mobius.MDMOperationTypeInstall,
				Status:            &mobius.MDMDeliveryPending,
				Scope:             mobius.PayloadScopeSystem,
			},
		}, copies)
		return nil
	}

	// Enable NDES
	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		appCfg := &mobius.AppConfig{}
		appCfg.ServerSettings.ServerURL = "https://test.example.com"
		appCfg.MDM.EnabledAndConfigured = true
		appCfg.Integrations.NDESSCEPProxy.Valid = true
		return appCfg, nil
	}
	ctx = license.NewContext(ctx, &mobius.LicenseInfo{Tier: mobius.TierPremium})
	ds.BulkUpsertMDMManagedCertificatesFunc = func(ctx context.Context, payload []*mobius.MDMManagedCertificate) error {
		assert.Empty(t, payload)
		return nil
	}

	t.Run("replace $MOBIUS_VAR_"+mobius.MobiusVarNDESSCEPProxyURL, func(t *testing.T) {
		var upsertCount int
		failedCall = false
		failedCheck = func(payload []*mobius.MDMAppleBulkUpsertHostProfilePayload) {
			upsertCount++
			if upsertCount == 1 {
				// We update the profile with a new command UUID
				assert.Len(t, payload, 1, "at upsertCount %d", upsertCount)
			} else {
				assert.Len(t, payload, 0, "at upsertCount %d", upsertCount)
			}
		}
		enqueueFailForOp = ""
		newContents := "$MOBIUS_VAR_" + mobius.MobiusVarNDESSCEPProxyURL
		originalContents1 := contents1
		originalExpectedContents1 := expectedContents1
		contents1 = []byte(newContents)
		expectedContents1 = []byte("https://test.example.com" + apple_mdm.SCEPProxyPath + url.QueryEscape(fmt.Sprintf("%s,%s,NDES", hostUUID1, p1)))
		t.Cleanup(func() {
			contents1 = originalContents1
			expectedContents1 = originalExpectedContents1
		})
		err := ReconcileAppleProfiles(ctx, ds, cmdr, kitlog.NewNopLogger())
		require.NoError(t, err)
		assert.Equal(t, 2, upsertCount)
		checkAndReset(t, true, &ds.ListMDMAppleProfilesToInstallFuncInvoked)
		checkAndReset(t, true, &ds.ListMDMAppleProfilesToRemoveFuncInvoked)
		checkAndReset(t, true, &ds.GetMDMAppleProfilesContentsFuncInvoked)
		checkAndReset(t, true, &ds.BulkUpsertMDMAppleHostProfilesFuncInvoked)
		checkAndReset(t, true, &ds.GetNanoMDMUserEnrollmentFuncInvoked)
	})

	t.Run("preprocessor fails on $MOBIUS_VAR_"+mobius.MobiusVarHostEndUserEmailIDP, func(t *testing.T) {
		var failedCount int
		failedCall = false
		failedCheck = func(payload []*mobius.MDMAppleBulkUpsertHostProfilePayload) {
			failedCount++
			require.Len(t, payload, 0)
		}
		enqueueFailForOp = ""
		newContents := "$MOBIUS_VAR_" + mobius.MobiusVarHostEndUserEmailIDP
		originalContents1 := contents1
		contents1 = []byte(newContents)
		t.Cleanup(func() {
			contents1 = originalContents1
		})
		ds.GetHostEmailsFunc = func(ctx context.Context, hostUUID string, source string) ([]string, error) {
			return nil, errors.New("GetHostEmailsFuncError")
		}
		err := ReconcileAppleProfiles(ctx, ds, cmdr, kitlog.NewNopLogger())
		assert.ErrorContains(t, err, "GetHostEmailsFuncError")
		checkAndReset(t, true, &ds.ListMDMAppleProfilesToInstallFuncInvoked)
		checkAndReset(t, true, &ds.ListMDMAppleProfilesToRemoveFuncInvoked)
		checkAndReset(t, true, &ds.GetMDMAppleProfilesContentsFuncInvoked)
		checkAndReset(t, true, &ds.BulkUpsertMDMAppleHostProfilesFuncInvoked)
		checkAndReset(t, true, &ds.GetNanoMDMUserEnrollmentFuncInvoked)
	})

	t.Run("bad $MOBIUS_VAR", func(t *testing.T) {
		var failedCount int
		failedCall = false
		var hostUUIDs []string
		failedCheck = func(payload []*mobius.MDMAppleBulkUpsertHostProfilePayload) {
			if len(payload) > 0 {
				failedCount++
			}
			for _, p := range payload {
				assert.Equal(t, mobius.MDMDeliveryFailed, *p.Status)
				assert.Contains(t, p.Detail, "MOBIUS_VAR_BOZO")
				for i, hu := range hostUUIDs {
					if hu == p.HostUUID {
						// remove element
						hostUUIDs = append(hostUUIDs[:i], hostUUIDs[i+1:]...)
						break
					}
				}
			}
		}
		enqueueFailForOp = ""

		// All profiles will have bad contents
		badContents := "bad-content: $MOBIUS_VAR_BOZO"
		originalContents1 := contents1
		originalContents2 := contents2
		originalContents4 := contents4
		originalContents5 := contents5
		contents1 = []byte(badContents)
		contents2 = []byte(badContents)
		contents4 = []byte(badContents)
		contents5 = []byte(badContents)
		t.Cleanup(func() {
			contents1 = originalContents1
			contents2 = originalContents2
			contents4 = originalContents4
			contents5 = originalContents5
		})

		profilesToInstall, _ := ds.ListMDMAppleProfilesToInstallFunc(ctx)
		hostUUIDs = make([]string, 0, len(profilesToInstall))
		for _, p := range profilesToInstall {
			hostUUIDs = append(hostUUIDs, p.HostUUID)
		}

		err := ReconcileAppleProfiles(ctx, ds, cmdr, kitlog.NewNopLogger())
		require.NoError(t, err)
		assert.Empty(t, hostUUIDs, "all host+profile combinations should be updated")
		require.Equal(t, 4, failedCount, "number of profiles with bad content")
		checkAndReset(t, true, &ds.ListMDMAppleProfilesToInstallFuncInvoked)
		checkAndReset(t, true, &ds.ListMDMAppleProfilesToRemoveFuncInvoked)
		checkAndReset(t, true, &ds.GetMDMAppleProfilesContentsFuncInvoked)
		checkAndReset(t, true, &ds.BulkUpsertMDMAppleHostProfilesFuncInvoked)
		checkAndReset(t, true, &ds.GetNanoMDMUserEnrollmentFuncInvoked)
		// Check that individual updates were not done (bulk update should be done)
		checkAndReset(t, false, &ds.UpdateOrDeleteHostMDMAppleProfileFuncInvoked)
	})
}

func TestPreprocessProfileContents(t *testing.T) {
	ctx := context.Background()
	logger := kitlog.NewNopLogger()
	appCfg := &mobius.AppConfig{}
	appCfg.ServerSettings.ServerURL = "https://test.example.com"
	appCfg.MDM.EnabledAndConfigured = true
	appCfg.Integrations.NDESSCEPProxy.Valid = true
	ds := new(mock.Store)

	// No-op
	svc := eeservice.NewSCEPConfigService(logger, nil)
	digiCertService := digicert.NewService(digicert.WithLogger(logger))
	err := preprocessProfileContents(ctx, appCfg, ds, svc, digiCertService, logger, nil, nil, nil, nil)
	require.NoError(t, err)

	hostUUID := "host-1"
	cmdUUID := "cmd-1"
	var targets map[string]*cmdTarget
	populateTargets := func() {
		targets = map[string]*cmdTarget{
			"p1": {cmdUUID: cmdUUID, profIdent: "com.add.profile", enrollmentIDs: []string{hostUUID}},
		}
	}
	hostProfilesToInstallMap := make(map[hostProfileUUID]*mobius.MDMAppleBulkUpsertHostProfilePayload, 1)
	hostProfilesToInstallMap[hostProfileUUID{HostUUID: hostUUID, ProfileUUID: "p1"}] = &mobius.MDMAppleBulkUpsertHostProfilePayload{
		ProfileUUID:       "p1",
		ProfileIdentifier: "com.add.profile",
		HostUUID:          hostUUID,
		OperationType:     mobius.MDMOperationTypeInstall,
		Status:            &mobius.MDMDeliveryPending,
		CommandUUID:       cmdUUID,
		Scope:             mobius.PayloadScopeSystem,
	}
	userEnrollmentsToHostUUIDsMap := make(map[string]string)
	populateTargets()
	profileContents := map[string]mobileconfig.Mobileconfig{
		"p1": []byte("$MOBIUS_VAR_" + mobius.MobiusVarNDESSCEPProxyURL),
	}

	var updatedPayload *mobius.MDMAppleBulkUpsertHostProfilePayload
	ds.BulkUpsertMDMAppleHostProfilesFunc = func(ctx context.Context, payload []*mobius.MDMAppleBulkUpsertHostProfilePayload) error {
		require.Len(t, payload, 1)
		updatedPayload = payload[0]
		for _, p := range payload {
			require.NotNil(t, p.Status)
			assert.Equal(t, mobius.MDMDeliveryFailed, *p.Status)
			assert.Equal(t, cmdUUID, p.CommandUUID)
			assert.Equal(t, hostUUID, p.HostUUID)
			assert.Equal(t, mobius.MDMOperationTypeInstall, p.OperationType)
			assert.Equal(t, mobius.PayloadScopeSystem, p.Scope)
		}
		return nil
	}
	// Can't use NDES SCEP proxy with free tier
	ctx = license.NewContext(ctx, &mobius.LicenseInfo{Tier: mobius.TierFree})
	err = preprocessProfileContents(ctx, appCfg, ds, svc, digiCertService, logger, targets, profileContents, hostProfilesToInstallMap, userEnrollmentsToHostUUIDsMap)
	require.NoError(t, err)
	require.NotNil(t, updatedPayload)
	assert.Contains(t, updatedPayload.Detail, "Premium license")
	assert.Empty(t, targets)

	// Can't use NDES SCEP proxy without it being configured
	ctx = license.NewContext(ctx, &mobius.LicenseInfo{Tier: mobius.TierPremium})
	appCfg.Integrations.NDESSCEPProxy.Valid = false
	updatedPayload = nil
	populateTargets()
	err = preprocessProfileContents(ctx, appCfg, ds, svc, digiCertService, logger, targets, profileContents, hostProfilesToInstallMap, userEnrollmentsToHostUUIDsMap)
	require.NoError(t, err)
	require.NotNil(t, updatedPayload)
	assert.Contains(t, updatedPayload.Detail, "not configured")
	assert.NotNil(t, updatedPayload.VariablesUpdatedAt)
	assert.Empty(t, targets)

	// Unknown variable
	profileContents = map[string]mobileconfig.Mobileconfig{
		"p1": []byte("$MOBIUS_VAR_BOZO"),
	}
	appCfg.Integrations.NDESSCEPProxy.Valid = true
	updatedPayload = nil
	populateTargets()
	err = preprocessProfileContents(ctx, appCfg, ds, svc, digiCertService, logger, targets, profileContents, hostProfilesToInstallMap, userEnrollmentsToHostUUIDsMap)
	require.NoError(t, err)
	require.NotNil(t, updatedPayload)
	assert.Contains(t, updatedPayload.Detail, "MOBIUS_VAR_BOZO")
	assert.Empty(t, targets)

	ndesPassword := "test-password"
	ds.GetAllMDMConfigAssetsByNameFunc = func(ctx context.Context,
		assetNames []mobius.MDMAssetName, _ sqlx.QueryerContext,
	) (map[mobius.MDMAssetName]mobius.MDMConfigAsset, error) {
		return map[mobius.MDMAssetName]mobius.MDMConfigAsset{
			mobius.MDMAssetNDESPassword: {Value: []byte(ndesPassword)},
		}, nil
	}

	ds.BulkUpsertMDMAppleHostProfilesFunc = nil
	var updatedProfile *mobius.HostMDMAppleProfile
	ds.UpdateOrDeleteHostMDMAppleProfileFunc = func(ctx context.Context, profile *mobius.HostMDMAppleProfile) error {
		updatedProfile = profile
		require.NotNil(t, updatedProfile.Status)
		assert.Equal(t, mobius.MDMDeliveryFailed, *updatedProfile.Status)
		assert.Equal(t, cmdUUID, updatedProfile.CommandUUID)
		assert.Equal(t, hostUUID, updatedProfile.HostUUID)
		assert.Equal(t, mobius.MDMOperationTypeInstall, updatedProfile.OperationType)
		return nil
	}
	ds.BulkUpsertMDMManagedCertificatesFunc = func(ctx context.Context, payload []*mobius.MDMManagedCertificate) error {
		assert.Empty(t, payload)
		return nil
	}

	// Could not get NDES SCEP challenge
	profileContents = map[string]mobileconfig.Mobileconfig{
		"p1": []byte("$MOBIUS_VAR_" + mobius.MobiusVarNDESSCEPChallenge),
	}
	scepConfig := &scep_mock.SCEPConfigService{}
	scepConfig.GetNDESSCEPChallengeFunc = func(ctx context.Context, proxy mobius.NDESSCEPProxyIntegration) (string, error) {
		assert.Equal(t, ndesPassword, proxy.Password)
		return "", eeservice.NewNDESInvalidError("NDES error")
	}
	updatedProfile = nil
	populateTargets()
	ds.BulkUpsertMDMAppleHostProfilesFunc = func(ctx context.Context, payload []*mobius.MDMAppleBulkUpsertHostProfilePayload) error {
		assert.Empty(t, payload) // no profiles to update since MOBIUS VAR could not be populated
		return nil
	}
	err = preprocessProfileContents(ctx, appCfg, ds, scepConfig, digiCertService, logger, targets, profileContents, hostProfilesToInstallMap, userEnrollmentsToHostUUIDsMap)
	require.NoError(t, err)
	require.NotNil(t, updatedProfile)
	assert.Contains(t, updatedProfile.Detail, "MOBIUS_VAR_"+mobius.MobiusVarNDESSCEPChallenge)
	assert.Contains(t, updatedProfile.Detail, "update credentials")
	assert.NotNil(t, updatedProfile.VariablesUpdatedAt)
	assert.Empty(t, targets)

	// Password cache full
	scepConfig.GetNDESSCEPChallengeFunc = func(ctx context.Context, proxy mobius.NDESSCEPProxyIntegration) (string, error) {
		assert.Equal(t, ndesPassword, proxy.Password)
		return "", eeservice.NewNDESPasswordCacheFullError("NDES error")
	}
	updatedProfile = nil
	populateTargets()
	err = preprocessProfileContents(ctx, appCfg, ds, scepConfig, digiCertService, logger, targets, profileContents, hostProfilesToInstallMap, userEnrollmentsToHostUUIDsMap)
	require.NoError(t, err)
	require.NotNil(t, updatedProfile)
	assert.Contains(t, updatedProfile.Detail, "MOBIUS_VAR_"+mobius.MobiusVarNDESSCEPChallenge)
	assert.Contains(t, updatedProfile.Detail, "cached passwords")
	assert.NotNil(t, updatedProfile.VariablesUpdatedAt)
	assert.Empty(t, targets)

	// Insufficient permissions
	scepConfig.GetNDESSCEPChallengeFunc = func(ctx context.Context, proxy mobius.NDESSCEPProxyIntegration) (string, error) {
		assert.Equal(t, ndesPassword, proxy.Password)
		return "", eeservice.NewNDESInsufficientPermissionsError("NDES error")
	}
	updatedProfile = nil
	populateTargets()
	err = preprocessProfileContents(ctx, appCfg, ds, scepConfig, digiCertService, logger, targets, profileContents, hostProfilesToInstallMap, userEnrollmentsToHostUUIDsMap)
	require.NoError(t, err)
	require.NotNil(t, updatedProfile)
	assert.Contains(t, updatedProfile.Detail, "MOBIUS_VAR_"+mobius.MobiusVarNDESSCEPChallenge)
	assert.Contains(t, updatedProfile.Detail, "does not have sufficient permissions")
	assert.NotNil(t, updatedProfile.VariablesUpdatedAt)
	assert.Empty(t, targets)

	// Other NDES challenge error
	scepConfig.GetNDESSCEPChallengeFunc = func(ctx context.Context, proxy mobius.NDESSCEPProxyIntegration) (string, error) {
		assert.Equal(t, ndesPassword, proxy.Password)
		return "", errors.New("NDES error")
	}
	updatedProfile = nil
	populateTargets()
	err = preprocessProfileContents(ctx, appCfg, ds, scepConfig, digiCertService, logger, targets, profileContents, hostProfilesToInstallMap, userEnrollmentsToHostUUIDsMap)
	require.NoError(t, err)
	require.NotNil(t, updatedProfile)
	assert.Contains(t, updatedProfile.Detail, "MOBIUS_VAR_"+mobius.MobiusVarNDESSCEPChallenge)
	assert.NotContains(t, updatedProfile.Detail, "cached passwords")
	assert.NotContains(t, updatedProfile.Detail, "update credentials")
	assert.NotNil(t, updatedProfile.VariablesUpdatedAt)
	assert.Empty(t, targets)

	// NDES challenge
	challenge := "ndes-challenge"
	scepConfig.GetNDESSCEPChallengeFunc = func(ctx context.Context, proxy mobius.NDESSCEPProxyIntegration) (string, error) {
		assert.Equal(t, ndesPassword, proxy.Password)
		return challenge, nil
	}
	updatedProfile = nil
	ds.BulkUpsertMDMAppleHostProfilesFunc = func(ctx context.Context, payload []*mobius.MDMAppleBulkUpsertHostProfilePayload) error {
		for _, p := range payload {
			assert.NotEqual(t, cmdUUID, p.CommandUUID)
		}
		return nil
	}
	populateTargets()
	ds.BulkUpsertMDMManagedCertificatesFunc = func(ctx context.Context, payload []*mobius.MDMManagedCertificate) error {
		require.Len(t, payload, 1)
		assert.NotNil(t, payload[0].ChallengeRetrievedAt)
		return nil
	}
	err = preprocessProfileContents(ctx, appCfg, ds, scepConfig, digiCertService, logger, targets, profileContents, hostProfilesToInstallMap, userEnrollmentsToHostUUIDsMap)
	require.NoError(t, err)
	assert.Nil(t, updatedProfile)
	require.NotEmpty(t, targets)
	assert.Len(t, targets, 1)
	for profUUID, target := range targets {
		assert.NotEqual(t, profUUID, "p1") // new temporary UUID generated for specific host
		assert.NotEqual(t, cmdUUID, target.cmdUUID)
		assert.Equal(t, []string{hostUUID}, target.enrollmentIDs)
		assert.Equal(t, challenge, string(profileContents[profUUID]))
	}

	// NDES SCEP proxy URL
	profileContents = map[string]mobileconfig.Mobileconfig{
		"p1": []byte("$MOBIUS_VAR_" + mobius.MobiusVarNDESSCEPProxyURL),
	}
	expectedURL := "https://test.example.com" + apple_mdm.SCEPProxyPath + url.QueryEscape(fmt.Sprintf("%s,%s,NDES", hostUUID, "p1"))
	updatedProfile = nil
	populateTargets()
	ds.BulkUpsertMDMManagedCertificatesFunc = func(ctx context.Context, payload []*mobius.MDMManagedCertificate) error {
		assert.Empty(t, payload)
		return nil
	}
	err = preprocessProfileContents(ctx, appCfg, ds, scepConfig, digiCertService, logger, targets, profileContents, hostProfilesToInstallMap, userEnrollmentsToHostUUIDsMap)
	require.NoError(t, err)
	assert.Nil(t, updatedProfile)
	require.NotEmpty(t, targets)
	assert.Len(t, targets, 1)
	for profUUID, target := range targets {
		assert.NotEqual(t, profUUID, "p1") // new temporary UUID generated for specific host
		assert.NotEqual(t, cmdUUID, target.cmdUUID)
		assert.Equal(t, []string{hostUUID}, target.enrollmentIDs)
		assert.Equal(t, expectedURL, string(profileContents[profUUID]))
	}

	// No IdP email found
	ds.GetHostEmailsFunc = func(ctx context.Context, hostUUID string, source string) ([]string, error) {
		return nil, nil
	}
	profileContents = map[string]mobileconfig.Mobileconfig{
		"p1": []byte("$MOBIUS_VAR_" + mobius.MobiusVarHostEndUserEmailIDP),
	}
	updatedProfile = nil
	populateTargets()
	err = preprocessProfileContents(ctx, appCfg, ds, scepConfig, digiCertService, logger, targets, profileContents, hostProfilesToInstallMap, userEnrollmentsToHostUUIDsMap)
	require.NoError(t, err)
	require.NotNil(t, updatedProfile)
	assert.Contains(t, updatedProfile.Detail, "MOBIUS_VAR_"+mobius.MobiusVarHostEndUserEmailIDP)
	assert.Contains(t, updatedProfile.Detail, "no IdP email")
	assert.Empty(t, targets)

	// IdP email found
	email := "user@example.com"
	ds.GetHostEmailsFunc = func(ctx context.Context, hostUUID string, source string) ([]string, error) {
		return []string{email}, nil
	}
	updatedProfile = nil
	populateTargets()
	err = preprocessProfileContents(ctx, appCfg, ds, scepConfig, digiCertService, logger, targets, profileContents, hostProfilesToInstallMap, userEnrollmentsToHostUUIDsMap)
	require.NoError(t, err)
	assert.Nil(t, updatedProfile)
	require.NotEmpty(t, targets)
	assert.Len(t, targets, 1)
	for profUUID, target := range targets {
		assert.NotEqual(t, profUUID, "p1") // new temporary UUID generated for specific host
		assert.NotEqual(t, cmdUUID, target.cmdUUID)
		assert.Equal(t, []string{hostUUID}, target.enrollmentIDs)
		assert.Equal(t, email, string(profileContents[profUUID]))
	}

	// Hardware serial
	ds.ListHostsLiteByUUIDsFunc = func(ctx context.Context, _ mobius.TeamFilter, uuids []string) ([]*mobius.Host, error) {
		assert.Equal(t, []string{hostUUID}, uuids)
		return []*mobius.Host{
			{HardwareSerial: "serial1"},
		}, nil
	}
	profileContents = map[string]mobileconfig.Mobileconfig{
		"p1": []byte("$MOBIUS_VAR_" + mobius.MobiusVarHostHardwareSerial),
	}
	updatedProfile = nil
	populateTargets()
	err = preprocessProfileContents(ctx, appCfg, ds, scepConfig, digiCertService, logger, targets, profileContents, hostProfilesToInstallMap, userEnrollmentsToHostUUIDsMap)
	require.NoError(t, err)
	assert.Nil(t, updatedProfile)
	require.NotEmpty(t, targets)
	assert.Len(t, targets, 1)
	for profUUID, target := range targets {
		assert.NotEqual(t, profUUID, "p1") // new temporary UUID generated for specific host
		assert.NotEqual(t, cmdUUID, target.cmdUUID)
		assert.Equal(t, []string{hostUUID}, target.enrollmentIDs)
		assert.Equal(t, "serial1", string(profileContents[profUUID]))
	}

	// Hardware serial fail
	ds.ListHostsLiteByUUIDsFunc = func(ctx context.Context, _ mobius.TeamFilter, uuids []string) ([]*mobius.Host, error) {
		assert.Equal(t, []string{hostUUID}, uuids)
		return nil, nil
	}
	updatedProfile = nil
	populateTargets()
	err = preprocessProfileContents(ctx, appCfg, ds, scepConfig, digiCertService, logger, targets, profileContents, hostProfilesToInstallMap, userEnrollmentsToHostUUIDsMap)
	require.NoError(t, err)
	require.NotNil(t, updatedProfile)
	assert.Contains(t, updatedProfile.Detail, "Unexpected number of hosts (0) for UUID")
	assert.Empty(t, targets)

	// multiple profiles, multiple hosts
	populateTargets = func() {
		targets = map[string]*cmdTarget{
			"p1": {cmdUUID: cmdUUID, profIdent: "com.add.profile", enrollmentIDs: []string{hostUUID, "host-2"}},  // fails
			"p2": {cmdUUID: cmdUUID, profIdent: "com.add.profile2", enrollmentIDs: []string{hostUUID, "host-3"}}, // works
			"p3": {cmdUUID: cmdUUID, profIdent: "com.add.profile3", enrollmentIDs: []string{hostUUID, "host-4"}}, // no variables
		}
	}
	populateTargets()
	appCfg.Integrations.NDESSCEPProxy.Valid = false // NDES will fail
	profileContents = map[string]mobileconfig.Mobileconfig{
		"p1": []byte("$MOBIUS_VAR_" + mobius.MobiusVarNDESSCEPProxyURL),
		"p2": []byte("$MOBIUS_VAR_" + mobius.MobiusVarHostEndUserEmailIDP),
		"p3": []byte("no variables"),
	}
	addProfileToInstall := func(hostUUID, profileUUID, profileIdentifier string) {
		hostProfilesToInstallMap[hostProfileUUID{
			HostUUID:    hostUUID,
			ProfileUUID: profileUUID,
		}] = &mobius.MDMAppleBulkUpsertHostProfilePayload{
			ProfileUUID:       profileUUID,
			ProfileIdentifier: profileIdentifier,
			HostUUID:          hostUUID,
			OperationType:     mobius.MDMOperationTypeInstall,
			Status:            &mobius.MDMDeliveryPending,
			CommandUUID:       cmdUUID,
			Scope:             mobius.PayloadScopeSystem,
		}
	}
	addProfileToInstall(hostUUID, "p1", "com.add.profile")
	addProfileToInstall("host-2", "p1", "com.add.profile")
	addProfileToInstall(hostUUID, "p2", "com.add.profile2")
	addProfileToInstall("host-3", "p2", "com.add.profile2")
	addProfileToInstall(hostUUID, "p3", "com.add.profile3")
	addProfileToInstall("host-4", "p3", "com.add.profile3")
	expectedHostsToFail := []string{hostUUID, "host-2", "host-3"}
	ds.UpdateOrDeleteHostMDMAppleProfileFunc = func(ctx context.Context, profile *mobius.HostMDMAppleProfile) error {
		updatedProfile = profile
		require.NotNil(t, updatedProfile.Status)
		assert.Equal(t, mobius.MDMDeliveryFailed, *updatedProfile.Status)
		assert.NotEqual(t, cmdUUID, updatedProfile.CommandUUID)
		assert.Contains(t, expectedHostsToFail, updatedProfile.HostUUID)
		assert.Equal(t, mobius.MDMOperationTypeInstall, updatedProfile.OperationType)
		return nil
	}
	ds.BulkUpsertMDMAppleHostProfilesFunc = func(ctx context.Context, payload []*mobius.MDMAppleBulkUpsertHostProfilePayload) error {
		for _, p := range payload {
			require.NotNil(t, p.Status)
			if mobius.MDMDeliveryFailed == *p.Status {
				assert.Equal(t, cmdUUID, p.CommandUUID)
			} else {
				assert.NotEqual(t, cmdUUID, p.CommandUUID)
			}
			assert.Equal(t, mobius.MDMOperationTypeInstall, p.OperationType)
		}
		return nil
	}
	err = preprocessProfileContents(ctx, appCfg, ds, scepConfig, digiCertService, logger, targets, profileContents, hostProfilesToInstallMap, userEnrollmentsToHostUUIDsMap)
	require.NoError(t, err)
	require.NotEmpty(t, targets)
	assert.Len(t, targets, 3)
	assert.Nil(t, targets["p1"])    // error
	assert.Nil(t, targets["p2"])    // renamed
	assert.NotNil(t, targets["p3"]) // normal, no variables
	for profUUID, target := range targets {
		assert.Contains(t, [][]string{{hostUUID}, {"host-3"}, {hostUUID, "host-4"}}, target.enrollmentIDs)
		if profUUID == "p3" {
			assert.Equal(t, cmdUUID, target.cmdUUID)
		} else {
			assert.NotEqual(t, cmdUUID, target.cmdUUID)
		}
		assert.Contains(t, []string{email, "no variables"}, string(profileContents[profUUID]))
	}
}

func TestAppleMDMFileVaultEscrowFunctions(t *testing.T) {
	svc := Service{}

	err := svc.MDMAppleEnableFileVaultAndEscrow(context.Background(), ptr.Uint(1))
	require.ErrorIs(t, mobius.ErrMissingLicense, err)

	err = svc.MDMAppleDisableFileVaultAndEscrow(context.Background(), ptr.Uint(1))
	require.ErrorIs(t, mobius.ErrMissingLicense, err)
}

func TestGenerateEnrollmentProfileMobileConfig(t *testing.T) {
	// SCEP challenge should be escaped for XML
	b, err := apple_mdm.GenerateEnrollmentProfileMobileconfig("foo", "https://example.com", "foo&bar", "topic")
	require.NoError(t, err)
	require.Contains(t, string(b), "foo&amp;bar")
}

func TestEnsureMobiusdConfig(t *testing.T) {
	testError := errors.New("test error")
	testURL := "https://example.com"
	testTeamName := "test-team"
	logger := kitlog.NewNopLogger()
	mdmConfig := config.MDMConfig{
		AppleSCEPCert: "./testdata/server.pem",
		AppleSCEPKey:  "./testdata/server.key",
	}
	signingCert, _, _, err := mdmConfig.AppleSCEP()
	require.NoError(t, err)

	t.Run("no enroll secret found", func(t *testing.T) {
		ctx := context.Background()
		ds := new(mock.Store)

		ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
			return &mobius.AppConfig{}, nil
		}
		ds.AggregateEnrollSecretPerTeamFunc = func(ctx context.Context) ([]*mobius.EnrollSecret, error) {
			return []*mobius.EnrollSecret{}, nil
		}
		ds.BulkUpsertMDMAppleConfigProfilesFunc = func(ctx context.Context, ps []*mobius.MDMAppleConfigProfile) error {
			require.Empty(t, ps)
			return nil
		}
		err := ensureMobiusProfiles(ctx, ds, logger, signingCert.Certificate[0])
		require.NoError(t, err)
		require.True(t, ds.BulkUpsertMDMAppleConfigProfilesFuncInvoked)
		require.True(t, ds.AggregateEnrollSecretPerTeamFuncInvoked)
		require.True(t, ds.AppConfigFuncInvoked)
	})

	t.Run("all enroll secrets empty", func(t *testing.T) {
		ctx := context.Background()
		ds := new(mock.Store)
		secrets := []*mobius.EnrollSecret{
			{Secret: "", TeamID: nil},
			{Secret: "", TeamID: ptr.Uint(1)},
			{Secret: "", TeamID: ptr.Uint(2)},
		}
		ds.AggregateEnrollSecretPerTeamFunc = func(ctx context.Context) ([]*mobius.EnrollSecret, error) {
			return secrets, nil
		}
		ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
			return &mobius.AppConfig{}, nil
		}
		ds.BulkUpsertMDMAppleConfigProfilesFunc = func(ctx context.Context, ps []*mobius.MDMAppleConfigProfile) error {
			require.Empty(t, ps)
			return nil
		}
		err := ensureMobiusProfiles(ctx, ds, logger, signingCert.Certificate[0])
		require.NoError(t, err)
		require.True(t, ds.BulkUpsertMDMAppleConfigProfilesFuncInvoked)
		require.True(t, ds.AggregateEnrollSecretPerTeamFuncInvoked)
		require.True(t, ds.AppConfigFuncInvoked)
	})

	t.Run("uses the enroll secret of each team if available", func(t *testing.T) {
		ctx := context.Background()
		ds := new(mock.Store)
		secrets := []*mobius.EnrollSecret{
			{Secret: "global", TeamID: nil},
			{Secret: "team-1", TeamID: ptr.Uint(1)},
			{Secret: "team-2", TeamID: ptr.Uint(2)},
		}
		ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
			appCfg := &mobius.AppConfig{}
			appCfg.ServerSettings.ServerURL = testURL
			appCfg.MDM.DeprecatedAppleBMDefaultTeam = testTeamName
			return appCfg, nil
		}
		ds.AggregateEnrollSecretPerTeamFunc = func(ctx context.Context) ([]*mobius.EnrollSecret, error) {
			return secrets, nil
		}
		ds.BulkUpsertMDMAppleConfigProfilesFunc = func(ctx context.Context, ps []*mobius.MDMAppleConfigProfile) error {
			// mobiusdaemon + CA profiles
			require.Len(t, ps, len(secrets)*2)
			var mobiusdaemon, mobiusCA []*mobius.MDMAppleConfigProfile
			for _, p := range ps {
				switch p.Identifier {
				case mobileconfig.MobiusdConfigPayloadIdentifier:
					mobiusdaemon = append(mobiusdaemon, p)
				case mobileconfig.MobiusCARootConfigPayloadIdentifier:
					mobiusCA = append(mobiusCA, p)
				}
			}
			require.Len(t, mobiusdaemon, 3)
			require.Len(t, mobiusCA, 3)

			for i, p := range mobiusdaemon {
				require.Contains(t, string(p.Mobileconfig), testURL)
				require.Contains(t, string(p.Mobileconfig), secrets[i].Secret)
			}
			return nil
		}

		err := ensureMobiusProfiles(ctx, ds, logger, signingCert.Certificate[0])
		require.NoError(t, err)
		require.True(t, ds.AggregateEnrollSecretPerTeamFuncInvoked)
		require.True(t, ds.BulkUpsertMDMAppleConfigProfilesFuncInvoked)
	})

	t.Run("if the team doesn't have an enroll secret, fallback to no team", func(t *testing.T) {
		ctx := context.Background()
		ds := new(mock.Store)
		secrets := []*mobius.EnrollSecret{
			{Secret: "global", TeamID: nil},
			{Secret: "", TeamID: ptr.Uint(1)},
		}
		ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
			appCfg := &mobius.AppConfig{}
			appCfg.ServerSettings.ServerURL = testURL
			appCfg.MDM.DeprecatedAppleBMDefaultTeam = testTeamName
			return appCfg, nil
		}
		ds.AggregateEnrollSecretPerTeamFunc = func(ctx context.Context) ([]*mobius.EnrollSecret, error) {
			return secrets, nil
		}
		ds.BulkUpsertMDMAppleConfigProfilesFunc = func(ctx context.Context, ps []*mobius.MDMAppleConfigProfile) error {
			// mobiusdaemon + CA profiles
			require.Len(t, ps, len(secrets)*2)
			var mobiusdaemon, mobiusCA []*mobius.MDMAppleConfigProfile
			for _, p := range ps {
				switch p.Identifier {
				case mobileconfig.MobiusdConfigPayloadIdentifier:
					mobiusdaemon = append(mobiusdaemon, p)
				case mobileconfig.MobiusCARootConfigPayloadIdentifier:
					mobiusCA = append(mobiusCA, p)
				}
			}
			require.Len(t, mobiusdaemon, 2)
			require.Len(t, mobiusCA, 2)

			for i, p := range mobiusdaemon {
				require.Contains(t, string(p.Mobileconfig), testURL)
				require.Contains(t, string(p.Mobileconfig), secrets[i].Secret)
			}
			return nil
		}
		err := ensureMobiusProfiles(ctx, ds, logger, signingCert.Certificate[0])
		require.NoError(t, err)
		require.True(t, ds.AppConfigFuncInvoked)
		require.True(t, ds.AggregateEnrollSecretPerTeamFuncInvoked)
		require.True(t, ds.BulkUpsertMDMAppleConfigProfilesFuncInvoked)
	})

	t.Run("returns an error if there's a problem retrieving AppConfig", func(t *testing.T) {
		ctx := context.Background()
		ds := new(mock.Store)
		ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
			return nil, testError
		}
		err := ensureMobiusProfiles(ctx, ds, logger, signingCert.Certificate[0])
		require.ErrorIs(t, err, testError)
	})

	t.Run("returns an error if there's a problem retrieving secrets", func(t *testing.T) {
		ctx := context.Background()
		ds := new(mock.Store)
		ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
			return &mobius.AppConfig{}, nil
		}
		ds.AggregateEnrollSecretPerTeamFunc = func(ctx context.Context) ([]*mobius.EnrollSecret, error) {
			return nil, testError
		}
		err := ensureMobiusProfiles(ctx, ds, logger, signingCert.Certificate[0])
		require.ErrorIs(t, err, testError)
	})

	t.Run("returns an error if there's a problem upserting profiles", func(t *testing.T) {
		ctx := context.Background()
		ds := new(mock.Store)
		secrets := []*mobius.EnrollSecret{
			{Secret: "global", TeamID: nil},
			{Secret: "team-1", TeamID: ptr.Uint(1)},
		}
		ds.AggregateEnrollSecretPerTeamFunc = func(ctx context.Context) ([]*mobius.EnrollSecret, error) {
			return secrets, nil
		}
		ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
			return &mobius.AppConfig{}, nil
		}
		ds.BulkUpsertMDMAppleConfigProfilesFunc = func(ctx context.Context, p []*mobius.MDMAppleConfigProfile) error {
			return testError
		}
		err := ensureMobiusProfiles(ctx, ds, logger, signingCert.Certificate[0])
		require.ErrorIs(t, err, testError)
		require.True(t, ds.AppConfigFuncInvoked)
		require.True(t, ds.AggregateEnrollSecretPerTeamFuncInvoked)
		require.True(t, ds.BulkUpsertMDMAppleConfigProfilesFuncInvoked)
	})
}

func TestMDMAppleSetupAssistant(t *testing.T) {
	svc, ctx, ds := setupAppleMDMService(t, &mobius.LicenseInfo{Tier: mobius.TierPremium})

	ds.NewActivityFunc = func(
		ctx context.Context, user *mobius.User, activity mobius.ActivityDetails, details []byte, createdAt time.Time,
	) error {
		return nil
	}
	ds.NewJobFunc = func(ctx context.Context, j *mobius.Job) (*mobius.Job, error) {
		return j, nil
	}
	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		return &mobius.AppConfig{}, nil
	}
	ds.GetMDMAppleSetupAssistantFunc = func(ctx context.Context, teamID *uint) (*mobius.MDMAppleSetupAssistant, error) {
		return &mobius.MDMAppleSetupAssistant{}, nil
	}
	ds.SetOrUpdateMDMAppleSetupAssistantFunc = func(ctx context.Context, asst *mobius.MDMAppleSetupAssistant) (*mobius.MDMAppleSetupAssistant, error) {
		return asst, nil
	}
	ds.DeleteMDMAppleSetupAssistantFunc = func(ctx context.Context, teamID *uint) error {
		return nil
	}
	ds.TeamFunc = func(ctx context.Context, id uint) (*mobius.Team, error) {
		return &mobius.Team{ID: id}, nil
	}
	ds.GetMDMAppleEnrollmentProfileByTypeFunc = func(ctx context.Context, typ mobius.MDMAppleEnrollmentType) (*mobius.MDMAppleEnrollmentProfile, error) {
		return &mobius.MDMAppleEnrollmentProfile{Token: "foobar"}, nil
	}
	ds.CountABMTokensWithTermsExpiredFunc = func(ctx context.Context) (int, error) {
		return 0, nil
	}

	testCases := []struct {
		name            string
		user            *mobius.User
		teamID          *uint
		shouldFailRead  bool
		shouldFailWrite bool
	}{
		{"no role no team", test.UserNoRoles, nil, true, true},
		{"no role team", test.UserNoRoles, ptr.Uint(1), true, true},
		{"global admin no team", test.UserAdmin, nil, false, false},
		{"global admin team", test.UserAdmin, ptr.Uint(1), false, false},
		{"global maintainer no team", test.UserMaintainer, nil, false, false},
		{"global maintainer team", test.UserMaintainer, ptr.Uint(1), false, false},
		{"global observer no team", test.UserObserver, nil, true, true},
		{"global observer team", test.UserObserver, ptr.Uint(1), true, true},
		{"global observer+ no team", test.UserObserverPlus, nil, true, true},
		{"global observer+ team", test.UserObserverPlus, ptr.Uint(1), true, true},
		{"global gitops no team", test.UserGitOps, nil, true, false},
		{"global gitops team", test.UserGitOps, ptr.Uint(1), true, false},
		{"team admin no team", test.UserTeamAdminTeam1, nil, true, true},
		{"team admin team", test.UserTeamAdminTeam1, ptr.Uint(1), false, false},
		{"team admin other team", test.UserTeamAdminTeam2, ptr.Uint(1), true, true},
		{"team maintainer no team", test.UserTeamMaintainerTeam1, nil, true, true},
		{"team maintainer team", test.UserTeamMaintainerTeam1, ptr.Uint(1), false, false},
		{"team maintainer other team", test.UserTeamMaintainerTeam2, ptr.Uint(1), true, true},
		{"team observer no team", test.UserTeamObserverTeam1, nil, true, true},
		{"team observer team", test.UserTeamObserverTeam1, ptr.Uint(1), true, true},
		{"team observer other team", test.UserTeamObserverTeam2, ptr.Uint(1), true, true},
		{"team observer+ no team", test.UserTeamObserverPlusTeam1, nil, true, true},
		{"team observer+ team", test.UserTeamObserverPlusTeam1, ptr.Uint(1), true, true},
		{"team observer+ other team", test.UserTeamObserverPlusTeam2, ptr.Uint(1), true, true},
		{"team gitops no team", test.UserTeamGitOpsTeam1, nil, true, true},
		{"team gitops team", test.UserTeamGitOpsTeam1, ptr.Uint(1), true, false},
		{"team gitops other team", test.UserTeamGitOpsTeam2, ptr.Uint(1), true, true},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			// prepare the context with the user and license
			ctx := viewer.NewContext(ctx, viewer.Viewer{User: tt.user})

			_, err := svc.GetMDMAppleSetupAssistant(ctx, tt.teamID)
			checkAuthErr(t, tt.shouldFailRead, err)

			_, err = svc.SetOrUpdateMDMAppleSetupAssistant(ctx, &mobius.MDMAppleSetupAssistant{
				Name:    "test",
				Profile: json.RawMessage("{}"),
				TeamID:  tt.teamID,
			})
			checkAuthErr(t, tt.shouldFailWrite, err)

			err = svc.DeleteMDMAppleSetupAssistant(ctx, tt.teamID)
			checkAuthErr(t, tt.shouldFailWrite, err)
		})
	}
}

func TestMDMApplePreassignEndpoints(t *testing.T) {
	svc, ctx, _ := setupAppleMDMService(t, &mobius.LicenseInfo{Tier: mobius.TierPremium})

	checkAuthErr := func(t *testing.T, err error, shouldFailWithAuth bool) {
		t.Helper()

		if shouldFailWithAuth {
			require.Error(t, err)
			require.Contains(t, err.Error(), authz.ForbiddenErrorMessage)
		} else {
			require.NoError(t, err)
		}
	}

	testCases := []struct {
		name       string
		user       *mobius.User
		shouldFail bool
	}{
		{"no role", test.UserNoRoles, true},
		{"global admin", test.UserAdmin, false},
		{"global maintainer", test.UserMaintainer, true},
		{"global observer", test.UserObserver, true},
		{"global observer+", test.UserObserverPlus, true},
		{"global gitops", test.UserGitOps, false},
		{"team admin", test.UserTeamAdminTeam1, true},
		{"team maintainer", test.UserTeamMaintainerTeam1, true},
		{"team observer", test.UserTeamObserverTeam1, true},
		{"team observer+", test.UserTeamObserverPlusTeam1, true},
		{"team gitops", test.UserTeamGitOpsTeam1, true},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			// prepare the context with the user
			ctx := viewer.NewContext(ctx, viewer.Viewer{User: tt.user})

			err := svc.MDMApplePreassignProfile(ctx, mobius.MDMApplePreassignProfilePayload{
				ExternalHostIdentifier: "test",
				HostUUID:               "test",
				Profile:                mobileconfigForTest("N1", "I1"),
			})
			checkAuthErr(t, err, tt.shouldFail)

			err = svc.MDMAppleMatchPreassignment(ctx, "test")
			checkAuthErr(t, err, tt.shouldFail)
		})
	}
}

// Helper for creating scoped mobileconfigs. scope is optional and if set to nil is not included in
// the mobileconfig so that default behavior is used.
func scopedMobileconfigForTest(name, identifier string, scope *mobius.PayloadScope, vars ...string) []byte {
	var varsStr strings.Builder
	for i, v := range vars {
		if !strings.HasPrefix(v, "MOBIUS_VAR_") {
			v = "MOBIUS_VAR_" + v
		}
		varsStr.WriteString(fmt.Sprintf("<key>Var %d</key><string>$%s</string>", i, v))
	}
	scopeEntry := ""
	if scope != nil {
		scopeEntry = fmt.Sprintf(`\n<key>PayloadScope</key>\n<string>%s</string>`, string(*scope))
	}

	return []byte(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array/>
	<key>PayloadDisplayName</key>
	<string>%s</string>
	<key>PayloadIdentifier</key>
	<string>%s</string>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadUUID</key>
	<string>%s</string>%s
	<key>PayloadVersion</key>
	<integer>1</integer>
	%s
</dict>
</plist>
`, name, identifier, uuid.New().String(), scopeEntry, varsStr.String()))
}

func mobileconfigForTest(name, identifier string, vars ...string) []byte {
	return scopedMobileconfigForTest(name, identifier, nil, vars...)
}

func declBytesForTest(identifier string, payloadContent string) []byte {
	tmpl := `{
		"Type": "com.apple.configuration.decl%s",
		"Identifier": "com.mobius.config%s",
		"Payload": {
			"ServiceType": "com.apple.service%s"
		}
	}`

	declBytes := []byte(fmt.Sprintf(tmpl, identifier, identifier, payloadContent))
	return declBytes
}

func mobileconfigForTestWithContent(outerName, outerIdentifier, innerIdentifier, innerType, innerName string) []byte {
	if innerName == "" {
		innerName = outerName + ".inner"
	}

	return []byte(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array>
          <dict>
            <key>PayloadDisplayName</key>
            <string>%s</string>
            <key>PayloadIdentifier</key>
            <string>%s</string>
            <key>PayloadType</key>
            <string>%s</string>
            <key>PayloadUUID</key>
            <string>3548D750-6357-4910-8DEA-D80ADCE2C787</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>ShowRecoveryKey</key>
            <false/>
          </dict>
	</array>
	<key>PayloadDisplayName</key>
	<string>%s</string>
	<key>PayloadIdentifier</key>
	<string>%s</string>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadUUID</key>
	<string>%s</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
</dict>
</plist>
`, innerName, innerIdentifier, innerType, outerName, outerIdentifier, uuid.New().String()))
}

func generateCertWithAPNsTopic() ([]byte, []byte, error) {
	// generate a new private key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	// set up the OID for UID
	oidUID := asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 1}

	// set up a certificate template with the required UID in the Subject
	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			ExtraNames: []pkix.AttributeTypeAndValue{
				{
					Type:  oidUID,
					Value: "com.apple.mgmt.Example",
				},
			},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// create a self-signed certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	// encode to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return certPEM, keyPEM, nil
}

func setupTest(t *testing.T) (context.Context, kitlog.Logger, *mock.Store, *config.MobiusConfig, *mdmmock.MDMAppleStore, *apple_mdm.MDMAppleCommander) {
	ctx := context.Background()
	logger := kitlog.NewNopLogger()
	cfg := config.TestConfig()
	ds := new(mock.Store)
	mdmStorage := &mdmmock.MDMAppleStore{}
	pushFactory, _ := newMockAPNSPushProviderFactory()
	pusher := nanomdm_pushsvc.New(
		mdmStorage,
		mdmStorage,
		pushFactory,
		stdlogfmt.New(),
	)
	mdmConfig := config.MDMConfig{
		AppleSCEPCert: "./testdata/server.pem",
		AppleSCEPKey:  "./testdata/server.key",
	}
	apnsCert, apnsKey, err := mysql.GenerateTestCertBytes(mdmtesting.NewTestMDMAppleCertTemplate())
	require.NoError(t, err)
	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		appCfg := &mobius.AppConfig{}
		appCfg.MDM.EnabledAndConfigured = true
		return appCfg, nil
	}

	_, pemCert, pemKey, err := mdmConfig.AppleSCEP()
	require.NoError(t, err)
	ds.GetAllMDMConfigAssetsByNameFunc = func(ctx context.Context, assetNames []mobius.MDMAssetName,
		_ sqlx.QueryerContext,
	) (map[mobius.MDMAssetName]mobius.MDMConfigAsset, error) {
		return map[mobius.MDMAssetName]mobius.MDMConfigAsset{
			mobius.MDMAssetCACert:   {Value: pemCert},
			mobius.MDMAssetCAKey:    {Value: pemKey},
			mobius.MDMAssetAPNSKey:  {Value: apnsKey},
			mobius.MDMAssetAPNSCert: {Value: apnsCert},
		}, nil
	}
	mdmStorage.GetAllMDMConfigAssetsByNameFunc = func(ctx context.Context, assetNames []mobius.MDMAssetName,
		_ sqlx.QueryerContext,
	) (map[mobius.MDMAssetName]mobius.MDMConfigAsset, error) {
		return map[mobius.MDMAssetName]mobius.MDMConfigAsset{
			mobius.MDMAssetCACert:   {Value: pemCert},
			mobius.MDMAssetCAKey:    {Value: pemKey},
			mobius.MDMAssetAPNSKey:  {Value: apnsKey},
			mobius.MDMAssetAPNSCert: {Value: apnsCert},
		}, nil
	}

	commander := apple_mdm.NewMDMAppleCommander(mdmStorage, pusher)

	return ctx, logger, ds, &cfg, mdmStorage, commander
}

func TestRenewSCEPCertificatesMDMConfigNotSet(t *testing.T) {
	ctx, logger, ds, cfg, _, commander := setupTest(t)
	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		appCfg := &mobius.AppConfig{}
		appCfg.MDM.EnabledAndConfigured = false
		return appCfg, nil
	}
	err := RenewSCEPCertificates(ctx, logger, ds, cfg, commander)
	require.NoError(t, err)
}

func TestRenewSCEPCertificatesCommanderNil(t *testing.T) {
	ctx, logger, ds, cfg, _, _ := setupTest(t)
	err := RenewSCEPCertificates(ctx, logger, ds, cfg, nil)
	require.NoError(t, err)
}

func TestRenewSCEPCertificatesBranches(t *testing.T) {
	tests := []struct {
		name               string
		customExpectations func(*testing.T, *mock.Store, *config.MobiusConfig, *mdmmock.MDMAppleStore, *apple_mdm.MDMAppleCommander)
		expectedError      bool
	}{
		{
			name: "No Certs to Renew",
			customExpectations: func(t *testing.T, ds *mock.Store, cfg *config.MobiusConfig, appleStore *mdmmock.MDMAppleStore, commander *apple_mdm.MDMAppleCommander) {
				ds.GetHostCertAssociationsToExpireFunc = func(ctx context.Context, expiryDays int, limit int) ([]mobius.SCEPIdentityAssociation, error) {
					return nil, nil
				}
			},
			expectedError: false,
		},
		{
			name: "GetHostCertAssociationsToExpire Errors",
			customExpectations: func(t *testing.T, ds *mock.Store, cfg *config.MobiusConfig, appleStore *mdmmock.MDMAppleStore, commander *apple_mdm.MDMAppleCommander) {
				ds.GetHostCertAssociationsToExpireFunc = func(ctx context.Context, expiryDays int, limit int) ([]mobius.SCEPIdentityAssociation, error) {
					return nil, errors.New("database error")
				}
			},
			expectedError: true,
		},
		{
			name: "AppConfig Errors",
			customExpectations: func(t *testing.T, ds *mock.Store, cfg *config.MobiusConfig, appleStore *mdmmock.MDMAppleStore, commander *apple_mdm.MDMAppleCommander) {
				ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
					return nil, errors.New("app config error")
				}
			},
			expectedError: true,
		},
		{
			name: "InstallProfile for hostsWithoutRefs",
			customExpectations: func(t *testing.T, ds *mock.Store, cfg *config.MobiusConfig, appleStore *mdmmock.MDMAppleStore, commander *apple_mdm.MDMAppleCommander) {
				var wantCommandUUID string
				ds.GetHostCertAssociationsToExpireFunc = func(ctx context.Context, expiryDays int, limit int) ([]mobius.SCEPIdentityAssociation, error) {
					return []mobius.SCEPIdentityAssociation{{HostUUID: "hostUUID1", EnrollReference: ""}}, nil
				}

				appleStore.EnqueueCommandFunc = func(ctx context.Context, id []string, cmd *mdm.CommandWithSubtype) (map[string]error,
					error,
				) {
					require.Equal(t, "InstallProfile", cmd.Command.Command.RequestType)
					wantCommandUUID = cmd.CommandUUID
					return map[string]error{}, nil
				}
				ds.SetCommandForPendingSCEPRenewalFunc = func(ctx context.Context, assocs []mobius.SCEPIdentityAssociation, cmdUUID string) error {
					require.Len(t, assocs, 1)
					require.Equal(t, "hostUUID1", assocs[0].HostUUID)
					require.Equal(t, cmdUUID, wantCommandUUID)
					return nil
				}

				t.Cleanup(func() {
					require.True(t, appleStore.EnqueueCommandFuncInvoked)
					require.True(t, ds.SetCommandForPendingSCEPRenewalFuncInvoked)
				})
			},
			expectedError: false,
		},
		{
			name: "InstallProfile for hostsWithoutRefs fails",
			customExpectations: func(t *testing.T, ds *mock.Store, cfg *config.MobiusConfig, appleStore *mdmmock.MDMAppleStore, commander *apple_mdm.MDMAppleCommander) {
				ds.GetHostCertAssociationsToExpireFunc = func(ctx context.Context, expiryDays int, limit int) ([]mobius.SCEPIdentityAssociation, error) {
					return []mobius.SCEPIdentityAssociation{{HostUUID: "hostUUID1", EnrollReference: ""}}, nil
				}

				appleStore.EnqueueCommandFunc = func(ctx context.Context, id []string, cmd *mdm.CommandWithSubtype) (map[string]error,
					error,
				) {
					return map[string]error{}, errors.New("foo")
				}
			},
			expectedError: true,
		},
		{
			name: "InstallProfile for hostsWithRefs",
			customExpectations: func(t *testing.T, ds *mock.Store, cfg *config.MobiusConfig, appleStore *mdmmock.MDMAppleStore, commander *apple_mdm.MDMAppleCommander) {
				var wantCommandUUID string
				ds.GetHostCertAssociationsToExpireFunc = func(ctx context.Context, expiryDays int, limit int) ([]mobius.SCEPIdentityAssociation, error) {
					return []mobius.SCEPIdentityAssociation{{HostUUID: "hostUUID2", EnrollReference: "ref1"}}, nil
				}
				appleStore.EnqueueCommandFunc = func(ctx context.Context, id []string, cmd *mdm.CommandWithSubtype) (map[string]error,
					error,
				) {
					require.Equal(t, "InstallProfile", cmd.Command.Command.RequestType)
					wantCommandUUID = cmd.CommandUUID
					return map[string]error{}, nil
				}
				ds.SetCommandForPendingSCEPRenewalFunc = func(ctx context.Context, assocs []mobius.SCEPIdentityAssociation, cmdUUID string) error {
					require.Len(t, assocs, 1)
					require.Equal(t, "hostUUID2", assocs[0].HostUUID)
					require.Equal(t, cmdUUID, wantCommandUUID)
					return nil
				}
				t.Cleanup(func() {
					require.True(t, appleStore.EnqueueCommandFuncInvoked)
					require.True(t, ds.SetCommandForPendingSCEPRenewalFuncInvoked)
				})
			},
			expectedError: false,
		},
		{
			name: "InstallProfile for hostsWithRefs fails",
			customExpectations: func(t *testing.T, ds *mock.Store, cfg *config.MobiusConfig, appleStore *mdmmock.MDMAppleStore, commander *apple_mdm.MDMAppleCommander) {
				ds.GetHostCertAssociationsToExpireFunc = func(ctx context.Context, expiryDays int, limit int) ([]mobius.SCEPIdentityAssociation, error) {
					return []mobius.SCEPIdentityAssociation{{HostUUID: "hostUUID1", EnrollReference: "ref1"}}, nil
				}

				appleStore.EnqueueCommandFunc = func(ctx context.Context, id []string, cmd *mdm.CommandWithSubtype) (map[string]error,
					error,
				) {
					return map[string]error{}, errors.New("foo")
				}
			},
			expectedError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, logger, ds, cfg, appleStorage, commander := setupTest(t)

			ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
				appCfg := &mobius.AppConfig{}
				appCfg.OrgInfo.OrgName = "fl33t"
				appCfg.ServerSettings.ServerURL = "https://foo.example.com"
				appCfg.MDM.EnabledAndConfigured = true
				return appCfg, nil
			}

			ds.GetHostCertAssociationsToExpireFunc = func(ctx context.Context, expiryDays int, limit int) ([]mobius.SCEPIdentityAssociation, error) {
				return []mobius.SCEPIdentityAssociation{}, nil
			}

			ds.SetCommandForPendingSCEPRenewalFunc = func(ctx context.Context, assocs []mobius.SCEPIdentityAssociation, cmdUUID string) error {
				return nil
			}

			appleStorage.RetrievePushInfoFunc = func(ctx context.Context, targets []string) (map[string]*mdm.Push, error) {
				pushes := make(map[string]*mdm.Push, len(targets))
				for _, uuid := range targets {
					pushes[uuid] = &mdm.Push{
						PushMagic: "magic" + uuid,
						Token:     []byte("token" + uuid),
						Topic:     "topic" + uuid,
					}
				}

				return pushes, nil
			}

			appleStorage.RetrievePushCertFunc = func(ctx context.Context, topic string) (*tls.Certificate, string, error) {
				apnsCert, apnsKey, err := mysql.GenerateTestCertBytes(mdmtesting.NewTestMDMAppleCertTemplate())
				require.NoError(t, err)
				cert, err := tls.X509KeyPair(apnsCert, apnsKey)
				return &cert, "", err
			}

			tc.customExpectations(t, ds, cfg, appleStorage, commander)

			err := RenewSCEPCertificates(ctx, logger, ds, cfg, commander)
			if tc.expectedError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestMDMCommandAndReportResultsIOSIPadOSRefetch(t *testing.T) {
	ctx := context.Background()
	hostID := uint(42)
	hostUUID := "ABC-DEF-GHI"
	commandUUID := mobius.RefetchDeviceCommandUUIDPrefix + "UUID"

	ds := new(mock.Store)
	svc := MDMAppleCheckinAndCommandService{ds: ds}

	ds.HostByIdentifierFunc = func(ctx context.Context, identifier string) (*mobius.Host, error) {
		return &mobius.Host{
			ID:   hostID,
			UUID: hostUUID,
		}, nil
	}
	ds.UpdateHostFunc = func(ctx context.Context, host *mobius.Host) error {
		require.Equal(t, "Work iPad", host.ComputerName)
		require.Equal(t, "Work iPad", host.Hostname)
		require.Equal(t, "iPadOS 17.5.1", host.OSVersion)
		require.Equal(t, "ff:ff:ff:ff:ff:ff", host.PrimaryMac)
		require.Equal(t, "iPad13,18", host.HardwareModel)
		require.WithinDuration(t, time.Now(), host.DetailUpdatedAt, 1*time.Minute)
		return nil
	}
	ds.SetOrUpdateHostDisksSpaceFunc = func(ctx context.Context, hostID uint, gigsAvailable, percentAvailable, gigsTotal float64) error {
		require.Equal(t, hostID, hostID)
		require.NotZero(t, 51, int64(gigsAvailable))
		require.NotZero(t, 79, int64(percentAvailable))
		require.NotZero(t, 64, int64(gigsTotal))
		return nil
	}
	ds.UpdateHostOperatingSystemFunc = func(ctx context.Context, hostID uint, hostOS mobius.OperatingSystem) error {
		require.Equal(t, hostID, hostID)
		require.Equal(t, "iPadOS", hostOS.Name)
		require.Equal(t, "17.5.1", hostOS.Version)
		require.Equal(t, "ipados", hostOS.Platform)
		return nil
	}
	ds.RemoveHostMDMCommandFunc = func(ctx context.Context, command mobius.HostMDMCommand) error {
		assert.Equal(t, hostID, command.HostID)
		assert.Equal(t, mobius.RefetchDeviceCommandUUIDPrefix, command.CommandType)
		return nil
	}

	_, err := svc.CommandAndReportResults(
		&mdm.Request{Context: ctx},
		&mdm.CommandResults{
			Enrollment:  mdm.Enrollment{UDID: hostUUID},
			CommandUUID: commandUUID,
			Raw: []byte(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
        <key>CommandUUID</key>
        <string>REFETCH-fd23f8ac-1c50-41c7-a5bb-f13633c9ea97</string>
        <key>QueryResponses</key>
        <dict>
                <key>AvailableDeviceCapacity</key>
                <real>51.260395520000003</real>
                <key>DeviceCapacity</key>
                <real>64</real>
                <key>DeviceName</key>
                <string>Work iPad</string>
                <key>OSVersion</key>
                <string>17.5.1</string>
                <key>ProductName</key>
                <string>iPad13,18</string>
                <key>WiFiMAC</key>
                <string>ff:ff:ff:ff:ff:ff</string>
        </dict>
        <key>Status</key>
        <string>Acknowledged</string>
        <key>UDID</key>
        <string>FFFFFFFF-FFFFFFFFFFFFFFFF</string>
</dict>
</plist>`),
		},
	)
	require.NoError(t, err)

	require.True(t, ds.UpdateHostFuncInvoked)
	require.True(t, ds.HostByIdentifierFuncInvoked)
	require.True(t, ds.SetOrUpdateHostDisksSpaceFuncInvoked)
	require.True(t, ds.UpdateHostOperatingSystemFuncInvoked)
	assert.True(t, ds.RemoveHostMDMCommandFuncInvoked)
}

func TestUnmarshalAppList(t *testing.T) {
	ctx := context.Background()
	noApps := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CommandUUID</key>
	<string>c05c1a68-4127-4fde-b0da-965cbd63f88f</string>
	<key>InstalledApplicationList</key>
	<array/>
	<key>Status</key>
	<string>Acknowledged</string>
	<key>UDID</key>
	<string>00008030-000E6D623CD2202E</string>
</dict>
</plist>`)
	software, err := unmarshalAppList(ctx, noApps, "ipados_apps")
	require.NoError(t, err)
	assert.Empty(t, software)

	apps := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CommandUUID</key>
	<string>21ed54fc-0e6d-4fe3-8c4f-feca0c548ce1</string>
	<key>InstalledApplicationList</key>
	<array>
		<dict>
			<key>Identifier</key>
			<string>com.google.ios.youtube</string>
			<key>Name</key>
			<string>YouTube</string>
			<key>ShortVersion</key>
			<string>19.29.1</string>
		</dict>
		<dict>
			<key>Identifier</key>
			<string>com.evernote.iPhone.Evernote</string>
			<key>Name</key>
			<string>Evernote</string>
			<key>Installing</key>
			<false/>
			<key>ShortVersion</key>
			<string>10.98.0</string>
		</dict>
		<dict>
			<key>Identifier</key>
			<string>com.netflix.Netflix</string>
			<key>Name</key>
			<string>Netflix</string>
			<key>ShortVersion</key>
			<string>16.41.0</string>
		</dict>
	</array>
	<key>Status</key>
	<string>Acknowledged</string>
	<key>UDID</key>
	<string>00008101-001514810EA3A01E</string>
</dict>
</plist>`)
	expectedSoftware := []mobius.Software{
		{
			Name:             "YouTube",
			Version:          "19.29.1",
			Source:           "ios_apps",
			BundleIdentifier: "com.google.ios.youtube",
		},
		{
			Name:             "Evernote",
			Version:          "10.98.0",
			Source:           "ios_apps",
			BundleIdentifier: "com.evernote.iPhone.Evernote",
			Installed:        true,
		},
		{
			Name:             "Netflix",
			Version:          "16.41.0",
			Source:           "ios_apps",
			BundleIdentifier: "com.netflix.Netflix",
		},
	}
	software, err = unmarshalAppList(ctx, apps, "ios_apps")
	require.NoError(t, err)
	assert.ElementsMatch(t, expectedSoftware, software)
}

func TestCheckMDMAppleEnrollmentWithMinimumOSVersion(t *testing.T) {
	svc, ctx, ds := setupAppleMDMService(t, &mobius.LicenseInfo{Tier: mobius.TierPremium})

	gdmf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// load the test data from the file
		b, err := os.ReadFile("../mdm/apple/gdmf/testdata/gdmf.json")
		require.NoError(t, err)
		_, err = w.Write(b)
		require.NoError(t, err)
	}))
	defer gdmf.Close()
	t.Setenv("MOBIUS_DEV_GDMF_URL", gdmf.URL)

	latestMacOSVersion := "14.6.1"
	latestMacOSBuild := "23G93"

	testCases := []struct {
		name           string
		machineInfo    *mobius.MDMAppleMachineInfo
		updateRequired *mobius.MDMAppleSoftwareUpdateRequiredDetails
		err            string
	}{
		{
			name: "OS version is greater than latest",
			machineInfo: &mobius.MDMAppleMachineInfo{
				MDMCanRequestSoftwareUpdate: true,
				Product:                     "Mac15,7",
				OSVersion:                   "14.6.2",
				SupplementalBuildVersion:    "IRRELEVANT",
				SoftwareUpdateDeviceID:      "J516sAP",
			},
			updateRequired: nil,
		},
		{
			name: "OS version is equal to latest",
			machineInfo: &mobius.MDMAppleMachineInfo{
				MDMCanRequestSoftwareUpdate: true,
				Product:                     "Mac15,7",
				OSVersion:                   latestMacOSVersion,
				SupplementalBuildVersion:    "IRRELEVANT",
				SoftwareUpdateDeviceID:      "J516sAP",
			},
			updateRequired: nil,
		},
		{
			name: "OS version is less than latest",
			machineInfo: &mobius.MDMAppleMachineInfo{
				MDMCanRequestSoftwareUpdate: true,
				Product:                     "Mac15,7",
				OSVersion:                   "14.4",
				SupplementalBuildVersion:    "IRRELEVANT",
				SoftwareUpdateDeviceID:      "J516sAP",
			},
			updateRequired: &mobius.MDMAppleSoftwareUpdateRequiredDetails{
				OSVersion:    latestMacOSVersion,
				BuildVersion: latestMacOSBuild,
			},
		},
		{
			name: "OS version is less than latest but MDM cannot request software update",
			machineInfo: &mobius.MDMAppleMachineInfo{
				MDMCanRequestSoftwareUpdate: false,
				Product:                     "Mac15,7",
				OSVersion:                   "14.4",
				SupplementalBuildVersion:    "IRRELEVANT",
				SoftwareUpdateDeviceID:      "J516sAP",
			},
			updateRequired: nil,
		},
		{
			name: "no match for software update device ID",
			machineInfo: &mobius.MDMAppleMachineInfo{
				MDMCanRequestSoftwareUpdate: true,
				Product:                     "Mac15,7",
				OSVersion:                   "14.4",
				SupplementalBuildVersion:    "IRRELEVANT",
				SoftwareUpdateDeviceID:      "INVALID",
			},
			updateRequired: nil,
			err:            "", // no error, allow enrollment to proceed without software update
		},
		{
			name:           "no machine info",
			machineInfo:    nil,
			updateRequired: nil,
			err:            "", // no error, allow enrollment to proceed without software update
		},
		{
			name: "cannot parse OS version",
			machineInfo: &mobius.MDMAppleMachineInfo{
				MDMCanRequestSoftwareUpdate: true,
				Product:                     "Mac15,7",
				OSVersion:                   "INVALID",
				SupplementalBuildVersion:    "IRRELEVANT",
				SoftwareUpdateDeviceID:      "J516sAP",
			},
			updateRequired: nil,
			err:            "", // no error, allow enrollment to proceed without software update
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			t.Run("settings minimum equal to latest", func(t *testing.T) {
				ds.GetMDMAppleOSUpdatesSettingsByHostSerialFunc = func(ctx context.Context, serial string) (*mobius.AppleOSUpdateSettings, error) {
					return &mobius.AppleOSUpdateSettings{
						MinimumVersion: optjson.SetString(latestMacOSVersion),
					}, nil
				}
				sur, err := svc.CheckMDMAppleEnrollmentWithMinimumOSVersion(ctx, tt.machineInfo)
				if tt.err != "" {
					require.Error(t, err)
					require.Contains(t, err.Error(), tt.err)
				} else {
					require.NoError(t, err)
				}
				if tt.updateRequired != nil {
					require.Equal(t, &mobius.MDMAppleSoftwareUpdateRequired{
						Code:    mobius.MDMAppleSoftwareUpdateRequiredCode,
						Details: *tt.updateRequired,
					}, sur)
				} else {
					require.Nil(t, sur)
				}
			})

			t.Run("settings minimum below latest", func(t *testing.T) {
				ds.GetMDMAppleOSUpdatesSettingsByHostSerialFunc = func(ctx context.Context, serial string) (*mobius.AppleOSUpdateSettings, error) {
					return &mobius.AppleOSUpdateSettings{
						MinimumVersion: optjson.SetString("14.5"),
					}, nil
				}
				sur, err := svc.CheckMDMAppleEnrollmentWithMinimumOSVersion(ctx, tt.machineInfo)
				if tt.err != "" {
					require.Error(t, err)
					require.Contains(t, err.Error(), tt.err)
				} else {
					require.NoError(t, err)
				}
				if tt.updateRequired != nil {
					require.Equal(t, &mobius.MDMAppleSoftwareUpdateRequired{
						Code:    mobius.MDMAppleSoftwareUpdateRequiredCode,
						Details: *tt.updateRequired,
					}, sur)
				} else {
					require.Nil(t, sur)
				}
			})

			t.Run("settings minimum above latest", func(t *testing.T) {
				// edge case, but in practice it would get treated as if minimum was equal to latest
				ds.GetMDMAppleOSUpdatesSettingsByHostSerialFunc = func(ctx context.Context, serial string) (*mobius.AppleOSUpdateSettings, error) {
					return &mobius.AppleOSUpdateSettings{
						MinimumVersion: optjson.SetString("14.7"),
					}, nil
				}
				sur, err := svc.CheckMDMAppleEnrollmentWithMinimumOSVersion(ctx, tt.machineInfo)
				if tt.err != "" {
					require.Error(t, err)
					require.Contains(t, err.Error(), tt.err)
				} else {
					require.NoError(t, err)
				}
				if tt.updateRequired != nil {
					require.Equal(t, &mobius.MDMAppleSoftwareUpdateRequired{
						Code:    mobius.MDMAppleSoftwareUpdateRequiredCode,
						Details: *tt.updateRequired,
					}, sur)
				} else {
					require.Nil(t, sur)
				}
			})

			t.Run("device above settings minimum", func(t *testing.T) {
				ds.GetMDMAppleOSUpdatesSettingsByHostSerialFunc = func(ctx context.Context, serial string) (*mobius.AppleOSUpdateSettings, error) {
					return &mobius.AppleOSUpdateSettings{
						MinimumVersion: optjson.SetString("14.1"),
					}, nil
				}
				sur, err := svc.CheckMDMAppleEnrollmentWithMinimumOSVersion(ctx, tt.machineInfo)
				if tt.err != "" {
					require.Error(t, err)
					require.Contains(t, err.Error(), tt.err)
				} else {
					require.NoError(t, err)
				}

				require.Nil(t, sur)
			})

			t.Run("minimum not set", func(t *testing.T) {
				ds.GetMDMAppleOSUpdatesSettingsByHostSerialFunc = func(ctx context.Context, serial string) (*mobius.AppleOSUpdateSettings, error) {
					return &mobius.AppleOSUpdateSettings{}, nil
				}
				sur, err := svc.CheckMDMAppleEnrollmentWithMinimumOSVersion(ctx, tt.machineInfo)
				require.NoError(t, err)
				require.Nil(t, sur)

				ds.GetMDMAppleOSUpdatesSettingsByHostSerialFunc = func(ctx context.Context, serial string) (*mobius.AppleOSUpdateSettings, error) {
					return &mobius.AppleOSUpdateSettings{
						MinimumVersion: optjson.SetString(""),
					}, nil
				}
				sur, err = svc.CheckMDMAppleEnrollmentWithMinimumOSVersion(ctx, tt.machineInfo)
				require.NoError(t, err)
				require.Nil(t, sur)
			})

			t.Run("minimum not found", func(t *testing.T) {
				ds.GetMDMAppleOSUpdatesSettingsByHostSerialFunc = func(ctx context.Context, serial string) (*mobius.AppleOSUpdateSettings, error) {
					return nil, &notFoundError{}
				}
				sur, err := svc.CheckMDMAppleEnrollmentWithMinimumOSVersion(ctx, tt.machineInfo)
				require.NoError(t, err)
				require.Nil(t, sur)
			})
		})
	}

	t.Run("gdmf server is down", func(t *testing.T) {
		gdmf.Close()

		for _, tt := range testCases {
			t.Run(tt.name, func(t *testing.T) {
				ds.GetMDMAppleOSUpdatesSettingsByHostSerialFunc = func(ctx context.Context, serial string) (*mobius.AppleOSUpdateSettings, error) {
					return &mobius.AppleOSUpdateSettings{MinimumVersion: optjson.SetString(latestMacOSVersion)}, nil
				}

				sur, err := svc.CheckMDMAppleEnrollmentWithMinimumOSVersion(ctx, tt.machineInfo)
				if tt.err != "" {
					require.Error(t, err)
					require.Contains(t, err.Error(), tt.err) // still can get errors parsing the versions from the device info header or config settings
				} else {
					require.NoError(t, err)
				}

				require.Nil(t, sur) // if gdmf server is down, we don't enforce os updates for DEP
			})
		}
	})
}

func TestPreprocessProfileContentsEndUserIDP(t *testing.T) {
	ctx := context.Background()
	logger := kitlog.NewNopLogger()
	appCfg := &mobius.AppConfig{}
	appCfg.ServerSettings.ServerURL = "https://test.example.com"
	appCfg.MDM.EnabledAndConfigured = true
	ds := new(mock.Store)

	svc := eeservice.NewSCEPConfigService(logger, nil)
	digiCertService := digicert.NewService(digicert.WithLogger(logger))

	hostUUID := "host-1"
	cmdUUID := "cmd-1"
	var targets map[string]*cmdTarget
	// this is a func to re-create it each time because calling the preprocess function modifies this
	populateTargets := func() {
		targets = map[string]*cmdTarget{
			"p1": {cmdUUID: cmdUUID, profIdent: "com.add.profile", enrollmentIDs: []string{hostUUID}},
		}
	}
	hostProfilesToInstallMap := map[hostProfileUUID]*mobius.MDMAppleBulkUpsertHostProfilePayload{
		{HostUUID: hostUUID, ProfileUUID: "p1"}: {
			ProfileUUID:       "p1",
			ProfileIdentifier: "com.add.profile",
			HostUUID:          hostUUID,
			OperationType:     mobius.MDMOperationTypeInstall,
			Status:            &mobius.MDMDeliveryPending,
			CommandUUID:       cmdUUID,
		},
	}

	userEnrollmentsToHostUUIDsMap := make(map[string]string)

	var updatedPayload *mobius.MDMAppleBulkUpsertHostProfilePayload
	var expectedStatus mobius.MDMDeliveryStatus
	ds.BulkUpsertMDMAppleHostProfilesFunc = func(ctx context.Context, payload []*mobius.MDMAppleBulkUpsertHostProfilePayload) error {
		require.Len(t, payload, 1)
		updatedPayload = payload[0]
		require.NotNil(t, updatedPayload.Status)
		assert.Equal(t, expectedStatus, *updatedPayload.Status)
		// cmdUUID was replaced by a new unique command on success
		assert.NotEqual(t, cmdUUID, updatedPayload.CommandUUID)
		assert.Equal(t, hostUUID, updatedPayload.HostUUID)
		assert.Equal(t, mobius.MDMOperationTypeInstall, updatedPayload.OperationType)
		return nil
	}
	ds.HostIDsByIdentifierFunc = func(ctx context.Context, filter mobius.TeamFilter, idents []string) ([]uint, error) {
		require.Len(t, idents, 1)
		require.Equal(t, hostUUID, idents[0])
		return []uint{1}, nil
	}
	var updatedProfile *mobius.HostMDMAppleProfile
	ds.UpdateOrDeleteHostMDMAppleProfileFunc = func(ctx context.Context, profile *mobius.HostMDMAppleProfile) error {
		updatedProfile = profile
		require.NotNil(t, profile.Status)
		assert.Equal(t, expectedStatus, *profile.Status)
		return nil
	}

	cases := []struct {
		desc           string
		profileContent string
		expectedStatus mobius.MDMDeliveryStatus
		setup          func()
		assert         func(output string)
	}{
		{
			desc:           "username only scim",
			profileContent: "$MOBIUS_VAR_" + mobius.MobiusVarHostEndUserIDPUsername,
			expectedStatus: mobius.MDMDeliveryPending,
			setup: func() {
				ds.ScimUserByHostIDFunc = func(ctx context.Context, hostID uint) (*mobius.ScimUser, error) {
					require.EqualValues(t, 1, hostID)
					return &mobius.ScimUser{UserName: "user1@example.com", Groups: []mobius.ScimUserGroup{}}, nil
				}
				ds.ListHostDeviceMappingFunc = func(ctx context.Context, id uint) ([]*mobius.HostDeviceMapping, error) {
					return nil, nil
				}
			},
			assert: func(output string) {
				assert.Empty(t, updatedPayload.Detail) // no error detail
				assert.Len(t, targets, 1)              // target is still present
				require.Equal(t, "user1@example.com", output)
			},
		},
		{
			desc:           "username local part only scim",
			profileContent: "$MOBIUS_VAR_" + mobius.MobiusVarHostEndUserIDPUsernameLocalPart,
			expectedStatus: mobius.MDMDeliveryPending,
			setup: func() {
				ds.ScimUserByHostIDFunc = func(ctx context.Context, hostID uint) (*mobius.ScimUser, error) {
					require.EqualValues(t, 1, hostID)
					return &mobius.ScimUser{UserName: "user1@example.com", Groups: []mobius.ScimUserGroup{}}, nil
				}
				ds.ListHostDeviceMappingFunc = func(ctx context.Context, id uint) ([]*mobius.HostDeviceMapping, error) {
					return nil, nil
				}
			},
			assert: func(output string) {
				assert.Empty(t, updatedPayload.Detail) // no error detail
				assert.Len(t, targets, 1)              // target is still present
				require.Equal(t, "user1", output)
			},
		},
		{
			desc:           "groups only scim",
			profileContent: "$MOBIUS_VAR_" + mobius.MobiusVarHostEndUserIDPGroups,
			expectedStatus: mobius.MDMDeliveryPending,
			setup: func() {
				ds.ScimUserByHostIDFunc = func(ctx context.Context, hostID uint) (*mobius.ScimUser, error) {
					require.EqualValues(t, 1, hostID)
					return &mobius.ScimUser{UserName: "user1@example.com", Groups: []mobius.ScimUserGroup{
						{DisplayName: "a"},
						{DisplayName: "b"},
					}}, nil
				}
				ds.ListHostDeviceMappingFunc = func(ctx context.Context, id uint) ([]*mobius.HostDeviceMapping, error) {
					return nil, nil
				}
			},
			assert: func(output string) {
				assert.Empty(t, updatedPayload.Detail) // no error detail
				assert.Len(t, targets, 1)              // target is still present
				require.Equal(t, "a,b", output)
			},
		},
		{
			desc:           "multiple times username only scim",
			profileContent: strings.Repeat("${MOBIUS_VAR_"+mobius.MobiusVarHostEndUserIDPUsername+"}", 3),
			expectedStatus: mobius.MDMDeliveryPending,
			setup: func() {
				ds.ScimUserByHostIDFunc = func(ctx context.Context, hostID uint) (*mobius.ScimUser, error) {
					require.EqualValues(t, 1, hostID)
					return &mobius.ScimUser{UserName: "user1@example.com", Groups: []mobius.ScimUserGroup{}}, nil
				}
				ds.ListHostDeviceMappingFunc = func(ctx context.Context, id uint) ([]*mobius.HostDeviceMapping, error) {
					return nil, nil
				}
			},
			assert: func(output string) {
				assert.Empty(t, updatedPayload.Detail) // no error detail
				assert.Len(t, targets, 1)              // target is still present
				require.Equal(t, "user1@example.comuser1@example.comuser1@example.com", output)
			},
		},
		{
			desc:           "all 3 vars with scim",
			profileContent: "${MOBIUS_VAR_" + mobius.MobiusVarHostEndUserIDPUsername + "}${MOBIUS_VAR_" + mobius.MobiusVarHostEndUserIDPUsernameLocalPart + "}${MOBIUS_VAR_" + mobius.MobiusVarHostEndUserIDPGroups + "}",
			expectedStatus: mobius.MDMDeliveryPending,
			setup: func() {
				ds.ScimUserByHostIDFunc = func(ctx context.Context, hostID uint) (*mobius.ScimUser, error) {
					require.EqualValues(t, 1, hostID)
					return &mobius.ScimUser{UserName: "user1@example.com", Groups: []mobius.ScimUserGroup{
						{DisplayName: "a"},
						{DisplayName: "b"},
					}}, nil
				}
				ds.ListHostDeviceMappingFunc = func(ctx context.Context, id uint) ([]*mobius.HostDeviceMapping, error) {
					return nil, nil
				}
			},
			assert: func(output string) {
				assert.Empty(t, updatedPayload.Detail) // no error detail
				assert.Len(t, targets, 1)              // target is still present
				require.Equal(t, "user1@example.comuser1a,b", output)
			},
		},
		{
			desc:           "username no scim, with idp",
			profileContent: "$MOBIUS_VAR_" + mobius.MobiusVarHostEndUserIDPUsername,
			expectedStatus: mobius.MDMDeliveryPending,
			setup: func() {
				ds.ScimUserByHostIDFunc = func(ctx context.Context, hostID uint) (*mobius.ScimUser, error) {
					return nil, newNotFoundError()
				}
				ds.ListHostDeviceMappingFunc = func(ctx context.Context, id uint) ([]*mobius.HostDeviceMapping, error) {
					return []*mobius.HostDeviceMapping{
						{Email: "idp@example.com", Source: mobius.DeviceMappingMDMIdpAccounts},
						{Email: "other@example.com", Source: mobius.DeviceMappingGoogleChromeProfiles},
					}, nil
				}
			},
			assert: func(output string) {
				assert.Empty(t, updatedPayload.Detail) // no error detail
				assert.Len(t, targets, 1)              // target is still present
				require.Equal(t, "idp@example.com", output)
			},
		},
		{
			desc:           "username scim and idp",
			profileContent: "$MOBIUS_VAR_" + mobius.MobiusVarHostEndUserIDPUsername,
			expectedStatus: mobius.MDMDeliveryPending,
			setup: func() {
				ds.ScimUserByHostIDFunc = func(ctx context.Context, hostID uint) (*mobius.ScimUser, error) {
					return &mobius.ScimUser{UserName: "user1@example.com", Groups: []mobius.ScimUserGroup{}}, nil
				}
				ds.ListHostDeviceMappingFunc = func(ctx context.Context, id uint) ([]*mobius.HostDeviceMapping, error) {
					return []*mobius.HostDeviceMapping{
						{Email: "idp@example.com", Source: mobius.DeviceMappingMDMIdpAccounts},
						{Email: "other@example.com", Source: mobius.DeviceMappingGoogleChromeProfiles},
					}, nil
				}
			},
			assert: func(output string) {
				assert.Empty(t, updatedPayload.Detail) // no error detail
				assert.Len(t, targets, 1)              // target is still present
				require.Equal(t, "user1@example.com", output)
			},
		},
		{
			desc:           "username no idp user",
			profileContent: "$MOBIUS_VAR_" + mobius.MobiusVarHostEndUserIDPUsername,
			expectedStatus: mobius.MDMDeliveryFailed,
			setup: func() {
				ds.ScimUserByHostIDFunc = func(ctx context.Context, hostID uint) (*mobius.ScimUser, error) {
					return nil, newNotFoundError()
				}
				ds.ListHostDeviceMappingFunc = func(ctx context.Context, id uint) ([]*mobius.HostDeviceMapping, error) {
					return []*mobius.HostDeviceMapping{
						{Email: "other@example.com", Source: mobius.DeviceMappingGoogleChromeProfiles},
					}, nil
				}
			},
			assert: func(output string) {
				assert.Len(t, targets, 0) // target is not present
				assert.Contains(t, updatedProfile.Detail, "There is no IdP username for this host. Mobius couldn’t populate $MOBIUS_VAR_HOST_END_USER_IDP_USERNAME.")
			},
		},
		{
			desc:           "username local part no idp user",
			profileContent: "$MOBIUS_VAR_" + mobius.MobiusVarHostEndUserIDPUsernameLocalPart,
			expectedStatus: mobius.MDMDeliveryFailed,
			setup: func() {
				ds.ScimUserByHostIDFunc = func(ctx context.Context, hostID uint) (*mobius.ScimUser, error) {
					return nil, newNotFoundError()
				}
				ds.ListHostDeviceMappingFunc = func(ctx context.Context, id uint) ([]*mobius.HostDeviceMapping, error) {
					return []*mobius.HostDeviceMapping{
						{Email: "other@example.com", Source: mobius.DeviceMappingGoogleChromeProfiles},
					}, nil
				}
			},
			assert: func(output string) {
				assert.Len(t, targets, 0) // target is not present
				assert.Contains(t, updatedProfile.Detail, "There is no IdP username for this host. Mobius couldn’t populate $MOBIUS_VAR_HOST_END_USER_IDP_USERNAME_LOCAL_PART.")
			},
		},
		{
			desc:           "groups no idp user",
			profileContent: "$MOBIUS_VAR_" + mobius.MobiusVarHostEndUserIDPGroups,
			expectedStatus: mobius.MDMDeliveryFailed,
			setup: func() {
				ds.ScimUserByHostIDFunc = func(ctx context.Context, hostID uint) (*mobius.ScimUser, error) {
					return nil, newNotFoundError()
				}
				ds.ListHostDeviceMappingFunc = func(ctx context.Context, id uint) ([]*mobius.HostDeviceMapping, error) {
					return []*mobius.HostDeviceMapping{}, nil
				}
			},
			assert: func(output string) {
				assert.Len(t, targets, 0) // target is not present
				assert.Contains(t, updatedProfile.Detail, "There is no IdP groups for this host. Mobius couldn’t populate $MOBIUS_VAR_HOST_END_USER_IDP_GROUPS.")
			},
		},
		{
			desc:           "groups with scim user but no group",
			profileContent: "$MOBIUS_VAR_" + mobius.MobiusVarHostEndUserIDPGroups,
			expectedStatus: mobius.MDMDeliveryFailed,
			setup: func() {
				ds.ScimUserByHostIDFunc = func(ctx context.Context, hostID uint) (*mobius.ScimUser, error) {
					return &mobius.ScimUser{UserName: "user1@example.com", Groups: []mobius.ScimUserGroup{}}, nil
				}
				ds.ListHostDeviceMappingFunc = func(ctx context.Context, id uint) ([]*mobius.HostDeviceMapping, error) {
					return []*mobius.HostDeviceMapping{}, nil
				}
			},
			assert: func(output string) {
				assert.Len(t, targets, 0) // target is not present
				assert.Contains(t, updatedProfile.Detail, "There is no IdP groups for this host. Mobius couldn’t populate $MOBIUS_VAR_HOST_END_USER_IDP_GROUPS.")
			},
		},
		{
			desc:           "profile with scim department",
			profileContent: "$MOBIUS_VAR_" + mobius.MobiusVarHostEndUserIDPDepartment,
			expectedStatus: mobius.MDMDeliveryPending,
			setup: func() {
				ds.ScimUserByHostIDFunc = func(ctx context.Context, hostID uint) (*mobius.ScimUser, error) {
					require.EqualValues(t, 1, hostID)
					return &mobius.ScimUser{
						UserName:   "user1@example.com",
						Groups:     []mobius.ScimUserGroup{},
						Department: ptr.String("Engineering"),
					}, nil
				}
				ds.ListHostDeviceMappingFunc = func(ctx context.Context, id uint) ([]*mobius.HostDeviceMapping, error) {
					return nil, nil
				}
			},
			assert: func(output string) {
				assert.Empty(t, updatedPayload.Detail) // no error detail
				assert.Len(t, targets, 1)              // target is still present
				require.Equal(t, "Engineering", output)
			},
		},
		{
			// Given department is not required, we don't make a profile fail if the user has no department,
			// we replace by empty string instead.
			desc:           "profile with scim department, user has no department, replaces with empty string",
			profileContent: "$MOBIUS_VAR_" + mobius.MobiusVarHostEndUserIDPDepartment,
			expectedStatus: mobius.MDMDeliveryPending,
			setup: func() {
				ds.ScimUserByHostIDFunc = func(ctx context.Context, hostID uint) (*mobius.ScimUser, error) {
					require.EqualValues(t, 1, hostID)
					return &mobius.ScimUser{
						UserName:   "user1@example.com",
						Groups:     []mobius.ScimUserGroup{},
						Department: nil,
					}, nil
				}
				ds.ListHostDeviceMappingFunc = func(ctx context.Context, id uint) ([]*mobius.HostDeviceMapping, error) {
					return nil, nil
				}
			},
			assert: func(output string) {
				assert.Empty(t, updatedPayload.Detail) // no error detail
				assert.Len(t, targets, 1)              // target is still present
				require.Empty(t, output)               // replaces to empty string
			},
		},
	}

	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			c.setup()

			profileContents := map[string]mobileconfig.Mobileconfig{
				"p1": []byte(c.profileContent),
			}
			populateTargets()
			expectedStatus = c.expectedStatus
			updatedPayload = nil
			updatedProfile = nil

			err := preprocessProfileContents(ctx, appCfg, ds, svc, digiCertService, logger, targets, profileContents, hostProfilesToInstallMap, userEnrollmentsToHostUUIDsMap)
			require.NoError(t, err)
			var output string
			if expectedStatus == mobius.MDMDeliveryFailed {
				require.Nil(t, updatedPayload)
				require.NotNil(t, updatedProfile)
			} else {
				require.NotNil(t, updatedPayload)
				require.Nil(t, updatedProfile)
				output = string(profileContents[updatedPayload.CommandUUID])
			}

			c.assert(output)
		})
	}
}

func TestValidateConfigProfileMobiusVariables(t *testing.T) {
	t.Parallel()
	appConfig := &mobius.AppConfig{
		Integrations: mobius.Integrations{
			DigiCert: optjson.Slice[mobius.DigiCertIntegration]{
				Set:   true,
				Valid: true,
				Value: []mobius.DigiCertIntegration{
					getDigiCertIntegration("https://example.com", "caName"),
					getDigiCertIntegration("https://example.com", "caName2"),
				},
			},
			CustomSCEPProxy: optjson.Slice[mobius.CustomSCEPProxyIntegration]{
				Set:   true,
				Valid: true,
				Value: []mobius.CustomSCEPProxyIntegration{
					getCustomSCEPIntegration("https://example.com", "scepName"),
					getCustomSCEPIntegration("https://example.com", "scepName2"),
				},
			},
		},
	}

	cases := []struct {
		name    string
		profile string
		errMsg  string
		vars    []string
	}{
		{
			name: "DigiCert badCA",
			profile: digiCertForValidation("$MOBIUS_VAR_DIGICERT_PASSWORD_bad", "$MOBIUS_VAR_DIGICERT_DATA_bad", "Name",
				"com.apple.security.pkcs12"),
			errMsg: "_bad is not supported in configuration profiles",
		},
		{
			name:    "DigiCert password missing",
			profile: digiCertForValidation("password", "$MOBIUS_VAR_DIGICERT_DATA_caName", "Name", "com.apple.security.pkcs12"),
			errMsg:  "Missing $MOBIUS_VAR_DIGICERT_PASSWORD_caName",
		},
		{
			name: "DigiCert data missing",
			profile: digiCertForValidation("$MOBIUS_VAR_DIGICERT_PASSWORD_caName", "data", "Name",
				"com.apple.security.pkcs12"),
			errMsg: "Missing $MOBIUS_VAR_DIGICERT_DATA_caName",
		},
		{
			name: "DigiCert password and data CA names don't match",
			profile: digiCertForValidation("$MOBIUS_VAR_DIGICERT_PASSWORD_caName", "$MOBIUS_VAR_DIGICERT_DATA_caName2", "Name",
				"com.apple.security.pkcs12"),
			errMsg: "Missing $MOBIUS_VAR_DIGICERT_DATA_caName in the profile",
		},
		{
			name: "DigiCert password shows up an extra time",
			profile: digiCertForValidation("$MOBIUS_VAR_DIGICERT_PASSWORD_caName", "$MOBIUS_VAR_DIGICERT_DATA_caName",
				"$MOBIUS_VAR_DIGICERT_PASSWORD_caName",
				"com.apple.security.pkcs12"),
			errMsg: "$MOBIUS_VAR_DIGICERT_PASSWORD_caName is already present in configuration profile",
		},
		{
			name: "DigiCert data shows up an extra time",
			profile: digiCertForValidation("$MOBIUS_VAR_DIGICERT_PASSWORD_caName", "$MOBIUS_VAR_DIGICERT_DATA_caName",
				"$MOBIUS_VAR_DIGICERT_DATA_caName",
				"com.apple.security.pkcs12"),
			errMsg: "$MOBIUS_VAR_DIGICERT_DATA_caName is already present in configuration profile",
		},
		{
			name: "DigiCert profile is not pkcs12",
			profile: digiCertForValidation("$MOBIUS_VAR_DIGICERT_PASSWORD_caName", "$MOBIUS_VAR_DIGICERT_DATA_caName", "Name",
				"com.apple.security.pkcs13"),
			errMsg: "Variables $MOBIUS_VAR_DIGICERT_PASSWORD_caName and $MOBIUS_VAR_DIGICERT_DATA_caName can only be included in the 'com.apple.security.pkcs12' payload",
		},
		{
			name: "DigiCert password is not a mobius variable",
			profile: digiCertForValidation("x$MOBIUS_VAR_DIGICERT_PASSWORD_caName", "${MOBIUS_VAR_DIGICERT_DATA_caName}", "Name",
				"com.apple.security.pkcs12"),
			errMsg: "included in the 'com.apple.security.pkcs12' payload under Password and PayloadContent, respectively",
		},
		{
			name: "DigiCert data is not a mobius variable",
			profile: digiCertForValidation("${MOBIUS_VAR_DIGICERT_PASSWORD_caName}", "x${MOBIUS_VAR_DIGICERT_DATA_caName}", "Name",
				"com.apple.security.pkcs12"),
			errMsg: "Failed to parse PKCS12 payload with Mobius variables",
		},
		{
			name: "DigiCert happy path",
			profile: digiCertForValidation("${MOBIUS_VAR_DIGICERT_PASSWORD_caName}", "${MOBIUS_VAR_DIGICERT_DATA_caName}", "Name",
				"com.apple.security.pkcs12"),
			errMsg: "",
			vars:   []string{"DIGICERT_PASSWORD_caName", "DIGICERT_DATA_caName"},
		},
		{
			name: "DigiCert 2 profiles with swapped variables",
			profile: digiCertForValidation2("${MOBIUS_VAR_DIGICERT_PASSWORD_caName}", "${MOBIUS_VAR_DIGICERT_DATA_caName2}",
				"$MOBIUS_VAR_DIGICERT_PASSWORD_caName2", "$MOBIUS_VAR_DIGICERT_DATA_caName"),
			errMsg: "CA name mismatch between $MOBIUS_VAR_DIGICERT_PASSWORD_caName",
		},
		{
			name: "DigiCert 2 profiles happy path",
			profile: digiCertForValidation2("${MOBIUS_VAR_DIGICERT_PASSWORD_caName}", "${MOBIUS_VAR_DIGICERT_DATA_caName}",
				"$MOBIUS_VAR_DIGICERT_PASSWORD_caName2", "$MOBIUS_VAR_DIGICERT_DATA_caName2"),
			errMsg: "",
			vars:   []string{"DIGICERT_PASSWORD_caName", "DIGICERT_DATA_caName", "DIGICERT_PASSWORD_caName2", "DIGICERT_DATA_caName2"},
		},
		{
			name: "Custom SCEP badCA",
			profile: customSCEPForValidation("$MOBIUS_VAR_CUSTOM_SCEP_CHALLENGE_bad", "$MOBIUS_VAR_CUSTOM_SCEP_PROXY_URL_bad", "Name",
				"com.apple.security.scep"),
			errMsg: "_bad is not supported in configuration profiles",
		},
		{
			name:    "Custom SCEP challenge missing",
			profile: customSCEPForValidation("challenge", "$MOBIUS_VAR_CUSTOM_SCEP_PROXY_URL_scepName", "Name", "com.apple.security.scep"),
			errMsg:  "SCEP profile for custom SCEP certificate authority requires: $MOBIUS_VAR_CUSTOM_SCEP_CHALLENGE_<CA_NAME>, $MOBIUS_VAR_CUSTOM_SCEP_PROXY_URL_<CA_NAME>, and $MOBIUS_VAR_SCEP_RENEWAL_ID variables.",
		},
		{
			name: "Custom SCEP url missing",
			profile: customSCEPForValidation("$MOBIUS_VAR_CUSTOM_SCEP_CHALLENGE_scepName", "https://bozo.com", "Name",
				"com.apple.security.scep"),
			errMsg: "SCEP profile for custom SCEP certificate authority requires: $MOBIUS_VAR_CUSTOM_SCEP_CHALLENGE_<CA_NAME>, $MOBIUS_VAR_CUSTOM_SCEP_PROXY_URL_<CA_NAME>, and $MOBIUS_VAR_SCEP_RENEWAL_ID variables.",
		},
		{
			name: "Custom SCEP challenge and url CA names don't match",
			profile: customSCEPForValidation("$MOBIUS_VAR_CUSTOM_SCEP_CHALLENGE_scepName", "$MOBIUS_VAR_CUSTOM_SCEP_PROXY_URL_scepName2",
				"Name", "com.apple.security.scep"),
			errMsg: "Missing $MOBIUS_VAR_CUSTOM_SCEP_PROXY_URL_scepName in the profile",
		},
		{
			name: "Custom SCEP challenge shows up an extra time",
			profile: customSCEPForValidation("$MOBIUS_VAR_CUSTOM_SCEP_CHALLENGE_scepName", "$MOBIUS_VAR_CUSTOM_SCEP_PROXY_URL_scepName",
				"$MOBIUS_VAR_CUSTOM_SCEP_CHALLENGE_scepName",
				"com.apple.security.scep"),
			errMsg: "$MOBIUS_VAR_CUSTOM_SCEP_CHALLENGE_scepName is already present in configuration profile",
		},
		{
			name: "Custom SCEP url shows up an extra time",
			profile: customSCEPForValidation("$MOBIUS_VAR_CUSTOM_SCEP_CHALLENGE_scepName", "$MOBIUS_VAR_CUSTOM_SCEP_PROXY_URL_scepName",
				"$MOBIUS_VAR_CUSTOM_SCEP_PROXY_URL_scepName",
				"com.apple.security.scep"),
			errMsg: "$MOBIUS_VAR_CUSTOM_SCEP_PROXY_URL_scepName is already present in configuration profile",
		},
		{
			name: "Custom SCEP renewal ID shows up in the wrong place",
			profile: customSCEPForValidationWithoutRenewalID("$MOBIUS_VAR_CUSTOM_SCEP_CHALLENGE_scepName", "$MOBIUS_VAR_CUSTOM_SCEP_PROXY_URL_scepName",
				"$MOBIUS_VAR_SCEP_RENEWAL_ID",
				"com.apple.security.scep"),
			errMsg: "Variable $MOBIUS_VAR_SCEP_RENEWAL_ID must be in the SCEP certificate's common name (CN).",
		},
		{
			name: "Custom SCEP profile is not scep",
			profile: customSCEPForValidation("$MOBIUS_VAR_CUSTOM_SCEP_CHALLENGE_scepName", "$MOBIUS_VAR_CUSTOM_SCEP_PROXY_URL_scepName",
				"Name", "com.apple.security.SCEP"),
			errMsg: mobius.SCEPVariablesNotInSCEPPayloadErrMsg,
		},
		{
			name: "Custom SCEP challenge is not a mobius variable",
			profile: customSCEPForValidation("x$MOBIUS_VAR_CUSTOM_SCEP_CHALLENGE_scepName", "${MOBIUS_VAR_CUSTOM_SCEP_PROXY_URL_scepName}",
				"Name", "com.apple.security.scep"),
			errMsg: "must be in the SCEP certificate's \"Challenge\" field",
		},
		{
			name: "Custom SCEP url is not a mobius variable",
			profile: customSCEPForValidation("${MOBIUS_VAR_CUSTOM_SCEP_CHALLENGE_scepName}", "x${MOBIUS_VAR_CUSTOM_SCEP_PROXY_URL_scepName}",
				"Name", "com.apple.security.scep"),
			errMsg: "must be in the SCEP certificate's \"URL\" field",
		},
		{
			name: "Custom SCEP happy path",
			profile: customSCEPForValidation("${MOBIUS_VAR_CUSTOM_SCEP_CHALLENGE_scepName}", "${MOBIUS_VAR_CUSTOM_SCEP_PROXY_URL_scepName}",
				"Name", "com.apple.security.scep"),
			errMsg: "",
			vars:   []string{"CUSTOM_SCEP_CHALLENGE_scepName", "CUSTOM_SCEP_PROXY_URL_scepName", "SCEP_RENEWAL_ID"},
		},
		{
			name: "Custom SCEP 2 profiles with swapped variables",
			profile: customSCEPForValidation2("${MOBIUS_VAR_CUSTOM_SCEP_CHALLENGE_scepName2}", "${MOBIUS_VAR_CUSTOM_SCEP_PROXY_URL_scepName}",
				"$MOBIUS_VAR_CUSTOM_SCEP_CHALLENGE_scepName", "$MOBIUS_VAR_CUSTOM_SCEP_PROXY_URL_scepName2"),
			errMsg: mobius.MultipleSCEPPayloadsErrMsg,
		},
		{
			name: "Custom SCEP 2 valid profiles should error",
			profile: customSCEPForValidation2("${MOBIUS_VAR_CUSTOM_SCEP_CHALLENGE_scepName}", "${MOBIUS_VAR_CUSTOM_SCEP_PROXY_URL_scepName}",
				"challenge", "http://example2.com"),
			errMsg: mobius.MultipleSCEPPayloadsErrMsg,
		},
		{
			name:    "Custom SCEP and DigiCert profiles happy path",
			profile: customSCEPDigiCertForValidation("${MOBIUS_VAR_CUSTOM_SCEP_CHALLENGE_scepName}", "${MOBIUS_VAR_CUSTOM_SCEP_PROXY_URL_scepName}"),
			errMsg:  "",
			vars:    []string{"DIGICERT_PASSWORD_caName", "DIGICERT_DATA_caName", "CUSTOM_SCEP_CHALLENGE_scepName", "CUSTOM_SCEP_PROXY_URL_scepName", "SCEP_RENEWAL_ID"},
		},
		{
			name:    "Custom profile with IdP variables and unknown variable",
			profile: customProfileForValidation("$MOBIUS_VAR_HOST_END_USER_IDP_NO_SUCH_VAR"),
			errMsg:  "Mobius variable $MOBIUS_VAR_HOST_END_USER_IDP_NO_SUCH_VAR is not supported in configuration profiles.",
		},
		{
			name:    "Custom profile with IdP variables happy path",
			profile: customProfileForValidation("value"),
			errMsg:  "",
			vars: []string{
				"HOST_END_USER_IDP_USERNAME",
				"HOST_END_USER_IDP_USERNAME_LOCAL_PART",
				"HOST_END_USER_IDP_GROUPS",
				"HOST_END_USER_IDP_DEPARTMENT",
			},
		},
		{
			name: "Custom SCEP and NDES 2 valid profiles should error",
			profile: customSCEPForValidation2("${MOBIUS_VAR_CUSTOM_SCEP_CHALLENGE_scepName}", "${MOBIUS_VAR_CUSTOM_SCEP_PROXY_URL_scepName}",
				"$MOBIUS_VAR_NDES_SCEP_CHALLENGE", "$MOBIUS_VAR_NDES_SCEP_PROXY_URL"),
			errMsg: mobius.MultipleSCEPPayloadsErrMsg,
		},
		{
			name:    "NDES challenge missing",
			profile: customSCEPForValidation("challenge", "$MOBIUS_VAR_NDES_SCEP_PROXY_URL", "Name", "com.apple.security.scep"),
			errMsg:  mobius.NDESSCEPVariablesMissingErrMsg,
		},
		{
			name: "NDES url missing",
			profile: customSCEPForValidation("$MOBIUS_VAR_NDES_SCEP_CHALLENGE", "https://bozo.com", "Name",
				"com.apple.security.scep"),
			errMsg: mobius.NDESSCEPVariablesMissingErrMsg,
		},
		{
			name: "NDES challenge shows up an extra time",
			profile: customSCEPForValidation("$MOBIUS_VAR_NDES_SCEP_CHALLENGE", "$MOBIUS_VAR_NDES_SCEP_PROXY_URL",
				"$MOBIUS_VAR_NDES_SCEP_CHALLENGE",
				"com.apple.security.scep"),
			errMsg: "$MOBIUS_VAR_NDES_SCEP_CHALLENGE is already present in configuration profile",
		},
		{
			name: "NDES url shows up an extra time",
			profile: customSCEPForValidation("$MOBIUS_VAR_NDES_SCEP_CHALLENGE", "$MOBIUS_VAR_NDES_SCEP_PROXY_URL",
				"$MOBIUS_VAR_NDES_SCEP_PROXY_URL",
				"com.apple.security.scep"),
			errMsg: "$MOBIUS_VAR_NDES_SCEP_PROXY_URL is already present in configuration profile",
		},
		{
			name: "NDES renewal ID shows up in the wrong place",
			profile: customSCEPForValidationWithoutRenewalID("$MOBIUS_VAR_NDES_SCEP_CHALLENGE", "$MOBIUS_VAR_NDES_SCEP_PROXY_URL",
				"$MOBIUS_VAR_SCEP_RENEWAL_ID",
				"com.apple.security.scep"),
			errMsg: "Variable $MOBIUS_VAR_SCEP_RENEWAL_ID must be in the SCEP certificate's common name (CN).",
		},
		{
			name: "NDES profile is not scep",
			profile: customSCEPForValidation("$MOBIUS_VAR_NDES_SCEP_CHALLENGE", "$MOBIUS_VAR_NDES_SCEP_PROXY_URL",
				"Name", "com.apple.security.SCEP"),
			errMsg: mobius.SCEPVariablesNotInSCEPPayloadErrMsg,
		},
		{
			name: "NDES challenge is not a mobius variable",
			profile: customSCEPForValidation("x$MOBIUS_VAR_NDES_SCEP_CHALLENGE", "${MOBIUS_VAR_NDES_SCEP_PROXY_URL}",
				"Name", "com.apple.security.scep"),
			errMsg: "Variable \"$MOBIUS_VAR_NDES_SCEP_CHALLENGE\" must be in the SCEP certificate's \"Challenge\" field.",
		},
		{
			name: "NDES url is not a mobius variable",
			profile: customSCEPForValidation("${MOBIUS_VAR_NDES_SCEP_CHALLENGE}", "x${MOBIUS_VAR_NDES_SCEP_PROXY_URL}",
				"Name", "com.apple.security.scep"),
			errMsg: "Variable \"$MOBIUS_VAR_NDES_SCEP_PROXY_URL\" must be in the SCEP certificate's \"URL\" field.",
		},
		{
			name: "SCEP renewal ID without other variables",
			profile: customSCEPForValidation("challenge", "url",
				"Name", "com.apple.security.scep"),
			errMsg: mobius.SCEPRenewalIDWithoutURLChallengeErrMsg,
		},
		{
			name: "NDES happy path",
			profile: customSCEPForValidation("${MOBIUS_VAR_NDES_SCEP_CHALLENGE}", "${MOBIUS_VAR_NDES_SCEP_PROXY_URL}",
				"Name", "com.apple.security.scep"),
			errMsg: "",
			vars:   []string{"NDES_SCEP_CHALLENGE", "NDES_SCEP_PROXY_URL", "SCEP_RENEWAL_ID"},
		},
		{
			name: "NDES 2 valid profiles should error",
			profile: customSCEPForValidation2("${MOBIUS_VAR_NDES_SCEP_CHALLENGE}", "${MOBIUS_VAR_NDES_SCEP_PROXY_URL}",
				"challenge", "http://example2.com"),
			errMsg: mobius.MultipleSCEPPayloadsErrMsg,
		},
		{
			name:    "NDES and DigiCert profiles happy path",
			profile: customSCEPDigiCertForValidation("${MOBIUS_VAR_NDES_SCEP_CHALLENGE}", "${MOBIUS_VAR_NDES_SCEP_PROXY_URL}"),
			errMsg:  "",
			vars: []string{
				"DIGICERT_PASSWORD_caName", "DIGICERT_DATA_caName", "NDES_SCEP_CHALLENGE", "NDES_SCEP_PROXY_URL",
				"SCEP_RENEWAL_ID",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			vars, err := validateConfigProfileMobiusVariables(appConfig, tc.profile)
			if tc.errMsg != "" {
				assert.ErrorContains(t, err, tc.errMsg)
				assert.Empty(t, vars)
			} else {
				assert.NoError(t, err)
				gotVars := make([]string, 0, len(vars))
				for v := range vars {
					gotVars = append(gotVars, v)
				}
				assert.ElementsMatch(t, tc.vars, gotVars)
			}
		})
	}
}

//go:embed testdata/profiles/digicert-validation.mobileconfig
var digiCertValidationMobileconfig string

func digiCertForValidation(password, data, name, payloadType string) string {
	return fmt.Sprintf(digiCertValidationMobileconfig, password, data, name, payloadType)
}

//go:embed testdata/profiles/digicert-validation2.mobileconfig
var digiCertValidation2Mobileconfig string

func digiCertForValidation2(password1, data1, password2, data2 string) string {
	return fmt.Sprintf(digiCertValidation2Mobileconfig, password1, data1, password2, data2)
}

//go:embed testdata/profiles/custom-scep-validation.mobileconfig
var customSCEPValidationMobileconfig string

func customSCEPForValidation(challenge, url, name, payloadType string) string {
	return fmt.Sprintf(customSCEPValidationMobileconfig, challenge, url, name, payloadType)
}

func customSCEPForValidationWithoutRenewalID(challenge, url, name, payloadType string) string {
	configProfile := strings.ReplaceAll(customSCEPValidationMobileconfig, "$MOBIUS_VAR_SCEP_RENEWAL_ID", "")
	return fmt.Sprintf(configProfile, challenge, url, name, payloadType)
}

//go:embed testdata/profiles/custom-scep-validation2.mobileconfig
var customSCEPValidation2Mobileconfig string

func customSCEPForValidation2(challenge1, url1, challenge2, url2 string) string {
	return fmt.Sprintf(customSCEPValidation2Mobileconfig, challenge1, url1, challenge2, url2)
}

//go:embed testdata/profiles/custom-scep-digicert-validation.mobileconfig
var customSCEPDigiCertValidationMobileconfig string

func customSCEPDigiCertForValidation(challenge, url string) string {
	return fmt.Sprintf(customSCEPDigiCertValidationMobileconfig, challenge, url)
}

//go:embed testdata/profiles/custom-profile-validation.mobileconfig
var customProfileValidationMobileconfig string

func customProfileForValidation(value string) string {
	return fmt.Sprintf(customProfileValidationMobileconfig, value)
}
