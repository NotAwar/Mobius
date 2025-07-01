package service

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/notawar/mobius/v4/server/mdm/apple/mobileconfig"
	"github.com/notawar/mobius/v4/server/mdm/microsoft/syncml"
	nanodep_client "github.com/notawar/mobius/v4/server/mdm/nanodep/client"
	nanodep_mock "github.com/notawar/mobius/v4/server/mock/nanodep"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"

	"github.com/notawar/mobius/v4/server/authz"
	"github.com/notawar/mobius/v4/server/config"
	authz_ctx "github.com/notawar/mobius/v4/server/contexts/authz"
	"github.com/notawar/mobius/v4/server/contexts/license"
	"github.com/notawar/mobius/v4/server/contexts/viewer"
	"github.com/notawar/mobius/v4/server/mobius"
	"github.com/notawar/mobius/v4/server/mdm/scep/x509util"
	"github.com/notawar/mobius/v4/server/mock"
	"github.com/notawar/mobius/v4/server/ptr"
	"github.com/notawar/mobius/v4/server/test"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestGetMDMApple(t *testing.T) {
	ds := new(mock.Store)
	license := &mobius.LicenseInfo{Tier: mobius.TierFree}
	cfg := config.TestConfig()
	svc, ctx := newTestServiceWithConfig(t, ds, cfg, nil, nil, &TestServerOpts{License: license, SkipCreateTestUsers: true})

	certPEM, err := os.ReadFile("testdata/server.pem")
	require.NoError(t, err)

	keyPEM, err := os.ReadFile("testdata/server.key")
	require.NoError(t, err)

	ds.GetAllMDMConfigAssetsByNameFunc = func(ctx context.Context, assetNames []mobius.MDMAssetName,
		_ sqlx.QueryerContext,
	) (map[mobius.MDMAssetName]mobius.MDMConfigAsset, error) {
		return map[mobius.MDMAssetName]mobius.MDMConfigAsset{
			mobius.MDMAssetAPNSCert: {Name: mobius.MDMAssetAPNSCert, Value: certPEM},
			mobius.MDMAssetAPNSKey:  {Name: mobius.MDMAssetAPNSKey, Value: keyPEM},
			mobius.MDMAssetCACert:   {Name: mobius.MDMAssetCACert, Value: certPEM},
			mobius.MDMAssetCAKey:    {Name: mobius.MDMAssetCAKey, Value: keyPEM},
		}, nil
	}

	ctx = test.UserContext(ctx, test.UserAdmin)
	got, err := svc.GetAppleMDM(ctx)
	require.NoError(t, err)

	// NOTE: to inspect the test certificate, you can use:
	// openssl x509 -in ./server/service/testdata/server.pem -text -noout
	require.Equal(t, &mobius.AppleMDM{
		CommonName:   "servq.groob.io",
		SerialNumber: "1",
		Issuer:       "groob-ca",
		RenewDate:    time.Date(2017, 10, 24, 13, 11, 44, 0, time.UTC),
	}, got)
}

func TestMDMAppleAuthorization(t *testing.T) {
	ds := new(mock.Store)
	license := &mobius.LicenseInfo{Tier: mobius.TierPremium}

	depStorage := new(nanodep_mock.Storage)
	depSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		switch r.URL.Path {
		case "/session":
			_, _ = w.Write([]byte(`{"auth_session_token": "xyz"}`))
		case "/account":
			_, _ = w.Write([]byte(`{"admin_id": "abc", "org_name": "test_org"}`))
		}
	}))
	t.Cleanup(depSrv.Close)

	depStorage.RetrieveConfigFunc = func(p0 context.Context, p1 string) (*nanodep_client.Config, error) {
		return &nanodep_client.Config{BaseURL: depSrv.URL}, nil
	}
	depStorage.RetrieveAuthTokensFunc = func(ctx context.Context, name string) (*nanodep_client.OAuth1Tokens, error) {
		return &nanodep_client.OAuth1Tokens{}, nil
	}
	depStorage.StoreAssignerProfileFunc = func(ctx context.Context, name string, profileUUID string) error {
		return nil
	}

	svc, ctx := newTestService(t, ds, nil, nil, &TestServerOpts{License: license, SkipCreateTestUsers: true, DEPStorage: depStorage})
	ds.GetAllMDMConfigAssetsHashesFunc = func(ctx context.Context, assetNames []mobius.MDMAssetName) (map[mobius.MDMAssetName]string, error) {
		return map[mobius.MDMAssetName]string{
			mobius.MDMAssetAPNSCert: "apnscert",
			mobius.MDMAssetAPNSKey:  "apnskey",
			mobius.MDMAssetCACert:   "scepcert",
			mobius.MDMAssetCAKey:    "scepkey",
		}, nil
	}

	ds.GetAllMDMConfigAssetsByNameFunc = func(ctx context.Context, assetNames []mobius.MDMAssetName,
		_ sqlx.QueryerContext,
	) (map[mobius.MDMAssetName]mobius.MDMConfigAsset, error) {
		return map[mobius.MDMAssetName]mobius.MDMConfigAsset{}, nil
	}

	ds.InsertMDMConfigAssetsFunc = func(ctx context.Context, assets []mobius.MDMConfigAsset, _ sqlx.ExtContext) error { return nil }

	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		return &mobius.AppConfig{OrgInfo: mobius.OrgInfo{OrgName: "Nurv"}}, nil
	}

	ds.SaveAppConfigFunc = func(ctx context.Context, info *mobius.AppConfig) error {
		return nil
	}

	ds.NewActivityFunc = func(ctx context.Context, user *mobius.User, activity mobius.ActivityDetails, details []byte, createdAt time.Time) error {
		return nil
	}

	ds.ListABMTokensFunc = func(ctx context.Context) ([]*mobius.ABMToken, error) {
		return nil, nil
	}
	ds.ListVPPTokensFunc = func(ctx context.Context) ([]*mobius.VPPTokenDB, error) {
		return nil, nil
	}
	ds.GetVPPTokenFunc = func(ctx context.Context, id uint) (*mobius.VPPTokenDB, error) {
		return nil, &notFoundErr{}
	}

	ds.DeleteMDMConfigAssetsByNameFunc = func(ctx context.Context, assetNames []mobius.MDMAssetName) error { return nil }

	// use a custom implementation of checkAuthErr as the service call will fail
	// with a not found error (given that MDM is not really configured) in case
	// of success, and the package-wide checkAuthErr requires no error.
	checkAuthErr := func(t *testing.T, shouldFail bool, err error) {
		if shouldFail {
			require.Error(t, err)
			require.Equal(t, (&authz.Forbidden{}).Error(), err.Error())
		} else if err != nil {
			require.NotEqual(t, (&authz.Forbidden{}).Error(), err.Error())
		}
	}
	testAuthdMethods := func(t *testing.T, user *mobius.User, shouldFailWithAuth bool) {
		ctx := test.UserContext(ctx, user)
		_, err := svc.GetAppleMDM(ctx)
		checkAuthErr(t, shouldFailWithAuth, err)
		_, err = svc.GetAppleBM(ctx)
		checkAuthErr(t, shouldFailWithAuth, err)

		// deliberately send invalid args so it doesn't actually generate a CSR
		_, err = svc.RequestMDMAppleCSR(ctx, "not-an-email", "")
		require.Error(t, err) // it *will* always fail, but not necessarily due to authorization
		checkAuthErr(t, shouldFailWithAuth, err)

		_, err = svc.GetMDMAppleCSR(ctx)
		checkAuthErr(t, shouldFailWithAuth, err)

		err = svc.UploadMDMAppleAPNSCert(ctx, nil)
		require.Error(t, err)
		checkAuthErr(t, shouldFailWithAuth, err)

		err = svc.DeleteMDMAppleAPNSCert(ctx) // Don't expect anything other than an authz error here, since this is pretty much just a DB wrapper.
		checkAuthErr(t, shouldFailWithAuth, err)

		_, err = svc.UploadVPPToken(ctx, nil)
		checkAuthErr(t, shouldFailWithAuth, err)

		_, err = svc.GetVPPTokens(ctx)
		checkAuthErr(t, shouldFailWithAuth, err)

		err = svc.DeleteVPPToken(ctx, 0)
		checkAuthErr(t, shouldFailWithAuth, err)
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
}

func TestVerifyMDMAppleConfigured(t *testing.T) {
	ds := new(mock.Store)
	license := &mobius.LicenseInfo{Tier: mobius.TierPremium}
	cfg := config.TestConfig()
	svc, baseCtx := newTestServiceWithConfig(t, ds, cfg, nil, nil, &TestServerOpts{License: license, SkipCreateTestUsers: true})

	// mdm not configured
	authzCtx := &authz_ctx.AuthorizationContext{}
	ctx := authz_ctx.NewContext(baseCtx, authzCtx)
	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		return &mobius.AppConfig{MDM: mobius.MDM{EnabledAndConfigured: false}}, nil
	}
	err := svc.VerifyMDMAppleConfigured(ctx)
	require.ErrorIs(t, err, mobius.ErrMDMNotConfigured)
	require.True(t, ds.AppConfigFuncInvoked)
	ds.AppConfigFuncInvoked = false
	require.True(t, authzCtx.Checked())

	err = svc.VerifyMDMAppleOrWindowsConfigured(ctx)
	require.ErrorIs(t, err, mobius.ErrMDMNotConfigured)
	require.True(t, ds.AppConfigFuncInvoked)
	ds.AppConfigFuncInvoked = false
	require.True(t, authzCtx.Checked())

	// error retrieving app config
	authzCtx = &authz_ctx.AuthorizationContext{}
	ctx = authz_ctx.NewContext(baseCtx, authzCtx)
	testErr := errors.New("test err")
	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		return nil, testErr
	}
	err = svc.VerifyMDMAppleConfigured(ctx)
	require.ErrorIs(t, err, testErr)
	require.True(t, ds.AppConfigFuncInvoked)
	ds.AppConfigFuncInvoked = false
	require.True(t, authzCtx.Checked())

	err = svc.VerifyMDMAppleOrWindowsConfigured(ctx)
	require.ErrorIs(t, err, testErr)
	require.True(t, ds.AppConfigFuncInvoked)
	ds.AppConfigFuncInvoked = false
	require.True(t, authzCtx.Checked())

	// mdm configured
	authzCtx = &authz_ctx.AuthorizationContext{}
	ctx = authz_ctx.NewContext(baseCtx, authzCtx)
	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		return &mobius.AppConfig{MDM: mobius.MDM{EnabledAndConfigured: true}}, nil
	}
	err = svc.VerifyMDMAppleConfigured(ctx)
	require.NoError(t, err)
	require.True(t, ds.AppConfigFuncInvoked)
	ds.AppConfigFuncInvoked = false
	require.False(t, authzCtx.Checked())

	err = svc.VerifyMDMAppleOrWindowsConfigured(ctx)
	require.NoError(t, err)
	require.True(t, ds.AppConfigFuncInvoked)
	ds.AppConfigFuncInvoked = false
	require.False(t, authzCtx.Checked())
}

func TestVerifyMDMWindowsConfigured(t *testing.T) {
	ds := new(mock.Store)
	license := &mobius.LicenseInfo{Tier: mobius.TierPremium}
	cfg := config.TestConfig()
	svc, baseCtx := newTestServiceWithConfig(t, ds, cfg, nil, nil, &TestServerOpts{License: license, SkipCreateTestUsers: true})

	// mdm not configured
	authzCtx := &authz_ctx.AuthorizationContext{}
	ctx := authz_ctx.NewContext(baseCtx, authzCtx)
	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		return &mobius.AppConfig{MDM: mobius.MDM{WindowsEnabledAndConfigured: false}}, nil
	}

	err := svc.VerifyMDMWindowsConfigured(ctx)
	require.ErrorIs(t, err, mobius.ErrWindowsMDMNotConfigured)
	require.True(t, ds.AppConfigFuncInvoked)
	ds.AppConfigFuncInvoked = false
	require.True(t, authzCtx.Checked())

	err = svc.VerifyMDMAppleOrWindowsConfigured(ctx)
	require.ErrorIs(t, err, mobius.ErrMDMNotConfigured)
	require.True(t, ds.AppConfigFuncInvoked)
	ds.AppConfigFuncInvoked = false
	require.True(t, authzCtx.Checked())

	// error retrieving app config
	authzCtx = &authz_ctx.AuthorizationContext{}
	ctx = authz_ctx.NewContext(baseCtx, authzCtx)
	testErr := errors.New("test err")
	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		return nil, testErr
	}

	err = svc.VerifyMDMWindowsConfigured(ctx)
	require.ErrorIs(t, err, testErr)
	require.True(t, ds.AppConfigFuncInvoked)
	ds.AppConfigFuncInvoked = false
	require.True(t, authzCtx.Checked())

	err = svc.VerifyMDMAppleOrWindowsConfigured(ctx)
	require.ErrorIs(t, err, testErr)
	require.True(t, ds.AppConfigFuncInvoked)
	ds.AppConfigFuncInvoked = false
	require.True(t, authzCtx.Checked())

	// mdm configured
	authzCtx = &authz_ctx.AuthorizationContext{}
	ctx = authz_ctx.NewContext(baseCtx, authzCtx)
	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		return &mobius.AppConfig{MDM: mobius.MDM{WindowsEnabledAndConfigured: true}}, nil
	}

	err = svc.VerifyMDMWindowsConfigured(ctx)
	require.NoError(t, err)
	require.True(t, ds.AppConfigFuncInvoked)
	ds.AppConfigFuncInvoked = false
	require.False(t, authzCtx.Checked())

	err = svc.VerifyMDMAppleOrWindowsConfigured(ctx)
	require.NoError(t, err)
	require.True(t, ds.AppConfigFuncInvoked)
	ds.AppConfigFuncInvoked = false
	require.False(t, authzCtx.Checked())
}

func TestMicrosoftWSTEPConfig(t *testing.T) {
	ds := new(mock.Store)
	license := &mobius.LicenseInfo{Tier: mobius.TierFree}

	ds.WSTEPNewSerialFunc = func(context.Context) (*big.Int, error) {
		return big.NewInt(1337), nil
	}
	ds.WSTEPStoreCertificateFunc = func(ctx context.Context, name string, crt *x509.Certificate) error {
		require.Equal(t, "test-client", name)
		require.Equal(t, "test-client", crt.Subject.CommonName)
		require.Equal(t, "Mobius", crt.Subject.OrganizationalUnit[0])
		return nil
	}

	certPath := "testdata/server.pem"
	keyPath := "testdata/server.key"

	// sanity check that the test data is valid
	wantCertPEM, err := os.ReadFile(certPath)
	require.NoError(t, err)
	wantKeyPEM, err := os.ReadFile(keyPath)
	require.NoError(t, err)

	// specify the test data in the server config
	cfg := config.TestConfig()
	cfg.MDM.WindowsWSTEPIdentityCert = certPath
	cfg.MDM.WindowsWSTEPIdentityKey = keyPath

	// check that config.MDM.MicrosoftWSTEP() returns the expected values
	_, cfgCertPEM, cfgKeyPEM, err := cfg.MDM.MicrosoftWSTEP()
	require.NoError(t, err)
	require.NotEmpty(t, cfgCertPEM)
	require.Equal(t, wantCertPEM, cfgCertPEM)
	require.NotEmpty(t, cfgKeyPEM)
	require.Equal(t, wantKeyPEM, cfgKeyPEM)

	// start the test service
	svc, ctx := newTestServiceWithConfig(t, ds, cfg, nil, nil, &TestServerOpts{License: license, SkipCreateTestUsers: true})
	ctx = test.UserContext(ctx, test.UserAdmin)

	// test CSR signing
	clienPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	csrTemplate := x509util.CertificateRequest{
		CertificateRequest: x509.CertificateRequest{
			Subject: pkix.Name{
				CommonName: "test-cient",
			},
			SignatureAlgorithm: x509.SHA256WithRSA,
		},
	}
	csrDerBytes, err := x509util.CreateCertificateRequest(rand.Reader, &csrTemplate, clienPrivateKey)
	require.NoError(t, err)
	csr, err := x509.ParseCertificateRequest(csrDerBytes)
	require.NoError(t, err)

	// test the service method
	rawDER, _, err := svc.SignMDMMicrosoftClientCSR(ctx, "test-client", csr)
	require.NoError(t, err)
	require.True(t, ds.WSTEPNewSerialFuncInvoked)
	require.True(t, ds.WSTEPStoreCertificateFuncInvoked)

	// TODO: additional assertions on the signed certificate
	parsedCert, err := x509.ParseCertificate(rawDER)
	require.NoError(t, err)
	require.Equal(t, "test-client", parsedCert.Subject.CommonName)
	require.Equal(t, "Mobius", parsedCert.Subject.OrganizationalUnit[0])
}

func TestRunMDMCommandAuthz(t *testing.T) {
	ds := new(mock.Store)
	svc, ctx := newTestService(t, ds, nil, nil)

	singleUnenrolledHost := []*mobius.Host{{ID: 1, TeamID: ptr.Uint(1), UUID: "a", Platform: "darwin"}}
	team1And2UnenrolledHosts := []*mobius.Host{{ID: 1, TeamID: ptr.Uint(1), UUID: "a"}, {ID: 2, TeamID: ptr.Uint(2), UUID: "b"}}
	team2And3UnenrolledHosts := []*mobius.Host{{ID: 2, TeamID: ptr.Uint(2), UUID: "b"}, {ID: 3, TeamID: ptr.Uint(3), UUID: "c"}}

	ds.AreHostsConnectedToMobiusMDMFunc = func(ctx context.Context, hosts []*mobius.Host) (map[string]bool, error) {
		res := make(map[string]bool, len(hosts))
		for _, h := range hosts {
			res[h.UUID] = true
		}
		return res, nil
	}

	userTeamMaintainerTeam1And2 := &mobius.User{
		ID: 100,
		Teams: []mobius.UserTeam{
			{
				Team: mobius.Team{ID: 1},
				Role: mobius.RoleMaintainer,
			},
			{
				Team: mobius.Team{ID: 2},
				Role: mobius.RoleMaintainer,
			},
		},
	}
	userTeamAdminTeam1And2 := &mobius.User{
		ID: 101,
		Teams: []mobius.UserTeam{
			{
				Team: mobius.Team{ID: 1},
				Role: mobius.RoleAdmin,
			},
			{
				Team: mobius.Team{ID: 2},
				Role: mobius.RoleAdmin,
			},
		},
	}
	userTeamAdminTeam1ObserverTeam2 := &mobius.User{
		ID: 102,
		Teams: []mobius.UserTeam{
			{
				Team: mobius.Team{ID: 1},
				Role: mobius.RoleAdmin,
			},
			{
				Team: mobius.Team{ID: 2},
				Role: mobius.RoleObserver,
			},
		},
	}

	checkAuthErr := func(t *testing.T, shouldFailWithAuth bool, err error) {
		t.Helper()

		if shouldFailWithAuth {
			require.Error(t, err)
			require.Contains(t, err.Error(), authz.ForbiddenErrorMessage)
		} else {
			// call always fails, but due to the host not being enrolled in MDM
			require.Error(t, err)
			require.NotContains(t, err.Error(), authz.ForbiddenErrorMessage)
		}
	}

	enqueueCmdCases := []struct {
		desc               string
		user               *mobius.User
		hosts              []*mobius.Host
		shouldFailWithAuth bool
	}{
		{"no role", test.UserNoRoles, singleUnenrolledHost, true},
		{"maintainer", test.UserMaintainer, singleUnenrolledHost, false},
		{"admin", test.UserAdmin, singleUnenrolledHost, false},
		{"observer", test.UserObserver, singleUnenrolledHost, true},
		{"observer+", test.UserObserverPlus, singleUnenrolledHost, true},
		{"gitops", test.UserGitOps, singleUnenrolledHost, false},
		{"team 1 admin", test.UserTeamAdminTeam1, singleUnenrolledHost, false},
		{"team 2 admin", test.UserTeamAdminTeam2, singleUnenrolledHost, true},
		{"team 1 maintainer", test.UserTeamMaintainerTeam1, singleUnenrolledHost, false},
		{"team 2 maintainer", test.UserTeamMaintainerTeam2, singleUnenrolledHost, true},
		{"team 1 observer", test.UserTeamObserverTeam1, singleUnenrolledHost, true},
		{"team 2 observer", test.UserTeamObserverTeam2, singleUnenrolledHost, true},
		{"team 1 observer+", test.UserTeamObserverPlusTeam1, singleUnenrolledHost, true},
		{"team 2 observer+", test.UserTeamObserverPlusTeam2, singleUnenrolledHost, true},
		{"team 1 gitops", test.UserTeamGitOpsTeam1, singleUnenrolledHost, false},
		{"team 2 gitops", test.UserTeamGitOpsTeam2, singleUnenrolledHost, true},
		{"team 1 admin mix of teams", test.UserTeamAdminTeam1, team1And2UnenrolledHosts, true},
		{"team 1 maintainer mix of teams", test.UserTeamMaintainerTeam1, team1And2UnenrolledHosts, true},
		{"admin mix of teams", test.UserAdmin, team1And2UnenrolledHosts, false},
		{"team 1 admin 2 other teams", test.UserTeamAdminTeam1, team2And3UnenrolledHosts, true},
		{"team 1 maintainer 2 other teams", test.UserTeamMaintainerTeam1, team2And3UnenrolledHosts, true},
		{"admin mix of teams", test.UserAdmin, team1And2UnenrolledHosts, false},
		{"admin mix of 2 other teams", test.UserAdmin, team2And3UnenrolledHosts, false},
		{"team 1 and 2 admin on allowed teams", userTeamAdminTeam1And2, team1And2UnenrolledHosts, false},
		{"team 1 and 2 maintainer on allowed teams", userTeamMaintainerTeam1And2, team1And2UnenrolledHosts, false},
		{"team 1 and 2 admin on other teams", userTeamAdminTeam1And2, team2And3UnenrolledHosts, true},
		{"team 1 and 2 maintainer on other teams", userTeamMaintainerTeam1And2, team2And3UnenrolledHosts, true},
		{"team 1 admin and 2 observer on team 1", userTeamAdminTeam1ObserverTeam2, singleUnenrolledHost, false},
		{"team 1 admin and 2 observer on team 2 and 3", userTeamAdminTeam1ObserverTeam2, team2And3UnenrolledHosts, true},
		{"team 1 admin and 2 observer on team 1 and 2", userTeamAdminTeam1ObserverTeam2, team1And2UnenrolledHosts, true},
	}
	for _, c := range enqueueCmdCases {
		t.Run(c.desc, func(t *testing.T) {
			ds.ListHostsLiteByUUIDsFunc = func(ctx context.Context, filter mobius.TeamFilter, uuids []string) ([]*mobius.Host, error) {
				return c.hosts, nil
			}

			ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
				return &mobius.AppConfig{
					MDM: mobius.MDM{
						EnabledAndConfigured:        true,
						WindowsEnabledAndConfigured: true,
					},
				}, nil
			}

			ctx = test.UserContext(ctx, c.user)
			_, err := svc.RunMDMCommand(ctx, "base64command", []string{"uuid"})
			checkAuthErr(t, c.shouldFailWithAuth, err)
		})
	}
}

func TestRunMDMCommandValidations(t *testing.T) {
	ds := new(mock.Store)
	svc, ctx := newTestService(t, ds, nil, nil)

	enrolledMDMInfo := &mobius.HostMDM{Enrolled: true, InstalledFromDep: false, Name: mobius.WellKnownMDMMobius, IsServer: false}
	singleUnenrolledHost := []*mobius.Host{{ID: 0xf1337, TeamID: ptr.Uint(1), UUID: "unenrolled"}}
	differentPlatformsHosts := []*mobius.Host{
		{ID: 1, UUID: "a", Platform: "darwin"},
		{ID: 2, UUID: "b", Platform: "windows"},
	}
	linuxSingleHost := []*mobius.Host{{ID: 1, TeamID: ptr.Uint(1), UUID: "a", Platform: "linux"}}
	windowsSingleHost := []*mobius.Host{{ID: 1, TeamID: ptr.Uint(1), UUID: "a", Platform: "windows"}}
	macosSingleHost := []*mobius.Host{{ID: 1, TeamID: ptr.Uint(1), UUID: "a", Platform: "darwin"}}

	ds.GetHostMDMFunc = func(ctx context.Context, hostID uint) (*mobius.HostMDM, error) {
		if hostID == 0xf1337 {
			return nil, sql.ErrNoRows
		}
		return enrolledMDMInfo, nil
	}

	ds.AreHostsConnectedToMobiusMDMFunc = func(ctx context.Context, hosts []*mobius.Host) (map[string]bool, error) {
		res := make(map[string]bool, len(hosts))
		for _, h := range hosts {
			res[h.UUID] = h.ID != 0xf1337
		}
		return res, nil
	}

	cases := []struct {
		desc          string
		hosts         []*mobius.Host
		mdmConfigured bool
		wantErr       string
	}{
		{"no hosts", []*mobius.Host{}, false, "No hosts targeted."},
		{"unenrolled host", singleUnenrolledHost, false, "Can't run the MDM command because one or more hosts have MDM turned off."},
		{"different platforms", differentPlatformsHosts, false, "All hosts must be on the same platform."},
		{"invalid platform", linuxSingleHost, false, "Invalid platform."},
		{"mdm not configured (windows)", windowsSingleHost, false, "Windows MDM isn't turned on."},
		{"mdm not configured (macos)", macosSingleHost, false, "macOS MDM isn't turned on."},
		{"invalid base64 encoding", macosSingleHost, true, "unable to decode base64 command"},
	}

	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			ds.ListHostsLiteByUUIDsFunc = func(ctx context.Context, filter mobius.TeamFilter, uuids []string) ([]*mobius.Host, error) {
				return c.hosts, nil
			}
			ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
				return &mobius.AppConfig{
					MDM: mobius.MDM{
						EnabledAndConfigured:        c.mdmConfigured,
						WindowsEnabledAndConfigured: c.mdmConfigured,
					},
				}, nil
			}
			ctx = test.UserContext(ctx, test.UserAdmin)
			_, err := svc.RunMDMCommand(ctx, "!@#", []string{"unused for this test"})
			require.Error(t, err)
			require.ErrorContains(t, err, c.wantErr)
		})
	}
}

func TestMDMCommonAuthorization(t *testing.T) {
	ds := new(mock.Store)
	license := &mobius.LicenseInfo{Tier: mobius.TierPremium}
	svc, ctx := newTestService(t, ds, nil, nil, &TestServerOpts{License: license, SkipCreateTestUsers: true})

	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		return &mobius.AppConfig{MDM: mobius.MDM{EnabledAndConfigured: true, WindowsEnabledAndConfigured: true}}, nil
	}

	ds.GetMDMAppleFileVaultSummaryFunc = func(ctx context.Context, teamID *uint) (*mobius.MDMAppleFileVaultSummary, error) {
		return &mobius.MDMAppleFileVaultSummary{}, nil
	}
	ds.GetMDMWindowsBitLockerSummaryFunc = func(ctx context.Context, teamID *uint) (*mobius.MDMWindowsBitLockerSummary, error) {
		return &mobius.MDMWindowsBitLockerSummary{}, nil
	}
	ds.GetMDMWindowsProfilesSummaryFunc = func(ctx context.Context, teamID *uint) (*mobius.MDMProfilesSummary, error) {
		return &mobius.MDMProfilesSummary{}, nil
	}

	ds.GetLinuxDiskEncryptionSummaryFunc = func(ctx context.Context, teamID *uint) (mobius.MDMLinuxDiskEncryptionSummary, error) {
		return mobius.MDMLinuxDiskEncryptionSummary{}, nil
	}
	ds.GetConfigEnableDiskEncryptionFunc = func(ctx context.Context, teamID *uint) (bool, error) {
		return false, nil
	}

	ds.AreHostsConnectedToMobiusMDMFunc = func(ctx context.Context, hosts []*mobius.Host) (map[string]bool, error) {
		res := make(map[string]bool, len(hosts))
		for _, h := range hosts {
			res[h.UUID] = true
		}
		return res, nil
	}

	ds.GetMDMAppleConfigProfileFunc = func(ctx context.Context, pid string) (*mobius.MDMAppleConfigProfile, error) {
		var tid uint
		if pid == "a-team-1-profile" {
			tid = 1
		}
		return &mobius.MDMAppleConfigProfile{
			ProfileUUID: pid,
			TeamID:      &tid,
		}, nil
	}
	ds.GetMDMConfigProfileStatusFunc = func(ctx context.Context, pid string) (mobius.MDMConfigProfileStatus, error) {
		return mobius.MDMConfigProfileStatus{}, nil
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

	checkShouldFail := func(err error, shouldFail bool) {
		if !shouldFail {
			require.NoError(t, err)
		} else {
			require.Error(t, err)
			require.Contains(t, err.Error(), authz.ForbiddenErrorMessage)
		}
	}

	for _, tt := range testCases {
		ctx := viewer.NewContext(ctx, viewer.Viewer{User: tt.user})
		ds.TeamFunc = mockTeamFuncWithUser(tt.user)

		t.Run(tt.name, func(t *testing.T) {
			// test authz for MDM summary endpoints (no team)
			_, err := svc.GetMDMDiskEncryptionSummary(ctx, nil)
			checkShouldFail(err, tt.shouldFailGlobal)
			_, err = svc.GetMDMWindowsProfilesSummary(ctx, nil)
			checkShouldFail(err, tt.shouldFailGlobal)
			_, err = svc.GetMDMConfigProfileStatus(ctx, "a-no-team-profile")
			checkShouldFail(err, tt.shouldFailGlobal)

			// test authz for MDM summary endpoints (team 1)
			_, err = svc.GetMDMDiskEncryptionSummary(ctx, ptr.Uint(1))
			checkShouldFail(err, tt.shouldFailTeam)
			_, err = svc.GetMDMWindowsProfilesSummary(ctx, ptr.Uint(1))
			checkShouldFail(err, tt.shouldFailTeam)
			_, err = svc.GetMDMConfigProfileStatus(ctx, "a-team-1-profile")
			checkShouldFail(err, tt.shouldFailTeam)
		})
	}
}

func TestEnqueueWindowsMDMCommand(t *testing.T) {
	ds := new(mock.Store)
	svc, ctx := newTestService(t, ds, nil, nil)
	ds.MDMWindowsInsertCommandForHostsFunc = func(ctx context.Context, deviceIDs []string, cmd *mobius.MDMWindowsCommand) error {
		return nil
	}
	ds.AreHostsConnectedToMobiusMDMFunc = func(ctx context.Context, hosts []*mobius.Host) (map[string]bool, error) {
		res := make(map[string]bool, len(hosts))
		for _, h := range hosts {
			res[h.UUID] = true
		}
		return res, nil
	}

	cases := []struct {
		desc        string
		premium     bool
		xmlCmd      string
		wantErr     string
		wantReqType string
	}{
		{"invalid xml", false, `!!$$`, "The payload isn't valid XML", ""},
		{"empty xml", false, ``, "The payload isn't valid XML", ""},
		{"unrelated xml", false, `<Unrelated></Unrelated>`, "You can run only <Exec> command type", ""},
		{"no command Exec", false, `<Exec></Exec>`, "You can run only a single <Exec> command", ""},
		{"non-exec command", false, `
			<Get>
				<CmdID>1</CmdID>
				<Item>
					<Target>
						<LocURI>./DevDetail/SwV</LocURI>
					</Target>
				</Item>
			</Get>`, "You can run only <Exec> command type", ""},
		{"multi-exec command", false, `
			<Exec>
				<CmdID>1</CmdID>
				<Item>
					<Target>
						<LocURI>./DevDetail/SwV</LocURI>
					</Target>
				</Item>
				<Item>
					<Target>
						<LocURI>./DevDetail/SwV2</LocURI>
					</Target>
				</Item>
			</Exec>`, "You can run only a single <Exec> command", ""},
		{"premium command, non premium license", false, `
			<Exec>
				<CmdID>1</CmdID>
				<Item>
					<Target>
						<LocURI>./Device/Vendor/MSFT/RemoteWipe/doWipe</LocURI>
					</Target>
				</Item>
			</Exec>`, "Requires Mobius Premium license", ""},
		{"premium command, premium license", true, `
			<Exec>
				<CmdID>1</CmdID>
				<Item>
					<Target>
						<LocURI>./Device/Vendor/MSFT/RemoteWipe/doWipe</LocURI>
					</Target>
				</Item>
			</Exec>`, "", "./Device/Vendor/MSFT/RemoteWipe/doWipe"},
		{"non-premium command", false, `
			<Exec>
				<CmdID>1</CmdID>
				<Item>
					<Target>
						<LocURI>./FooBar</LocURI>
					</Target>
				</Item>
			</Exec>`, "", "./FooBar"},
		{"multi top-level Execs", false, `
			<Exec>
				<CmdID>1</CmdID>
				<Item>
					<Target>
						<LocURI>./FooBar</LocURI>
					</Target>
				</Item>
			</Exec>
			<Exec>
				<CmdID>2</CmdID>
				<Item>
					<Target>
						<LocURI>./FooBar2</LocURI>
					</Target>
				</Item>
			</Exec>`, "You can run only a single <Exec> command", ""},
	}

	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			ctx = test.UserContext(ctx, test.UserAdmin)
			if c.premium {
				ctx = license.NewContext(ctx, &mobius.LicenseInfo{Tier: mobius.TierPremium})
			}

			var svcImpl *Service
			switch v := svc.(type) {
			case validationMiddleware:
				svcImpl = v.Service.(*Service)
			case *Service:
				svcImpl = v
			}
			res, err := svcImpl.enqueueMicrosoftMDMCommand(ctx, []byte(c.xmlCmd), []string{"uuid"})

			if c.wantErr != "" {
				require.Error(t, err)
				require.ErrorContains(t, err, c.wantErr)
			} else {
				require.NoError(t, err)
				require.NotEmpty(t, res.CommandUUID)
				require.Equal(t, "windows", res.Platform)
				require.Equal(t, c.wantReqType, res.RequestType)
			}
		})
	}
}

func TestGetMDMDiskEncryptionSummary(t *testing.T) {
	ds := new(mock.Store)
	license := &mobius.LicenseInfo{Tier: mobius.TierPremium}
	svc, ctx := newTestService(t, ds, nil, nil, &TestServerOpts{License: license})

	ctx = test.UserContext(ctx, test.UserAdmin)

	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		return &mobius.AppConfig{MDM: mobius.MDM{EnabledAndConfigured: true}}, nil
	}
	ds.GetMDMAppleFileVaultSummaryFunc = func(ctx context.Context, teamID *uint) (*mobius.MDMAppleFileVaultSummary, error) {
		require.Nil(t, teamID)
		return &mobius.MDMAppleFileVaultSummary{Verified: 1, Verifying: 2, ActionRequired: 3, Failed: 4, Enforcing: 5, RemovingEnforcement: 6}, nil
	}
	ds.GetMDMWindowsBitLockerSummaryFunc = func(ctx context.Context, teamID *uint) (*mobius.MDMWindowsBitLockerSummary, error) {
		require.Nil(t, teamID)
		// Use default zeros verifying, action_required, or removing_enforcement
		return &mobius.MDMWindowsBitLockerSummary{Verified: 7, Failed: 8, Enforcing: 9}, nil
	}
	ds.AreHostsConnectedToMobiusMDMFunc = func(ctx context.Context, hosts []*mobius.Host) (map[string]bool, error) {
		res := make(map[string]bool, len(hosts))
		for _, h := range hosts {
			res[h.UUID] = true
		}
		return res, nil
	}

	ds.GetLinuxDiskEncryptionSummaryFunc = func(ctx context.Context, teamID *uint) (mobius.MDMLinuxDiskEncryptionSummary, error) {
		require.Nil(t, teamID)
		return mobius.MDMLinuxDiskEncryptionSummary{Verified: 1, ActionRequired: 2, Failed: 3}, nil
	}
	ds.GetConfigEnableDiskEncryptionFunc = func(ctx context.Context, teamID *uint) (bool, error) {
		return true, nil
	}

	// Test that the summary properly combines the results of the two methods
	des, err := svc.GetMDMDiskEncryptionSummary(ctx, nil)
	require.NoError(t, err)
	require.NotNil(t, des)
	require.Equal(t, *des, mobius.MDMDiskEncryptionSummary{
		Verified: mobius.MDMPlatformsCounts{
			MacOS:   1,
			Windows: 7,
			Linux:   1,
		},
		Verifying: mobius.MDMPlatformsCounts{
			MacOS:   2,
			Windows: 0,
		},
		ActionRequired: mobius.MDMPlatformsCounts{
			MacOS:   3,
			Windows: 0,
			Linux:   2,
		},
		Failed: mobius.MDMPlatformsCounts{
			MacOS:   4,
			Windows: 8,
			Linux:   3,
		},
		Enforcing: mobius.MDMPlatformsCounts{
			MacOS:   5,
			Windows: 9,
		},
		RemovingEnforcement: mobius.MDMPlatformsCounts{
			MacOS:   6,
			Windows: 0,
		},
	})
}

// TODO: Add tests for Apple DDM authz?

func TestMDMWindowsConfigProfileAuthz(t *testing.T) {
	ds := new(mock.Store)
	// while the config profiles are not premium-only, teams are and we want to test with teams.
	license := &mobius.LicenseInfo{Tier: mobius.TierPremium}
	svc, ctx := newTestService(t, ds, nil, nil, &TestServerOpts{License: license, SkipCreateTestUsers: true})

	testCases := []struct {
		name                  string
		user                  *mobius.User
		shouldFailGlobalRead  bool
		shouldFailTeamRead    bool
		shouldFailGlobalWrite bool
		shouldFailTeamWrite   bool
	}{
		{
			"global admin",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)},
			false,
			false,
			false,
			false,
		},
		{
			"global maintainer",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleMaintainer)},
			false,
			false,
			false,
			false,
		},
		{
			"global observer",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleObserver)},
			true,
			true,
			true,
			true,
		},
		{
			"global observer+",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleObserverPlus)},
			true,
			true,
			true,
			true,
		},
		{
			// this is authorized because any logged-in user can read teams (the
			// first authorization check) and then gitops have write-access the the
			// profiles.
			"global gitops",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleGitOps)},
			false,
			false,
			false,
			false,
		},
		{
			"team admin, belongs to team",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleAdmin}}},
			true,
			false,
			true,
			false,
		},
		{
			"team admin, DOES NOT belong to team",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 2}, Role: mobius.RoleAdmin}}},
			true,
			true,
			true,
			true,
		},
		{
			"team maintainer, belongs to team",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleMaintainer}}},
			true,
			false,
			true,
			false,
		},
		{
			"team maintainer, DOES NOT belong to team",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 2}, Role: mobius.RoleMaintainer}}},
			true,
			true,
			true,
			true,
		},
		{
			"team observer, belongs to team",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleObserver}}},
			true,
			true,
			true,
			true,
		},
		{
			"team observer, DOES NOT belong to team",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 2}, Role: mobius.RoleObserver}}},
			true,
			true,
			true,
			true,
		},
		{
			"team observer+, belongs to team",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleObserverPlus}}},
			true,
			true,
			true,
			true,
		},
		{
			"team observer+, DOES NOT belong to team",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 2}, Role: mobius.RoleObserverPlus}}},
			true,
			true,
			true,
			true,
		},
		{
			// this is authorized because any logged-in user can read teams (the
			// first authorization check) and then gitops have write-access the the
			// profiles.
			"team gitops, belongs to team",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleGitOps}}},
			true,
			false,
			true,
			false,
		},
		{
			"team gitops, DOES NOT belong to team",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 2}, Role: mobius.RoleGitOps}}},
			true,
			true,
			true,
			true,
		},
		{
			"user no roles",
			&mobius.User{ID: 1337},
			true,
			true,
			true,
			true,
		},
	}

	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		return &mobius.AppConfig{
			MDM: mobius.MDM{
				EnabledAndConfigured:        true,
				WindowsEnabledAndConfigured: true,
			},
		}, nil
	}
	ds.NewActivityFunc = func(context.Context, *mobius.User, mobius.ActivityDetails, []byte, time.Time) error {
		return nil
	}
	ds.GetMDMWindowsConfigProfileFunc = func(ctx context.Context, pid string) (*mobius.MDMWindowsConfigProfile, error) {
		var tid uint
		if pid == "team-1" {
			tid = 1
		}
		return &mobius.MDMWindowsConfigProfile{
			ProfileUUID: pid,
			TeamID:      &tid,
		}, nil
	}
	ds.TeamFunc = func(ctx context.Context, tid uint) (*mobius.Team, error) {
		return &mobius.Team{ID: tid, Name: "team1"}, nil
	}
	ds.DeleteMDMWindowsConfigProfileFunc = func(ctx context.Context, profileUUID string) error {
		return nil
	}
	ds.NewMDMWindowsConfigProfileFunc = func(ctx context.Context, cp mobius.MDMWindowsConfigProfile) (*mobius.MDMWindowsConfigProfile, error) {
		return &cp, nil
	}
	ds.ListMDMConfigProfilesFunc = func(ctx context.Context, teamID *uint, opt mobius.ListOptions) ([]*mobius.MDMConfigProfilePayload, *mobius.PaginationMetadata, error) {
		return nil, nil, nil
	}
	ds.BulkSetPendingMDMHostProfilesFunc = func(ctx context.Context, hostIDs []uint, teamIDs []uint, profileUUIDs []string,
		hostUUIDs []string,
	) (updates mobius.MDMProfilesUpdates, err error) {
		return mobius.MDMProfilesUpdates{}, nil
	}
	ds.ValidateEmbeddedSecretsFunc = func(ctx context.Context, documents []string) error {
		return nil
	}

	checkShouldFail := func(t *testing.T, err error, shouldFail bool) {
		if !shouldFail {
			require.NoError(t, err)
		} else {
			require.Error(t, err)
			require.Contains(t, err.Error(), authz.ForbiddenErrorMessage)
		}
	}

	const winProfContent = `<Replace></Replace>`
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			ctx := viewer.NewContext(ctx, viewer.Viewer{User: tt.user})

			// test authz get config profile (no team)
			_, err := svc.GetMDMWindowsConfigProfile(ctx, "global")
			checkShouldFail(t, err, tt.shouldFailGlobalRead)

			// test authz get config profile (team 1)
			_, err = svc.GetMDMWindowsConfigProfile(ctx, "team-1")
			checkShouldFail(t, err, tt.shouldFailTeamRead)

			// test authz list config profiles (no team)
			_, _, err = svc.ListMDMConfigProfiles(ctx, nil, mobius.ListOptions{})
			checkShouldFail(t, err, tt.shouldFailGlobalRead)

			// test authz list config profiles (team 1)
			_, _, err = svc.ListMDMConfigProfiles(ctx, ptr.Uint(1), mobius.ListOptions{})
			checkShouldFail(t, err, tt.shouldFailTeamRead)

			// test authz create new profile (no team)
			_, err = svc.NewMDMWindowsConfigProfile(ctx, 0, "prof", strings.NewReader(winProfContent), nil, mobius.LabelsIncludeAll)
			checkShouldFail(t, err, tt.shouldFailGlobalWrite)

			// test authz create new profile (team 1)
			_, err = svc.NewMDMWindowsConfigProfile(ctx, 1, "prof", strings.NewReader(winProfContent), nil, mobius.LabelsIncludeAll)
			checkShouldFail(t, err, tt.shouldFailTeamWrite)

			// test authz delete config profile (no team)
			err = svc.DeleteMDMWindowsConfigProfile(ctx, "global")
			checkShouldFail(t, err, tt.shouldFailGlobalWrite)

			// test authz delete config profile (team 1)
			err = svc.DeleteMDMWindowsConfigProfile(ctx, "team-1")
			checkShouldFail(t, err, tt.shouldFailTeamWrite)
		})
	}
}

func TestUploadWindowsMDMConfigProfileValidations(t *testing.T) {
	ds := new(mock.Store)
	license := &mobius.LicenseInfo{Tier: mobius.TierPremium}
	svc, ctx := newTestService(t, ds, nil, nil, &TestServerOpts{License: license, SkipCreateTestUsers: true})

	ds.TeamFunc = func(ctx context.Context, tid uint) (*mobius.Team, error) {
		if tid != 1 {
			return nil, &notFoundError{}
		}
		return &mobius.Team{ID: tid, Name: "team1"}, nil
	}
	ds.NewActivityFunc = func(context.Context, *mobius.User, mobius.ActivityDetails, []byte, time.Time) error {
		return nil
	}
	ds.NewMDMWindowsConfigProfileFunc = func(ctx context.Context, cp mobius.MDMWindowsConfigProfile) (*mobius.MDMWindowsConfigProfile, error) {
		if bytes.Contains(cp.SyncML, []byte("duplicate")) {
			return nil, &alreadyExistsError{}
		}
		cp.ProfileUUID = uuid.New().String()
		return &cp, nil
	}
	ds.BulkSetPendingMDMHostProfilesFunc = func(ctx context.Context, hostIDs []uint, teamIDs []uint, profileUUIDs []string,
		hostUUIDs []string,
	) (updates mobius.MDMProfilesUpdates, err error) {
		return mobius.MDMProfilesUpdates{}, nil
	}
	ds.ExpandEmbeddedSecretsFunc = func(ctx context.Context, document string) (string, error) {
		return document, nil
	}
	ds.ValidateEmbeddedSecretsFunc = func(ctx context.Context, documents []string) error {
		return nil
	}

	cases := []struct {
		desc          string
		tmID          uint
		profile       string
		mdmConfigured bool
		wantErr       string
	}{
		{"empty profile", 0, "", true, "The file should include valid XML."},
		{"plist data", 0, string(mcBytesForTest("Foo", "Bar", "UUID")), true, "The file should include valid XML: processing instructions are not allowed."},
		{"random non-xml data", 0, "\x00\x01\x02", true, "The file should include valid XML:"},
		{"valid windows profile", 0, `<Replace></Replace>`, true, ""},
		{"mdm not enabled", 0, `<Replace></Replace>`, false, "Windows MDM isn't turned on."},
		{"duplicate profile name", 0, `<Replace>duplicate</Replace>`, true, "configuration profile with this name already exists"},
		{"multiple Replace", 0, `<Replace>a</Replace><Replace>b</Replace>`, true, ""},
		{"Replace and non-Replace", 0, `<Replace>a</Replace><Get>b</Get>`, true, "Windows configuration profiles can only have <Replace> or <Add> top level elements."},
		{
			"BitLocker profile", 0,
			`<Replace><Item><Target><LocURI>./Device/Vendor/MSFT/BitLocker/AllowStandardUserEncryption</LocURI></Target></Item></Replace>`, true,
			syncml.DiskEncryptionProfileRestrictionErrMsg,
		},
		{"Windows updates profile", 0, `<Replace><Item><Target><LocURI> ./Device/Vendor/MSFT/Policy/Config/Update/ConfigureDeadlineNoAutoRebootForFeatureUpdates </LocURI></Target></Item></Replace>`, true, "Custom configuration profiles can't include Windows updates settings."},
		{"unsupported Mobius variable", 0, `<Replace>$MOBIUS_VAR_BOZO</Replace>`, true, "Mobius variable"},

		{"team empty profile", 1, "", true, "The file should include valid XML."},
		{"team plist data", 1, string(mcBytesForTest("Foo", "Bar", "UUID")), true, "The file should include valid XML: processing instructions are not allowed."},
		{"team random non-xml data", 1, "\x00\x01\x02", true, "The file should include valid XML:"},
		{"team valid windows profile", 1, `<Replace></Replace>`, true, ""},
		{"team mdm not enabled", 1, `<Replace></Replace>`, false, "Windows MDM isn't turned on."},
		{"team duplicate profile name", 1, `<Replace>duplicate</Replace>`, true, "configuration profile with this name already exists"},
		{"team multiple Replace", 1, `<Replace>a</Replace><Replace>b</Replace>`, true, ""},
		{"team Replace and non-Replace", 1, `<Replace>a</Replace><Get>b</Get>`, true, "Windows configuration profiles can only have <Replace> or <Add> top level elements."},
		{
			"team BitLocker profile", 1,
			`<Replace><Item><Target><LocURI>./Device/Vendor/MSFT/BitLocker/AllowStandardUserEncryption</LocURI></Target></Item></Replace>`, true,
			syncml.DiskEncryptionProfileRestrictionErrMsg,
		},
		{"team Windows updates profile", 1, `<Replace><Item><Target><LocURI> ./Device/Vendor/MSFT/Policy/Config/Update/ConfigureDeadlineNoAutoRebootForFeatureUpdates </LocURI></Target></Item></Replace>`, true, "Custom configuration profiles can't include Windows updates settings."},

		{"invalid team", 2, `<Replace></Replace>`, true, "not found"},
	}

	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
				return &mobius.AppConfig{
					MDM: mobius.MDM{
						EnabledAndConfigured:        true,
						WindowsEnabledAndConfigured: c.mdmConfigured,
					},
				}, nil
			}
			ctx = test.UserContext(ctx, test.UserAdmin)
			_, err := svc.NewMDMWindowsConfigProfile(ctx, c.tmID, "foo", strings.NewReader(c.profile), nil, mobius.LabelsIncludeAll)
			if c.wantErr != "" {
				require.Error(t, err)
				require.ErrorContains(t, err, c.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestMDMBatchSetProfiles(t *testing.T) {
	ds := new(mock.Store)
	svc, ctx := newTestService(t, ds, nil, nil, &TestServerOpts{License: &mobius.LicenseInfo{Tier: mobius.TierPremium}, SkipCreateTestUsers: true})

	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		return &mobius.AppConfig{
			OrgInfo: mobius.OrgInfo{
				OrgName: "Foo Inc.",
			},
			ServerSettings: mobius.ServerSettings{
				ServerURL: "https://foo.example.com",
			},
			MDM: mobius.MDM{
				EnabledAndConfigured:        true,
				WindowsEnabledAndConfigured: true,
			},
		}, nil
	}

	ds.TeamByNameFunc = func(ctx context.Context, name string) (*mobius.Team, error) {
		return &mobius.Team{ID: 1, Name: name}, nil
	}
	ds.TeamFunc = func(ctx context.Context, id uint) (*mobius.Team, error) {
		return &mobius.Team{ID: id, Name: "team"}, nil
	}
	ds.BatchSetMDMProfilesFunc = func(ctx context.Context, tmID *uint, macProfiles []*mobius.MDMAppleConfigProfile,
		winProfiles []*mobius.MDMWindowsConfigProfile, macDecls []*mobius.MDMAppleDeclaration, profVars []mobius.MDMProfileIdentifierMobiusVariables,
	) (updates mobius.MDMProfilesUpdates, err error) {
		return mobius.MDMProfilesUpdates{}, nil
	}
	ds.NewActivityFunc = func(
		ctx context.Context, user *mobius.User, activity mobius.ActivityDetails, details []byte, createdAt time.Time,
	) error {
		return nil
	}
	ds.BulkSetPendingMDMHostProfilesFunc = func(ctx context.Context, hostIDs []uint, teamIDs []uint, profileUUIDs []string,
		hostUUIDs []string,
	) (updates mobius.MDMProfilesUpdates, err error) {
		return mobius.MDMProfilesUpdates{}, nil
	}
	ds.ValidateEmbeddedSecretsFunc = func(ctx context.Context, documents []string) error {
		return nil
	}
	ds.ExpandEmbeddedSecretsAndUpdatedAtFunc = func(ctx context.Context, document string) (string, *time.Time, error) {
		return document, nil, nil
	}

	testCases := []struct {
		name     string
		user     *mobius.User
		premium  bool
		teamID   *uint
		teamName *string
		profiles []mobius.MDMProfileBatchPayload
		wantErr  string
	}{
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
			"duplicate macOS profile name",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)},
			true,
			ptr.Uint(1),
			nil,
			[]mobius.MDMProfileBatchPayload{
				{Name: "N1", Contents: mobileconfigForTest("N1", "I1")},
				{Name: "N2", Contents: mobileconfigForTest("N1", "I2")},
			},
			`The name provided for the profile must match the profile PayloadDisplayName: "N1"`,
		},
		{
			"duplicate macOS profile identifier",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)},
			true,
			ptr.Uint(1),
			nil,
			[]mobius.MDMProfileBatchPayload{
				{Name: "N1", Contents: mobileconfigForTest("N1", "I1")},
				{Name: "N2", Contents: mobileconfigForTest("N2", "I2")},
				{Name: "N3", Contents: mobileconfigForTest("N3", "I1")},
			},
			`More than one configuration profile have the same identifier (PayloadIdentifier): "I1"`,
		},
		{
			"only macOS",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)},
			false,
			nil,
			nil,
			[]mobius.MDMProfileBatchPayload{
				{Name: "N1", Contents: mobileconfigForTest("N1", "I1")},
				{Name: "N2", Contents: mobileconfigForTest("N2", "I2")},
				{Name: "N3", Contents: mobileconfigForTest("N3", "I3 $MOBIUS_VAR_HOST_END_USER_EMAIL_IDP")},
				{Name: "N4", Contents: declBytesForTest("D1", "d1content")},
			},
			``,
		},
		{
			"mixed profiles",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)},
			false,
			nil,
			nil,
			[]mobius.MDMProfileBatchPayload{
				{Name: "N1", Contents: syncMLForTest("./foo/bar")},
				{Name: "N2", Contents: syncMLForTest("./baz")},
				{Name: "N3", Contents: syncMLForTest("./zab")},
				{Name: "N4", Contents: mobileconfigForTest("N4", "I1")},
				{Name: "N5", Contents: mobileconfigForTest("N5", "I2")},
				{Name: "N6", Contents: mobileconfigForTest("N6", "I3")},
			},
			``,
		},
		{
			"only windows",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)},
			false,
			nil,
			nil,
			[]mobius.MDMProfileBatchPayload{
				{Name: "N1", Contents: syncMLForTest("./foo/bar")},
				{Name: "N2", Contents: syncMLForTest("./baz")},
				{Name: "N3", Contents: syncMLForTest("./zab")},
			},
			``,
		},
		{
			"unsupported payload type",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)},
			false,
			nil,
			nil,
			[]mobius.MDMProfileBatchPayload{
				{
					Name: "foo", Contents: []byte(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
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
			</plist>`, mobileconfig.MobiusFileVaultPayloadType)),
				},
			},
			mobileconfig.DiskEncryptionProfileRestrictionErrMsg,
		},
		{
			"unsupported Apple config profile Mobius variable",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)},
			false,
			nil,
			nil,
			[]mobius.MDMProfileBatchPayload{
				{Name: "N4", Contents: mobileconfigForTest("N4", "I${MOBIUS_VAR_BOZO}1")},
			},
			"Mobius variable",
		},
		{
			"unsupported Apple declaration Mobius variable",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)},
			false,
			nil,
			nil,
			[]mobius.MDMProfileBatchPayload{
				{Name: "N4", Contents: declBytesForTest("D1", "d1content ${MOBIUS_VAR_BOZO}")},
			},
			"Mobius variable",
		},
		{
			"unsupported Windows Mobius variable",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)},
			false,
			nil,
			nil,
			[]mobius.MDMProfileBatchPayload{
				{Name: "N1", Contents: syncMLForTest("./foo/$MOBIUS_VAR_BOZO/bar")},
			},
			"Mobius variable",
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			defer func() { ds.BatchSetMDMProfilesFuncInvoked = false }()

			// prepare the context with the user and license
			ctx := viewer.NewContext(ctx, viewer.Viewer{User: tt.user})
			tier := mobius.TierFree
			if tt.premium {
				tier = mobius.TierPremium
			}
			ctx = license.NewContext(ctx, &mobius.LicenseInfo{Tier: tier})

			err := svc.BatchSetMDMProfiles(ctx, tt.teamID, tt.teamName, tt.profiles, false, false, nil, false)
			if tt.wantErr == "" {
				require.NoError(t, err)
				require.True(t, ds.BatchSetMDMProfilesFuncInvoked)
				return
			}
			require.Error(t, err)
			require.ErrorContains(t, err, tt.wantErr)
			require.False(t, ds.BatchSetMDMProfilesFuncInvoked)
		})
	}
}

func TestValidateProfiles(t *testing.T) {
	tests := []struct {
		name     string
		profiles []mobius.MDMProfileBatchPayload
		wantErr  bool
		errMsg   string
	}{
		{
			name: "Valid Darwin Profile",
			profiles: []mobius.MDMProfileBatchPayload{
				{Name: "darwinProfile", Contents: []byte("<?xml version=\"1.0\" encoding=\"UTF-8\"?>")},
			},
			wantErr: false,
		},
		{
			name: "Valid Windows Profile",
			profiles: []mobius.MDMProfileBatchPayload{
				{Name: "windowsProfile", Contents: []byte("<replace><Target><LocURI>Custom/URI</LocURI></Target></replace>")},
			},
			wantErr: false,
		},
		{
			name: "Invalid Profile",
			profiles: []mobius.MDMProfileBatchPayload{
				{Name: "invalidProfile", Contents: []byte("invalid data")},
			},
			wantErr: true,
		},
		{
			name: "Mixed Valid and Invalid Profiles",
			profiles: []mobius.MDMProfileBatchPayload{
				{Name: "validProfile", Contents: []byte("<?xml version=\"1.0\" encoding=\"UTF-8\"?>")},
				{Name: "invalidProfile", Contents: []byte("invalid data")},
			},
			wantErr: true,
		},
		{
			name: "Empty Profile",
			profiles: []mobius.MDMProfileBatchPayload{
				{Name: "emptyProfile", Contents: []byte("")},
			},
			wantErr: true,
		},
		{
			name: "Windows Profile With Deprecated Labels",
			profiles: []mobius.MDMProfileBatchPayload{
				{Name: "windowsProfile", Labels: []string{"a"}, Contents: []byte("<replace><Target><LocURI>Custom/URI</LocURI></Target></replace>")},
			},
			wantErr: false,
		},
		{
			name: "Windows Profile With Excluded Labels",
			profiles: []mobius.MDMProfileBatchPayload{
				{Name: "windowsProfile", LabelsExcludeAny: []string{"a"}, Contents: []byte("<replace><Target><LocURI>Custom/URI</LocURI></Target></replace>")},
			},
			wantErr: false,
		},
		{
			name: "Windows Profile With Included Labels",
			profiles: []mobius.MDMProfileBatchPayload{
				{Name: "windowsProfile", LabelsIncludeAll: []string{"a"}, Contents: []byte("<replace><Target><LocURI>Custom/URI</LocURI></Target></replace>")},
			},
			wantErr: false,
		},
		{
			name: "Windows Profile With Mixed Labels",
			profiles: []mobius.MDMProfileBatchPayload{
				{Name: "windowsProfile", Labels: []string{"z"}, LabelsIncludeAll: []string{"a"}, Contents: []byte("<replace><Target><LocURI>Custom/URI</LocURI></Target></replace>")},
			},
			wantErr: true,
		},
		{
			name: "Too large profile",
			profiles: []mobius.MDMProfileBatchPayload{
				{Name: "hugeprofile", Contents: []byte(strings.Repeat("a", 1024*1024+1))},
			},
			wantErr: true,
			errMsg:  "validation failed: mdm maximum configuration profile file size is 1 MB",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Convert slice to a map
			profiles := make(map[int]mobius.MDMProfileBatchPayload, len(tt.profiles))
			for i, profile := range tt.profiles {
				profiles[i] = profile
			}
			err := validateProfiles(profiles)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					require.Equal(t, tt.errMsg, err.Error())
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestBackwardsCompatProfilesParamUnmarshalJSON(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		expect      backwardsCompatProfilesParam
		expectError bool
	}{
		{
			name:        "empty input",
			input:       []byte(""),
			expect:      nil,
			expectError: false,
		},
		{
			name:  "new format",
			input: []byte(`[{"name": "profile1", "contents": "Zm9vCg=="}, {"name": "profile2", "contents": "YmFyCg=="}]`),
			expect: backwardsCompatProfilesParam{
				{Name: "profile1", Contents: []byte("foo\n")},
				{Name: "profile2", Contents: []byte("bar\n")},
			},
			expectError: false,
		},
		{
			name:  "new format with labels",
			input: []byte(`[{"name": "profile1", "contents": "Zm9vCg==", "labels": ["foo", "bar"]}, {"name": "profile2", "contents": "YmFyCg=="}]`),
			expect: backwardsCompatProfilesParam{
				{Name: "profile1", Contents: []byte("foo\n"), Labels: []string{"foo", "bar"}},
				{Name: "profile2", Contents: []byte("bar\n")},
			},
			expectError: false,
		},
		{
			name:  "old format",
			input: []byte(`{"profile1": "Zm9vCg==", "profile2": "YmFyCg=="}`),
			expect: backwardsCompatProfilesParam{
				{Name: "profile1", Contents: []byte("foo\n")},
				{Name: "profile2", Contents: []byte("bar\n")},
			},
			expectError: false,
		},
		{
			name:        "invalid json",
			input:       []byte(`{invalid json}`),
			expect:      nil,
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var bcp backwardsCompatProfilesParam
			err := bcp.UnmarshalJSON(tc.input)
			if tc.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.ElementsMatch(t, tc.expect, bcp)
			}
		})
	}
}

func TestMDMResendConfigProfileAuthz(t *testing.T) {
	ds := new(mock.Store)
	// while the config profiles are not premium-only, teams are and we want to test with teams.
	license := &mobius.LicenseInfo{Tier: mobius.TierPremium}
	svc, ctx := newTestService(t, ds, nil, nil, &TestServerOpts{License: license, SkipCreateTestUsers: true})

	testCases := []struct {
		name                  string
		user                  *mobius.User
		shouldFailGlobalRead  bool
		shouldFailTeamRead    bool
		shouldFailGlobalWrite bool
		shouldFailTeamWrite   bool
	}{
		{
			"global admin",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)},
			false,
			false,
			false,
			false,
		},
		{
			"global maintainer",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleMaintainer)},
			false,
			false,
			false,
			false,
		},
		{
			"global observer",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleObserver)},
			true,
			true,
			true,
			true,
		},
		{
			"global observer+",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleObserverPlus)},
			true,
			true,
			true,
			true,
		},
		{
			// this is authorized because gitops can access hosts by identifier (the
			// first authorization check) and then gitops have write-access the
			// profiles.
			"global gitops",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleGitOps)},
			false,
			false,
			false,
			false,
		},
		{
			"team admin, belongs to team",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleAdmin}}},
			true,
			false,
			true,
			false,
		},
		{
			"team admin, DOES NOT belong to team",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 2}, Role: mobius.RoleAdmin}}},
			true,
			true,
			true,
			true,
		},
		{
			"team maintainer, belongs to team",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleMaintainer}}},
			true,
			false,
			true,
			false,
		},
		{
			"team maintainer, DOES NOT belong to team",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 2}, Role: mobius.RoleMaintainer}}},
			true,
			true,
			true,
			true,
		},
		{
			"team observer, belongs to team",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleObserver}}},
			true,
			true,
			true,
			true,
		},
		{
			"team observer, DOES NOT belong to team",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 2}, Role: mobius.RoleObserver}}},
			true,
			true,
			true,
			true,
		},
		{
			"team observer+, belongs to team",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleObserverPlus}}},
			true,
			true,
			true,
			true,
		},
		{
			"team observer+, DOES NOT belong to team",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 2}, Role: mobius.RoleObserverPlus}}},
			true,
			true,
			true,
			true,
		},
		{
			// this is authorized because gitops can access hosts by identifier (the
			// first authorization check) and then gitops have write-access the
			// profiles.
			"team gitops, belongs to team",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleGitOps}}},
			true,
			false,
			true,
			false,
		},
		{
			"team gitops, DOES NOT belong to team",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 2}, Role: mobius.RoleGitOps}}},
			true,
			true,
			true,
			true,
		},
		{
			"user no roles",
			&mobius.User{ID: 1337},
			true,
			true,
			true,
			true,
		},
	}

	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		return &mobius.AppConfig{
			MDM: mobius.MDM{
				EnabledAndConfigured:        true,
				WindowsEnabledAndConfigured: true,
			},
		}, nil
	}

	ds.HostLiteFunc = func(ctx context.Context, hid uint) (*mobius.Host, error) {
		if hid == 1 {
			return &mobius.Host{ID: hid, UUID: "host-uuid-1", Platform: "darwin", TeamID: ptr.Uint(1)}, nil
		} else if hid == 1337 {
			return &mobius.Host{ID: hid, UUID: "host-uuid-no-team", Platform: "darwin", TeamID: nil}, nil
		}
		return nil, &notFoundErr{}
	}
	ds.GetMDMAppleConfigProfileFunc = func(ctx context.Context, pid string) (*mobius.MDMAppleConfigProfile, error) {
		var tid uint
		if pid == "a-team-1-profile" {
			tid = 1
		}
		return &mobius.MDMAppleConfigProfile{
			ProfileUUID: pid,
			TeamID:      &tid,
		}, nil
	}
	ds.GetHostMDMProfileInstallStatusFunc = func(ctx context.Context, hostUUID string, profUUID string) (mobius.MDMDeliveryStatus, error) {
		return mobius.MDMDeliveryFailed, nil
	}
	ds.ResendHostMDMProfileFunc = func(ctx context.Context, hostUUID, profUUID string) error {
		return nil
	}
	ds.NewActivityFunc = func(context.Context, *mobius.User, mobius.ActivityDetails, []byte, time.Time) error {
		return nil
	}
	ds.BatchResendMDMProfileToHostsFunc = func(ctx context.Context, profUUID string, filters mobius.BatchResendMDMProfileFilters) (int64, error) {
		return 0, nil
	}

	checkShouldFail := func(t *testing.T, err error, shouldFail bool) {
		if !shouldFail {
			require.NoError(t, err)
		} else {
			require.Error(t, err)
			require.Contains(t, err.Error(), authz.ForbiddenErrorMessage)
		}
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			ctx := viewer.NewContext(ctx, viewer.Viewer{User: tt.user})
			// ds.TeamFunc = mockTeamFuncWithUser(tt.user)

			// test authz resend config profile (no team)
			err := svc.ResendHostMDMProfile(ctx, 1337, "a-no-team-profile")
			checkShouldFail(t, err, tt.shouldFailGlobalWrite)
			err = svc.BatchResendMDMProfileToHosts(ctx, "a-no-team-profile", mobius.BatchResendMDMProfileFilters{ProfileStatus: mobius.MDMDeliveryFailed})
			checkShouldFail(t, err, tt.shouldFailGlobalWrite)

			// test authz resend config profile (team 1)
			err = svc.ResendHostMDMProfile(ctx, 1, "a-team-1-profile")
			checkShouldFail(t, err, tt.shouldFailTeamWrite)
			err = svc.BatchResendMDMProfileToHosts(ctx, "a-team-1-profile", mobius.BatchResendMDMProfileFilters{ProfileStatus: mobius.MDMDeliveryFailed})
			checkShouldFail(t, err, tt.shouldFailTeamWrite)
		})
	}
}

func TestBatchSetMDMProfilesLabels(t *testing.T) {
	ds := new(mock.Store)
	// while the config profiles are not premium-only, teams are and we want to test with teams.
	license := &mobius.LicenseInfo{Tier: mobius.TierPremium}
	svc, ctx := newTestService(t, ds, nil, nil, &TestServerOpts{License: license, SkipCreateTestUsers: true})
	_ = ctx

	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		return &mobius.AppConfig{
			MDM: mobius.MDM{
				EnabledAndConfigured:        true,
				WindowsEnabledAndConfigured: true,
			},
		}, nil
	}
	ds.TeamFunc = func(ctx context.Context, tid uint) (*mobius.Team, error) {
		return &mobius.Team{
			ID:   tid,
			Name: "team1",
		}, nil
	}

	type ProfileLabels struct {
		IncludeAll bool
		IncludeAny bool
		ExcludeAny bool
	}

	profileLabels := map[string]*ProfileLabels{}

	ds.BatchSetMDMProfilesFunc = func(ctx context.Context, tmID *uint, macProfiles []*mobius.MDMAppleConfigProfile, winProfiles []*mobius.MDMWindowsConfigProfile, macDeclarations []*mobius.MDMAppleDeclaration, profVars []mobius.MDMProfileIdentifierMobiusVariables) (updates mobius.MDMProfilesUpdates, err error) {
		for _, profile := range macProfiles {
			profileLabels[profile.Name] = &ProfileLabels{}
			if len(profile.LabelsIncludeAll) > 0 {
				assert.True(t, profile.LabelsIncludeAll[0].RequireAll, "profile label missing RequireAll: %s", profile.Name)
				assert.False(t, profile.LabelsIncludeAll[0].Exclude, "profile label shouldn't have Exclude: %s", profile.Name)
				profileLabels[profile.Name].IncludeAll = true
			}
			if len(profile.LabelsIncludeAny) > 0 {
				assert.False(t, profile.LabelsIncludeAny[0].RequireAll, "profile label shouldn't have RequireAll: %s", profile.Name)
				assert.False(t, profile.LabelsIncludeAny[0].Exclude, "profile label shouldn't have Exclude: %s", profile.Name)
				profileLabels[profile.Name].IncludeAny = true
			}
			if len(profile.LabelsExcludeAny) > 0 {
				assert.False(t, profile.LabelsExcludeAny[0].RequireAll, "profile label shouldn't have RequireAll: %s", profile.Name)
				assert.True(t, profile.LabelsExcludeAny[0].Exclude, "profile label should have Exclude: %s", profile.Name)
				profileLabels[profile.Name].ExcludeAny = true
			}
		}

		for _, profile := range winProfiles {
			profileLabels[profile.Name] = &ProfileLabels{}
			if len(profile.LabelsIncludeAll) > 0 {
				assert.True(t, profile.LabelsIncludeAll[0].RequireAll, "profile label missing RequireAll: %s", profile.Name)
				assert.False(t, profile.LabelsIncludeAll[0].Exclude, "profile label shouldn't have Exclude: %s", profile.Name)
				profileLabels[profile.Name].IncludeAll = true
			}
			if len(profile.LabelsIncludeAny) > 0 {
				assert.False(t, profile.LabelsIncludeAny[0].RequireAll, "profile label shouldn't have RequireAll: %s", profile.Name)
				assert.False(t, profile.LabelsIncludeAny[0].Exclude, "profile label shouldn't have Exclude: %s", profile.Name)
				profileLabels[profile.Name].IncludeAny = true
			}
			if len(profile.LabelsExcludeAny) > 0 {
				assert.False(t, profile.LabelsExcludeAny[0].RequireAll, "profile label shouldn't have RequireAll: %s", profile.Name)
				assert.True(t, profile.LabelsExcludeAny[0].Exclude, "profile label should have Exclude: %s", profile.Name)
				profileLabels[profile.Name].ExcludeAny = true
			}
		}

		for _, profile := range macDeclarations {
			profileLabels[profile.Name] = &ProfileLabels{}
			if len(profile.LabelsIncludeAll) > 0 {
				assert.True(t, profile.LabelsIncludeAll[0].RequireAll, "profile label missing RequireAll: %s", profile.Name)
				assert.False(t, profile.LabelsIncludeAll[0].Exclude, "profile label shouldn't have Exclude: %s", profile.Name)
				profileLabels[profile.Name].IncludeAll = true
			}
			if len(profile.LabelsIncludeAny) > 0 {
				assert.False(t, profile.LabelsIncludeAny[0].RequireAll, "profile label shouldn't have RequireAll: %s", profile.Name)
				assert.False(t, profile.LabelsIncludeAny[0].Exclude, "profile label shouldn't have Exclude: %s", profile.Name)
				profileLabels[profile.Name].IncludeAny = true
			}
			if len(profile.LabelsExcludeAny) > 0 {
				assert.False(t, profile.LabelsExcludeAny[0].RequireAll, "profile label shouldn't have RequireAll: %s", profile.Name)
				assert.True(t, profile.LabelsExcludeAny[0].Exclude, "profile label should have Exclude: %s", profile.Name)
				profileLabels[profile.Name].ExcludeAny = true
			}
		}

		return mobius.MDMProfilesUpdates{}, nil
	}
	ds.BulkSetPendingMDMHostProfilesFunc = func(ctx context.Context, hostIDs, teamIDs []uint, profileUUIDs, hostUUIDs []string) (updates mobius.MDMProfilesUpdates, err error) {
		return mobius.MDMProfilesUpdates{}, nil
	}
	var labelID uint
	ds.LabelIDsByNameFunc = func(ctx context.Context, labels []string) (map[string]uint, error) {
		m := map[string]uint{}
		for _, label := range labels {
			if label != "baddy" {
				labelID++
				m[label] = labelID
			}
		}
		return m, nil
	}
	ds.ValidateEmbeddedSecretsFunc = func(ctx context.Context, documents []string) error {
		return nil
	}
	ds.ExpandEmbeddedSecretsAndUpdatedAtFunc = func(ctx context.Context, document string) (string, *time.Time, error) {
		return document, nil, nil
	}

	profiles := []mobius.MDMProfileBatchPayload{
		// macOS
		{
			Name:             "MIncAll",
			Contents:         mobileconfigForTest("MIncAll", "1"),
			LabelsIncludeAll: []string{"a", "b"},
		},
		{
			Name:             "MIncAny",
			Contents:         mobileconfigForTest("MIncAny", "2"),
			LabelsIncludeAny: []string{"a", "b"},
		},
		{
			Name:             "MExclAny",
			Contents:         mobileconfigForTest("MExclAny", "3"),
			LabelsExcludeAny: []string{"a", "b"},
		},
		// Windows
		{
			Name:             "WIncAll",
			Contents:         syncMLForTest("./Foo/Bar"),
			LabelsIncludeAll: []string{"a", "b"},
		},
		{
			Name:             "WIncAny",
			Contents:         syncMLForTest("./Foo/Barz"),
			LabelsIncludeAny: []string{"a", "b"},
		},
		{
			Name:             "WExclAny",
			Contents:         syncMLForTest("./Foo/Barf"),
			LabelsExcludeAny: []string{"a", "b"},
		},
		// Declarative
		{
			Name:             "DIncAll",
			Contents:         declarationForTest("DIncAll"),
			LabelsIncludeAll: []string{"a", "b"},
		},
		{
			Name:             "DIncAny",
			Contents:         declarationForTest("DIncAny"),
			LabelsIncludeAny: []string{"a", "b"},
		},
		{
			Name:             "DExclAny",
			Contents:         declarationForTest("DExclAny"),
			LabelsExcludeAny: []string{"a", "b"},
		},
	}

	authCtx := test.UserContext(ctx, test.UserAdmin)

	err := svc.BatchSetMDMProfiles(authCtx, ptr.Uint(1), nil, profiles, false, false, ptr.Bool(true), false)
	require.NoError(t, err)

	assert.Equal(t, ProfileLabels{IncludeAll: true}, *profileLabels["MIncAll"])
	assert.Equal(t, ProfileLabels{IncludeAny: true}, *profileLabels["MIncAny"])
	assert.Equal(t, ProfileLabels{ExcludeAny: true}, *profileLabels["MExclAny"])

	assert.Equal(t, ProfileLabels{IncludeAll: true}, *profileLabels["WIncAll"])
	assert.Equal(t, ProfileLabels{IncludeAny: true}, *profileLabels["WIncAny"])
	assert.Equal(t, ProfileLabels{ExcludeAny: true}, *profileLabels["WExclAny"])

	assert.Equal(t, ProfileLabels{IncludeAll: true}, *profileLabels["DIncAll"])
	assert.Equal(t, ProfileLabels{IncludeAny: true}, *profileLabels["DIncAny"])
	assert.Equal(t, ProfileLabels{ExcludeAny: true}, *profileLabels["DExclAny"])

	// Test that a bad label doesn't pass validation...
	err = svc.BatchSetMDMProfiles(authCtx, ptr.Uint(1), nil, []mobius.MDMProfileBatchPayload{{
		Name:             "Baddy",
		Contents:         declarationForTest("Baddy"),
		LabelsExcludeAny: []string{"baddy"},
	}}, false, false, ptr.Bool(true), false)
	require.Error(t, err)
	require.ErrorContains(t, err, "some or all the labels provided don't exist")

	// ...unless we're in dry run mode
	err = svc.BatchSetMDMProfiles(authCtx, ptr.Uint(1), nil, []mobius.MDMProfileBatchPayload{{
		Name:             "Baddy",
		Contents:         declarationForTest("Baddy"),
		LabelsExcludeAny: []string{"baddy"},
	}}, true, false, ptr.Bool(true), false)
	require.NoError(t, err)
}
