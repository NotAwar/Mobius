package service

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/notawar/mobius/ee/server/service/digicert"
	"github.com/notawar/mobius/pkg/optjson"
	"github.com/notawar/mobius/server"
	"github.com/notawar/mobius/server/config"
	"github.com/notawar/mobius/server/contexts/license"
	"github.com/notawar/mobius/server/contexts/viewer"
	nanodep_client "github.com/notawar/mobius/server/mdm/nanodep/client"
	"github.com/notawar/mobius/server/mobius"
	"github.com/notawar/mobius/server/mock"
	nanodep_mock "github.com/notawar/mobius/server/mock/nanodep"
	scep_mock "github.com/notawar/mobius/server/mock/scep"
	"github.com/notawar/mobius/server/ptr"
	"github.com/notawar/mobius/server/test"
	"github.com/go-kit/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAppConfigAuth(t *testing.T) {
	ds := new(mock.Store)
	svc, ctx := newTestService(t, ds, nil, nil)

	// start a TLS server and use its URL as the server URL in the app config,
	// required by the CertificateChain service call.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		return &mobius.AppConfig{
			OrgInfo: mobius.OrgInfo{
				OrgName: "Test",
			},
			ServerSettings: mobius.ServerSettings{
				ServerURL: srv.URL,
			},
		}, nil
	}
	ds.SaveAppConfigFunc = func(ctx context.Context, conf *mobius.AppConfig) error {
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

	testCases := []struct {
		name            string
		user            *mobius.User
		shouldFailWrite bool
		shouldFailRead  bool
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
			true,
			false,
		},
		{
			"global observer",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleObserver)},
			true,
			false,
		},
		{
			"global observer+",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleObserverPlus)},
			true,
			false,
		},
		{
			"global gitops",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleGitOps)},
			false,
			false,
		},
		{
			"team admin",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleAdmin}}},
			true,
			false,
		},
		{
			"team maintainer",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleMaintainer}}},
			true,
			false,
		},
		{
			"team observer",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleObserver}}},
			true,
			false,
		},
		{
			"team observer+",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleObserverPlus}}},
			true,
			false,
		},
		{
			"team gitops",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleGitOps}}},
			true,
			false,
		},
		{
			"user without roles",
			&mobius.User{ID: 777},
			true,
			true,
		},
	}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			ctx := viewer.NewContext(ctx, viewer.Viewer{User: tt.user})

			_, err := svc.AppConfigObfuscated(ctx)
			checkAuthErr(t, tt.shouldFailRead, err)

			_, err = svc.ModifyAppConfig(ctx, []byte(`{}`), mobius.ApplySpecOptions{})
			checkAuthErr(t, tt.shouldFailWrite, err)

			_, err = svc.CertificateChain(ctx)
			checkAuthErr(t, tt.shouldFailRead, err)
		})
	}
}

// TestVersion tests that all users can access the version endpoint.
func TestVersion(t *testing.T) {
	ds := new(mock.Store)
	svc, ctx := newTestService(t, ds, nil, nil)

	testCases := []struct {
		name string
		user *mobius.User
	}{
		{
			"global admin",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)},
		},
		{
			"global maintainer",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleMaintainer)},
		},
		{
			"global observer",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleObserver)},
		},
		{
			"global observer+",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleObserverPlus)},
		},
		{
			"global gitops",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleGitOps)},
		},
		{
			"team admin",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleAdmin}}},
		},
		{
			"team maintainer",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleMaintainer}}},
		},
		{
			"team observer",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleObserver}}},
		},
		{
			"team observer+",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleObserverPlus}}},
		},
		{
			"team gitops",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleGitOps}}},
		},
		{
			"user without roles",
			&mobius.User{ID: 777},
		},
	}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			ctx := viewer.NewContext(ctx, viewer.Viewer{User: tt.user})
			_, err := svc.Version(ctx)
			require.NoError(t, err)
		})
	}
}

func TestEnrollSecretAuth(t *testing.T) {
	ds := new(mock.Store)
	svc, ctx := newTestService(t, ds, nil, nil)

	ds.ApplyEnrollSecretsFunc = func(ctx context.Context, tid *uint, secrets []*mobius.EnrollSecret) error {
		return nil
	}
	ds.GetEnrollSecretsFunc = func(ctx context.Context, tid *uint) ([]*mobius.EnrollSecret, error) {
		return nil, nil
	}

	testCases := []struct {
		name            string
		user            *mobius.User
		shouldFailWrite bool
		shouldFailRead  bool
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
			"team admin",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleAdmin}}},
			true,
			true,
		},
		{
			"team maintainer",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleMaintainer}}},
			true,
			true,
		},
		{
			"team observer",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleObserver}}},
			true,
			true,
		},
		{
			"user",
			&mobius.User{ID: 777},
			true,
			true,
		},
	}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			ctx := viewer.NewContext(ctx, viewer.Viewer{User: tt.user})

			err := svc.ApplyEnrollSecretSpec(
				ctx, &mobius.EnrollSecretSpec{Secrets: []*mobius.EnrollSecret{{Secret: "ABC"}}}, mobius.ApplySpecOptions{},
			)
			checkAuthErr(t, tt.shouldFailWrite, err)

			_, err = svc.GetEnrollSecretSpec(ctx)
			checkAuthErr(t, tt.shouldFailRead, err)
		})
	}
}

func TestApplyEnrollSecretWithGlobalEnrollConfig(t *testing.T) {
	ds := new(mock.Store)

	cfg := config.TestConfig()
	svc, ctx := newTestServiceWithConfig(t, ds, cfg, nil, nil)
	ctx = test.UserContext(ctx, test.UserAdmin)

	// Dry run
	ds.IsEnrollSecretAvailableFunc = func(ctx context.Context, secret string, isNew bool, teamID *uint) (bool, error) {
		assert.False(t, isNew)
		assert.Nil(t, teamID)
		return true, nil
	}
	err := svc.ApplyEnrollSecretSpec(
		ctx, &mobius.EnrollSecretSpec{Secrets: []*mobius.EnrollSecret{{Secret: "ABC"}}}, mobius.ApplySpecOptions{DryRun: true},
	)
	assert.True(t, ds.IsEnrollSecretAvailableFuncInvoked)
	assert.NoError(t, err)

	// Dry run fails
	ds.IsEnrollSecretAvailableFuncInvoked = false
	ds.IsEnrollSecretAvailableFunc = func(ctx context.Context, secret string, isNew bool, teamID *uint) (bool, error) {
		assert.False(t, isNew)
		assert.Nil(t, teamID)
		return false, nil
	}
	err = svc.ApplyEnrollSecretSpec(
		ctx, &mobius.EnrollSecretSpec{Secrets: []*mobius.EnrollSecret{{Secret: "ABC"}}}, mobius.ApplySpecOptions{DryRun: true},
	)
	assert.True(t, ds.IsEnrollSecretAvailableFuncInvoked)
	assert.ErrorContains(t, err, "secret is already being used")

	// Dry run with error
	ds.IsEnrollSecretAvailableFuncInvoked = false
	ds.IsEnrollSecretAvailableFunc = func(ctx context.Context, secret string, isNew bool, teamID *uint) (bool, error) {
		return false, assert.AnError
	}
	err = svc.ApplyEnrollSecretSpec(
		ctx, &mobius.EnrollSecretSpec{Secrets: []*mobius.EnrollSecret{{Secret: "ABC"}}}, mobius.ApplySpecOptions{DryRun: true},
	)
	assert.True(t, ds.IsEnrollSecretAvailableFuncInvoked)
	assert.Equal(t, assert.AnError, err)

	ds.IsEnrollSecretAvailableFunc = nil
	ds.ApplyEnrollSecretsFunc = func(ctx context.Context, teamID *uint, secrets []*mobius.EnrollSecret) error {
		return nil
	}
	err = svc.ApplyEnrollSecretSpec(
		ctx, &mobius.EnrollSecretSpec{Secrets: []*mobius.EnrollSecret{{Secret: "ABC"}}}, mobius.ApplySpecOptions{},
	)
	require.True(t, ds.ApplyEnrollSecretsFuncInvoked)
	require.NoError(t, err)

	// try to change the enroll secret with the config set
	ds.ApplyEnrollSecretsFuncInvoked = false
	cfg.Packaging.GlobalEnrollSecret = "xyz"
	svc, ctx = newTestServiceWithConfig(t, ds, cfg, nil, nil)
	ctx = test.UserContext(ctx, test.UserAdmin)
	err = svc.ApplyEnrollSecretSpec(ctx, &mobius.EnrollSecretSpec{Secrets: []*mobius.EnrollSecret{{Secret: "DEF"}}}, mobius.ApplySpecOptions{})
	require.Error(t, err)
	require.False(t, ds.ApplyEnrollSecretsFuncInvoked)
}

func TestCertificateChain(t *testing.T) {
	server, teardown := setupCertificateChain(t)
	defer teardown()

	certFile := "testdata/server.pem"
	cert, err := tls.LoadX509KeyPair(certFile, "testdata/server.key")
	require.Nil(t, err)
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	server.StartTLS()

	u, err := url.Parse(server.URL)
	require.Nil(t, err)

	conn, err := connectTLS(context.Background(), u)
	require.Nil(t, err)

	have, want := len(conn.ConnectionState().PeerCertificates), len(cert.Certificate)
	require.Equal(t, have, want)

	original, _ := os.ReadFile(certFile)
	returned, err := chain(context.Background(), conn.ConnectionState(), "")
	require.Nil(t, err)
	require.Equal(t, returned, original)
}

func echoHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dump, err := httputil.DumpRequest(r, true)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(dump) //nolint:errcheck
	})
}

func setupCertificateChain(t *testing.T) (server *httptest.Server, teardown func()) {
	server = httptest.NewUnstartedServer(echoHandler())
	return server, server.Close
}

func TestSSONotPresent(t *testing.T) {
	invalid := &mobius.InvalidArgumentError{}
	var p mobius.AppConfig
	validateSSOSettings(p, &mobius.AppConfig{}, invalid, &mobius.LicenseInfo{})
	assert.False(t, invalid.HasErrors())
}

func TestNeedFieldsPresent(t *testing.T) {
	invalid := &mobius.InvalidArgumentError{}
	config := mobius.AppConfig{
		SSOSettings: &mobius.SSOSettings{
			EnableSSO: true,
			SSOProviderSettings: mobius.SSOProviderSettings{
				EntityID:    "mobius",
				IssuerURI:   "http://issuer.idp.com",
				MetadataURL: "http://isser.metadata.com",
				IDPName:     "onelogin",
			},
		},
	}
	validateSSOSettings(config, &mobius.AppConfig{}, invalid, &mobius.LicenseInfo{})
	assert.False(t, invalid.HasErrors())
}

func TestShortIDPName(t *testing.T) {
	invalid := &mobius.InvalidArgumentError{}
	config := mobius.AppConfig{
		SSOSettings: &mobius.SSOSettings{
			EnableSSO: true,
			SSOProviderSettings: mobius.SSOProviderSettings{
				EntityID:    "mobius",
				IssuerURI:   "http://issuer.idp.com",
				MetadataURL: "http://isser.metadata.com",
				// A customer once found the Mobius server erroring when they used "SSO" for their IdP name.
				IDPName: "SSO",
			},
		},
	}
	validateSSOSettings(config, &mobius.AppConfig{}, invalid, &mobius.LicenseInfo{})
	assert.False(t, invalid.HasErrors())
}

func TestMissingMetadata(t *testing.T) {
	invalid := &mobius.InvalidArgumentError{}
	config := mobius.AppConfig{
		SSOSettings: &mobius.SSOSettings{
			EnableSSO: true,
			SSOProviderSettings: mobius.SSOProviderSettings{
				EntityID:  "mobius",
				IssuerURI: "http://issuer.idp.com",
				IDPName:   "onelogin",
			},
		},
	}
	validateSSOSettings(config, &mobius.AppConfig{}, invalid, &mobius.LicenseInfo{})
	require.True(t, invalid.HasErrors())
	assert.Contains(t, invalid.Error(), "metadata")
	assert.Contains(t, invalid.Error(), "either metadata or metadata_url must be defined")
}

func TestSSOValidationValidatesSchemaInMetadataURL(t *testing.T) {
	var schemas []string
	schemas = append(schemas, getURISchemas()...)
	schemas = append(schemas, "asdfaklsdfjalksdfja")

	for _, scheme := range schemas {
		actual := &mobius.InvalidArgumentError{}
		sut := mobius.AppConfig{
			SSOSettings: &mobius.SSOSettings{
				EnableSSO: true,
				SSOProviderSettings: mobius.SSOProviderSettings{
					EntityID:    "mobius",
					IDPName:     "onelogin",
					MetadataURL: fmt.Sprintf("%s://somehost", scheme),
				},
			},
		}

		validateSSOSettings(sut, &mobius.AppConfig{}, actual, &mobius.LicenseInfo{})

		require.Equal(t, scheme == "http" || scheme == "https", !actual.HasErrors())
		require.Equal(t, scheme == "http" || scheme == "https", !strings.Contains(actual.Error(), "metadata_url"))
		require.Equal(t, scheme == "http" || scheme == "https", !strings.Contains(actual.Error(), "must be either https or http"))
	}
}

func TestJITProvisioning(t *testing.T) {
	config := mobius.AppConfig{
		SSOSettings: &mobius.SSOSettings{
			EnableSSO:             true,
			EnableJITProvisioning: true,
			SSOProviderSettings: mobius.SSOProviderSettings{
				EntityID:    "mobius",
				IssuerURI:   "http://issuer.idp.com",
				IDPName:     "onelogin",
				MetadataURL: "http://isser.metadata.com",
			},
		},
	}

	t.Run("doesn't allow to enable JIT provisioning without a premium license", func(t *testing.T) {
		invalid := &mobius.InvalidArgumentError{}
		validateSSOSettings(config, &mobius.AppConfig{}, invalid, &mobius.LicenseInfo{})
		require.True(t, invalid.HasErrors())
		assert.Contains(t, invalid.Error(), "enable_jit_provisioning")
		assert.Contains(t, invalid.Error(), "missing or invalid license")
	})

	t.Run("allows JIT provisioning to be enabled with a premium license", func(t *testing.T) {
		invalid := &mobius.InvalidArgumentError{}
		validateSSOSettings(config, &mobius.AppConfig{}, invalid, &mobius.LicenseInfo{Tier: mobius.TierPremium})
		require.False(t, invalid.HasErrors())
	})

	t.Run("doesn't care if JIT provisioning is set to false on free licenses", func(t *testing.T) {
		invalid := &mobius.InvalidArgumentError{}
		oldConfig := &mobius.AppConfig{
			SSOSettings: &mobius.SSOSettings{
				EnableJITProvisioning: false,
			},
		}
		config.SSOSettings.EnableJITProvisioning = false
		validateSSOSettings(config, oldConfig, invalid, &mobius.LicenseInfo{})
		require.False(t, invalid.HasErrors())
	})
}

func TestAppConfigSecretsObfuscated(t *testing.T) {
	ds := new(mock.Store)
	svc, ctx := newTestService(t, ds, nil, nil)

	// start a TLS server and use its URL as the server URL in the app config,
	// required by the CertificateChain service call.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		return &mobius.AppConfig{
			SMTPSettings: &mobius.SMTPSettings{
				SMTPPassword: "smtppassword",
			},
			Integrations: mobius.Integrations{
				Jira: []*mobius.JiraIntegration{
					{APIToken: "jiratoken"},
				},
				Zendesk: []*mobius.ZendeskIntegration{
					{APIToken: "zendesktoken"},
				},
				GoogleCalendar: []*mobius.GoogleCalendarIntegration{
					{ApiKey: map[string]string{mobius.GoogleCalendarPrivateKey: "google-calendar-private-key"}},
				},
			},
		}, nil
	}

	testCases := []struct {
		name       string
		user       *mobius.User
		shouldFail bool
	}{
		{
			"global admin",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)},
			false,
		},
		{
			"global maintainer",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleMaintainer)},
			false,
		},
		{
			"global observer",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleObserver)},
			false,
		},
		{
			"global observer+",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleObserverPlus)},
			false,
		},
		{
			"global gitops",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleGitOps)},
			false,
		},
		{
			"team admin",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleAdmin}}},
			false,
		},
		{
			"team maintainer",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleMaintainer}}},
			false,
		},
		{
			"team observer",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleObserver}}},
			false,
		},
		{
			"team observer+",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleObserverPlus}}},
			false,
		},
		{
			"team gitops",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleGitOps}}},
			false,
		},
		{
			"user without roles",
			&mobius.User{ID: 777},
			true,
		},
	}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			ctx := viewer.NewContext(ctx, viewer.Viewer{User: tt.user})

			ac, err := svc.AppConfigObfuscated(ctx)
			if tt.shouldFail {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, ac.SMTPSettings.SMTPPassword, mobius.MaskedPassword)
				require.Equal(t, ac.Integrations.Jira[0].APIToken, mobius.MaskedPassword)
				require.Equal(t, ac.Integrations.Zendesk[0].APIToken, mobius.MaskedPassword)
				// Google Calendar private key is not obfuscated
				require.Equal(t, ac.Integrations.GoogleCalendar[0].ApiKey[mobius.GoogleCalendarPrivateKey], "google-calendar-private-key")
			}
		})
	}
}

// TestModifyAppConfigSMTPConfigured tests that disabling SMTP
// should set the SMTPConfigured field to false.
func TestModifyAppConfigSMTPConfigured(t *testing.T) {
	ds := new(mock.Store)
	svc, ctx := newTestService(t, ds, nil, nil)

	// SMTP is initially enabled and configured.
	dsAppConfig := &mobius.AppConfig{
		OrgInfo: mobius.OrgInfo{
			OrgName: "Test",
		},
		ServerSettings: mobius.ServerSettings{
			ServerURL: "https://example.org",
		},
		SMTPSettings: &mobius.SMTPSettings{
			SMTPEnabled:    true,
			SMTPConfigured: true,
		},
	}

	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		return dsAppConfig, nil
	}
	ds.SaveAppConfigFunc = func(ctx context.Context, conf *mobius.AppConfig) error {
		*dsAppConfig = *conf
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

	// Disable SMTP.
	newAppConfig := mobius.AppConfig{
		SMTPSettings: &mobius.SMTPSettings{
			SMTPEnabled:    false,
			SMTPConfigured: true,
		},
	}
	b, err := json.Marshal(newAppConfig.SMTPSettings) // marshaling appconfig sets all fields, resetting e.g. OrgName to empty
	require.NoError(t, err)
	b = []byte(`{"smtp_settings":` + string(b) + `}`)

	admin := &mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)}
	ctx = viewer.NewContext(ctx, viewer.Viewer{User: admin})
	updatedAppConfig, err := svc.ModifyAppConfig(ctx, b, mobius.ApplySpecOptions{})
	require.NoError(t, err)

	// After disabling SMTP, the app config should be "not configured".
	require.False(t, updatedAppConfig.SMTPSettings.SMTPEnabled)
	require.False(t, updatedAppConfig.SMTPSettings.SMTPConfigured)
	require.False(t, dsAppConfig.SMTPSettings.SMTPEnabled)
	require.False(t, dsAppConfig.SMTPSettings.SMTPConfigured)
}

// TestTransparencyURL tests that Mobius Premium licensees can use custom transparency urls and Mobius
// Free licensees are restricted to the default transparency url.
func TestTransparencyURL(t *testing.T) {
	ds := new(mock.Store)

	admin := &mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)}

	checkLicenseErr := func(t *testing.T, shouldFail bool, err error) {
		if shouldFail {
			require.Error(t, err)
			require.ErrorContains(t, err, "missing or invalid license")
		} else {
			require.NoError(t, err)
		}
	}
	testCases := []struct {
		name             string
		licenseTier      string
		initialURL       string
		newURL           string
		expectedURL      string
		shouldFailModify bool
	}{
		{
			name:             "customURL",
			licenseTier:      "free",
			initialURL:       "",
			newURL:           "customURL",
			expectedURL:      "",
			shouldFailModify: true,
		},
		{
			name:             "customURL",
			licenseTier:      mobius.TierPremium,
			initialURL:       "",
			newURL:           "customURL",
			expectedURL:      "customURL",
			shouldFailModify: false,
		},
		{
			name:             "emptyURL",
			licenseTier:      "free",
			initialURL:       "",
			newURL:           "",
			expectedURL:      "",
			shouldFailModify: false,
		},
		{
			name:             "emptyURL",
			licenseTier:      mobius.TierPremium,
			initialURL:       "customURL",
			newURL:           "",
			expectedURL:      "",
			shouldFailModify: false,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			svc, ctx := newTestService(t, ds, nil, nil, &TestServerOpts{License: &mobius.LicenseInfo{Tier: tt.licenseTier}})
			ctx = viewer.NewContext(ctx, viewer.Viewer{User: admin})

			dsAppConfig := &mobius.AppConfig{
				OrgInfo: mobius.OrgInfo{
					OrgName: "Test",
				},
				ServerSettings: mobius.ServerSettings{
					ServerURL: "https://example.org",
				},
				MobiusDesktop: mobius.MobiusDesktopSettings{TransparencyURL: tt.initialURL},
			}

			ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
				return dsAppConfig, nil
			}

			ds.SaveAppConfigFunc = func(ctx context.Context, conf *mobius.AppConfig) error {
				*dsAppConfig = *conf
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

			ac, err := svc.AppConfigObfuscated(ctx)
			require.NoError(t, err)
			require.Equal(t, tt.initialURL, ac.MobiusDesktop.TransparencyURL)

			raw, err := json.Marshal(mobius.MobiusDesktopSettings{TransparencyURL: tt.newURL})
			require.NoError(t, err)
			raw = []byte(`{"mobius_desktop":` + string(raw) + `}`)
			modified, err := svc.ModifyAppConfig(ctx, raw, mobius.ApplySpecOptions{})
			checkLicenseErr(t, tt.shouldFailModify, err)

			if modified != nil {
				require.Equal(t, tt.expectedURL, modified.MobiusDesktop.TransparencyURL)
				ac, err = svc.AppConfigObfuscated(ctx)
				require.NoError(t, err)
				require.Equal(t, tt.expectedURL, ac.MobiusDesktop.TransparencyURL)
			}

			expectedURL := mobius.DefaultTransparencyURL
			expectedSecureframeURL := mobius.SecureframeTransparencyURL
			if tt.expectedURL != "" {
				expectedURL = tt.expectedURL
				expectedSecureframeURL = tt.expectedURL
			}

			transparencyURL, err := svc.GetTransparencyURL(ctx)
			require.NoError(t, err)
			require.Equal(t, expectedURL, transparencyURL)

			cfg := config.TestConfig()
			cfg.Partnerships.EnableSecureframe = true
			svc, ctx = newTestServiceWithConfig(t, ds, cfg, nil, nil, &TestServerOpts{License: &mobius.LicenseInfo{Tier: tt.licenseTier}})
			ctx = viewer.NewContext(ctx, viewer.Viewer{User: admin})
			transparencyURL, err = svc.GetTransparencyURL(ctx)
			require.NoError(t, err)
			require.Equal(t, expectedSecureframeURL, transparencyURL)
		})
	}
}

// TestTransparencyURLDowngradeLicense tests scenarios where a transparency url value has previously
// been stored (for example, if a licensee downgraded without manually resetting the transparency url)
func TestTransparencyURLDowngradeLicense(t *testing.T) {
	ds := new(mock.Store)

	admin := &mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)}

	cfg := config.TestConfig()
	svc, ctx := newTestServiceWithConfig(t, ds, cfg, nil, nil, &TestServerOpts{License: &mobius.LicenseInfo{Tier: "free"}})
	ctx = viewer.NewContext(ctx, viewer.Viewer{User: admin})

	dsAppConfig := &mobius.AppConfig{
		OrgInfo: mobius.OrgInfo{
			OrgName: "Test",
		},
		ServerSettings: mobius.ServerSettings{
			ServerURL: "https://example.org",
		},
		MobiusDesktop: mobius.MobiusDesktopSettings{TransparencyURL: "https://example.com/transparency"},
	}

	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		return dsAppConfig, nil
	}

	ds.SaveAppConfigFunc = func(ctx context.Context, conf *mobius.AppConfig) error {
		*dsAppConfig = *conf
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

	ac, err := svc.AppConfigObfuscated(ctx)
	require.NoError(t, err)
	require.Equal(t, "https://example.com/transparency", ac.MobiusDesktop.TransparencyURL)

	// delivered URL should be the default one
	transparencyUrl, err := svc.GetTransparencyURL(ctx)
	require.NoError(t, err)
	require.Equal(t, mobius.DefaultTransparencyURL, transparencyUrl)

	// delivered URL should be the Secureframe one if we have that config value set
	cfg.Partnerships.EnableSecureframe = true
	svc, ctx = newTestServiceWithConfig(t, ds, cfg, nil, nil, &TestServerOpts{License: &mobius.LicenseInfo{Tier: "free"}})
	ctx = viewer.NewContext(ctx, viewer.Viewer{User: admin})
	transparencyUrl, err = svc.GetTransparencyURL(ctx)
	require.NoError(t, err)
	require.Equal(t, mobius.SecureframeTransparencyURL, transparencyUrl)

	// setting transparency url fails
	raw, err := json.Marshal(mobius.MobiusDesktopSettings{TransparencyURL: "https://f1337.com/transparency"})
	require.NoError(t, err)
	raw = []byte(`{"mobius_desktop":` + string(raw) + `}`)
	_, err = svc.ModifyAppConfig(ctx, raw, mobius.ApplySpecOptions{})
	require.Error(t, err)
	require.ErrorContains(t, err, "missing or invalid license")

	// setting unrelated config value does not fail and resets transparency url to ""
	raw, err = json.Marshal(mobius.OrgInfo{OrgName: "f1337"})
	require.NoError(t, err)
	raw = []byte(`{"org_info":` + string(raw) + `}`)
	modified, err := svc.ModifyAppConfig(ctx, raw, mobius.ApplySpecOptions{})
	require.NoError(t, err)
	require.NotNil(t, modified)
	require.Equal(t, "", modified.MobiusDesktop.TransparencyURL)
	ac, err = svc.AppConfigObfuscated(ctx)
	require.NoError(t, err)
	require.Equal(t, "f1337", ac.OrgInfo.OrgName)
	require.Equal(t, "", ac.MobiusDesktop.TransparencyURL)
}

func TestMDMAppleConfig(t *testing.T) {
	ds := new(mock.Store)
	depStorage := new(nanodep_mock.Storage)

	admin := &mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)}

	depSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		switch r.URL.Path {
		case "/session":
			_, _ = w.Write([]byte(`{"auth_session_token": "xyz"}`))
		case "/profile":
			_, _ = w.Write([]byte(`{"profile_uuid": "xyz"}`))
		}
	}))
	t.Cleanup(depSrv.Close)

	const licenseErr = "missing or invalid license"
	const notFoundErr = "not found"
	testCases := []struct {
		name          string
		licenseTier   string
		oldMDM        mobius.MDM
		newMDM        mobius.MDM
		expectedMDM   mobius.MDM
		expectedError string
		findTeam      bool
	}{
		{
			name:        "nochange",
			licenseTier: "free",
			expectedMDM: mobius.MDM{
				AppleBusinessManager: optjson.Slice[mobius.MDMAppleABMAssignmentInfo]{Set: true, Value: []mobius.MDMAppleABMAssignmentInfo{}},
				MacOSSetup: mobius.MacOSSetup{
					BootstrapPackage:            optjson.String{Set: true},
					MacOSSetupAssistant:         optjson.String{Set: true},
					EnableReleaseDeviceManually: optjson.SetBool(false),
					Software:                    optjson.Slice[*mobius.MacOSSetupSoftware]{Set: true, Value: []*mobius.MacOSSetupSoftware{}},
					Script:                      optjson.String{Set: true},
					ManualAgentInstall:          optjson.Bool{Set: true},
				},
				MacOSUpdates:            mobius.AppleOSUpdateSettings{MinimumVersion: optjson.String{Set: true}, Deadline: optjson.String{Set: true}},
				IOSUpdates:              mobius.AppleOSUpdateSettings{MinimumVersion: optjson.String{Set: true}, Deadline: optjson.String{Set: true}},
				IPadOSUpdates:           mobius.AppleOSUpdateSettings{MinimumVersion: optjson.String{Set: true}, Deadline: optjson.String{Set: true}},
				VolumePurchasingProgram: optjson.Slice[mobius.MDMAppleVolumePurchasingProgramInfo]{Set: true, Value: []mobius.MDMAppleVolumePurchasingProgramInfo{}},
				WindowsUpdates:          mobius.WindowsUpdates{DeadlineDays: optjson.Int{Set: true}, GracePeriodDays: optjson.Int{Set: true}},
				WindowsSettings: mobius.WindowsSettings{
					CustomSettings: optjson.Slice[mobius.MDMProfileSpec]{Set: true, Value: []mobius.MDMProfileSpec{}},
				},
			},
		}, {
			name:          "newDefaultTeamNoLicense",
			licenseTier:   "free",
			newMDM:        mobius.MDM{DeprecatedAppleBMDefaultTeam: "foobar"},
			expectedError: licenseErr,
		}, {
			name:          "notFoundNew",
			licenseTier:   "premium",
			newMDM:        mobius.MDM{DeprecatedAppleBMDefaultTeam: "foobar"},
			expectedError: notFoundErr,
		}, {
			name:          "notFoundEdit",
			licenseTier:   "premium",
			oldMDM:        mobius.MDM{DeprecatedAppleBMDefaultTeam: "foobar"},
			newMDM:        mobius.MDM{DeprecatedAppleBMDefaultTeam: "bar"},
			expectedError: notFoundErr,
		}, {
			name:        "foundNew",
			licenseTier: "premium",
			findTeam:    true,
			newMDM:      mobius.MDM{DeprecatedAppleBMDefaultTeam: "foobar"},
			expectedMDM: mobius.MDM{
				AppleBusinessManager:         optjson.Slice[mobius.MDMAppleABMAssignmentInfo]{Set: true, Value: []mobius.MDMAppleABMAssignmentInfo{}},
				DeprecatedAppleBMDefaultTeam: "foobar",
				MacOSSetup: mobius.MacOSSetup{
					BootstrapPackage:            optjson.String{Set: true},
					MacOSSetupAssistant:         optjson.String{Set: true},
					EnableReleaseDeviceManually: optjson.SetBool(false),
					Software:                    optjson.Slice[*mobius.MacOSSetupSoftware]{Set: true, Value: []*mobius.MacOSSetupSoftware{}},
					Script:                      optjson.String{Set: true},
					ManualAgentInstall:          optjson.Bool{Set: true},
				},
				MacOSUpdates:            mobius.AppleOSUpdateSettings{MinimumVersion: optjson.String{Set: true}, Deadline: optjson.String{Set: true}},
				IOSUpdates:              mobius.AppleOSUpdateSettings{MinimumVersion: optjson.String{Set: true}, Deadline: optjson.String{Set: true}},
				IPadOSUpdates:           mobius.AppleOSUpdateSettings{MinimumVersion: optjson.String{Set: true}, Deadline: optjson.String{Set: true}},
				VolumePurchasingProgram: optjson.Slice[mobius.MDMAppleVolumePurchasingProgramInfo]{Set: true, Value: []mobius.MDMAppleVolumePurchasingProgramInfo{}},
				WindowsUpdates:          mobius.WindowsUpdates{DeadlineDays: optjson.Int{Set: true}, GracePeriodDays: optjson.Int{Set: true}},
				WindowsSettings: mobius.WindowsSettings{
					CustomSettings: optjson.Slice[mobius.MDMProfileSpec]{Set: true, Value: []mobius.MDMProfileSpec{}},
				},
			},
		}, {
			name:        "foundEdit",
			licenseTier: "premium",
			findTeam:    true,
			oldMDM:      mobius.MDM{DeprecatedAppleBMDefaultTeam: "bar"},
			newMDM:      mobius.MDM{DeprecatedAppleBMDefaultTeam: "foobar"},
			expectedMDM: mobius.MDM{
				AppleBusinessManager:         optjson.Slice[mobius.MDMAppleABMAssignmentInfo]{Set: true, Value: []mobius.MDMAppleABMAssignmentInfo{}},
				DeprecatedAppleBMDefaultTeam: "foobar",
				MacOSSetup: mobius.MacOSSetup{
					BootstrapPackage:            optjson.String{Set: true},
					MacOSSetupAssistant:         optjson.String{Set: true},
					EnableReleaseDeviceManually: optjson.SetBool(false),
					Software:                    optjson.Slice[*mobius.MacOSSetupSoftware]{Set: true, Value: []*mobius.MacOSSetupSoftware{}},
					Script:                      optjson.String{Set: true},
					ManualAgentInstall:          optjson.Bool{Set: true},
				},
				MacOSUpdates:            mobius.AppleOSUpdateSettings{MinimumVersion: optjson.String{Set: true}, Deadline: optjson.String{Set: true}},
				IOSUpdates:              mobius.AppleOSUpdateSettings{MinimumVersion: optjson.String{Set: true}, Deadline: optjson.String{Set: true}},
				IPadOSUpdates:           mobius.AppleOSUpdateSettings{MinimumVersion: optjson.String{Set: true}, Deadline: optjson.String{Set: true}},
				VolumePurchasingProgram: optjson.Slice[mobius.MDMAppleVolumePurchasingProgramInfo]{Set: true, Value: []mobius.MDMAppleVolumePurchasingProgramInfo{}},
				WindowsUpdates:          mobius.WindowsUpdates{DeadlineDays: optjson.Int{Set: true}, GracePeriodDays: optjson.Int{Set: true}},
				WindowsSettings: mobius.WindowsSettings{
					CustomSettings: optjson.Slice[mobius.MDMProfileSpec]{Set: true, Value: []mobius.MDMProfileSpec{}},
				},
			},
		}, {
			name:          "ssoFree",
			licenseTier:   "free",
			findTeam:      true,
			newMDM:        mobius.MDM{EndUserAuthentication: mobius.MDMEndUserAuthentication{SSOProviderSettings: mobius.SSOProviderSettings{EntityID: "foo"}}},
			expectedError: licenseErr,
		}, {
			name:        "ssoFreeNoChanges",
			licenseTier: "free",
			findTeam:    true,
			newMDM:      mobius.MDM{EndUserAuthentication: mobius.MDMEndUserAuthentication{SSOProviderSettings: mobius.SSOProviderSettings{EntityID: "foo"}}},
			oldMDM:      mobius.MDM{EndUserAuthentication: mobius.MDMEndUserAuthentication{SSOProviderSettings: mobius.SSOProviderSettings{EntityID: "foo"}}},
			expectedMDM: mobius.MDM{
				AppleBusinessManager:  optjson.Slice[mobius.MDMAppleABMAssignmentInfo]{Set: true, Value: []mobius.MDMAppleABMAssignmentInfo{}},
				EndUserAuthentication: mobius.MDMEndUserAuthentication{SSOProviderSettings: mobius.SSOProviderSettings{EntityID: "foo"}},
				MacOSSetup: mobius.MacOSSetup{
					BootstrapPackage:            optjson.String{Set: true},
					MacOSSetupAssistant:         optjson.String{Set: true},
					EnableReleaseDeviceManually: optjson.SetBool(false),
					Software:                    optjson.Slice[*mobius.MacOSSetupSoftware]{Set: true, Value: []*mobius.MacOSSetupSoftware{}},
					Script:                      optjson.String{Set: true},
					ManualAgentInstall:          optjson.Bool{Set: true},
				},
				MacOSUpdates:            mobius.AppleOSUpdateSettings{MinimumVersion: optjson.String{Set: true}, Deadline: optjson.String{Set: true}},
				IOSUpdates:              mobius.AppleOSUpdateSettings{MinimumVersion: optjson.String{Set: true}, Deadline: optjson.String{Set: true}},
				IPadOSUpdates:           mobius.AppleOSUpdateSettings{MinimumVersion: optjson.String{Set: true}, Deadline: optjson.String{Set: true}},
				VolumePurchasingProgram: optjson.Slice[mobius.MDMAppleVolumePurchasingProgramInfo]{Set: true, Value: []mobius.MDMAppleVolumePurchasingProgramInfo{}},
				WindowsUpdates:          mobius.WindowsUpdates{DeadlineDays: optjson.Int{Set: true}, GracePeriodDays: optjson.Int{Set: true}},
				WindowsSettings: mobius.WindowsSettings{
					CustomSettings: optjson.Slice[mobius.MDMProfileSpec]{Set: true, Value: []mobius.MDMProfileSpec{}},
				},
			},
		}, {
			name:        "ssoAllFields",
			licenseTier: "premium",
			findTeam:    true,
			newMDM: mobius.MDM{EndUserAuthentication: mobius.MDMEndUserAuthentication{SSOProviderSettings: mobius.SSOProviderSettings{
				EntityID:    "mobius",
				IssuerURI:   "http://issuer.idp.com",
				MetadataURL: "http://isser.metadata.com",
				IDPName:     "onelogin",
			}}},
			expectedMDM: mobius.MDM{
				AppleBusinessManager: optjson.Slice[mobius.MDMAppleABMAssignmentInfo]{Set: true, Value: []mobius.MDMAppleABMAssignmentInfo{}},
				EndUserAuthentication: mobius.MDMEndUserAuthentication{SSOProviderSettings: mobius.SSOProviderSettings{
					EntityID:    "mobius",
					IssuerURI:   "http://issuer.idp.com",
					MetadataURL: "http://isser.metadata.com",
					IDPName:     "onelogin",
				}},
				MacOSSetup: mobius.MacOSSetup{
					BootstrapPackage:            optjson.String{Set: true},
					MacOSSetupAssistant:         optjson.String{Set: true},
					EnableReleaseDeviceManually: optjson.SetBool(false),
					Software:                    optjson.Slice[*mobius.MacOSSetupSoftware]{Set: true, Value: []*mobius.MacOSSetupSoftware{}},
					Script:                      optjson.String{Set: true},
					ManualAgentInstall:          optjson.Bool{Set: true},
				},
				MacOSUpdates:            mobius.AppleOSUpdateSettings{MinimumVersion: optjson.String{Set: true}, Deadline: optjson.String{Set: true}},
				IOSUpdates:              mobius.AppleOSUpdateSettings{MinimumVersion: optjson.String{Set: true}, Deadline: optjson.String{Set: true}},
				IPadOSUpdates:           mobius.AppleOSUpdateSettings{MinimumVersion: optjson.String{Set: true}, Deadline: optjson.String{Set: true}},
				VolumePurchasingProgram: optjson.Slice[mobius.MDMAppleVolumePurchasingProgramInfo]{Set: true, Value: []mobius.MDMAppleVolumePurchasingProgramInfo{}},
				WindowsUpdates:          mobius.WindowsUpdates{DeadlineDays: optjson.Int{Set: true}, GracePeriodDays: optjson.Int{Set: true}},
				WindowsSettings: mobius.WindowsSettings{
					CustomSettings: optjson.Slice[mobius.MDMProfileSpec]{Set: true, Value: []mobius.MDMProfileSpec{}},
				},
			},
		}, {
			name:        "ssoShortEntityID",
			licenseTier: "premium",
			findTeam:    true,
			newMDM: mobius.MDM{EndUserAuthentication: mobius.MDMEndUserAuthentication{SSOProviderSettings: mobius.SSOProviderSettings{
				EntityID:    "f",
				IssuerURI:   "http://issuer.idp.com",
				MetadataURL: "http://isser.metadata.com",
				IDPName:     "onelogin",
			}}},
			expectedError: "validation failed: entity_id must be 5 or more characters",
		}, {
			name:        "ssoMissingMetadata",
			licenseTier: "premium",
			findTeam:    true,
			newMDM: mobius.MDM{EndUserAuthentication: mobius.MDMEndUserAuthentication{SSOProviderSettings: mobius.SSOProviderSettings{
				EntityID:  "mobius",
				IssuerURI: "http://issuer.idp.com",
				IDPName:   "onelogin",
			}}},
			expectedError: "either metadata or metadata_url must be defined",
		}, {
			name:        "ssoMultiMetadata",
			licenseTier: "premium",
			findTeam:    true,
			newMDM: mobius.MDM{EndUserAuthentication: mobius.MDMEndUserAuthentication{SSOProviderSettings: mobius.SSOProviderSettings{
				EntityID:    "mobius",
				IssuerURI:   "http://issuer.idp.com",
				Metadata:    "not-empty",
				MetadataURL: "not-empty",
				IDPName:     "onelogin",
			}}},
			expectedError: "invalid URI for request",
		}, {
			name:        "ssoIdPName",
			licenseTier: "premium",
			findTeam:    true,
			newMDM: mobius.MDM{EndUserAuthentication: mobius.MDMEndUserAuthentication{SSOProviderSettings: mobius.SSOProviderSettings{
				EntityID:  "mobius",
				IssuerURI: "http://issuer.idp.com",
				Metadata:  "not-empty",
			}}},
			expectedError: "idp_name required",
		}, {
			name:        "disableDiskEncryption",
			licenseTier: "premium",
			newMDM: mobius.MDM{
				EnableDiskEncryption: optjson.SetBool(false),
			},
			expectedMDM: mobius.MDM{
				AppleBusinessManager: optjson.Slice[mobius.MDMAppleABMAssignmentInfo]{Set: true, Value: []mobius.MDMAppleABMAssignmentInfo{}},
				EnableDiskEncryption: optjson.Bool{Set: true, Valid: true, Value: false},
				MacOSSetup: mobius.MacOSSetup{
					BootstrapPackage:            optjson.String{Set: true},
					MacOSSetupAssistant:         optjson.String{Set: true},
					EnableReleaseDeviceManually: optjson.SetBool(false),
					Software:                    optjson.Slice[*mobius.MacOSSetupSoftware]{Set: true, Value: []*mobius.MacOSSetupSoftware{}},
					Script:                      optjson.String{Set: true},
					ManualAgentInstall:          optjson.Bool{Set: true},
				},
				MacOSUpdates:            mobius.AppleOSUpdateSettings{MinimumVersion: optjson.String{Set: true}, Deadline: optjson.String{Set: true}},
				IOSUpdates:              mobius.AppleOSUpdateSettings{MinimumVersion: optjson.String{Set: true}, Deadline: optjson.String{Set: true}},
				IPadOSUpdates:           mobius.AppleOSUpdateSettings{MinimumVersion: optjson.String{Set: true}, Deadline: optjson.String{Set: true}},
				VolumePurchasingProgram: optjson.Slice[mobius.MDMAppleVolumePurchasingProgramInfo]{Set: true, Value: []mobius.MDMAppleVolumePurchasingProgramInfo{}},
				WindowsUpdates:          mobius.WindowsUpdates{DeadlineDays: optjson.Int{Set: true}, GracePeriodDays: optjson.Int{Set: true}},
				WindowsSettings: mobius.WindowsSettings{
					CustomSettings: optjson.Slice[mobius.MDMProfileSpec]{Set: true, Value: []mobius.MDMProfileSpec{}},
				},
			},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			svc, ctx := newTestService(t, ds, nil, nil, &TestServerOpts{License: &mobius.LicenseInfo{Tier: tt.licenseTier}, DEPStorage: depStorage})
			ctx = viewer.NewContext(ctx, viewer.Viewer{User: admin})

			dsAppConfig := &mobius.AppConfig{
				OrgInfo:        mobius.OrgInfo{OrgName: "Test"},
				ServerSettings: mobius.ServerSettings{ServerURL: "https://example.org"},
				MDM:            tt.oldMDM,
			}

			ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
				return dsAppConfig, nil
			}

			ds.SaveAppConfigFunc = func(ctx context.Context, conf *mobius.AppConfig) error {
				*dsAppConfig = *conf
				return nil
			}
			ds.TeamByNameFunc = func(ctx context.Context, name string) (*mobius.Team, error) {
				if tt.findTeam {
					return &mobius.Team{}, nil
				}
				return nil, sql.ErrNoRows
			}
			ds.NewMDMAppleEnrollmentProfileFunc = func(ctx context.Context, enrollmentPayload mobius.MDMAppleEnrollmentProfilePayload) (*mobius.MDMAppleEnrollmentProfile, error) {
				return &mobius.MDMAppleEnrollmentProfile{}, nil
			}
			ds.GetMDMAppleEnrollmentProfileByTypeFunc = func(ctx context.Context, typ mobius.MDMAppleEnrollmentType) (*mobius.MDMAppleEnrollmentProfile, error) {
				raw := json.RawMessage("{}")
				return &mobius.MDMAppleEnrollmentProfile{DEPProfile: &raw}, nil
			}
			ds.NewJobFunc = func(ctx context.Context, job *mobius.Job) (*mobius.Job, error) {
				return job, nil
			}
			ds.ListABMTokensFunc = func(ctx context.Context) ([]*mobius.ABMToken, error) {
				return []*mobius.ABMToken{{ID: 1}}, nil
			}
			ds.SaveABMTokenFunc = func(ctx context.Context, token *mobius.ABMToken) error {
				return nil
			}
			depStorage.RetrieveConfigFunc = func(p0 context.Context, p1 string) (*nanodep_client.Config, error) {
				return &nanodep_client.Config{BaseURL: depSrv.URL}, nil
			}
			depStorage.RetrieveAuthTokensFunc = func(ctx context.Context, name string) (*nanodep_client.OAuth1Tokens, error) {
				return &nanodep_client.OAuth1Tokens{}, nil
			}
			depStorage.StoreAssignerProfileFunc = func(ctx context.Context, name string, profileUUID string) error {
				return nil
			}
			ds.SaveABMTokenFunc = func(ctx context.Context, tok *mobius.ABMToken) error {
				return nil
			}
			ds.ListVPPTokensFunc = func(ctx context.Context) ([]*mobius.VPPTokenDB, error) {
				return []*mobius.VPPTokenDB{}, nil
			}
			ds.ListABMTokensFunc = func(ctx context.Context) ([]*mobius.ABMToken, error) {
				return []*mobius.ABMToken{{OrganizationName: t.Name()}}, nil
			}

			ac, err := svc.AppConfigObfuscated(ctx)
			require.NoError(t, err)
			require.Equal(t, tt.oldMDM, ac.MDM)

			raw, err := json.Marshal(tt.newMDM)
			require.NoError(t, err)
			raw = []byte(`{"mdm":` + string(raw) + `}`)
			modified, err := svc.ModifyAppConfig(ctx, raw, mobius.ApplySpecOptions{})
			if tt.expectedError != "" {
				require.Error(t, err)
				require.ErrorContains(t, err, tt.expectedError)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.expectedMDM, modified.MDM)
			ac, err = svc.AppConfigObfuscated(ctx)
			require.NoError(t, err)
			require.Equal(t, tt.expectedMDM, ac.MDM)
		})
	}
}

func TestDiskEncryptionSetting(t *testing.T) {
	ds := new(mock.Store)

	admin := &mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)}
	t.Run("enableDiskEncryptionWithNoPrivateKey", func(t *testing.T) {
		testConfig = config.TestConfig()
		testConfig.Server.PrivateKey = ""
		svc, ctx := newTestServiceWithConfig(t, ds, testConfig, nil, nil, &TestServerOpts{License: &mobius.LicenseInfo{Tier: mobius.TierPremium}})
		ctx = viewer.NewContext(ctx, viewer.Viewer{User: admin})

		dsAppConfig := &mobius.AppConfig{
			OrgInfo:        mobius.OrgInfo{OrgName: "Test"},
			ServerSettings: mobius.ServerSettings{ServerURL: "https://example.org"},
			MDM:            mobius.MDM{},
		}

		ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
			return dsAppConfig, nil
		}

		ds.SaveAppConfigFunc = func(ctx context.Context, conf *mobius.AppConfig) error {
			*dsAppConfig = *conf
			return nil
		}
		ds.TeamByNameFunc = func(ctx context.Context, name string) (*mobius.Team, error) {
			return nil, sql.ErrNoRows
		}
		ds.NewMDMAppleEnrollmentProfileFunc = func(ctx context.Context, enrollmentPayload mobius.MDMAppleEnrollmentProfilePayload) (*mobius.MDMAppleEnrollmentProfile, error) {
			return &mobius.MDMAppleEnrollmentProfile{}, nil
		}
		ds.GetMDMAppleEnrollmentProfileByTypeFunc = func(ctx context.Context, typ mobius.MDMAppleEnrollmentType) (*mobius.MDMAppleEnrollmentProfile, error) {
			raw := json.RawMessage("{}")
			return &mobius.MDMAppleEnrollmentProfile{DEPProfile: &raw}, nil
		}
		ds.NewJobFunc = func(ctx context.Context, job *mobius.Job) (*mobius.Job, error) {
			return job, nil
		}

		ac, err := svc.AppConfigObfuscated(ctx)
		require.NoError(t, err)
		require.Equal(t, dsAppConfig.MDM, ac.MDM)

		raw, err := json.Marshal(mobius.MDM{
			EnableDiskEncryption: optjson.SetBool(true),
		})
		require.NoError(t, err)
		raw = []byte(`{"mdm":` + string(raw) + `}`)
		_, err = svc.ModifyAppConfig(ctx, raw, mobius.ApplySpecOptions{})
		require.Error(t, err)
		require.ErrorContains(t, err, "Missing required private key")
	})
}

func TestModifyAppConfigSMTPSSOAgentOptions(t *testing.T) {
	ds := new(mock.Store)
	svc, ctx := newTestService(t, ds, nil, nil)

	// SMTP and SSO are initially set.
	agentOptions := json.RawMessage(`
{
  "config": {
      "options": {
        "distributed_interval": 10
      }
  },
  "overrides": {
    "platforms": {
      "darwin": {
        "options": {
          "distributed_interval": 5
        }
      }
    }
  }
}`)
	dsAppConfig := &mobius.AppConfig{
		OrgInfo: mobius.OrgInfo{
			OrgName: "Test",
		},
		ServerSettings: mobius.ServerSettings{
			ServerURL: "https://example.org",
		},
		SMTPSettings: &mobius.SMTPSettings{
			SMTPEnabled:       true,
			SMTPConfigured:    true,
			SMTPSenderAddress: "foobar@example.com",
		},
		SSOSettings: &mobius.SSOSettings{
			EnableSSO: true,
			SSOProviderSettings: mobius.SSOProviderSettings{
				MetadataURL: "foobar.example.com/metadata",
			},
		},
		AgentOptions: &agentOptions,
	}

	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		return dsAppConfig, nil
	}
	ds.SaveAppConfigFunc = func(ctx context.Context, conf *mobius.AppConfig) error {
		*dsAppConfig = *conf
		return nil
	}
	ds.NewActivityFunc = func(
		ctx context.Context, user *mobius.User, activity mobius.ActivityDetails, details []byte, createdAt time.Time,
	) error {
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

	// Not sending smtp_settings, sso_settings or agent_settings will do nothing.
	b := []byte(`{}`)
	admin := &mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)}
	ctx = viewer.NewContext(ctx, viewer.Viewer{User: admin})
	updatedAppConfig, err := svc.ModifyAppConfig(ctx, b, mobius.ApplySpecOptions{})
	require.NoError(t, err)

	require.True(t, updatedAppConfig.SMTPSettings.SMTPEnabled)
	require.True(t, dsAppConfig.SMTPSettings.SMTPEnabled)
	require.True(t, updatedAppConfig.SSOSettings.EnableSSO)
	require.True(t, dsAppConfig.SSOSettings.EnableSSO)
	require.Equal(t, agentOptions, *updatedAppConfig.AgentOptions)
	require.Equal(t, agentOptions, *dsAppConfig.AgentOptions)

	// Not sending sso_settings or agent settings will not change them, and
	// sending SMTP settings will change them.
	b = []byte(`{"smtp_settings": {"enable_smtp": false}}`)
	updatedAppConfig, err = svc.ModifyAppConfig(ctx, b, mobius.ApplySpecOptions{})
	require.NoError(t, err)

	require.False(t, updatedAppConfig.SMTPSettings.SMTPEnabled)
	require.False(t, dsAppConfig.SMTPSettings.SMTPEnabled)
	require.True(t, updatedAppConfig.SSOSettings.EnableSSO)
	require.True(t, dsAppConfig.SSOSettings.EnableSSO)
	require.Equal(t, agentOptions, *updatedAppConfig.AgentOptions)
	require.Equal(t, agentOptions, *dsAppConfig.AgentOptions)

	// Not sending smtp_settings or agent settings will not change them, and
	// sending SSO settings will change them.
	b = []byte(`{"sso_settings": {"enable_sso": false}}`)
	updatedAppConfig, err = svc.ModifyAppConfig(ctx, b, mobius.ApplySpecOptions{})
	require.NoError(t, err)

	require.False(t, updatedAppConfig.SMTPSettings.SMTPEnabled)
	require.False(t, dsAppConfig.SMTPSettings.SMTPEnabled)
	require.False(t, updatedAppConfig.SSOSettings.EnableSSO)
	require.False(t, dsAppConfig.SSOSettings.EnableSSO)
	require.Equal(t, agentOptions, *updatedAppConfig.AgentOptions)
	require.Equal(t, agentOptions, *dsAppConfig.AgentOptions)

	// Not sending smtp_settings or sso_settings will not change them, and
	// sending agent options will change them.
	newAgentOptions := json.RawMessage(`{
  "config": {
      "options": {
        "distributed_interval": 100
      }
  },
  "overrides": {
    "platforms": {
      "darwin": {
        "options": {
          "distributed_interval": 2
        }
      }
    }
  }
}`)
	b = []byte(`{"agent_options": ` + string(newAgentOptions) + `}`)
	updatedAppConfig, err = svc.ModifyAppConfig(ctx, b, mobius.ApplySpecOptions{})
	require.NoError(t, err)

	require.False(t, updatedAppConfig.SMTPSettings.SMTPEnabled)
	require.False(t, dsAppConfig.SMTPSettings.SMTPEnabled)
	require.False(t, updatedAppConfig.SSOSettings.EnableSSO)
	require.False(t, dsAppConfig.SSOSettings.EnableSSO)
	require.Equal(t, newAgentOptions, *dsAppConfig.AgentOptions)
	require.Equal(t, newAgentOptions, *dsAppConfig.AgentOptions)
}

// TestModifyEnableAnalytics tests that a premium customer cannot set ServerSettings.EnableAnalytics to be false.
// Free customers should be able to set the value to false, however.
func TestModifyEnableAnalytics(t *testing.T) {
	ds := new(mock.Store)

	admin := &mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)}

	testCases := []struct {
		name                  string
		expectedEnabled       bool
		newEnabled            bool
		initialEnabled        bool
		licenseTier           string
		allowDisableTelemetry bool
		initialURL            string
		newURL                string
		expectedURL           string
		shouldFailModify      bool
	}{
		{
			name:            "mobius free",
			expectedEnabled: false,
			initialEnabled:  true,
			newEnabled:      false,
			licenseTier:     mobius.TierFree,
		},
		{
			name:            "mobius premium",
			expectedEnabled: true,
			initialEnabled:  true,
			newEnabled:      false,
			licenseTier:     mobius.TierPremium,
		},
		{
			name:                  "mobius premium with allow disable telemetry",
			expectedEnabled:       false,
			initialEnabled:        true,
			newEnabled:            false,
			licenseTier:           mobius.TierPremium,
			allowDisableTelemetry: true,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			svc, ctx := newTestService(t, ds, nil, nil, &TestServerOpts{License: &mobius.LicenseInfo{Tier: tt.licenseTier, AllowDisableTelemetry: tt.allowDisableTelemetry}})
			ctx = viewer.NewContext(ctx, viewer.Viewer{User: admin})

			dsAppConfig := &mobius.AppConfig{
				OrgInfo: mobius.OrgInfo{
					OrgName: "Test",
				},
				ServerSettings: mobius.ServerSettings{
					EnableAnalytics: true,
					ServerURL:       "https://localhost:8080",
				},
			}

			ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
				return dsAppConfig, nil
			}

			ds.SaveAppConfigFunc = func(ctx context.Context, conf *mobius.AppConfig) error {
				*dsAppConfig = *conf
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

			ac, err := svc.AppConfigObfuscated(ctx)
			require.NoError(t, err)
			require.Equal(t, tt.initialEnabled, ac.ServerSettings.EnableAnalytics)

			raw, err := json.Marshal(mobius.ServerSettings{EnableAnalytics: tt.newEnabled, ServerURL: "https://localhost:8080"})
			require.NoError(t, err)
			raw = []byte(`{"server_settings":` + string(raw) + `}`)
			modified, err := svc.ModifyAppConfig(ctx, raw, mobius.ApplySpecOptions{})
			require.NoError(t, err)

			if modified != nil {
				require.Equal(t, tt.expectedEnabled, modified.ServerSettings.EnableAnalytics)
				ac, err = svc.AppConfigObfuscated(ctx)
				require.NoError(t, err)
				require.Equal(t, tt.expectedEnabled, ac.ServerSettings.EnableAnalytics)
			}
		})
	}
}

func TestModifyAppConfigForNDESSCEPProxy(t *testing.T) {
	t.Parallel()
	ds := new(mock.Store)
	svc, ctx := newTestService(t, ds, nil, nil, &TestServerOpts{License: &mobius.LicenseInfo{Tier: mobius.TierFree}})
	scepURL := "https://example.com/mscep/mscep.dll"
	adminURL := "https://example.com/mscep_admin/"
	username := "user"
	password := "password"

	appConfig := &mobius.AppConfig{
		OrgInfo: mobius.OrgInfo{
			OrgName: "Test",
		},
		ServerSettings: mobius.ServerSettings{
			ServerURL: "https://localhost:8080",
		},
	}
	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		if appConfig.Integrations.NDESSCEPProxy.Valid {
			appConfig.Integrations.NDESSCEPProxy.Value.Password = mobius.MaskedPassword
		}
		return appConfig, nil
	}
	ds.SaveAppConfigFunc = func(ctx context.Context, conf *mobius.AppConfig) error {
		appConfig = conf
		return nil
	}
	ds.ListABMTokensFunc = func(ctx context.Context) ([]*mobius.ABMToken, error) {
		return []*mobius.ABMToken{{ID: 1}}, nil
	}
	ds.SaveABMTokenFunc = func(ctx context.Context, token *mobius.ABMToken) error {
		return nil
	}
	ds.ListVPPTokensFunc = func(ctx context.Context) ([]*mobius.VPPTokenDB, error) {
		return []*mobius.VPPTokenDB{}, nil
	}

	jsonPayloadBase := `
{
	"integrations": {
		"ndes_scep_proxy": {
			"url": "%s",
			"admin_url": "%s",
			"username": "%s",
			"password": "%s"
		}
	}
}
`
	jsonPayload := fmt.Sprintf(jsonPayloadBase, scepURL, adminURL, username, password)
	admin := &mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)}
	ctx = viewer.NewContext(ctx, viewer.Viewer{User: admin})

	// SCEP proxy not configured for free users
	_, err := svc.ModifyAppConfig(ctx, []byte(jsonPayload), mobius.ApplySpecOptions{})
	assert.ErrorContains(t, err, ErrMissingLicense.Error())
	assert.ErrorContains(t, err, "integrations.ndes_scep_proxy")

	mobiusConfig := config.TestConfig()
	scepConfig := &scep_mock.SCEPConfigService{}
	scepConfig.ValidateSCEPURLFunc = func(_ context.Context, _ string) error { return nil }
	scepConfig.ValidateNDESSCEPAdminURLFunc = func(_ context.Context, _ mobius.NDESSCEPProxyIntegration) error { return nil }
	svc, ctx = newTestServiceWithConfig(t, ds, mobiusConfig, nil, nil, &TestServerOpts{
		License:           &mobius.LicenseInfo{Tier: mobius.TierPremium},
		SCEPConfigService: scepConfig,
	})
	ctx = viewer.NewContext(ctx, viewer.Viewer{User: admin})
	ds.NewActivityFunc = func(ctx context.Context, user *mobius.User, activity mobius.ActivityDetails, details []byte,
		createdAt time.Time,
	) error {
		assert.IsType(t, mobius.ActivityAddedNDESSCEPProxy{}, activity)
		return nil
	}
	ac, err := svc.ModifyAppConfig(ctx, []byte(jsonPayload), mobius.ApplySpecOptions{})
	require.NoError(t, err)
	checkSCEPProxy := func() {
		require.NotNil(t, ac.Integrations.NDESSCEPProxy)
		assert.Equal(t, scepURL, ac.Integrations.NDESSCEPProxy.Value.URL)
		assert.Equal(t, adminURL, ac.Integrations.NDESSCEPProxy.Value.AdminURL)
		assert.Equal(t, username, ac.Integrations.NDESSCEPProxy.Value.Username)
		assert.Equal(t, mobius.MaskedPassword, ac.Integrations.NDESSCEPProxy.Value.Password)
	}
	checkSCEPProxy()
	assert.True(t, scepConfig.ValidateSCEPURLFuncInvoked)
	assert.True(t, scepConfig.ValidateNDESSCEPAdminURLFuncInvoked)
	assert.True(t, ds.SaveAppConfigFuncInvoked)
	ds.SaveAppConfigFuncInvoked = false
	assert.True(t, ds.NewActivityFuncInvoked)
	ds.NewActivityFuncInvoked = false

	// Validation not done if there is no change
	appConfig = ac
	scepConfig.ValidateSCEPURLFuncInvoked = false
	scepConfig.ValidateNDESSCEPAdminURLFuncInvoked = false
	jsonPayload = fmt.Sprintf(jsonPayloadBase, " "+scepURL, adminURL+" ", " "+username+" ", mobius.MaskedPassword)
	ac, err = svc.ModifyAppConfig(ctx, []byte(jsonPayload), mobius.ApplySpecOptions{})
	require.NoError(t, err, jsonPayload)
	checkSCEPProxy()
	assert.False(t, scepConfig.ValidateSCEPURLFuncInvoked)
	assert.False(t, scepConfig.ValidateNDESSCEPAdminURLFuncInvoked)
	assert.False(t, ds.NewActivityFuncInvoked)
	ds.NewActivityFuncInvoked = false

	// Validation not done if there is no change, part 2
	scepConfig.ValidateSCEPURLFuncInvoked = false
	scepConfig.ValidateNDESSCEPAdminURLFuncInvoked = false
	ac, err = svc.ModifyAppConfig(ctx, []byte(`{"integrations":{}}`), mobius.ApplySpecOptions{})
	require.NoError(t, err)
	checkSCEPProxy()
	assert.False(t, scepConfig.ValidateSCEPURLFuncInvoked)
	assert.False(t, scepConfig.ValidateNDESSCEPAdminURLFuncInvoked)
	assert.False(t, ds.NewActivityFuncInvoked)
	ds.NewActivityFuncInvoked = false

	// Validation done for SCEP URL. Password is blank, which is not considered a change.
	scepURL = "https://new.com/mscep/mscep.dll"
	jsonPayload = fmt.Sprintf(jsonPayloadBase, scepURL, adminURL, username, "")
	ds.NewActivityFunc = func(ctx context.Context, user *mobius.User, activity mobius.ActivityDetails, details []byte,
		createdAt time.Time,
	) error {
		assert.IsType(t, mobius.ActivityEditedNDESSCEPProxy{}, activity)
		return nil
	}
	ac, err = svc.ModifyAppConfig(ctx, []byte(jsonPayload), mobius.ApplySpecOptions{})
	require.NoError(t, err)
	checkSCEPProxy()
	assert.True(t, scepConfig.ValidateSCEPURLFuncInvoked)
	assert.False(t, scepConfig.ValidateNDESSCEPAdminURLFuncInvoked)
	appConfig = ac
	scepConfig.ValidateSCEPURLFuncInvoked = false
	scepConfig.ValidateNDESSCEPAdminURLFuncInvoked = false
	assert.True(t, ds.NewActivityFuncInvoked)
	ds.NewActivityFuncInvoked = false

	// Validation done for SCEP admin URL
	adminURL = "https://new.com/mscep_admin/"
	jsonPayload = fmt.Sprintf(jsonPayloadBase, scepURL, adminURL, username, mobius.MaskedPassword)
	ac, err = svc.ModifyAppConfig(ctx, []byte(jsonPayload), mobius.ApplySpecOptions{})
	require.NoError(t, err)
	checkSCEPProxy()
	assert.False(t, scepConfig.ValidateSCEPURLFuncInvoked)
	assert.True(t, scepConfig.ValidateNDESSCEPAdminURLFuncInvoked)
	assert.True(t, ds.NewActivityFuncInvoked)
	ds.NewActivityFuncInvoked = false

	// Validation fails
	scepConfig.ValidateSCEPURLFuncInvoked = false
	scepConfig.ValidateNDESSCEPAdminURLFuncInvoked = false
	scepConfig.ValidateSCEPURLFunc = func(_ context.Context, _ string) error {
		return errors.New("**invalid** 1")
	}
	scepConfig.ValidateNDESSCEPAdminURLFunc = func(_ context.Context, _ mobius.NDESSCEPProxyIntegration) error {
		return errors.New("**invalid** 2")
	}
	scepURL = "https://new2.com/mscep/mscep.dll"
	jsonPayload = fmt.Sprintf(jsonPayloadBase, scepURL, adminURL, username, password)
	ac, err = svc.ModifyAppConfig(ctx, []byte(jsonPayload), mobius.ApplySpecOptions{})
	assert.ErrorContains(t, err, "**invalid**")
	assert.True(t, scepConfig.ValidateSCEPURLFuncInvoked)
	assert.True(t, scepConfig.ValidateNDESSCEPAdminURLFuncInvoked)
	assert.False(t, ds.NewActivityFuncInvoked)
	ds.NewActivityFuncInvoked = false

	// Reset validation
	scepConfig.ValidateSCEPURLFuncInvoked = false
	scepConfig.ValidateNDESSCEPAdminURLFuncInvoked = false
	scepConfig.ValidateSCEPURLFunc = func(_ context.Context, _ string) error { return nil }
	scepConfig.ValidateNDESSCEPAdminURLFunc = func(_ context.Context, _ mobius.NDESSCEPProxyIntegration) error { return nil }

	// Config cleared with explicit null
	payload := `
{
	"integrations": {
		"ndes_scep_proxy": null
	}
}
`
	// First, dry run.
	appConfig.Integrations.NDESSCEPProxy.Valid = true
	ac, err = svc.ModifyAppConfig(ctx, []byte(payload), mobius.ApplySpecOptions{DryRun: true})
	require.NoError(t, err)
	assert.False(t, ac.Integrations.NDESSCEPProxy.Valid)
	// Also check what was saved.
	assert.False(t, appConfig.Integrations.NDESSCEPProxy.Valid)
	assert.False(t, scepConfig.ValidateSCEPURLFuncInvoked)
	assert.False(t, scepConfig.ValidateNDESSCEPAdminURLFuncInvoked)
	assert.False(t, ds.HardDeleteMDMConfigAssetFuncInvoked, "DB write should not happen in dry run")
	assert.False(t, ds.NewActivityFuncInvoked)
	ds.NewActivityFuncInvoked = false

	// Second, real run.
	appConfig.Integrations.NDESSCEPProxy.Valid = true
	ds.NewActivityFunc = func(ctx context.Context, user *mobius.User, activity mobius.ActivityDetails, details []byte,
		createdAt time.Time,
	) error {
		assert.IsType(t, mobius.ActivityDeletedNDESSCEPProxy{}, activity)
		return nil
	}
	ds.HardDeleteMDMConfigAssetFunc = func(ctx context.Context, assetName mobius.MDMAssetName) error {
		return nil
	}
	ac, err = svc.ModifyAppConfig(ctx, []byte(payload), mobius.ApplySpecOptions{})
	require.NoError(t, err)
	assert.False(t, ac.Integrations.NDESSCEPProxy.Valid)
	// Also check what was saved.
	assert.False(t, appConfig.Integrations.NDESSCEPProxy.Valid)
	assert.False(t, scepConfig.ValidateSCEPURLFuncInvoked)
	assert.False(t, scepConfig.ValidateNDESSCEPAdminURLFuncInvoked)
	assert.True(t, ds.HardDeleteMDMConfigAssetFuncInvoked)
	ds.HardDeleteMDMConfigAssetFuncInvoked = false
	assert.True(t, ds.NewActivityFuncInvoked)
	ds.NewActivityFuncInvoked = false

	// Deleting again should be a no-op
	appConfig.Integrations.NDESSCEPProxy.Valid = false
	ac, err = svc.ModifyAppConfig(ctx, []byte(payload), mobius.ApplySpecOptions{})
	require.NoError(t, err)
	assert.False(t, ac.Integrations.NDESSCEPProxy.Valid)
	assert.False(t, appConfig.Integrations.NDESSCEPProxy.Valid)
	assert.False(t, scepConfig.ValidateSCEPURLFuncInvoked)
	assert.False(t, scepConfig.ValidateNDESSCEPAdminURLFuncInvoked)
	assert.False(t, ds.HardDeleteMDMConfigAssetFuncInvoked)
	ds.HardDeleteMDMConfigAssetFuncInvoked = false
	assert.False(t, ds.NewActivityFuncInvoked)
	ds.NewActivityFuncInvoked = false

	// Cannot configure NDES without private key
	mobiusConfig.Server.PrivateKey = ""
	svc, ctx = newTestServiceWithConfig(t, ds, mobiusConfig, nil, nil, &TestServerOpts{License: &mobius.LicenseInfo{Tier: mobius.TierPremium}})
	ctx = viewer.NewContext(ctx, viewer.Viewer{User: admin})
	_, err = svc.ModifyAppConfig(ctx, []byte(jsonPayload), mobius.ApplySpecOptions{})
	assert.ErrorContains(t, err, "private key")
}

func TestAppConfigCAs(t *testing.T) {
	t.Parallel()

	pathRegex := regexp.MustCompile(`^/mpki/api/v2/profile/([a-zA-Z0-9_-]+)$`)
	mockDigiCertServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		matches := pathRegex.FindStringSubmatch(r.URL.Path)
		if len(matches) != 2 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		profileID := matches[1]

		resp := map[string]string{
			"id":     profileID,
			"name":   "Test CA",
			"status": "Active",
		}
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(resp)
		require.NoError(t, err)
	}))
	defer mockDigiCertServer.Close()

	setUpDigiCert := func() configCASuite {
		mt := configCASuite{
			ctx:          license.NewContext(context.Background(), &mobius.LicenseInfo{Tier: mobius.TierPremium}),
			invalid:      &mobius.InvalidArgumentError{},
			newAppConfig: getAppConfigWithDigiCertIntegration(mockDigiCertServer.URL, "WIFI"),
			oldAppConfig: &mobius.AppConfig{},
			appConfig:    &mobius.AppConfig{},
			svc:          &Service{logger: log.NewLogfmtLogger(os.Stdout)},
		}
		mt.svc.config.Server.PrivateKey = "exists"
		mt.svc.digiCertService = digicert.NewService()
		addMockDatastoreForCA(t, mt)
		return mt
	}
	setUpCustomSCEP := func() configCASuite {
		mt := configCASuite{
			ctx:          license.NewContext(context.Background(), &mobius.LicenseInfo{Tier: mobius.TierPremium}),
			invalid:      &mobius.InvalidArgumentError{},
			newAppConfig: getAppConfigWithSCEPIntegration("https://example.com", "SCEP_WIFI"),
			oldAppConfig: &mobius.AppConfig{},
			appConfig:    &mobius.AppConfig{},
			svc:          &Service{logger: log.NewLogfmtLogger(os.Stdout)},
		}
		mt.svc.config.Server.PrivateKey = "exists"
		scepConfig := &scep_mock.SCEPConfigService{}
		scepConfig.ValidateSCEPURLFunc = func(_ context.Context, _ string) error { return nil }
		mt.svc.scepConfigService = scepConfig
		addMockDatastoreForCA(t, mt)
		return mt
	}

	t.Run("free license", func(t *testing.T) {
		mt := setUpDigiCert()
		mt.ctx = license.NewContext(context.Background(), &mobius.LicenseInfo{Tier: mobius.TierFree})
		mt.newAppConfig = &mobius.AppConfig{}
		status, err := mt.svc.processAppConfigCAs(mt.ctx, mt.newAppConfig, mt.oldAppConfig, mt.appConfig, mt.invalid)
		require.NoError(t, err)
		assert.Empty(t, mt.invalid.Errors)
		assert.Empty(t, status.ndes)
		assert.Empty(t, status.digicert)
		assert.Empty(t, status.customSCEPProxy)

		mt.invalid = &mobius.InvalidArgumentError{}
		mt.newAppConfig = &mobius.AppConfig{}
		mt.newAppConfig.Integrations.DigiCert.Set = true
		mt.newAppConfig.Integrations.DigiCert.Valid = true
		status, err = mt.svc.processAppConfigCAs(mt.ctx, mt.newAppConfig, mt.oldAppConfig, mt.appConfig, mt.invalid)
		require.NoError(t, err)
		checkExpectedCAValidationError(t, mt.invalid, status, "digicert", ErrMissingLicense.Error())

		mt.invalid = &mobius.InvalidArgumentError{}
		mt.newAppConfig = &mobius.AppConfig{}
		mt.newAppConfig.Integrations.CustomSCEPProxy.Set = true
		mt.newAppConfig.Integrations.CustomSCEPProxy.Valid = true
		status, err = mt.svc.processAppConfigCAs(mt.ctx, mt.newAppConfig, mt.oldAppConfig, mt.appConfig, mt.invalid)
		require.NoError(t, err)
		checkExpectedCAValidationError(t, mt.invalid, status, "custom_scep_proxy", ErrMissingLicense.Error())
	})

	t.Run("digicert keep old value", func(t *testing.T) {
		mt := setUpDigiCert()
		mt.ctx = license.NewContext(context.Background(), &mobius.LicenseInfo{Tier: mobius.TierPremium})
		mt.oldAppConfig = mt.newAppConfig
		mt.appConfig = mt.oldAppConfig.Copy()
		mt.newAppConfig = &mobius.AppConfig{}
		status, err := mt.svc.processAppConfigCAs(mt.ctx, mt.newAppConfig, mt.oldAppConfig, mt.appConfig, mt.invalid)
		require.NoError(t, err)
		assert.Empty(t, mt.invalid.Errors)
		assert.Empty(t, status.ndes)
		assert.Empty(t, status.digicert)
		assert.Empty(t, status.customSCEPProxy)
		assert.Len(t, mt.appConfig.Integrations.DigiCert.Value, 1)
	})

	t.Run("custom_scep keep old value", func(t *testing.T) {
		mt := setUpCustomSCEP()
		mt.ctx = license.NewContext(context.Background(), &mobius.LicenseInfo{Tier: mobius.TierPremium})
		mt.oldAppConfig = mt.newAppConfig
		mt.appConfig = mt.oldAppConfig.Copy()
		mt.newAppConfig = &mobius.AppConfig{}
		status, err := mt.svc.processAppConfigCAs(mt.ctx, mt.newAppConfig, mt.oldAppConfig, mt.appConfig, mt.invalid)
		require.NoError(t, err)
		assert.Empty(t, mt.invalid.Errors)
		assert.Empty(t, status.ndes)
		assert.Empty(t, status.digicert)
		assert.Empty(t, status.customSCEPProxy)
		assert.Len(t, mt.appConfig.Integrations.CustomSCEPProxy.Value, 1)
	})

	t.Run("missing server private key", func(t *testing.T) {
		mt := setUpDigiCert()
		mt.svc.config.Server.PrivateKey = ""
		status, err := mt.svc.processAppConfigCAs(mt.ctx, mt.newAppConfig, mt.oldAppConfig, mt.appConfig, mt.invalid)
		require.NoError(t, err)
		checkExpectedCAValidationError(t, mt.invalid, status, "integrations.digicert", "private key")

		mt = setUpCustomSCEP()
		mt.svc.config.Server.PrivateKey = ""
		status, err = mt.svc.processAppConfigCAs(mt.ctx, mt.newAppConfig, mt.oldAppConfig, mt.appConfig, mt.invalid)
		require.NoError(t, err)
		checkExpectedCAValidationError(t, mt.invalid, status, "integrations.custom_scep_proxy", "private key")
	})

	t.Run("invalid integration name", func(t *testing.T) {
		testCases := []struct {
			testName      string
			name          string
			errorContains []string
		}{
			{
				testName:      "empty",
				name:          "",
				errorContains: []string{"CA name cannot be empty"},
			},
			{
				testName:      "NDES",
				name:          "NDES",
				errorContains: []string{"CA name cannot be NDES"},
			},
			{
				testName:      "too long",
				name:          strings.Repeat("a", 256),
				errorContains: []string{"CA name cannot be longer than"},
			},
			{
				testName:      "invalid characters",
				name:          "a/b",
				errorContains: []string{"Only letters, numbers and underscores allowed"},
			},
		}

		for _, tc := range testCases {
			t.Run(tc.testName, func(t *testing.T) {
				baseErrorContains := tc.errorContains
				mt := setUpDigiCert()
				mt.newAppConfig = getAppConfigWithDigiCertIntegration(mockDigiCertServer.URL, tc.name)
				status, err := mt.svc.processAppConfigCAs(mt.ctx, mt.newAppConfig, mt.oldAppConfig, mt.appConfig, mt.invalid)
				require.NoError(t, err)
				errorContains := baseErrorContains
				errorContains = append(errorContains, "integrations.digicert.name")
				checkExpectedCAValidationError(t, mt.invalid, status, errorContains...)

				mt = setUpCustomSCEP()
				mt.newAppConfig = getAppConfigWithSCEPIntegration("https://example.com", tc.name)
				status, err = mt.svc.processAppConfigCAs(mt.ctx, mt.newAppConfig, mt.oldAppConfig, mt.appConfig, mt.invalid)
				require.NoError(t, err)
				errorContains = baseErrorContains
				errorContains = append(errorContains, "integrations.custom_scep_proxy.name")
				checkExpectedCAValidationError(t, mt.invalid, status, errorContains...)
			})
		}
	})

	t.Run("invalid digicert URL", func(t *testing.T) {
		mt := setUpDigiCert()
		mt.newAppConfig.Integrations.DigiCert.Value[0].URL = ""
		status, err := mt.svc.processAppConfigCAs(mt.ctx, mt.newAppConfig, mt.oldAppConfig, mt.appConfig, mt.invalid)
		require.NoError(t, err)
		checkExpectedCAValidationError(t, mt.invalid, status, "integrations.digicert.url",
			"empty url")

		mt = setUpDigiCert()
		mt.newAppConfig.Integrations.DigiCert.Value[0].URL = "nonhttp://bad.com"
		status, err = mt.svc.processAppConfigCAs(mt.ctx, mt.newAppConfig, mt.oldAppConfig, mt.appConfig, mt.invalid)
		require.NoError(t, err)
		checkExpectedCAValidationError(t, mt.invalid, status, "integrations.digicert.url",
			"URL must be https or http")
	})

	t.Run("invalid custom_scep URL", func(t *testing.T) {
		mt := setUpCustomSCEP()
		mt.newAppConfig.Integrations.CustomSCEPProxy.Value[0].URL = ""
		status, err := mt.svc.processAppConfigCAs(mt.ctx, mt.newAppConfig, mt.oldAppConfig, mt.appConfig, mt.invalid)
		require.NoError(t, err)
		checkExpectedCAValidationError(t, mt.invalid, status, "integrations.custom_scep_proxy.url",
			"empty url")

		mt = setUpCustomSCEP()
		mt.newAppConfig.Integrations.CustomSCEPProxy.Value[0].URL = "nonhttp://bad.com"
		status, err = mt.svc.processAppConfigCAs(mt.ctx, mt.newAppConfig, mt.oldAppConfig, mt.appConfig, mt.invalid)
		require.NoError(t, err)
		checkExpectedCAValidationError(t, mt.invalid, status, "integrations.custom_scep_proxy.url",
			"URL must be https or http")
	})

	t.Run("duplicate digicert integration name", func(t *testing.T) {
		mt := setUpDigiCert()
		mt.newAppConfig.Integrations.DigiCert.Value = append(mt.newAppConfig.Integrations.DigiCert.Value,
			mt.newAppConfig.Integrations.DigiCert.Value[0])
		status, err := mt.svc.processAppConfigCAs(mt.ctx, mt.newAppConfig, mt.oldAppConfig, mt.appConfig, mt.invalid)
		require.NoError(t, err)
		checkExpectedCAValidationError(t, mt.invalid, status, "integrations.digicert.name",
			"name is already used by another certificate authority")
	})

	t.Run("duplicate custom_scep integration name", func(t *testing.T) {
		mt := setUpCustomSCEP()
		mt.newAppConfig.Integrations.CustomSCEPProxy.Value = append(mt.newAppConfig.Integrations.CustomSCEPProxy.Value,
			mt.newAppConfig.Integrations.CustomSCEPProxy.Value[0])
		status, err := mt.svc.processAppConfigCAs(mt.ctx, mt.newAppConfig, mt.oldAppConfig, mt.appConfig, mt.invalid)
		require.NoError(t, err)
		checkExpectedCAValidationError(t, mt.invalid, status, "integrations.custom_scep_proxy.name",
			"name is already used by another certificate authority")
	})

	t.Run("same digicert and custom_scep integration name", func(t *testing.T) {
		mtSCEP := setUpCustomSCEP()
		mt := setUpDigiCert()
		mt.newAppConfig.Integrations.CustomSCEPProxy = mtSCEP.newAppConfig.Integrations.CustomSCEPProxy
		mt.newAppConfig.Integrations.CustomSCEPProxy.Value[0].Name = mt.newAppConfig.Integrations.DigiCert.Value[0].Name
		status, err := mt.svc.processAppConfigCAs(mt.ctx, mt.newAppConfig, mt.oldAppConfig, mt.appConfig, mt.invalid)
		require.NoError(t, err)
		checkExpectedCAValidationError(t, mt.invalid, status, "integrations.custom_scep_proxy.name",
			"name is already used by another certificate authority")
	})

	t.Run("digicert more than 1 user principal name", func(t *testing.T) {
		mt := setUpDigiCert()
		mt.newAppConfig.Integrations.DigiCert.Value[0].CertificateUserPrincipalNames = append(mt.newAppConfig.Integrations.DigiCert.Value[0].CertificateUserPrincipalNames,
			"another")
		status, err := mt.svc.processAppConfigCAs(mt.ctx, mt.newAppConfig, mt.oldAppConfig, mt.appConfig, mt.invalid)
		require.NoError(t, err)
		checkExpectedCAValidationError(t, mt.invalid, status, "integrations.digicert.certificate_user_principal_names",
			"one certificate user principal name")
	})

	t.Run("digicert empty user principal name", func(t *testing.T) {
		mt := setUpDigiCert()
		mt.newAppConfig.Integrations.DigiCert.Value[0].CertificateUserPrincipalNames = []string{" "}
		status, err := mt.svc.processAppConfigCAs(mt.ctx, mt.newAppConfig, mt.oldAppConfig, mt.appConfig, mt.invalid)
		require.NoError(t, err)
		checkExpectedCAValidationError(t, mt.invalid, status, "integrations.digicert.certificate_user_principal_names",
			"user principal name cannot be empty")
	})

	t.Run("digicert Mobius vars in user principal name", func(t *testing.T) {
		mt := setUpDigiCert()
		mt.newAppConfig.Integrations.DigiCert.Value[0].CertificateUserPrincipalNames[0] = "$MOBIUS_VAR_" + mobius.MobiusVarHostEndUserEmailIDP + " ${MOBIUS_VAR_" + mobius.MobiusVarHostHardwareSerial + "}"
		_, err := mt.svc.processAppConfigCAs(mt.ctx, mt.newAppConfig, mt.oldAppConfig, mt.appConfig, mt.invalid)
		require.NoError(t, err)
		assert.Empty(t, mt.invalid.Errors)

		mt.newAppConfig.Integrations.DigiCert.Value[0].CertificateUserPrincipalNames[0] = "$MOBIUS_VAR_BOZO"
		status, err := mt.svc.processAppConfigCAs(mt.ctx, mt.newAppConfig, mt.oldAppConfig, mt.appConfig, mt.invalid)
		require.NoError(t, err)
		checkExpectedCAValidationError(t, mt.invalid, status, "integrations.digicert.certificate_user_principal_names",
			"MOBIUS_VAR_BOZO is not allowed")
	})

	t.Run("digicert Mobius vars in common name", func(t *testing.T) {
		mt := setUpDigiCert()
		mt.newAppConfig.Integrations.DigiCert.Value[0].CertificateCommonName = "${MOBIUS_VAR_" + mobius.MobiusVarHostEndUserEmailIDP + "}${MOBIUS_VAR_" + mobius.MobiusVarHostHardwareSerial + "}"
		_, err := mt.svc.processAppConfigCAs(mt.ctx, mt.newAppConfig, mt.oldAppConfig, mt.appConfig, mt.invalid)
		require.NoError(t, err)
		assert.Empty(t, mt.invalid.Errors)

		mt.newAppConfig.Integrations.DigiCert.Value[0].CertificateCommonName = "$MOBIUS_VAR_BOZO"
		status, err := mt.svc.processAppConfigCAs(mt.ctx, mt.newAppConfig, mt.oldAppConfig, mt.appConfig, mt.invalid)
		require.NoError(t, err)
		checkExpectedCAValidationError(t, mt.invalid, status, "integrations.digicert.certificate_common_name",
			"MOBIUS_VAR_BOZO is not allowed")
	})

	t.Run("digicert Mobius vars in seat id", func(t *testing.T) {
		mt := setUpDigiCert()
		mt.newAppConfig.Integrations.DigiCert.Value[0].CertificateSeatID = "$MOBIUS_VAR_" + mobius.MobiusVarHostEndUserEmailIDP + " $MOBIUS_VAR_" + mobius.MobiusVarHostHardwareSerial
		_, err := mt.svc.processAppConfigCAs(mt.ctx, mt.newAppConfig, mt.oldAppConfig, mt.appConfig, mt.invalid)
		require.NoError(t, err)
		assert.Empty(t, mt.invalid.Errors)

		mt.newAppConfig.Integrations.DigiCert.Value[0].CertificateSeatID = "$MOBIUS_VAR_BOZO"
		status, err := mt.svc.processAppConfigCAs(mt.ctx, mt.newAppConfig, mt.oldAppConfig, mt.appConfig, mt.invalid)
		require.NoError(t, err)
		checkExpectedCAValidationError(t, mt.invalid, status, "integrations.digicert.certificate_seat_id",
			"MOBIUS_VAR_BOZO is not allowed")
	})

	t.Run("digicert API token not set", func(t *testing.T) {
		mt := setUpDigiCert()
		mt.newAppConfig.Integrations.DigiCert.Value[0].APIToken = mobius.MaskedPassword
		status, err := mt.svc.processAppConfigCAs(mt.ctx, mt.newAppConfig, mt.oldAppConfig, mt.appConfig, mt.invalid)
		require.NoError(t, err)
		checkExpectedCAValidationError(t, mt.invalid, status, "integrations.digicert.api_token", "DigiCert API token must be set")
	})

	t.Run("custom_scep challenge not set", func(t *testing.T) {
		mt := setUpCustomSCEP()
		mt.newAppConfig.Integrations.CustomSCEPProxy.Value[0].Challenge = mobius.MaskedPassword
		status, err := mt.svc.processAppConfigCAs(mt.ctx, mt.newAppConfig, mt.oldAppConfig, mt.appConfig, mt.invalid)
		require.NoError(t, err)
		checkExpectedCAValidationError(t, mt.invalid, status, "integrations.custom_scep_proxy.challenge", "Custom SCEP challenge must be set")
	})

	t.Run("digicert common name not set", func(t *testing.T) {
		mt := setUpDigiCert()
		mt.newAppConfig.Integrations.DigiCert.Value[0].CertificateCommonName = "\n\t"
		status, err := mt.svc.processAppConfigCAs(mt.ctx, mt.newAppConfig, mt.oldAppConfig, mt.appConfig, mt.invalid)
		require.NoError(t, err)
		checkExpectedCAValidationError(t, mt.invalid, status, "integrations.digicert.certificate_common_name", "Common Name (CN) cannot be empty")
	})

	t.Run("digicert seat id not set", func(t *testing.T) {
		mt := setUpDigiCert()
		mt.newAppConfig.Integrations.DigiCert.Value[0].CertificateSeatID = "\t\n"
		status, err := mt.svc.processAppConfigCAs(mt.ctx, mt.newAppConfig, mt.oldAppConfig, mt.appConfig, mt.invalid)
		require.NoError(t, err)
		checkExpectedCAValidationError(t, mt.invalid, status, "integrations.digicert.certificate_seat_id", "Seat ID cannot be empty")
	})

	t.Run("digicert happy path -- add one", func(t *testing.T) {
		mt := setUpDigiCert()
		status, err := mt.svc.processAppConfigCAs(mt.ctx, mt.newAppConfig, mt.oldAppConfig, mt.appConfig, mt.invalid)
		require.NoError(t, err)
		assert.Empty(t, mt.invalid.Errors)
		assert.Empty(t, status.customSCEPProxy)
		require.Len(t, status.digicert, 1)
		assert.Equal(t, caStatusAdded, status.digicert[mt.newAppConfig.Integrations.DigiCert.Value[0].Name])
		require.Len(t, mt.appConfig.Integrations.DigiCert.Value, 1)
		assert.True(t, mt.newAppConfig.Integrations.DigiCert.Value[0].Equals(&mt.appConfig.Integrations.DigiCert.Value[0]))
	})

	t.Run("digicert happy path -- delete one", func(t *testing.T) {
		mt := setUpDigiCert()
		mt.oldAppConfig = mt.newAppConfig
		mt.appConfig = mt.oldAppConfig.Copy()
		mt.newAppConfig = &mobius.AppConfig{
			Integrations: mobius.Integrations{
				DigiCert: optjson.Slice[mobius.DigiCertIntegration]{
					Set:   true,
					Valid: true,
				},
			},
		}
		status, err := mt.svc.processAppConfigCAs(mt.ctx, mt.newAppConfig, mt.oldAppConfig, mt.appConfig, mt.invalid)
		require.NoError(t, err)
		assert.Empty(t, mt.invalid.Errors)
		assert.Empty(t, status.customSCEPProxy)
		require.Len(t, status.digicert, 1)
		assert.Equal(t, caStatusDeleted, status.digicert[mt.oldAppConfig.Integrations.DigiCert.Value[0].Name])
		assert.False(t, mt.appConfig.Integrations.DigiCert.Valid)
	})

	t.Run("digicert API token not set on modify", func(t *testing.T) {
		mt := setUpDigiCert()
		mt.oldAppConfig.Integrations.DigiCert.Value = append(mt.oldAppConfig.Integrations.DigiCert.Value,
			mt.newAppConfig.Integrations.DigiCert.Value[0])
		mt.appConfig = mt.oldAppConfig.Copy()
		mt.newAppConfig.Integrations.DigiCert.Value[0].URL = "https://new.com"
		mt.newAppConfig.Integrations.DigiCert.Value[0].APIToken = ""
		status, err := mt.svc.processAppConfigCAs(mt.ctx, mt.newAppConfig, mt.oldAppConfig, mt.appConfig, mt.invalid)
		require.NoError(t, err)
		checkExpectedCAValidationError(t, mt.invalid, status, "integrations.digicert.api_token", "DigiCert API token must be set when modifying")
	})

	t.Run("digicert happy path -- add one, delete one, modify one", func(t *testing.T) {
		mt := setUpDigiCert()
		mt.newAppConfig.Integrations.DigiCert = optjson.Slice[mobius.DigiCertIntegration]{
			Set:   true,
			Valid: true,
			Value: []mobius.DigiCertIntegration{
				{
					Name:                          "add",
					URL:                           mockDigiCertServer.URL,
					APIToken:                      "api_token",
					ProfileID:                     "profile_id",
					CertificateCommonName:         "common_name",
					CertificateUserPrincipalNames: []string{"user_principal_name"},
					CertificateSeatID:             "seat_id",
				},
				{
					Name:                          "modify",
					URL:                           mockDigiCertServer.URL,
					APIToken:                      "api_token",
					ProfileID:                     "profile_id",
					CertificateCommonName:         "common_name",
					CertificateUserPrincipalNames: nil,
					CertificateSeatID:             "seat_id",
				},
				{
					Name:                          "same",
					URL:                           mockDigiCertServer.URL,
					APIToken:                      "api_token",
					ProfileID:                     "profile_id",
					CertificateCommonName:         "other_cn",
					CertificateUserPrincipalNames: nil,
					CertificateSeatID:             "seat_id",
				},
			},
		}
		mt.oldAppConfig.Integrations.DigiCert = optjson.Slice[mobius.DigiCertIntegration]{
			Set:   true,
			Valid: true,
			Value: []mobius.DigiCertIntegration{
				{
					Name:                          "delete",
					URL:                           mockDigiCertServer.URL,
					APIToken:                      "api_token",
					ProfileID:                     "profile_id",
					CertificateCommonName:         "common_name",
					CertificateUserPrincipalNames: []string{"user_principal_name"},
					CertificateSeatID:             "seat_id",
				},
				{
					Name:                          "modify",
					URL:                           mockDigiCertServer.URL,
					APIToken:                      "api_token",
					ProfileID:                     "profile_id",
					CertificateCommonName:         "common_name",
					CertificateUserPrincipalNames: []string{"user_principal_name"},
					CertificateSeatID:             "seat_id",
				},
				{
					Name:                          "same",
					URL:                           mockDigiCertServer.URL,
					APIToken:                      "api_token",
					ProfileID:                     "profile_id",
					CertificateCommonName:         "other_cn",
					CertificateUserPrincipalNames: nil,
					CertificateSeatID:             "seat_id",
				},
			},
		}
		mt.appConfig = mt.oldAppConfig.Copy()
		status, err := mt.svc.processAppConfigCAs(mt.ctx, mt.newAppConfig, mt.oldAppConfig, mt.appConfig, mt.invalid)
		require.NoError(t, err)
		assert.Empty(t, mt.invalid.Errors)
		assert.Empty(t, status.customSCEPProxy)
		require.Len(t, status.digicert, 3)
		assert.Equal(t, caStatusAdded, status.digicert["add"])
		assert.Equal(t, caStatusEdited, status.digicert["modify"])
		assert.Equal(t, caStatusDeleted, status.digicert["delete"])
		require.Len(t, mt.appConfig.Integrations.DigiCert.Value, 3)
	})

	t.Run("custom_scep happy path -- add one", func(t *testing.T) {
		mt := setUpCustomSCEP()
		status, err := mt.svc.processAppConfigCAs(mt.ctx, mt.newAppConfig, mt.oldAppConfig, mt.appConfig, mt.invalid)
		require.NoError(t, err)
		assert.Empty(t, mt.invalid.Errors)
		assert.Empty(t, status.digicert)
		require.Len(t, status.customSCEPProxy, 1)
		assert.Equal(t, caStatusAdded, status.customSCEPProxy[mt.newAppConfig.Integrations.CustomSCEPProxy.Value[0].Name])
		require.Len(t, mt.appConfig.Integrations.CustomSCEPProxy.Value, 1)
		assert.True(t, mt.newAppConfig.Integrations.CustomSCEPProxy.Value[0].Equals(&mt.appConfig.Integrations.CustomSCEPProxy.Value[0]))
	})

	t.Run("custom_scep happy path -- delete one", func(t *testing.T) {
		mt := setUpCustomSCEP()
		mt.oldAppConfig = mt.newAppConfig
		mt.appConfig = mt.oldAppConfig.Copy()
		mt.newAppConfig = &mobius.AppConfig{
			Integrations: mobius.Integrations{
				CustomSCEPProxy: optjson.Slice[mobius.CustomSCEPProxyIntegration]{
					Set:   true,
					Valid: true,
				},
			},
		}
		status, err := mt.svc.processAppConfigCAs(mt.ctx, mt.newAppConfig, mt.oldAppConfig, mt.appConfig, mt.invalid)
		require.NoError(t, err)
		assert.Empty(t, mt.invalid.Errors)
		assert.Empty(t, status.digicert)
		require.Len(t, status.customSCEPProxy, 1)
		assert.Equal(t, caStatusDeleted, status.customSCEPProxy[mt.oldAppConfig.Integrations.CustomSCEPProxy.Value[0].Name])
		assert.False(t, mt.appConfig.Integrations.CustomSCEPProxy.Valid)
	})

	t.Run("custom_scep API token not set on modify", func(t *testing.T) {
		mt := setUpCustomSCEP()
		mt.oldAppConfig.Integrations.CustomSCEPProxy.Value = append(mt.oldAppConfig.Integrations.CustomSCEPProxy.Value,
			mt.newAppConfig.Integrations.CustomSCEPProxy.Value[0])
		mt.appConfig = mt.oldAppConfig.Copy()
		mt.newAppConfig.Integrations.CustomSCEPProxy.Value[0].URL = "https://new.com"
		mt.newAppConfig.Integrations.CustomSCEPProxy.Value[0].Challenge = ""
		status, err := mt.svc.processAppConfigCAs(mt.ctx, mt.newAppConfig, mt.oldAppConfig, mt.appConfig, mt.invalid)
		require.NoError(t, err)
		checkExpectedCAValidationError(t, mt.invalid, status, "integrations.custom_scep_proxy.challenge",
			"Custom SCEP challenge must be set when modifying")
	})

	t.Run("custom_scep happy path -- add one, delete one, modify one", func(t *testing.T) {
		mt := setUpCustomSCEP()
		mt.newAppConfig.Integrations.CustomSCEPProxy = optjson.Slice[mobius.CustomSCEPProxyIntegration]{
			Set:   true,
			Valid: true,
			Value: []mobius.CustomSCEPProxyIntegration{
				{
					Name:      "add",
					URL:       "https://example.com",
					Challenge: "challenge",
				},
				{
					Name:      "modify",
					URL:       "https://example.com",
					Challenge: "challenge",
				},
				{
					Name:      "SCEP_WIFI", // same
					URL:       "https://example.com",
					Challenge: "challenge",
				},
			},
		}
		mt.oldAppConfig.Integrations.CustomSCEPProxy = optjson.Slice[mobius.CustomSCEPProxyIntegration]{
			Set:   true,
			Valid: true,
			Value: []mobius.CustomSCEPProxyIntegration{
				{
					Name:      "delete",
					URL:       "https://example.com",
					Challenge: "challenge",
				},
				{
					Name:      "modify",
					URL:       "https://modify.com",
					Challenge: "challenge",
				},
				{
					Name:      "SCEP_WIFI", // same
					URL:       "https://example.com",
					Challenge: mobius.MaskedPassword,
				},
			},
		}
		mt.appConfig = mt.oldAppConfig.Copy()
		status, err := mt.svc.processAppConfigCAs(mt.ctx, mt.newAppConfig, mt.oldAppConfig, mt.appConfig, mt.invalid)
		require.NoError(t, err)
		assert.Empty(t, mt.invalid.Errors)
		assert.Empty(t, status.digicert)
		require.Len(t, status.customSCEPProxy, 3)
		assert.Equal(t, caStatusAdded, status.customSCEPProxy["add"])
		assert.Equal(t, caStatusEdited, status.customSCEPProxy["modify"])
		assert.Equal(t, caStatusDeleted, status.customSCEPProxy["delete"])
		require.Len(t, mt.appConfig.Integrations.CustomSCEPProxy.Value, 3)
	})
}

type configCASuite struct {
	ctx          context.Context
	svc          *Service
	appConfig    *mobius.AppConfig
	newAppConfig *mobius.AppConfig
	oldAppConfig *mobius.AppConfig
	invalid      *mobius.InvalidArgumentError
}

func addMockDatastoreForCA(t *testing.T, s configCASuite) {
	mockDS := &mock.Store{}
	s.svc.ds = mockDS
	mockDS.GetAllCAConfigAssetsByTypeFunc = func(ctx context.Context, assetType mobius.CAConfigAssetType) (map[string]mobius.CAConfigAsset, error) {
		switch assetType {
		case mobius.CAConfigDigiCert:
			return map[string]mobius.CAConfigAsset{
				"WIFI": {
					Name:  "WIFI",
					Value: []byte("api_token"),
					Type:  mobius.CAConfigDigiCert,
				},
			}, nil
		case mobius.CAConfigCustomSCEPProxy:
			return map[string]mobius.CAConfigAsset{
				"SCEP_WIFI": {
					Name:  "SCEP_WIFI",
					Value: []byte("challenge"),
					Type:  mobius.CAConfigCustomSCEPProxy,
				},
			}, nil
		default:
			t.Fatalf("unexpected asset type: %s", assetType)
		}
		return nil, nil
	}
}

func checkExpectedCAValidationError(t *testing.T, invalid *mobius.InvalidArgumentError, status appConfigCAStatus, contains ...string) {
	assert.Len(t, invalid.Errors, 1)
	for _, expected := range contains {
		assert.Contains(t, invalid.Error(), expected)
	}
	assert.Empty(t, status.ndes)
	assert.Empty(t, status.digicert)
	assert.Empty(t, status.customSCEPProxy)
}

func getAppConfigWithDigiCertIntegration(url string, name string) *mobius.AppConfig {
	newAppConfig := &mobius.AppConfig{
		Integrations: mobius.Integrations{
			DigiCert: optjson.Slice[mobius.DigiCertIntegration]{
				Set:   true,
				Valid: true,
				Value: []mobius.DigiCertIntegration{getDigiCertIntegration(url, name)},
			},
		},
	}
	return newAppConfig
}

func getDigiCertIntegration(url string, name string) mobius.DigiCertIntegration {
	digiCertCA := mobius.DigiCertIntegration{
		Name:                          name,
		URL:                           url,
		APIToken:                      "api_token",
		ProfileID:                     "profile_id",
		CertificateCommonName:         "common_name",
		CertificateUserPrincipalNames: []string{"user_principal_name"},
		CertificateSeatID:             "seat_id",
	}
	return digiCertCA
}

func getAppConfigWithSCEPIntegration(url string, name string) *mobius.AppConfig {
	newAppConfig := &mobius.AppConfig{
		Integrations: mobius.Integrations{
			CustomSCEPProxy: optjson.Slice[mobius.CustomSCEPProxyIntegration]{
				Set:   true,
				Valid: true,
				Value: []mobius.CustomSCEPProxyIntegration{getCustomSCEPIntegration(url, name)},
			},
		},
	}
	return newAppConfig
}

func getCustomSCEPIntegration(url string, name string) mobius.CustomSCEPProxyIntegration {
	challenge, _ := server.GenerateRandomText(6)
	return mobius.CustomSCEPProxyIntegration{
		Name:      name,
		URL:       url,
		Challenge: challenge,
	}
}
