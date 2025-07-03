//go:build enterprise
// +build enterprise

package service

import (
	"context"
	"testing"
	"time"

	"github.com/notawar/mobius/server/config"
	"github.com/notawar/mobius/server/contexts/viewer"
	"github.com/notawar/mobius/server/datastore/mysql"
	"github.com/notawar/mobius/server/mobius"
	"github.com/notawar/mobius/server/mock"
	"github.com/notawar/mobius/server/ptr"
	"github.com/notawar/mobius/server/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSessionAuth(t *testing.T) {
	ds := new(mock.Store)
	svc, ctx := newTestService(t, ds, nil, nil)

	ds.ListSessionsForUserFunc = func(ctx context.Context, id uint) ([]*mobius.Session, error) {
		if id == 999 {
			return []*mobius.Session{
				{ID: 1, UserID: id, AccessedAt: time.Now()},
			}, nil
		}
		return nil, nil
	}
	ds.SessionByIDFunc = func(ctx context.Context, id uint) (*mobius.Session, error) {
		return &mobius.Session{ID: id, UserID: 999, AccessedAt: time.Now()}, nil
	}
	ds.DestroySessionFunc = func(ctx context.Context, ssn *mobius.Session) error {
		return nil
	}
	ds.MarkSessionAccessedFunc = func(ctx context.Context, ssn *mobius.Session) error {
		return nil
	}

	testCases := []struct {
		name            string
		user            *mobius.User
		shouldFailWrite bool
		shouldFailRead  bool
	}{
		{
			"global admin",
			&mobius.User{ID: 111, GlobalRole: ptr.String(mobius.RoleAdmin)},
			false,
			false,
		},
		{
			"global maintainer",
			&mobius.User{ID: 111, GlobalRole: ptr.String(mobius.RoleMaintainer)},
			true,
			true,
		},
		{
			"global observer",
			&mobius.User{ID: 111, GlobalRole: ptr.String(mobius.RoleObserver)},
			true,
			true,
		},
		{
			"owner user",
			&mobius.User{ID: 999},
			false,
			false,
		},
		{
			"non-owner user",
			&mobius.User{ID: 888},
			true,
			true,
		},
	}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			ctx := viewer.NewContext(ctx, viewer.Viewer{User: tt.user})

			_, err := svc.GetInfoAboutSessionsForUser(ctx, 999)
			checkAuthErr(t, tt.shouldFailRead, err)

			_, err = svc.GetInfoAboutSession(ctx, 1)
			checkAuthErr(t, tt.shouldFailRead, err)

			err = svc.DeleteSession(ctx, 1)
			checkAuthErr(t, tt.shouldFailWrite, err)
		})
	}
}

func TestAuthenticate(t *testing.T) {
	ds := mysql.CreateMySQLDS(t)
	defer ds.Close()

	svc, ctx := newTestService(t, ds, nil, nil)
	createTestUsers(t, ds)

	loginTests := []struct {
		name     string
		email    string
		password string
		wantErr  error
	}{
		{
			name:     "admin1",
			email:    testUsers["admin1"].Email,
			password: testUsers["admin1"].PlaintextPassword,
		},
		{
			name:     "user1",
			email:    testUsers["user1"].Email,
			password: testUsers["user1"].PlaintextPassword,
		},
	}

	for _, tt := range loginTests {
		t.Run(tt.email, func(st *testing.T) {
			loggedIn, token, err := svc.Login(test.UserContext(ctx, test.UserAdmin), tt.email, tt.password, false)
			require.Nil(st, err, "login unsuccessful")
			assert.Equal(st, tt.email, loggedIn.Email)
			assert.NotEmpty(st, token)

			sessions, err := svc.GetInfoAboutSessionsForUser(test.UserContext(ctx, test.UserAdmin), loggedIn.ID)
			require.Nil(st, err)
			require.Len(st, sessions, 1, "user should have one session")
			session := sessions[0]
			assert.NotZero(st, session.UserID)
			assert.WithinDuration(st, time.Now(), session.AccessedAt, 3*time.Second,
				"access time should be set with current time at session creation")
		})
	}
}

func TestMFA(t *testing.T) {
	ds := new(mock.Store)
	svc, ctx := newTestService(t, ds, nil, nil)

	user := &mobius.User{MFAEnabled: true, Name: "Bob Smith", Email: "foo@example.com"}
	require.NoError(t, user.SetPassword(test.GoodPassword, 10, 10))
	ds.UserByEmailFunc = func(ctx context.Context, email string) (*mobius.User, error) {
		return user, nil
	}
	_, _, err := svc.Login(ctx, "foo@example.com", test.GoodPassword, false)
	require.Equal(t, err, mfaNotSupportedForClient)

	var sentMail mobius.Email
	mailer := &mockMailService{SendEmailFn: func(e mobius.Email) error {
		sentMail = e
		return nil
	}}
	mfaToken := "foovalidate"
	ds.NewMFATokenFunc = func(ctx context.Context, userID uint) (string, error) {
		return mfaToken, nil
	}
	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		return &mobius.AppConfig{}, nil
	}
	svcForMailing := validationMiddleware{&Service{
		ds:          ds,
		config:      config.TestConfig(),
		mailService: mailer,
	}, ds, nil}
	_, _, err = svcForMailing.Login(ctx, "foo@example.com", test.GoodPassword, true)
	require.Equal(t, err, sendingMFAEmail)
	require.Equal(t, "foo@example.com", sentMail.To[0])
	require.Equal(t, "Log in to Mobius", sentMail.Subject)

	var session *mobius.Session
	var mfaUser *mobius.User
	ds.SessionByMFATokenFunc = func(ctx context.Context, token string, sessionKeySize int) (*mobius.Session, mobius.User, error) {
		if token == mfaToken {
			return session, mfaUser, nil
		}
		return nil, nil, notFoundErr{}
	}
	resp, err := sessionCreateEndpoint(ctx, &sessionCreateRequest{Token: "foo"}, svc)
	require.NoError(t, err)
	require.NotNil(t, resp.Error())

	session = &mobius.Session{}
	mfaUser = user
	ds.NewActivityFunc = func(ctx context.Context, user *mobius.User, activity mobius.ActivityDetails, details []byte, createdAt time.Time) error {
		require.Equal(t, mfaUser, user)
		require.Equal(t, mobius.ActivityTypeUserLoggedIn{}.ActivityName(), activity.ActivityName())
		return nil
	}
	resp, err = sessionCreateEndpoint(ctx, &sessionCreateRequest{Token: mfaToken}, svc)
	require.NoError(t, err)
	require.Nil(t, resp.Error())
	require.True(t, ds.NewActivityFuncInvoked)
}

func TestGetSessionByKey(t *testing.T) {
	ds := new(mock.Store)
	svc, ctx := newTestService(t, ds, nil, nil)
	cfg := config.TestConfig()

	theSession := &mobius.Session{UserID: 123, Key: "abc"}

	ds.SessionByKeyFunc = func(ctx context.Context, key string) (*mobius.Session, error) {
		return theSession, nil
	}
	ds.DestroySessionFunc = func(ctx context.Context, ssn *mobius.Session) error {
		return nil
	}
	ds.MarkSessionAccessedFunc = func(ctx context.Context, ssn *mobius.Session) error {
		return nil
	}

	cases := []struct {
		desc     string
		accessed time.Duration
		apiOnly  bool
		fail     bool
	}{
		{"real user, accessed recently", -1 * time.Hour, false, false},
		{"real user, accessed too long ago", -(cfg.Session.Duration + time.Hour), false, true},
		{"api-only, accessed recently", -1 * time.Hour, true, false},
		{"api-only, accessed long ago", -(cfg.Session.Duration + time.Hour), true, false},
	}
	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			var authErr *mobius.AuthRequiredError
			ds.SessionByKeyFuncInvoked, ds.DestroySessionFuncInvoked, ds.MarkSessionAccessedFuncInvoked = false, false, false

			theSession.AccessedAt = time.Now().Add(tc.accessed)
			theSession.APIOnly = ptr.Bool(tc.apiOnly)
			_, err := svc.GetSessionByKey(ctx, theSession.Key)
			if tc.fail {
				require.Error(t, err)
				require.ErrorAs(t, err, &authErr)
				require.True(t, ds.SessionByKeyFuncInvoked)
				require.True(t, ds.DestroySessionFuncInvoked)
				require.False(t, ds.MarkSessionAccessedFuncInvoked)
			} else {
				require.NoError(t, err)
				require.True(t, ds.SessionByKeyFuncInvoked)
				require.False(t, ds.DestroySessionFuncInvoked)
				require.True(t, ds.MarkSessionAccessedFuncInvoked)
			}
		})
	}
}

type testAuth struct {
	userID              string
	userDisplayName     string
	requestID           string
	assertionAttributes []mobius.SAMLAttribute
}

var _ mobius.Auth = (*testAuth)(nil)

func (a *testAuth) UserID() string {
	return a.userID
}

func (a *testAuth) UserDisplayName() string {
	return a.userDisplayName
}

func (a *testAuth) RequestID() string {
	return a.requestID
}

func (a *testAuth) AssertionAttributes() []mobius.SAMLAttribute {
	return a.assertionAttributes
}

func TestGetSSOUser(t *testing.T) {
	ds := new(mock.Store)
	svc, ctx := newTestService(t, ds, nil, nil, &TestServerOpts{
		License: &mobius.LicenseInfo{
			Tier: mobius.TierPremium,
		},
	})

	ds.NewActivityFunc = func(
		ctx context.Context, user *mobius.User, activity mobius.ActivityDetails, details []byte, createdAt time.Time,
	) error {
		return nil
	}

	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		return &mobius.AppConfig{
			SSOSettings: &mobius.SSOSettings{
				EnableSSO:             true,
				EnableSSOIdPLogin:     true,
				EnableJITProvisioning: true,
			},
		}, nil
	}

	ds.UserByEmailFunc = func(ctx context.Context, email string) (*mobius.User, error) {
		return nil, newNotFoundError()
	}

	var newUser *mobius.User
	ds.NewUserFunc = func(ctx context.Context, user *mobius.User) (mobius.User, error) {
		newUser = user
		return user, nil
	}

	auth := &testAuth{
		userID:          "foo@example.com",
		userDisplayName: "foo@example.com",
		requestID:       "foobar",
		assertionAttributes: []mobius.SAMLAttribute{
			{
				Name: "MOBIUS_JIT_USER_ROLE_GLOBAL",
				Values: []mobius.SAMLAttributeValue{
					{Value: "admin"},
				},
			},
		},
	}

	// Test SSO login with a non-existent user.
	_, err := svc.GetSSOUser(ctx, auth)
	require.NoError(t, err)

	require.NotNil(t, newUser)
	require.NotNil(t, newUser.GlobalRole)
	require.Equal(t, "admin", *newUser.GlobalRole)
	require.Empty(t, newUser.Teams)

	// Test SSO login with the same (now existing) user (should update roles).

	// (1) Check that when a user's role attributes are unchanged then SavedUser is not called.

	ds.SaveUserFunc = func(ctx context.Context, user *mobius.User) error {
		return nil
	}

	ds.UserByEmailFunc = func(ctx context.Context, email string) (*mobius.User, error) {
		return newUser, nil
	}

	_, err = svc.GetSSOUser(ctx, auth)
	require.NoError(t, err)

	require.False(t, ds.SaveUserFuncInvoked)

	// (2) Test SSO login with the same user with roles updated in its attributes.

	var savedUser *mobius.User
	ds.SaveUserFunc = func(ctx context.Context, user *mobius.User) error {
		savedUser = user
		return nil
	}

	ds.TeamFunc = func(ctx context.Context, tid uint) (*mobius.Team, error) {
		return &mobius.Team{ID: tid}, nil
	}

	auth.assertionAttributes = []mobius.SAMLAttribute{
		{
			Name: "MOBIUS_JIT_USER_ROLE_TEAM_2",
			Values: []mobius.SAMLAttributeValue{
				{Value: "maintainer"},
			},
		},
	}

	_, err = svc.GetSSOUser(ctx, auth)
	require.NoError(t, err)

	require.NotNil(t, savedUser)
	require.Nil(t, savedUser.GlobalRole)
	require.Len(t, savedUser.Teams, 1)
	require.Equal(t, uint(2), savedUser.Teams[0].ID)
	require.Equal(t, "maintainer", savedUser.Teams[0].Role)

	require.True(t, ds.SaveUserFuncInvoked)

	// (3) Test existing user's role is not changed after a new login if EnableJITProvisioning is false.

	ds.SaveUserFuncInvoked = false

	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		return &mobius.AppConfig{
			SSOSettings: &mobius.SSOSettings{
				EnableSSO:             true,
				EnableSSOIdPLogin:     true,
				EnableJITProvisioning: false,
			},
		}, nil
	}

	auth.assertionAttributes = []mobius.SAMLAttribute{
		{
			Name: "MOBIUS_JIT_USER_ROLE_TEAM_2",
			Values: []mobius.SAMLAttributeValue{
				{Value: "admin"},
			},
		},
	}

	_, err = svc.GetSSOUser(ctx, auth)
	require.NoError(t, err)

	require.False(t, ds.SaveUserFuncInvoked)

	// (4) Test with invalid team ID in the attributes

	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		return &mobius.AppConfig{
			SSOSettings: &mobius.SSOSettings{
				EnableSSO:             true,
				EnableSSOIdPLogin:     true,
				EnableJITProvisioning: true,
			},
		}, nil
	}

	ds.TeamFunc = func(ctx context.Context, tid uint) (*mobius.Team, error) {
		return nil, newNotFoundError()
	}

	auth.assertionAttributes = []mobius.SAMLAttribute{
		{
			Name: "MOBIUS_JIT_USER_ROLE_TEAM_3",
			Values: []mobius.SAMLAttributeValue{
				{Value: "maintainer"},
			},
		},
	}

	_, err = svc.GetSSOUser(ctx, auth)
	require.Error(t, err)
}
