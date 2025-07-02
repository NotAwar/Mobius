package service

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/WatchBeam/clock"
	"github.com/notawar/mobius/server/authz"
	"github.com/notawar/mobius/server/config"
	"github.com/notawar/mobius/server/contexts/license"
	"github.com/notawar/mobius/server/contexts/viewer"
	"github.com/notawar/mobius/server/mobius"
	"github.com/notawar/mobius/server/mock"
	"github.com/notawar/mobius/server/ptr"
	"github.com/notawar/mobius/server/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/guregu/null.v3"
)

func TestInviteNewUserMock(t *testing.T) {
	ms := new(mock.Store)
	ms.UserByEmailFunc = mock.UserWithEmailNotFound()
	ms.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		return &mobius.AppConfig{ServerSettings: mobius.ServerSettings{ServerURL: "https://acme.co"}}, nil
	}

	ms.NewInviteFunc = func(ctx context.Context, i *mobius.Invite) (*mobius.Invite, error) {
		return i, nil
	}
	mailer := &mockMailService{SendEmailFn: func(e mobius.Email) error { return nil }}

	svc := validationMiddleware{&Service{
		ds:          ms,
		config:      config.TestConfig(),
		mailService: mailer,
		clock:       clock.NewMockClock(),
		authz:       authz.Must(),
	}, ms, nil}

	payload := mobius.InvitePayload{
		Email: ptr.String("user@acme.co"),
	}

	payload.SSOEnabled = ptr.Bool(true)
	payload.MFAEnabled = ptr.Bool(true)
	_, err := svc.InviteNewUser(test.UserContext(context.Background(), test.UserAdmin), payload)
	require.Error(t, err)

	payload.SSOEnabled = nil
	_, err = svc.InviteNewUser(test.UserContext(context.Background(), test.UserAdmin), payload)
	require.ErrorContains(t, err, "license")

	// happy path
	invite, err := svc.InviteNewUser(license.NewContext(test.UserContext(context.Background(), test.UserAdmin), &mobius.LicenseInfo{Tier: mobius.TierPremium}), payload)
	require.Nil(t, err)
	assert.Equal(t, test.UserAdmin.ID, invite.InvitedBy)
	assert.True(t, ms.NewInviteFuncInvoked)
	assert.True(t, ms.AppConfigFuncInvoked)
	assert.True(t, mailer.Invoked)

	ms.UserByEmailFunc = mock.UserByEmailWithUser(new(mobius.User))
	_, err = svc.InviteNewUser(test.UserContext(context.Background(), test.UserAdmin), payload)
	require.NotNil(t, err, "should err if the user we're inviting already exists")
}

func TestUpdateInvite(t *testing.T) {
	ms := new(mock.Store)
	ms.InviteFunc = func(ctx context.Context, id uint) (*mobius.Invite, error) {
		if id != 1 {
			return nil, sql.ErrNoRows
		}

		return &mobius.Invite{
			ID:         1,
			Name:       "John Appleseed",
			Email:      "john_appleseed@example.com",
			SSOEnabled: true,
			GlobalRole: null.NewString("observer", true),
		}, nil
	}
	ms.UpdateInviteFunc = func(ctx context.Context, id uint, i *mobius.Invite) (*mobius.Invite, error) {
		return nil, nil
	}

	mailer := &mockMailService{SendEmailFn: func(e mobius.Email) error { return nil }}

	svc := validationMiddleware{&Service{
		ds:          ms,
		config:      config.TestConfig(),
		mailService: mailer,
		clock:       clock.NewMockClock(),
		authz:       authz.Must(),
	}, ms, nil}

	// email is the same
	payload := mobius.InvitePayload{
		Name:  ptr.String("Johnny Appleseed"),
		Email: ptr.String("john_appleseed@example.com"),
	}

	ctx := test.UserContext(context.Background(), test.UserAdmin)

	// update the invite (email is the same)
	_, err := svc.UpdateInvite(ctx, 1, payload)
	require.NoError(t, err)
	require.True(t, ms.InviteFuncInvoked)

	payload = mobius.InvitePayload{MFAEnabled: ptr.Bool(true)}
	_, err = svc.UpdateInvite(ctx, 1, payload)
	require.Error(t, err)

	payload = mobius.InvitePayload{MFAEnabled: ptr.Bool(true), SSOEnabled: ptr.Bool(false)}
	_, err = svc.UpdateInvite(ctx, 1, payload)
	require.ErrorContains(t, err, "license")

	ms.UpdateInviteFuncInvoked = false
	ctx = license.NewContext(ctx, &mobius.LicenseInfo{Tier: mobius.TierPremium})
	_, err = svc.UpdateInvite(ctx, 1, payload)
	require.NoError(t, err)
	require.True(t, ms.UpdateInviteFuncInvoked)
}

func TestVerifyInvite(t *testing.T) {
	ms := new(mock.Store)
	svc, ctx := newTestService(t, ms, nil, nil)

	ms.InviteByTokenFunc = func(ctx context.Context, token string) (*mobius.Invite, error) {
		return &mobius.Invite{
			ID:    1,
			Token: "abcd",
			UpdateCreateTimestamps: mobius.UpdateCreateTimestamps{
				CreateTimestamp: mobius.CreateTimestamp{
					CreatedAt: time.Now().AddDate(-1, 0, 0),
				},
			},
		}, nil
	}
	wantErr := mobius.NewInvalidArgumentError("invite_token", "Invite token has expired.")
	_, err := svc.VerifyInvite(test.UserContext(ctx, test.UserAdmin), "abcd")
	assert.Equal(t, err, wantErr)

	wantErr = mobius.NewInvalidArgumentError("invite_token", "Invite Token does not match Email Address.")

	_, err = svc.VerifyInvite(test.UserContext(ctx, test.UserAdmin), "bad_token")
	assert.Equal(t, err, wantErr)
}

func TestDeleteInvite(t *testing.T) {
	ms := new(mock.Store)
	svc, ctx := newTestService(t, ms, nil, nil)

	ms.DeleteInviteFunc = func(context.Context, uint) error { return nil }
	err := svc.DeleteInvite(test.UserContext(ctx, test.UserAdmin), 1)
	require.Nil(t, err)
	assert.True(t, ms.DeleteInviteFuncInvoked)
}

func TestListInvites(t *testing.T) {
	ms := new(mock.Store)
	svc, ctx := newTestService(t, ms, nil, nil)

	ms.ListInvitesFunc = func(context.Context, mobius.ListOptions) ([]*mobius.Invite, error) {
		return nil, nil
	}
	_, err := svc.ListInvites(test.UserContext(ctx, test.UserAdmin), mobius.ListOptions{})
	require.Nil(t, err)
	assert.True(t, ms.ListInvitesFuncInvoked)
}

func TestInvitesAuth(t *testing.T) {
	ds := new(mock.Store)
	svc, ctx := newTestService(t, ds, nil, nil)

	ds.ListInvitesFunc = func(context.Context, mobius.ListOptions) ([]*mobius.Invite, error) {
		return nil, nil
	}
	ds.DeleteInviteFunc = func(context.Context, uint) error { return nil }
	ds.UserByEmailFunc = func(ctx context.Context, email string) (*mobius.User, error) {
		return nil, newNotFoundError()
	}
	ds.NewInviteFunc = func(ctx context.Context, i *mobius.Invite) (*mobius.Invite, error) {
		return &mobius.Invite{}, nil
	}
	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		return &mobius.AppConfig{}, nil
	}
	var testCases = []struct {
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
			true,
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
			true,
		},
		{
			"team maintainer, belongs to team",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleMaintainer}}},
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
			"team maintainer, DOES NOT belong to team",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 2}, Role: mobius.RoleMaintainer}}},
			true,
			true,
		},
		{
			"team admin, DOES NOT belong to team",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 2}, Role: mobius.RoleAdmin}}},
			true,
			true,
		},
		{
			"team observer, DOES NOT belong to team",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 2}, Role: mobius.RoleObserver}}},
			true,
			true,
		},
	}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			ctx := viewer.NewContext(ctx, viewer.Viewer{User: tt.user})

			_, err := svc.InviteNewUser(ctx, mobius.InvitePayload{
				Email:      ptr.String("e@mail.com"),
				Name:       ptr.String("name"),
				Position:   ptr.String("someposition"),
				SSOEnabled: ptr.Bool(false),
				GlobalRole: null.StringFromPtr(tt.user.GlobalRole),
				Teams: []mobius.UserTeam{
					{
						Team: mobius.Team{ID: 1},
						Role: mobius.RoleMaintainer,
					},
				},
			})
			checkAuthErr(t, tt.shouldFailWrite, err)

			_, err = svc.ListInvites(ctx, mobius.ListOptions{})
			checkAuthErr(t, tt.shouldFailRead, err)

			err = svc.DeleteInvite(ctx, 99)
			checkAuthErr(t, tt.shouldFailWrite, err)
		})
	}
}
