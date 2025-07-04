package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/notawar/mobius/server/authz"
	"github.com/notawar/mobius/server/contexts/ctxerr"
	"github.com/notawar/mobius/server/contexts/license"
	"github.com/notawar/mobius/server/contexts/viewer"
	"github.com/notawar/mobius/server/datastore/mysql"
	"github.com/notawar/mobius/server/mobius"
	"github.com/notawar/mobius/server/mock"
	"github.com/notawar/mobius/server/ptr"
	"github.com/notawar/mobius/server/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUserAuth(t *testing.T) {
	ds := new(mock.Store)
	svc, ctx := newTestService(t, ds, nil, nil)

	const (
		teamID      = 1
		otherTeamID = 2
	)
	ds.TeamsSummaryFunc = func(ctx context.Context) ([]*mobius.TeamSummary, error) {
		team1 := &mobius.TeamSummary{ID: teamID}
		team2 := &mobius.TeamSummary{ID: otherTeamID}
		return []*mobius.TeamSummary{team1, team2}, nil
	}
	ds.InviteByTokenFunc = func(ctx context.Context, token string) (*mobius.Invite, error) {
		return &mobius.Invite{
			Email: "some@email.com",
			Token: "ABCD",
			UpdateCreateTimestamps: mobius.UpdateCreateTimestamps{
				CreateTimestamp: mobius.CreateTimestamp{CreatedAt: time.Now()},
				UpdateTimestamp: mobius.UpdateTimestamp{UpdatedAt: time.Now()},
			},
		}, nil
	}
	ds.NewUserFunc = func(ctx context.Context, user *mobius.User) (*mobius.User, error) {
		return &mobius.User{}, nil
	}
	ds.DeleteInviteFunc = func(ctx context.Context, id uint) error {
		return nil
	}
	ds.InviteByEmailFunc = func(ctx context.Context, email string) (*mobius.Invite, error) {
		return nil, errors.New("AA")
	}

	userTeamMaintainerID := uint(999)
	userGlobalMaintainerID := uint(888)
	var self *mobius.User // to be set by tests
	ds.UserByIDFunc = func(ctx context.Context, id uint) (*mobius.User, error) {
		switch id {
		case userTeamMaintainerID:
			return &mobius.User{
				ID:    userTeamMaintainerID,
				Teams: []mobius.UserTeam{{Team: mobius.Team{ID: teamID}, Role: mobius.RoleMaintainer}},
			}, nil
		case userGlobalMaintainerID:
			return &mobius.User{
				ID:         userGlobalMaintainerID,
				GlobalRole: ptr.String(mobius.RoleMaintainer),
			}, nil
		default:
			return self, nil
		}
	}

	ds.SaveUserFunc = func(ctx context.Context, user *mobius.User) error {
		return nil
	}
	ds.ListUsersFunc = func(ctx context.Context, opts mobius.UserListOptions) ([]*mobius.User, error) {
		return nil, nil
	}
	ds.DeleteUserFunc = func(ctx context.Context, id uint) error {
		return nil
	}
	ds.DestroyAllSessionsForUserFunc = func(ctx context.Context, id uint) error {
		return nil
	}
	ds.ListSessionsForUserFunc = func(ctx context.Context, id uint) ([]*mobius.Session, error) {
		return nil, nil
	}
	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		return &mobius.AppConfig{}, nil
	}
	ds.NewActivityFunc = func(
		ctx context.Context, user *mobius.User, activity mobius.ActivityDetails, details []byte, createdAt time.Time,
	) error {
		return nil
	}

	testCases := []struct {
		name string
		user *mobius.User

		shouldFailGlobalWrite bool
		shouldFailTeamWrite   bool

		shouldFailWriteRoleGlobalToGlobal    bool
		shouldFailWriteRoleGlobalToTeam      bool
		shouldFailWriteRoleTeamToAnotherTeam bool
		shouldFailWriteRoleTeamToGlobal      bool

		shouldFailWriteRoleOwnDomain bool

		shouldFailGlobalRead bool
		shouldFailTeamRead   bool

		shouldFailGlobalDelete bool
		shouldFailTeamDelete   bool

		shouldFailGlobalPasswordReset bool
		shouldFailTeamPasswordReset   bool

		shouldFailGlobalChangePassword bool
		shouldFailTeamChangePassword   bool

		shouldFailListAll  bool
		shouldFailListTeam bool
	}{
		{
			name:                                 "global admin",
			user:                                 &mobius.User{ID: 1000, GlobalRole: ptr.String(mobius.RoleAdmin)},
			shouldFailGlobalWrite:                false,
			shouldFailTeamWrite:                  false,
			shouldFailWriteRoleGlobalToGlobal:    false,
			shouldFailWriteRoleGlobalToTeam:      false,
			shouldFailWriteRoleTeamToAnotherTeam: false,
			shouldFailWriteRoleTeamToGlobal:      false,
			shouldFailWriteRoleOwnDomain:         false,
			shouldFailGlobalRead:                 false,
			shouldFailTeamRead:                   false,
			shouldFailGlobalDelete:               false,
			shouldFailTeamDelete:                 false,
			shouldFailGlobalPasswordReset:        false,
			shouldFailTeamPasswordReset:          false,
			shouldFailGlobalChangePassword:       false,
			shouldFailTeamChangePassword:         false,
			shouldFailListAll:                    false,
			shouldFailListTeam:                   false,
		},
		{
			name:                                 "global maintainer",
			user:                                 &mobius.User{ID: 1000, GlobalRole: ptr.String(mobius.RoleMaintainer)},
			shouldFailGlobalWrite:                true,
			shouldFailTeamWrite:                  true,
			shouldFailWriteRoleGlobalToGlobal:    true,
			shouldFailWriteRoleGlobalToTeam:      true,
			shouldFailWriteRoleTeamToAnotherTeam: true,
			shouldFailWriteRoleTeamToGlobal:      true,
			shouldFailWriteRoleOwnDomain:         true,
			shouldFailGlobalRead:                 true,
			shouldFailTeamRead:                   true,
			shouldFailGlobalDelete:               true,
			shouldFailTeamDelete:                 true,
			shouldFailGlobalPasswordReset:        true,
			shouldFailTeamPasswordReset:          true,
			shouldFailGlobalChangePassword:       true,
			shouldFailTeamChangePassword:         true,
			shouldFailListAll:                    true,
			shouldFailListTeam:                   true,
		},
		{
			name:                                 "global observer",
			user:                                 &mobius.User{ID: 1000, GlobalRole: ptr.String(mobius.RoleObserver)},
			shouldFailGlobalWrite:                true,
			shouldFailTeamWrite:                  true,
			shouldFailWriteRoleGlobalToGlobal:    true,
			shouldFailWriteRoleGlobalToTeam:      true,
			shouldFailWriteRoleTeamToAnotherTeam: true,
			shouldFailWriteRoleTeamToGlobal:      true,
			shouldFailWriteRoleOwnDomain:         true,
			shouldFailGlobalRead:                 true,
			shouldFailTeamRead:                   true,
			shouldFailGlobalDelete:               true,
			shouldFailTeamDelete:                 true,
			shouldFailGlobalPasswordReset:        true,
			shouldFailTeamPasswordReset:          true,
			shouldFailGlobalChangePassword:       true,
			shouldFailTeamChangePassword:         true,
			shouldFailListAll:                    true,
			shouldFailListTeam:                   true,
		},
		{
			name:                                 "team admin, belongs to team",
			user:                                 &mobius.User{ID: 1000, Teams: []mobius.UserTeam{{Team: mobius.Team{ID: teamID}, Role: mobius.RoleAdmin}}},
			shouldFailGlobalWrite:                true,
			shouldFailTeamWrite:                  false,
			shouldFailWriteRoleGlobalToGlobal:    true,
			shouldFailWriteRoleGlobalToTeam:      true,
			shouldFailWriteRoleTeamToAnotherTeam: true,
			shouldFailWriteRoleTeamToGlobal:      true,
			shouldFailWriteRoleOwnDomain:         false,
			shouldFailGlobalRead:                 true,
			shouldFailTeamRead:                   false,
			shouldFailGlobalDelete:               true,
			shouldFailTeamDelete:                 false,
			shouldFailGlobalPasswordReset:        true,
			shouldFailTeamPasswordReset:          true,
			shouldFailGlobalChangePassword:       true,
			shouldFailTeamChangePassword:         true,
			shouldFailListAll:                    true,
			shouldFailListTeam:                   false,
		},
		{
			name:                                 "team maintainer, belongs to team",
			user:                                 &mobius.User{ID: 1000, Teams: []mobius.UserTeam{{Team: mobius.Team{ID: teamID}, Role: mobius.RoleMaintainer}}},
			shouldFailGlobalWrite:                true,
			shouldFailTeamWrite:                  true,
			shouldFailWriteRoleGlobalToGlobal:    true,
			shouldFailWriteRoleGlobalToTeam:      true,
			shouldFailWriteRoleTeamToAnotherTeam: true,
			shouldFailWriteRoleTeamToGlobal:      true,
			shouldFailWriteRoleOwnDomain:         true,
			shouldFailGlobalRead:                 true,
			shouldFailTeamRead:                   true,
			shouldFailGlobalDelete:               true,
			shouldFailTeamDelete:                 true,
			shouldFailGlobalPasswordReset:        true,
			shouldFailTeamPasswordReset:          true,
			shouldFailGlobalChangePassword:       true,
			shouldFailTeamChangePassword:         true,
			shouldFailListAll:                    true,
			shouldFailListTeam:                   true,
		},
		{
			name:                                 "team observer, belongs to team",
			user:                                 &mobius.User{ID: 1000, Teams: []mobius.UserTeam{{Team: mobius.Team{ID: teamID}, Role: mobius.RoleObserver}}},
			shouldFailGlobalWrite:                true,
			shouldFailTeamWrite:                  true,
			shouldFailWriteRoleGlobalToGlobal:    true,
			shouldFailWriteRoleGlobalToTeam:      true,
			shouldFailWriteRoleTeamToAnotherTeam: true,
			shouldFailWriteRoleTeamToGlobal:      true,
			shouldFailWriteRoleOwnDomain:         true,
			shouldFailGlobalRead:                 true,
			shouldFailTeamRead:                   true,
			shouldFailGlobalDelete:               true,
			shouldFailTeamDelete:                 true,
			shouldFailGlobalPasswordReset:        true,
			shouldFailTeamPasswordReset:          true,
			shouldFailGlobalChangePassword:       true,
			shouldFailTeamChangePassword:         true,
			shouldFailListAll:                    true,
			shouldFailListTeam:                   true,
		},
		{
			name:                                 "team maintainer, DOES NOT belong to team",
			user:                                 &mobius.User{ID: 1000, Teams: []mobius.UserTeam{{Team: mobius.Team{ID: otherTeamID}, Role: mobius.RoleMaintainer}}},
			shouldFailGlobalWrite:                true,
			shouldFailTeamWrite:                  true,
			shouldFailWriteRoleGlobalToGlobal:    true,
			shouldFailWriteRoleGlobalToTeam:      true,
			shouldFailWriteRoleTeamToAnotherTeam: true,
			shouldFailWriteRoleTeamToGlobal:      true,
			shouldFailWriteRoleOwnDomain:         true,
			shouldFailGlobalRead:                 true,
			shouldFailTeamRead:                   true,
			shouldFailGlobalDelete:               true,
			shouldFailTeamDelete:                 true,
			shouldFailGlobalPasswordReset:        true,
			shouldFailTeamPasswordReset:          true,
			shouldFailGlobalChangePassword:       true,
			shouldFailTeamChangePassword:         true,
			shouldFailListAll:                    true,
			shouldFailListTeam:                   true,
		},
		{
			name:                                 "team admin, DOES NOT belong to team",
			user:                                 &mobius.User{ID: 1000, Teams: []mobius.UserTeam{{Team: mobius.Team{ID: otherTeamID}, Role: mobius.RoleAdmin}}},
			shouldFailGlobalWrite:                true,
			shouldFailTeamWrite:                  true,
			shouldFailWriteRoleGlobalToGlobal:    true,
			shouldFailWriteRoleGlobalToTeam:      true,
			shouldFailWriteRoleTeamToAnotherTeam: true,
			shouldFailWriteRoleTeamToGlobal:      true,
			shouldFailWriteRoleOwnDomain:         false, // this is testing changing its own role in the team it belongs to.
			shouldFailGlobalRead:                 true,
			shouldFailTeamRead:                   true,
			shouldFailGlobalDelete:               true,
			shouldFailTeamDelete:                 true,
			shouldFailGlobalPasswordReset:        true,
			shouldFailTeamPasswordReset:          true,
			shouldFailGlobalChangePassword:       true,
			shouldFailTeamChangePassword:         true,
			shouldFailListAll:                    true,
			shouldFailListTeam:                   true,
		},
		{
			name:                                 "team observer, DOES NOT belong to team",
			user:                                 &mobius.User{ID: 1000, Teams: []mobius.UserTeam{{Team: mobius.Team{ID: otherTeamID}, Role: mobius.RoleObserver}}},
			shouldFailGlobalWrite:                true,
			shouldFailTeamWrite:                  true,
			shouldFailWriteRoleGlobalToGlobal:    true,
			shouldFailWriteRoleGlobalToTeam:      true,
			shouldFailWriteRoleTeamToAnotherTeam: true,
			shouldFailWriteRoleTeamToGlobal:      true,
			shouldFailWriteRoleOwnDomain:         true,
			shouldFailGlobalRead:                 true,
			shouldFailTeamRead:                   true,
			shouldFailGlobalDelete:               true,
			shouldFailTeamDelete:                 true,
			shouldFailGlobalPasswordReset:        true,
			shouldFailTeamPasswordReset:          true,
			shouldFailGlobalChangePassword:       true,
			shouldFailTeamChangePassword:         true,
			shouldFailListAll:                    true,
			shouldFailListTeam:                   true,
		},
	}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			ctx := viewer.NewContext(ctx, viewer.Viewer{User: tt.user})

			err := tt.user.SetPassword(test.GoodPassword, 10, 10)
			require.NoError(t, err)

			// To test a user reading/modifying itself.
			u := *tt.user
			self = &u

			// A user can always read itself (read rego action).
			_, err = svc.User(ctx, tt.user.ID)
			require.NoError(t, err)

			// A user can always write itself (write rego action).
			_, err = svc.ModifyUser(ctx, tt.user.ID, mobius.UserPayload{Name: ptr.String("Foo")})
			require.NoError(t, err)

			// A user can always change its own password (change_password rego action).
			_, err = svc.ModifyUser(ctx, tt.user.ID, mobius.UserPayload{Password: ptr.String(test.GoodPassword), NewPassword: ptr.String(test.GoodPassword2)})
			require.NoError(t, err)

			changeRole := func(role string) string {
				switch role {
				case mobius.RoleMaintainer:
					return mobius.RoleAdmin // promote
				case mobius.RoleAdmin:
					return mobius.RoleMaintainer // demote
				case mobius.RoleObserver:
					return mobius.RoleAdmin // promote
				default:
					t.Fatalf("unknown role: %s", role)
					return ""
				}
			}

			// Test a user modifying its own role within its domain (write_role rego action).
			if tt.user.GlobalRole != nil {
				_, err = svc.ModifyUser(ctx, tt.user.ID, mobius.UserPayload{GlobalRole: ptr.String(changeRole(*tt.user.GlobalRole))})
				checkAuthErr(t, tt.shouldFailWriteRoleOwnDomain, err)
			} else { // Team user
				ownTeamDifferentRole := []mobius.UserTeam{
					{
						Team: mobius.Team{ID: tt.user.Teams[0].ID},
						Role: changeRole(tt.user.Teams[0].Role),
					},
				}
				_, err = svc.ModifyUser(ctx, tt.user.ID, mobius.UserPayload{Teams: &ownTeamDifferentRole})
				checkAuthErr(t, tt.shouldFailWriteRoleOwnDomain, err)
			}

			teams := []mobius.UserTeam{{Team: mobius.Team{ID: teamID}, Role: mobius.RoleMaintainer}}
			_, _, err = svc.CreateUser(ctx, mobius.UserPayload{
				Name:     ptr.String("Some Name"),
				Email:    ptr.String("some@email.com"),
				Password: ptr.String(test.GoodPassword),
				Teams:    &teams,
			})
			checkAuthErr(t, tt.shouldFailTeamWrite, err)

			_, _, err = svc.CreateUser(ctx, mobius.UserPayload{
				Name:       ptr.String("Some Name"),
				Email:      ptr.String("some@email.com"),
				Password:   ptr.String(test.GoodPassword),
				GlobalRole: ptr.String(mobius.RoleAdmin),
			})
			checkAuthErr(t, tt.shouldFailGlobalWrite, err)

			_, err = svc.ModifyUser(ctx, userGlobalMaintainerID, mobius.UserPayload{Name: ptr.String("Foo")})
			checkAuthErr(t, tt.shouldFailGlobalWrite, err)

			_, err = svc.ModifyUser(ctx, userTeamMaintainerID, mobius.UserPayload{Name: ptr.String("Bar")})
			checkAuthErr(t, tt.shouldFailTeamWrite, err)

			_, err = svc.ModifyUser(ctx, userGlobalMaintainerID, mobius.UserPayload{GlobalRole: ptr.String(mobius.RoleMaintainer)})
			checkAuthErr(t, tt.shouldFailWriteRoleGlobalToGlobal, err)

			_, err = svc.ModifyUser(ctx, userGlobalMaintainerID, mobius.UserPayload{Teams: &teams})
			checkAuthErr(t, tt.shouldFailWriteRoleGlobalToTeam, err)

			anotherTeams := []mobius.UserTeam{{Team: mobius.Team{ID: otherTeamID}, Role: mobius.RoleMaintainer}}
			_, err = svc.ModifyUser(ctx, userTeamMaintainerID, mobius.UserPayload{Teams: &anotherTeams})
			checkAuthErr(t, tt.shouldFailWriteRoleTeamToAnotherTeam, err)

			_, err = svc.ModifyUser(ctx, userTeamMaintainerID, mobius.UserPayload{GlobalRole: ptr.String(mobius.RoleMaintainer)})
			checkAuthErr(t, tt.shouldFailWriteRoleTeamToGlobal, err)

			_, err = svc.User(ctx, userGlobalMaintainerID)
			checkAuthErr(t, tt.shouldFailGlobalRead, err)

			_, err = svc.User(ctx, userTeamMaintainerID)
			checkAuthErr(t, tt.shouldFailTeamRead, err)

			err = svc.DeleteUser(ctx, userGlobalMaintainerID)
			checkAuthErr(t, tt.shouldFailGlobalDelete, err)

			err = svc.DeleteUser(ctx, userTeamMaintainerID)
			checkAuthErr(t, tt.shouldFailTeamDelete, err)

			_, err = svc.RequirePasswordReset(ctx, userGlobalMaintainerID, false)
			checkAuthErr(t, tt.shouldFailGlobalPasswordReset, err)

			_, err = svc.RequirePasswordReset(ctx, userTeamMaintainerID, false)
			checkAuthErr(t, tt.shouldFailTeamPasswordReset, err)

			_, err = svc.ModifyUser(ctx, userGlobalMaintainerID, mobius.UserPayload{NewPassword: ptr.String(test.GoodPassword2)})
			checkAuthErr(t, tt.shouldFailGlobalChangePassword, err)

			_, err = svc.ModifyUser(ctx, userTeamMaintainerID, mobius.UserPayload{NewPassword: ptr.String(test.GoodPassword2)})
			checkAuthErr(t, tt.shouldFailTeamChangePassword, err)

			_, err = svc.ListUsers(ctx, mobius.UserListOptions{})
			checkAuthErr(t, tt.shouldFailListAll, err)

			_, err = svc.ListUsers(ctx, mobius.UserListOptions{TeamID: teamID})
			checkAuthErr(t, tt.shouldFailListTeam, err)
		})
	}
}

func TestModifyUserEmail(t *testing.T) {
	user := &mobius.User{
		ID:    3,
		Email: "foo@bar.com",
	}
	err := user.SetPassword(test.GoodPassword, 10, 10)
	require.NoError(t, err)
	ms := new(mock.Store)
	ms.PendingEmailChangeFunc = func(ctx context.Context, id uint, em, tk string) error {
		return nil
	}
	ms.UserByIDFunc = func(ctx context.Context, id uint) (*mobius.User, error) {
		return user, nil
	}
	ms.UserByEmailFunc = func(ctx context.Context, email string) (*mobius.User, error) {
		return nil, notFoundErr{}
	}
	ms.InviteByEmailFunc = func(ctx context.Context, email string) (*mobius.Invite, error) {
		return nil, notFoundErr{}
	}
	ms.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		config := &mobius.AppConfig{
			SMTPSettings: &mobius.SMTPSettings{
				SMTPConfigured:         true,
				SMTPAuthenticationType: mobius.AuthTypeNameNone,
				SMTPPort:               1025,
				SMTPServer:             "127.0.0.1",
				SMTPSenderAddress:      "xxx@mobius.co",
			},
		}
		return config, nil
	}
	ms.SaveUserFunc = func(ctx context.Context, u *mobius.User) error {
		// verify this isn't changed yet
		assert.Equal(t, "foo@bar.com", u.Email)
		// verify is changed per bug 1123
		assert.Equal(t, "minion", u.Position)
		return nil
	}
	svc, ctx := newTestService(t, ms, nil, nil)
	ctx = viewer.NewContext(ctx, viewer.Viewer{User: user})
	payload := mobius.UserPayload{
		Email:    ptr.String("zip@zap.com"),
		Password: ptr.String(test.GoodPassword),
		Position: ptr.String("minion"),
	}
	_, err = svc.ModifyUser(ctx, 3, payload)
	require.Nil(t, err)
	assert.True(t, ms.PendingEmailChangeFuncInvoked)
	assert.True(t, ms.SaveUserFuncInvoked)
}

func TestModifyUserEmailNoPassword(t *testing.T) {
	user := &mobius.User{
		ID:    3,
		Email: "foo@bar.com",
	}
	err := user.SetPassword(test.GoodPassword, 10, 10)
	require.NoError(t, err)
	ms := new(mock.Store)
	ms.PendingEmailChangeFunc = func(ctx context.Context, id uint, em, tk string) error {
		return nil
	}
	ms.UserByIDFunc = func(ctx context.Context, id uint) (*mobius.User, error) {
		return user, nil
	}
	ms.UserByEmailFunc = func(ctx context.Context, email string) (*mobius.User, error) {
		return user, nil
	}
	ms.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		config := &mobius.AppConfig{
			SMTPSettings: &mobius.SMTPSettings{
				SMTPConfigured:         true,
				SMTPAuthenticationType: mobius.AuthTypeNameNone,
				SMTPPort:               1025,
				SMTPServer:             "127.0.0.1",
				SMTPSenderAddress:      "xxx@mobius.co",
			},
		}
		return config, nil
	}
	ms.SaveUserFunc = func(ctx context.Context, u *mobius.User) error {
		return nil
	}
	svc, ctx := newTestService(t, ms, nil, nil)
	ctx = viewer.NewContext(ctx, viewer.Viewer{User: user})
	payload := mobius.UserPayload{
		Email: ptr.String("zip@zap.com"),
		// NO PASSWORD
	}
	_, err = svc.ModifyUser(ctx, 3, payload)
	require.NotNil(t, err)
	var iae *mobius.InvalidArgumentError
	ok := errors.As(err, &iae)
	require.True(t, ok)
	require.Len(t, iae.Errors, 1)
	assert.False(t, ms.PendingEmailChangeFuncInvoked)
	assert.False(t, ms.SaveUserFuncInvoked)
}

func TestMFAHandling(t *testing.T) {
	admin := &mobius.User{
		Name:       "Mobius Admin",
		Email:      "admin@foo.com",
		GlobalRole: ptr.String(mobius.RoleAdmin),
	}

	ms := new(mock.Store)
	svc, ctx := newTestService(t, ms, nil, nil)
	ctx = viewer.NewContext(ctx, viewer.Viewer{User: admin})

	payload := mobius.UserPayload{
		Email:      ptr.String("foo@example.com"),
		Name:       ptr.String("Full Name"),
		Password:   ptr.String(test.GoodPassword),
		MFAEnabled: ptr.Bool(true),
		SSOEnabled: ptr.Bool(true),
		GlobalRole: ptr.String(mobius.RoleObserver),
	}

	// test creation

	_, _, err := svc.CreateUser(ctx, payload)
	require.ErrorContains(t, err, "SSO")

	appConfig := &mobius.AppConfig{SMTPSettings: &mobius.SMTPSettings{}}
	ms.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		return appConfig, nil
	}

	payload.SSOEnabled = nil
	ms.InviteByEmailFunc = func(ctx context.Context, email string) (*mobius.Invite, error) {
		return nil, notFoundErr{}
	}
	_, _, err = svc.CreateUser(ctx, payload)
	require.ErrorContains(t, err, "mail")

	appConfig.SMTPSettings.SMTPConfigured = true
	ms.NewUserFunc = func(ctx context.Context, user *mobius.User) (*mobius.User, error) {
		user.ID = 4
		return user, nil
	}
	ms.NewActivityFunc = func(ctx context.Context, user *mobius.User, activity mobius.ActivityDetails, details []byte, createdAt time.Time) error {
		return nil
	}
	user, _, err := svc.CreateUser(ctx, payload)
	require.NoError(t, err)
	require.False(t, user.MFAEnabled)

	premiumCtx := license.NewContext(ctx, &mobius.LicenseInfo{Tier: mobius.TierPremium})
	user, _, err = svc.CreateUser(premiumCtx, payload)
	require.NoError(t, err)
	require.True(t, user.MFAEnabled)

	// test modification

	appConfig.SMTPSettings.SMTPConfigured = false
	ms.UserByIDFunc = func(ctx context.Context, id uint) (*mobius.User, error) {
		return user, nil
	}
	_, err = svc.ModifyUser(ctx, user.ID, mobius.UserPayload{SSOEnabled: ptr.Bool(true)})
	require.ErrorContains(t, err, "SSO")

	user.SSOEnabled = true
	user.MFAEnabled = false
	_, err = svc.ModifyUser(ctx, user.ID, mobius.UserPayload{MFAEnabled: ptr.Bool(true)})
	require.ErrorContains(t, err, "license")

	_, err = svc.ModifyUser(premiumCtx, user.ID, mobius.UserPayload{MFAEnabled: ptr.Bool(true)})
	require.ErrorContains(t, err, "SSO")

	user.SSOEnabled = false
	_, err = svc.ModifyUser(premiumCtx, user.ID, mobius.UserPayload{MFAEnabled: ptr.Bool(true)})
	require.ErrorContains(t, err, "mail")

	ms.SaveUserFunc = func(ctx context.Context, u *mobius.User) error {
		return nil
	}
	user.MFAEnabled = true // allow keeping MFA on when modifying a user with MFA already on
	_, err = svc.ModifyUser(ctx, user.ID, mobius.UserPayload{MFAEnabled: ptr.Bool(true), Name: ptr.String("Joe Bob")})
	require.NoError(t, err)
	_, err = svc.ModifyUser(ctx, user.ID, mobius.UserPayload{Name: ptr.String("Joe Bob")})
	require.NoError(t, err)

	user.MFAEnabled = false
	appConfig.SMTPSettings.SMTPConfigured = true
	_, err = svc.ModifyUser(premiumCtx, user.ID, mobius.UserPayload{MFAEnabled: ptr.Bool(true)})
	require.NoError(t, err)
}

func TestModifyAdminUserEmailNoPassword(t *testing.T) {
	user := &mobius.User{
		ID:    3,
		Email: "foo@bar.com",
	}
	err := user.SetPassword(test.GoodPassword, 10, 10)
	require.NoError(t, err)
	ms := new(mock.Store)
	ms.PendingEmailChangeFunc = func(ctx context.Context, id uint, em, tk string) error {
		return nil
	}
	ms.UserByIDFunc = func(ctx context.Context, id uint) (*mobius.User, error) {
		return user, nil
	}
	ms.UserByEmailFunc = func(ctx context.Context, email string) (*mobius.User, error) {
		return user, nil
	}
	ms.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		config := &mobius.AppConfig{
			SMTPSettings: &mobius.SMTPSettings{
				SMTPConfigured:         true,
				SMTPAuthenticationType: mobius.AuthTypeNameNone,
				SMTPPort:               1025,
				SMTPServer:             "127.0.0.1",
				SMTPSenderAddress:      "xxx@mobius.co",
			},
		}
		return config, nil
	}
	ms.SaveUserFunc = func(ctx context.Context, u *mobius.User) error {
		return nil
	}
	svc, ctx := newTestService(t, ms, nil, nil)
	ctx = viewer.NewContext(ctx, viewer.Viewer{User: user})
	payload := mobius.UserPayload{
		Email: ptr.String("zip@zap.com"),
		// NO PASSWORD
		// Password: &test.TestGoodPassword,
	}
	_, err = svc.ModifyUser(ctx, 3, payload)
	require.NotNil(t, err)
	var iae *mobius.InvalidArgumentError
	ok := errors.As(err, &iae)
	require.True(t, ok)
	require.Len(t, iae.Errors, 1)
	assert.False(t, ms.PendingEmailChangeFuncInvoked)
	assert.False(t, ms.SaveUserFuncInvoked)
}

func TestModifyAdminUserEmailPassword(t *testing.T) {
	user := &mobius.User{
		ID:    3,
		Email: "foo@bar.com",
	}
	err := user.SetPassword(test.GoodPassword, 10, 10)
	require.NoError(t, err)
	ms := new(mock.Store)
	ms.PendingEmailChangeFunc = func(ctx context.Context, id uint, em, tk string) error {
		return nil
	}
	ms.UserByEmailFunc = func(ctx context.Context, email string) (*mobius.User, error) {
		return nil, notFoundErr{}
	}
	ms.InviteByEmailFunc = func(ctx context.Context, email string) (*mobius.Invite, error) {
		return nil, notFoundErr{}
	}
	ms.UserByIDFunc = func(ctx context.Context, id uint) (*mobius.User, error) {
		return user, nil
	}
	ms.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		config := &mobius.AppConfig{
			SMTPSettings: &mobius.SMTPSettings{
				SMTPConfigured:         true,
				SMTPAuthenticationType: mobius.AuthTypeNameNone,
				SMTPPort:               1025,
				SMTPServer:             "127.0.0.1",
				SMTPSenderAddress:      "xxx@mobius.co",
			},
		}
		return config, nil
	}
	ms.SaveUserFunc = func(ctx context.Context, u *mobius.User) error {
		return nil
	}
	svc, ctx := newTestService(t, ms, nil, nil)
	ctx = viewer.NewContext(ctx, viewer.Viewer{User: user})
	payload := mobius.UserPayload{
		Email:    ptr.String("zip@zap.com"),
		Password: ptr.String(test.GoodPassword),
	}
	_, err = svc.ModifyUser(ctx, 3, payload)
	require.Nil(t, err)
	assert.True(t, ms.PendingEmailChangeFuncInvoked)
	assert.True(t, ms.SaveUserFuncInvoked)
}

func TestUsersWithDS(t *testing.T) {
	ds := mysql.CreateMySQLDS(t)

	cases := []struct {
		name string
		fn   func(t *testing.T, ds *mysql.Datastore)
	}{
		{"CreateUserForcePasswdReset", testUsersCreateUserForcePasswdReset},
		{"ChangePassword", testUsersChangePassword},
		{"RequirePasswordReset", testUsersRequirePasswordReset},
		{"UsersCreateUserWithAPIOnly", testUsersCreateUserWithAPIOnly},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			defer mysql.TruncateTables(t, ds)
			c.fn(t, ds)
		})
	}
}

// Test that CreateUser creates a user that will be forced to
// reset its password upon first login (see #2570).
func testUsersCreateUserForcePasswdReset(t *testing.T, ds *mysql.Datastore) {
	svc, ctx := newTestService(t, ds, nil, nil)

	// Create admin user.
	admin := &mobius.User{
		Name:       "Mobius Admin",
		Email:      "admin@foo.com",
		GlobalRole: ptr.String(mobius.RoleAdmin),
	}
	err := admin.SetPassword(test.GoodPassword, 10, 10)
	require.NoError(t, err)
	admin, err = ds.NewUser(ctx, admin)
	require.NoError(t, err)

	// As the admin, create a new user.
	ctx = viewer.NewContext(ctx, viewer.Viewer{User: admin})
	user, sessionKey, err := svc.CreateUser(ctx, mobius.UserPayload{
		Name:       ptr.String("Some Observer"),
		Email:      ptr.String("some-observer@email.com"),
		Password:   ptr.String(test.GoodPassword),
		GlobalRole: ptr.String(mobius.RoleObserver),
	})
	require.NoError(t, err)
	require.Nil(t, sessionKey) // only set when creating API-only users

	user, err = ds.UserByID(context.Background(), user.ID)
	require.NoError(t, err)
	require.True(t, user.AdminForcedPasswordReset)
}

func testUsersChangePassword(t *testing.T, ds *mysql.Datastore) {
	svc, ctx := newTestService(t, ds, nil, nil)
	users := createTestUsers(t, ds)
	passwordChangeTests := []struct {
		user        mobius.User
		oldPassword string
		newPassword string
		anyErr      bool
		wantErr     error
	}{
		{ // all good
			user:        users["admin1@example.com"],
			oldPassword: test.GoodPassword,
			newPassword: test.GoodPassword2,
		},
		{ // prevent password reuse
			user:        users["admin1@example.com"],
			oldPassword: test.GoodPassword2,
			newPassword: test.GoodPassword,
			wantErr:     mobius.NewInvalidArgumentError("new_password", "Cannot reuse old password"),
		},
		{ // all good
			user:        users["user1@example.com"],
			oldPassword: test.GoodPassword,
			newPassword: test.GoodPassword2,
		},
		{ // bad old password
			user:        users["user1@example.com"],
			oldPassword: "wrong_password",
			newPassword: test.GoodPassword2,
			anyErr:      true,
		},
		{ // missing old password
			user:        users["user1@example.com"],
			newPassword: test.GoodPassword2,
			wantErr:     mobius.NewInvalidArgumentError("old_password", "Old password cannot be empty"),
		},
	}

	for _, tt := range passwordChangeTests {
		t.Run("", func(t *testing.T) {
			tt := tt
			ctx = viewer.NewContext(ctx, viewer.Viewer{User: &tt.user})

			err := svc.ChangePassword(ctx, tt.oldPassword, tt.newPassword)
			if tt.anyErr { //nolint:gocritic // ignore ifElseChain
				require.NotNil(t, err)
			} else if tt.wantErr != nil {
				require.Equal(t, tt.wantErr, ctxerr.Cause(err))
			} else {
				require.Nil(t, err)
			}

			if err != nil {
				return
			}

			// Attempt login after successful change
			_, _, err = svc.Login(context.Background(), tt.user.Email, tt.newPassword, false)
			require.Nil(t, err, "should be able to login with new password")
		})
	}
}

func testUsersRequirePasswordReset(t *testing.T, ds *mysql.Datastore) {
	svc, ctx := newTestService(t, ds, nil, nil)
	createTestUsers(t, ds)

	for _, tt := range testUsers {
		t.Run(tt.Email, func(t *testing.T) {
			user, err := ds.UserByEmail(context.Background(), tt.Email)
			require.Nil(t, err)

			var sessions []*mobius.Session

			// Log user in
			_, _, err = svc.Login(test.UserContext(ctx, test.UserAdmin), tt.Email, tt.PlaintextPassword, false)
			require.Nil(t, err, "login unsuccessful")
			sessions, err = svc.GetInfoAboutSessionsForUser(test.UserContext(ctx, test.UserAdmin), user.ID)
			require.Nil(t, err)
			require.Len(t, sessions, 1, "user should have one session")

			// Reset and verify sessions destroyed
			retUser, err := svc.RequirePasswordReset(test.UserContext(ctx, test.UserAdmin), user.ID, true)
			require.Nil(t, err)
			assert.True(t, retUser.AdminForcedPasswordReset)
			checkUser, err := ds.UserByEmail(context.Background(), tt.Email)
			require.Nil(t, err)
			assert.True(t, checkUser.AdminForcedPasswordReset)
			sessions, err = svc.GetInfoAboutSessionsForUser(test.UserContext(ctx, test.UserAdmin), user.ID)
			require.Nil(t, err)
			require.Len(t, sessions, 0, "sessions should be destroyed")

			// try undo
			retUser, err = svc.RequirePasswordReset(test.UserContext(ctx, test.UserAdmin), user.ID, false)
			require.Nil(t, err)
			assert.False(t, retUser.AdminForcedPasswordReset)
			checkUser, err = ds.UserByEmail(context.Background(), tt.Email)
			require.Nil(t, err)
			assert.False(t, checkUser.AdminForcedPasswordReset)
		})
	}
}

func TestPerformRequiredPasswordReset(t *testing.T) {
	ds := mysql.CreateMySQLDS(t)

	svc, ctx := newTestService(t, ds, nil, nil)

	createTestUsers(t, ds)

	for _, tt := range testUsers {
		t.Run(tt.Email, func(t *testing.T) {
			user, err := ds.UserByEmail(context.Background(), tt.Email)
			require.Nil(t, err)

			_, err = svc.RequirePasswordReset(test.UserContext(ctx, test.UserAdmin), user.ID, true)
			require.Nil(t, err)

			ctx = refreshCtx(t, ctx, user, ds, nil)

			session, err := ds.NewSession(context.Background(), user.ID, 8)
			require.Nil(t, err)
			ctx = refreshCtx(t, ctx, user, ds, session)

			// should error when reset not required
			_, err = svc.RequirePasswordReset(ctx, user.ID, false)
			require.Nil(t, err)
			ctx = refreshCtx(t, ctx, user, ds, session)
			_, err = svc.PerformRequiredPasswordReset(ctx, test.GoodPassword2)
			require.NotNil(t, err)

			_, err = svc.RequirePasswordReset(ctx, user.ID, true)
			require.Nil(t, err)
			ctx = refreshCtx(t, ctx, user, ds, session)

			// should error when using same password
			_, err = svc.PerformRequiredPasswordReset(ctx, tt.PlaintextPassword)
			require.Equal(t, "validation failed: new_password Cannot reuse old password", err.Error())

			// should succeed with good new password
			u, err := svc.PerformRequiredPasswordReset(ctx, test.GoodPassword2)
			require.Nil(t, err)
			assert.False(t, u.AdminForcedPasswordReset)

			ctx = context.Background()

			// Now user should be able to login with new password
			u, _, err = svc.Login(ctx, tt.Email, test.GoodPassword2, false)
			require.Nil(t, err)
			assert.False(t, u.AdminForcedPasswordReset)
		})
	}
}

func TestResetPassword(t *testing.T) {
	ds := mysql.CreateMySQLDS(t)

	svc, ctx := newTestService(t, ds, nil, nil)
	createTestUsers(t, ds)
	passwordResetTests := []struct {
		token       string
		newPassword string
		wantErr     error
	}{
		{ // all good
			token:       "abcd",
			newPassword: test.GoodPassword2,
		},
		{ // prevent reuse
			token:       "abcd",
			newPassword: test.GoodPassword2,
			wantErr:     mobius.NewInvalidArgumentError("new_password", "Cannot reuse old password"),
		},
		{ // bad token
			token:       "dcbaz",
			newPassword: test.GoodPassword,
			wantErr:     mobius.NewAuthFailedError("invalid password reset token"),
		},
		{ // missing token
			newPassword: test.GoodPassword,
			wantErr:     mobius.NewInvalidArgumentError("token", "Token cannot be empty field"),
		},
	}

	for _, tt := range passwordResetTests {
		t.Run("", func(t *testing.T) {
			request := &mobius.PasswordResetRequest{
				UpdateCreateTimestamps: mobius.UpdateCreateTimestamps{
					CreateTimestamp: mobius.CreateTimestamp{
						CreatedAt: time.Now(),
					},
					UpdateTimestamp: mobius.UpdateTimestamp{
						UpdatedAt: time.Now(),
					},
				},
				ExpiresAt: time.Now().Add(time.Hour * 24),
				UserID:    1,
				Token:     "abcd",
			}
			_, err := ds.NewPasswordResetRequest(context.Background(), request)
			assert.Nil(t, err)

			serr := svc.ResetPassword(test.UserContext(ctx, &mobius.User{ID: 1}), tt.token, tt.newPassword)
			if tt.wantErr != nil {
				assert.Equal(t, tt.wantErr.Error(), ctxerr.Cause(serr).Error())
			} else {
				assert.Nil(t, serr)
			}
		})
	}
}

func refreshCtx(t *testing.T, ctx context.Context, user *mobius.User, ds mobius.Datastore, session *mobius.Session) context.Context {
	reloadedUser, err := ds.UserByEmail(ctx, user.Email)
	require.NoError(t, err)

	return viewer.NewContext(ctx, viewer.Viewer{User: reloadedUser, Session: session})
}

func TestAuthenticatedUser(t *testing.T) {
	ds := mysql.CreateMySQLDS(t)

	createTestUsers(t, ds)
	svc, ctx := newTestService(t, ds, nil, nil)
	admin1, err := ds.UserByEmail(context.Background(), "admin1@example.com")
	require.NoError(t, err)
	admin1Session, err := ds.NewSession(context.Background(), admin1.ID, 8)
	require.NoError(t, err)

	ctx = viewer.NewContext(ctx, viewer.Viewer{User: admin1, Session: admin1Session})
	user, err := svc.AuthenticatedUser(ctx)
	assert.Nil(t, err)
	assert.Equal(t, user, admin1)
}

func TestIsAdminOfTheModifiedTeams(t *testing.T) {
	type teamWithRole struct {
		teamID uint
		role   string
	}
	type roles struct {
		global *string
		teams  []teamWithRole
	}
	for _, tc := range []struct {
		name string
		// actionUserRoles are the roles of the user executing the role change action.
		actionUserRoles roles
		// targetUserOriginalTeams are the original teams the target user belongs to.
		targetUserOriginalTeams []teamWithRole
		// targetUserNewTeams are the new teams the target user will be added to.
		targetUserNewTeams []teamWithRole

		expected bool
	}{
		{
			name: "global-admin-allmighty",
			actionUserRoles: roles{
				global: ptr.String(mobius.RoleAdmin),
			},
			targetUserOriginalTeams: []teamWithRole{
				{
					teamID: 1,
					role:   mobius.RoleAdmin,
				},
			},
			targetUserNewTeams: []teamWithRole{
				{
					teamID: 2,
					role:   mobius.RoleAdmin,
				},
			},
			expected: true,
		},
		{
			name: "global-maintainer-cannot-modify-team-users",
			actionUserRoles: roles{
				global: ptr.String(mobius.RoleMaintainer),
			},
			targetUserOriginalTeams: []teamWithRole{
				{
					teamID: 1,
					role:   mobius.RoleAdmin,
				},
			},
			targetUserNewTeams: []teamWithRole{
				{
					teamID: 1,
					role:   mobius.RoleMaintainer,
				},
			},
			expected: false,
		},
		{
			name: "team-admin-of-original-and-new",
			actionUserRoles: roles{
				teams: []teamWithRole{
					{
						teamID: 1,
						role:   mobius.RoleAdmin,
					},
					{
						teamID: 2,
						role:   mobius.RoleAdmin,
					},
				},
			},
			targetUserOriginalTeams: []teamWithRole{
				{
					teamID: 1,
					role:   mobius.RoleAdmin,
				},
			},
			targetUserNewTeams: []teamWithRole{
				{
					teamID: 2,
					role:   mobius.RoleAdmin,
				},
			},
			expected: true,
		},
		{
			name: "team-admin-of-one-original-and-leave-other-team-unmodified",
			actionUserRoles: roles{
				teams: []teamWithRole{
					{
						teamID: 1,
						role:   mobius.RoleMaintainer,
					},
					{
						teamID: 2,
						role:   mobius.RoleAdmin,
					},
				},
			},
			targetUserOriginalTeams: []teamWithRole{
				{
					teamID: 1,
					role:   mobius.RoleMaintainer,
				},
				{
					teamID: 2,
					role:   mobius.RoleMaintainer,
				},
			},
			targetUserNewTeams: []teamWithRole{
				{
					teamID: 1,
					role:   mobius.RoleMaintainer,
				},
				{
					teamID: 2,
					role:   mobius.RoleAdmin,
				},
			},
			expected: true,
		},
		{
			name: "team-admin-of-original-only",
			actionUserRoles: roles{
				teams: []teamWithRole{
					{
						teamID: 1,
						role:   mobius.RoleAdmin,
					},
					{
						teamID: 2,
						role:   mobius.RoleMaintainer,
					},
				},
			},
			targetUserOriginalTeams: []teamWithRole{
				{
					teamID: 1,
					role:   mobius.RoleAdmin,
				},
			},
			targetUserNewTeams: []teamWithRole{
				{
					teamID: 2,
					role:   mobius.RoleAdmin,
				},
			},
			expected: false,
		},
		{
			name: "team-admin-of-new-only",
			actionUserRoles: roles{
				teams: []teamWithRole{
					{
						teamID: 1,
						role:   mobius.RoleObserver,
					},
					{
						teamID: 2,
						role:   mobius.RoleAdmin,
					},
				},
			},
			targetUserOriginalTeams: []teamWithRole{
				{
					teamID: 1,
					role:   mobius.RoleAdmin,
				},
			},
			targetUserNewTeams: []teamWithRole{
				{
					teamID: 2,
					role:   mobius.RoleAdmin,
				},
			},
			expected: false,
		},
		{
			name: "team-admin-but-new-another-team-observer",
			actionUserRoles: roles{
				teams: []teamWithRole{
					{
						teamID: 1,
						role:   mobius.RoleAdmin,
					},
				},
			},
			targetUserOriginalTeams: []teamWithRole{
				{
					teamID: 1,
					role:   mobius.RoleAdmin,
				},
			},
			targetUserNewTeams: []teamWithRole{
				{
					teamID: 1,
					role:   mobius.RoleAdmin,
				},
				{
					teamID: 2,
					role:   mobius.RoleObserver,
				},
			},
			expected: false,
		},
		{
			name: "team-admin-but-new-another-team-admin",
			actionUserRoles: roles{
				teams: []teamWithRole{
					{
						teamID: 1,
						role:   mobius.RoleAdmin,
					},
				},
			},
			targetUserOriginalTeams: []teamWithRole{
				{
					teamID: 1,
					role:   mobius.RoleAdmin,
				},
			},
			targetUserNewTeams: []teamWithRole{
				{
					teamID: 1,
					role:   mobius.RoleAdmin,
				},
				{
					teamID: 2,
					role:   mobius.RoleAdmin,
				},
			},
			expected: false,
		},
		{
			name: "team-admin-but-original-another-team",
			actionUserRoles: roles{
				teams: []teamWithRole{
					{
						teamID: 1,
						role:   mobius.RoleAdmin,
					},
				},
			},
			targetUserOriginalTeams: []teamWithRole{
				{
					teamID: 2,
					role:   mobius.RoleAdmin,
				},
			},
			targetUserNewTeams: []teamWithRole{
				{
					teamID: 1,
					role:   mobius.RoleAdmin,
				},
			},
			expected: false,
		},
		{
			name: "team-admin-but-change-role-another-team",
			actionUserRoles: roles{
				teams: []teamWithRole{
					{
						teamID: 1,
						role:   mobius.RoleAdmin,
					},
				},
			},
			targetUserOriginalTeams: []teamWithRole{
				{
					teamID: 1,
					role:   mobius.RoleAdmin,
				},
				{
					teamID: 2,
					role:   mobius.RoleAdmin,
				},
			},
			targetUserNewTeams: []teamWithRole{
				{
					teamID: 1,
					role:   mobius.RoleAdmin,
				},
				{
					teamID: 2,
					role:   mobius.RoleMaintainer,
				},
			},
			expected: false,
		},
		{
			name: "team-admin-of-one-original-only",
			actionUserRoles: roles{
				teams: []teamWithRole{
					{
						teamID: 1,
						role:   mobius.RoleMaintainer,
					},
					{
						teamID: 2,
						role:   mobius.RoleAdmin,
					},
				},
			},
			targetUserOriginalTeams: []teamWithRole{
				{
					teamID: 1,
					role:   mobius.RoleMaintainer,
				},
				{
					teamID: 2,
					role:   mobius.RoleMaintainer,
				},
			},
			targetUserNewTeams: []teamWithRole{
				{
					teamID: 1,
					role:   mobius.RoleAdmin,
				},
				{
					teamID: 2,
					role:   mobius.RoleAdmin,
				},
			},
			expected: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			userTeamsFn := func(twr []teamWithRole) []mobius.UserTeam {
				var userTeams []mobius.UserTeam
				for _, ot := range twr {
					userTeams = append(userTeams, mobius.UserTeam{
						Team: mobius.Team{ID: ot.teamID},
						Role: ot.role,
					})
				}
				return userTeams
			}

			actionUserTeams := userTeamsFn(tc.actionUserRoles.teams)
			originalUserTeams := userTeamsFn(tc.targetUserOriginalTeams)
			newUserTeams := userTeamsFn(tc.targetUserNewTeams)

			result := isAdminOfTheModifiedTeams(
				&mobius.User{
					GlobalRole: tc.actionUserRoles.global,
					Teams:      actionUserTeams,
				},
				originalUserTeams,
				newUserTeams,
			)
			require.Equal(t, tc.expected, result)
		})
	}
}

// TestAdminAddRoleOtherTeam is an explicit test to check that
// that an admin cannot add itself to another team.
func TestTeamAdminAddRoleOtherTeam(t *testing.T) {
	ds := new(mock.Store)
	svc, ctx := newTestService(t, ds, nil, nil)

	// adminTeam2 is a team admin of team with ID=2.
	adminTeam2 := &mobius.User{
		ID: 1,
		Teams: []mobius.UserTeam{
			{
				Team: mobius.Team{ID: 2},
				Role: mobius.RoleAdmin,
			},
		},
	}

	ds.UserByIDFunc = func(ctx context.Context, id uint) (*mobius.User, error) {
		if id != 1 {
			return nil, newNotFoundError()
		}
		return adminTeam2, nil
	}
	ds.SaveUserFunc = func(ctx context.Context, user *mobius.User) error {
		return nil
	}

	ctx = viewer.NewContext(ctx, viewer.Viewer{User: adminTeam2})
	require.NoError(t, adminTeam2.SetPassword("p4ssw0rd.1337", 10, 10))

	// adminTeam2 tries to add itself to team with ID=3 as admin.
	_, err := svc.ModifyUser(ctx, adminTeam2.ID, mobius.UserPayload{
		Teams: &[]mobius.UserTeam{
			{
				Team: mobius.Team{ID: 2},
				Role: mobius.RoleAdmin,
			},
			{
				Team: mobius.Team{ID: 3},
				Role: mobius.RoleAdmin,
			},
		},
	})
	require.Equal(t, (&authz.Forbidden{}).Error(), err.Error())
	require.False(t, ds.SaveUserFuncInvoked)
}

func testUsersCreateUserWithAPIOnly(t *testing.T, ds *mysql.Datastore) {
	svc, ctx := newTestService(t, ds, nil, nil)

	host, err := ds.NewHost(ctx, &mobius.Host{
		UUID:          "uuid-42",
		OsqueryHostID: ptr.String("osquery_host_id-42"),
	})
	require.NoError(t, err)

	// Create admin user.
	admin := &mobius.User{
		Name:       "Mobius Admin",
		Email:      "admin@foo.com",
		GlobalRole: ptr.String(mobius.RoleAdmin),
	}
	err = admin.SetPassword(test.GoodPassword, 10, 10)
	require.NoError(t, err)
	admin, err = ds.NewUser(ctx, admin)
	require.NoError(t, err)

	// As the admin, create a new API-only user.
	ctx = viewer.NewContext(ctx, viewer.Viewer{User: admin})
	apiOnlyUser, sessionKey, err := svc.CreateUser(ctx, mobius.UserPayload{
		Name:       ptr.String("Some Observer"),
		Email:      ptr.String("some-observer@email.com"),
		Password:   ptr.String(test.GoodPassword),
		GlobalRole: ptr.String(mobius.RoleObserver),
		APIOnly:    ptr.Bool(true),
	})
	require.NoError(t, err)
	require.NotNil(t, sessionKey)
	require.NotEmpty(t, *sessionKey)

	sessions, err := svc.GetInfoAboutSessionsForUser(ctx, apiOnlyUser.ID)
	require.NoError(t, err)
	require.Len(t, sessions, 1)
	session := sessions[0]
	require.Equal(t, *sessionKey, session.Key)

	refreshCtx(t, ctx, apiOnlyUser, ds, session)

	hosts, err := svc.ListHosts(ctx, mobius.HostListOptions{})
	require.NoError(t, err)
	require.Len(t, hosts, 1)
	require.Equal(t, host.ID, hosts[0].ID)
}
