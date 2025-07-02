package service

import (
	"context"
	"errors"
	"testing"

	"github.com/notawar/mobius/server/contexts/viewer"
	"github.com/notawar/mobius/server/mobius"
	"github.com/notawar/mobius/server/mock"
	"github.com/notawar/mobius/server/ptr"
	"github.com/stretchr/testify/assert"
)

func TestCreateSecretVariables(t *testing.T) {
	t.Parallel()
	ds := new(mock.Store)
	svc, ctx := newTestService(t, ds, nil, nil)

	ds.UpsertSecretVariablesFunc = func(ctx context.Context, secrets []mobius.SecretVariable) error {
		return nil
	}

	t.Run("authorization checks", func(t *testing.T) {
		testCases := []struct {
			name       string
			user       *mobius.User
			shouldFail bool
		}{
			{
				name:       "global admin",
				user:       &mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)},
				shouldFail: false,
			},
			{
				name:       "global maintainer",
				user:       &mobius.User{GlobalRole: ptr.String(mobius.RoleMaintainer)},
				shouldFail: false,
			},
			{
				name:       "global gitops",
				user:       &mobius.User{GlobalRole: ptr.String(mobius.RoleGitOps)},
				shouldFail: false,
			},
			{
				name:       "global observer",
				user:       &mobius.User{GlobalRole: ptr.String(mobius.RoleObserver)},
				shouldFail: true,
			},
			{
				name:       "global observer+",
				user:       &mobius.User{GlobalRole: ptr.String(mobius.RoleObserverPlus)},
				shouldFail: true,
			},
			{
				name:       "team admin",
				user:       &mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleAdmin}}},
				shouldFail: true,
			},
			{
				name:       "team maintainer",
				user:       &mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleMaintainer}}},
				shouldFail: true,
			},
			{
				name:       "team observer",
				user:       &mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleObserver}}},
				shouldFail: true,
			},
			{
				name:       "team observer+",
				user:       &mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleObserverPlus}}},
				shouldFail: true,
			},
			{
				name:       "team gitops",
				user:       &mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleGitOps}}},
				shouldFail: true,
			},
		}
		for _, tt := range testCases {
			t.Run(tt.name, func(t *testing.T) {
				ctx = viewer.NewContext(ctx, viewer.Viewer{User: tt.user})

				err := svc.CreateSecretVariables(ctx, []mobius.SecretVariable{{Name: "foo", Value: "bar"}}, false)
				checkAuthErr(t, tt.shouldFail, err)
			})
		}
	})

	t.Run("failure test", func(t *testing.T) {
		ctx = viewer.NewContext(ctx, viewer.Viewer{User: &mobius.User{GlobalRole: ptr.String(mobius.RoleGitOps)}})
		testSetEmptyPrivateKey = true
		t.Cleanup(func() {
			testSetEmptyPrivateKey = false
		})
		err := svc.CreateSecretVariables(ctx, []mobius.SecretVariable{{Name: "foo", Value: "bar"}}, true)
		assert.ErrorContains(t, err, "Couldn't save secret variables. Missing required private key")
		testSetEmptyPrivateKey = false

		ds.UpsertSecretVariablesFunc = func(ctx context.Context, secrets []mobius.SecretVariable) error {
			return errors.New("test error")
		}
		err = svc.CreateSecretVariables(ctx, []mobius.SecretVariable{{Name: "foo", Value: "bar"}}, false)
		assert.ErrorContains(t, err, "test error")
	})

}
