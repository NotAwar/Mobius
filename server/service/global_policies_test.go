package service

import (
	"context"
	"testing"
	"time"

	"github.com/notawar/mobius/server/contexts/viewer"
	"github.com/notawar/mobius/server/mobius"
	"github.com/notawar/mobius/server/mock"
	"github.com/notawar/mobius/server/ptr"
	"github.com/stretchr/testify/require"
)

func TestCheckPolicySpecAuthorization(t *testing.T) {
	t.Run("when team not found", func(t *testing.T) {
		ds := new(mock.Store)
		ds.TeamByNameFunc = func(ctx context.Context, name string) (*mobius.Team, error) {
			return nil, &notFoundError{}
		}

		svc, ctx := newTestService(t, ds, nil, nil)

		req := []*mobius.PolicySpec{
			{
				Team: "some_team",
			},
		}

		user := &mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)}
		ctx = viewer.NewContext(ctx, viewer.Viewer{User: user})

		actual := svc.ApplyPolicySpecs(ctx, req)
		var expected mobius.NotFoundError

		require.ErrorAs(t, actual, &expected)
	})
}

func TestGlobalPoliciesAuth(t *testing.T) {
	ds := new(mock.Store)
	svc, ctx := newTestService(t, ds, nil, nil)

	ds.NewGlobalPolicyFunc = func(ctx context.Context, authorID *uint, args mobius.PolicyPayload) (*mobius.Policy, error) {
		return &mobius.Policy{}, nil
	}
	ds.ListGlobalPoliciesFunc = func(ctx context.Context, opts mobius.ListOptions) ([]*mobius.Policy, error) {
		return nil, nil
	}
	ds.PoliciesByIDFunc = func(ctx context.Context, ids []uint) (map[uint]*mobius.Policy, error) {
		return nil, nil
	}
	ds.PolicyFunc = func(ctx context.Context, id uint) (*mobius.Policy, error) {
		return &mobius.Policy{
			PolicyData: mobius.PolicyData{
				ID: id,
			},
		}, nil
	}
	ds.DeleteGlobalPoliciesFunc = func(ctx context.Context, ids []uint) ([]uint, error) {
		return nil, nil
	}
	ds.TeamByNameFunc = func(ctx context.Context, name string) (*mobius.Team, error) {
		return &mobius.Team{ID: 1}, nil
	}
	ds.ApplyPolicySpecsFunc = func(ctx context.Context, authorID uint, specs []*mobius.PolicySpec) error {
		return nil
	}
	ds.NewActivityFunc = func(
		ctx context.Context, user *mobius.User, activity mobius.ActivityDetails, details []byte, createdAt time.Time,
	) error {
		return nil
	}
	ds.SavePolicyFunc = func(ctx context.Context, p *mobius.Policy, shouldDeleteAll bool, removePolicyStats bool) error {
		return nil
	}
	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		return &mobius.AppConfig{
			WebhookSettings: mobius.WebhookSettings{
				FailingPoliciesWebhook: mobius.FailingPoliciesWebhookSettings{
					Enable: false,
				},
			},
		}, nil
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
	}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			ctx := viewer.NewContext(ctx, viewer.Viewer{User: tt.user})

			_, err := svc.NewGlobalPolicy(ctx, mobius.PolicyPayload{
				Name:  "query1",
				Query: "select 1;",
			})
			checkAuthErr(t, tt.shouldFailWrite, err)

			_, err = svc.ListGlobalPolicies(ctx, mobius.ListOptions{})
			checkAuthErr(t, tt.shouldFailRead, err)

			_, err = svc.GetPolicyByIDQueries(ctx, 1)
			checkAuthErr(t, tt.shouldFailRead, err)

			_, err = svc.ModifyGlobalPolicy(ctx, 1, mobius.ModifyPolicyPayload{})
			checkAuthErr(t, tt.shouldFailWrite, err)

			_, err = svc.DeleteGlobalPolicies(ctx, []uint{1})
			checkAuthErr(t, tt.shouldFailWrite, err)

			err = svc.ApplyPolicySpecs(ctx, []*mobius.PolicySpec{
				{
					Name:  "query2",
					Query: "select 1;",
				},
			})
			checkAuthErr(t, tt.shouldFailWrite, err)
		})
	}
}

func TestRemoveGlobalPoliciesFromWebhookConfig(t *testing.T) {
	ds := new(mock.Store)
	svc := &Service{ds: ds}

	var storedAppConfig mobius.AppConfig

	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		return &storedAppConfig, nil
	}
	ds.SaveAppConfigFunc = func(ctx context.Context, info *mobius.AppConfig) error {
		storedAppConfig = *info
		return nil
	}

	for _, tc := range []struct {
		name     string
		currCfg  []uint
		toDelete []uint
		expCfg   []uint
	}{
		{
			name:     "delete-one",
			currCfg:  []uint{1},
			toDelete: []uint{1},
			expCfg:   []uint{},
		},
		{
			name:     "delete-all-2",
			currCfg:  []uint{1, 2, 3},
			toDelete: []uint{1, 2, 3},
			expCfg:   []uint{},
		},
		{
			name:     "basic",
			currCfg:  []uint{1, 2, 3},
			toDelete: []uint{1, 2},
			expCfg:   []uint{3},
		},
		{
			name:     "empty-cfg",
			currCfg:  []uint{},
			toDelete: []uint{1},
			expCfg:   []uint{},
		},
		{
			name:     "no-deletion-cfg",
			currCfg:  []uint{1},
			toDelete: []uint{2, 3, 4},
			expCfg:   []uint{1},
		},
		{
			name:     "no-deletion-cfg-2",
			currCfg:  []uint{1},
			toDelete: []uint{},
			expCfg:   []uint{1},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			storedAppConfig.WebhookSettings.FailingPoliciesWebhook.PolicyIDs = tc.currCfg
			err := svc.removeGlobalPoliciesFromWebhookConfig(context.Background(), tc.toDelete)
			require.NoError(t, err)
			require.Equal(t, tc.expCfg, storedAppConfig.WebhookSettings.FailingPoliciesWebhook.PolicyIDs)
		})
	}
}

// test ApplyPolicySpecsReturnsErrorOnDuplicatePolicyNamesInSpecs
func TestApplyPolicySpecsReturnsErrorOnDuplicatePolicyNamesInSpecs(t *testing.T) {
	ds := new(mock.Store)
	ds.TeamByNameFunc = func(ctx context.Context, name string) (*mobius.Team, error) {
		return nil, &notFoundError{}
	}

	svc, ctx := newTestService(t, ds, nil, nil)

	req := []*mobius.PolicySpec{
		{
			Name:     "query1",
			Query:    "select 1;",
			Platform: "windows",
		},
		{
			Name:     "query1",
			Query:    "select 1;",
			Platform: "windows",
		},
	}

	user := &mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)}
	ctx = viewer.NewContext(ctx, viewer.Viewer{User: user})

	err := svc.ApplyPolicySpecs(ctx, req)

	badRequestError := &mobius.BadRequestError{}
	require.ErrorAs(t, err, &badRequestError)
	require.Equal(t, "duplicate policy names not allowed", badRequestError.Message)
}

func TestApplyPolicySpecsLabelsValidation(t *testing.T) {
	ds := new(mock.Store)
	ds.NewGlobalPolicyFunc = func(ctx context.Context, authorID *uint, args mobius.PolicyPayload) (*mobius.Policy, error) {
		return &mobius.Policy{}, nil
	}
	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		return &mobius.AppConfig{}, nil
	}
	ds.NewActivityFunc = func(
		ctx context.Context, user *mobius.User, activity mobius.ActivityDetails, details []byte, createdAt time.Time,
	) error {
		return nil
	}
	ds.ApplyPolicySpecsFunc = func(ctx context.Context, authorID uint, specs []*mobius.PolicySpec) error {
		return nil
	}
	ds.LabelsByNameFunc = func(ctx context.Context, names []string) (map[string]*mobius.Label, error) {
		labels := make(map[string]*mobius.Label, len(names))
		for _, name := range names {
			if name == "foo" {
				labels["foo"] = &mobius.Label{
					Name: "foo",
					ID:   1,
				}
			}
		}
		return labels, nil
	}

	svc, ctx := newTestService(t, ds, nil, nil)

	testAdmin := mobius.User{
		ID:         1,
		Teams:      []mobius.UserTeam{},
		GlobalRole: ptr.String(mobius.RoleAdmin),
	}
	viewerCtx := viewer.NewContext(ctx, viewer.Viewer{User: &testAdmin})

	// Test that a query spec with a label that exists doesn't return an error
	err := svc.ApplyPolicySpecs(viewerCtx, []*mobius.PolicySpec{
		{
			Name:             "test query",
			Query:            "select 1",
			LabelsIncludeAny: []string{"foo"},
			Platform:         "darwin,windows",
		},
	})
	// Check that no error is returned
	require.NoError(t, err)

	// Test that a query spec with a label that doesn't exist returns an error.
	err = svc.ApplyPolicySpecs(viewerCtx, []*mobius.PolicySpec{
		{
			Name:             "test query",
			Query:            "select 1",
			LabelsIncludeAny: []string{"nope"},
			Platform:         "darwin,windows",
		},
	})

	require.Error(t, err)
}
