package service

import (
	"context"
	"testing"
	"time"

	"github.com/notawar/mobius/server/authz"
	"github.com/notawar/mobius/server/contexts/viewer"
	"github.com/notawar/mobius/server/mobius"
	"github.com/notawar/mobius/server/mock"
	"github.com/notawar/mobius/server/ptr"
	"github.com/stretchr/testify/require"
)

func TestTeamPoliciesAuth(t *testing.T) {
	ds := new(mock.Store)
	svc, ctx := newTestService(t, ds, nil, nil)

	ds.NewTeamPolicyFunc = func(ctx context.Context, teamID uint, authorID *uint, args mobius.PolicyPayload) (*mobius.Policy, error) {
		return &mobius.Policy{
			PolicyData: mobius.PolicyData{
				ID:     1,
				TeamID: ptr.Uint(1),
			},
		}, nil
	}
	ds.ListTeamPoliciesFunc = func(ctx context.Context, teamID uint, opts mobius.ListOptions, iopts mobius.ListOptions) (tpol, ipol []*mobius.Policy, err error) {
		return nil, nil, nil
	}
	ds.PoliciesByIDFunc = func(ctx context.Context, ids []uint) (map[uint]*mobius.Policy, error) {
		return nil, nil
	}
	ds.TeamPolicyFunc = func(ctx context.Context, teamID uint, policyID uint) (*mobius.Policy, error) {
		return &mobius.Policy{}, nil
	}
	ds.PolicyFunc = func(ctx context.Context, id uint) (*mobius.Policy, error) {
		if id == 1 {
			return &mobius.Policy{
				PolicyData: mobius.PolicyData{
					ID:     1,
					TeamID: ptr.Uint(1),
				},
			}, nil
		}
		return nil, nil
	}
	ds.SavePolicyFunc = func(ctx context.Context, p *mobius.Policy, shouldDeleteAll bool, removePolicyStats bool) error {
		return nil
	}
	ds.DeleteTeamPoliciesFunc = func(ctx context.Context, teamID uint, ids []uint) ([]uint, error) {
		return nil, nil
	}
	ds.TeamByNameFunc = func(ctx context.Context, name string) (*mobius.Team, error) {
		return &mobius.Team{ID: 1}, nil
	}
	ds.ApplyPolicySpecsFunc = func(ctx context.Context, authorID uint, specs []*mobius.PolicySpec) error {
		return nil
	}
	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		return &mobius.AppConfig{}, nil
	}
	ds.NewActivityFunc = func(
		ctx context.Context, user *mobius.User, activity mobius.ActivityDetails, details []byte, createdAt time.Time,
	) error {
		return nil
	}
	ds.TeamFunc = func(ctx context.Context, tid uint) (*mobius.Team, error) {
		return &mobius.Team{ID: 1}, nil
	}
	ds.GetSoftwareInstallerMetadataByIDFunc = func(ctx context.Context, id uint) (*mobius.SoftwareInstaller, error) {
		return &mobius.SoftwareInstaller{}, nil
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
			"team admin, belongs to team",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleAdmin}}},
			false,
			false,
		},
		{
			"team maintainer, belongs to team",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleMaintainer}}},
			false,
			false,
		},
		{
			"team observer, belongs to team",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleObserver}}},
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
			"team observer, and team admin of another team",
			&mobius.User{Teams: []mobius.UserTeam{
				{
					Team: mobius.Team{ID: 1},
					Role: mobius.RoleObserver,
				},
				{
					Team: mobius.Team{ID: 2},
					Role: mobius.RoleAdmin,
				},
			}},
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
			"team observer, DOES NOT belong to team",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 2}, Role: mobius.RoleObserver}}},
			true,
			true,
		},
	}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			ctx := viewer.NewContext(ctx, viewer.Viewer{User: tt.user})

			_, err := svc.NewTeamPolicy(ctx, 1, mobius.NewTeamPolicyPayload{
				Name:  "query1",
				Query: "select 1;",
			})
			checkAuthErr(t, tt.shouldFailWrite, err)

			_, _, err = svc.ListTeamPolicies(ctx, 1, mobius.ListOptions{}, mobius.ListOptions{}, false)
			checkAuthErr(t, tt.shouldFailRead, err)

			_, err = svc.GetTeamPolicyByIDQueries(ctx, 1, 1)
			checkAuthErr(t, tt.shouldFailRead, err)

			_, err = svc.ModifyTeamPolicy(ctx, 1, 1, mobius.ModifyPolicyPayload{})
			checkAuthErr(t, tt.shouldFailWrite, err)

			_, err = svc.DeleteTeamPolicies(ctx, 1, []uint{1})
			checkAuthErr(t, tt.shouldFailWrite, err)

			err = svc.ApplyPolicySpecs(ctx, []*mobius.PolicySpec{
				{
					Name:  "query1",
					Query: "select 1;",
					Team:  "team1",
				},
			})
			checkAuthErr(t, tt.shouldFailWrite, err)
		})
	}
}

func TestTeamPolicyVPPAutomationRejectsNonMacOS(t *testing.T) {
	ds := new(mock.Store)
	svc, ctx := newTestService(t, ds, nil, nil)
	ctx = viewer.NewContext(ctx, viewer.Viewer{User: &mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)}})

	appID := mobius.VPPAppID{AdamID: "123456", Platform: mobius.IOSPlatform}
	ds.TeamExistsFunc = func(ctx context.Context, id uint) (bool, error) {
		return true, nil
	}
	ds.SoftwareTitleByIDFunc = func(ctx context.Context, id uint, teamID *uint, tmFilter mobius.TeamFilter) (*mobius.SoftwareTitle, error) {
		return &mobius.SoftwareTitle{
			AppStoreApp: &mobius.VPPAppStoreApp{
				VPPAppID: appID,
			},
		}, nil
	}

	_, err := svc.NewTeamPolicy(ctx, 1, mobius.NewTeamPolicyPayload{
		Name:            "query1",
		Query:           "select 1;",
		SoftwareTitleID: ptr.Uint(123),
	})
	require.ErrorContains(t, err, "is associated to an iOS or iPadOS VPP app")
}

func checkAuthErr(t *testing.T, shouldFail bool, err error) {
	t.Helper()
	if shouldFail {
		require.Error(t, err)
		var forbiddenError *authz.Forbidden
		require.ErrorAs(t, err, &forbiddenError)
	} else {
		require.NoError(t, err)
	}
}
