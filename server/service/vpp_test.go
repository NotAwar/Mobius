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
	"github.com/notawar/mobius/server/test"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/require"
)

func TestVPPAuth(t *testing.T) {
	ds := new(mock.Store)

	license := &mobius.LicenseInfo{Tier: mobius.TierPremium, Expiration: time.Now().Add(24 * time.Hour)}

	svc, ctx := newTestService(t, ds, nil, nil, &TestServerOpts{License: license})

	// use a custom implementation of checkAuthErr as the service call will fail
	// with a different error for in case of authorization success and the
	// package-wide checkAuthErr requires no error.
	checkAuthErr := func(t *testing.T, shouldFail bool, err error) {
		if shouldFail {
			require.Error(t, err)
			require.Equal(t, (&authz.Forbidden{}).Error(), err.Error())
		} else if err != nil {
			require.NotEqual(t, (&authz.Forbidden{}).Error(), err.Error())
		}
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
			ctx := viewer.NewContext(ctx, viewer.Viewer{User: tt.user})

			ds.TeamExistsFunc = func(ctx context.Context, teamID uint) (bool, error) {
				return false, nil
			}
			ds.GetAllMDMConfigAssetsByNameFunc = func(ctx context.Context, assetNames []mobius.MDMAssetName,
				_ sqlx.QueryerContext) (map[mobius.MDMAssetName]mobius.MDMConfigAsset, error) {
				return map[mobius.MDMAssetName]mobius.MDMConfigAsset{}, nil
			}
			ds.TeamFunc = func(ctx context.Context, tid uint) (*mobius.Team, error) {
				return &mobius.Team{ID: 1}, nil
			}
			ds.GetVPPTokenByTeamIDFunc = func(ctx context.Context, teamID *uint) (*mobius.VPPTokenDB, error) {
				return &mobius.VPPTokenDB{ID: 1, OrgName: "org", Teams: []mobius.TeamTuple{{ID: 1}}}, nil
			}

			// Note: these calls always return an error because they're attempting to unmarshal a
			// non-existent VPP token.
			_, err := svc.GetAppStoreApps(ctx, tt.teamID)
			if tt.teamID == nil {
				require.Error(t, err)
			} else {
				checkAuthErr(t, tt.shouldFailRead, err)
			}

			_, err = svc.AddAppStoreApp(ctx, tt.teamID, mobius.VPPAppTeam{VPPAppID: mobius.VPPAppID{AdamID: "123", Platform: mobius.IOSPlatform}})
			if tt.teamID == nil {
				require.Error(t, err)
			} else {
				checkAuthErr(t, tt.shouldFailWrite, err)
			}
		})
	}
}
