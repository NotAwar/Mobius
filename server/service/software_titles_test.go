package service

import (
	"context"
	"testing"

	"github.com/notawar/mobius/v4/server/contexts/license"
	"github.com/notawar/mobius/v4/server/contexts/viewer"
	"github.com/notawar/mobius/v4/server/mobius"
	"github.com/notawar/mobius/v4/server/mock"
	"github.com/notawar/mobius/v4/server/ptr"
	"github.com/stretchr/testify/require"
)

func TestServiceSoftwareTitlesAuth(t *testing.T) {
	ds := new(mock.Store)

	ds.ListSoftwareTitlesFunc = func(ctx context.Context, opt mobius.SoftwareTitleListOptions, tmf mobius.TeamFilter) ([]mobius.SoftwareTitleListResult, int, *mobius.PaginationMetadata, error) {
		return []mobius.SoftwareTitleListResult{}, 0, &mobius.PaginationMetadata{}, nil
	}
	ds.SoftwareTitleByIDFunc = func(ctx context.Context, id uint, teamID *uint, tmFilter mobius.TeamFilter) (*mobius.SoftwareTitle, error) {
		return &mobius.SoftwareTitle{}, nil
	}
	ds.TeamExistsFunc = func(ctx context.Context, teamID uint) (bool, error) { return true, nil }
	ds.SoftwareTitleByIDFunc = func(ctx context.Context, id uint, teamID *uint, tmFilter mobius.TeamFilter) (*mobius.SoftwareTitle, error) {
		return &mobius.SoftwareTitle{BundleIdentifier: ptr.String("foo")}, nil
	}
	ds.UpdateSoftwareTitleNameFunc = func(ctx context.Context, id uint, name string) error {
		return nil
	}

	svc, ctx := newTestService(t, ds, nil, nil)

	for _, tc := range []struct {
		name                 string
		user                 *mobius.User
		shouldFailGlobalRead bool
		shouldFailTeamRead   bool
		shouldFailWrite      bool
	}{
		{
			name: "global-admin",
			user: &mobius.User{
				ID:         1,
				GlobalRole: ptr.String(mobius.RoleAdmin),
			},
			shouldFailGlobalRead: false,
			shouldFailTeamRead:   false,
			shouldFailWrite:      false,
		},
		{
			name: "global-maintainer",
			user: &mobius.User{
				ID:         1,
				GlobalRole: ptr.String(mobius.RoleMaintainer),
			},
			shouldFailGlobalRead: false,
			shouldFailTeamRead:   false,
			shouldFailWrite:      true,
		},
		{
			name: "global-observer",
			user: &mobius.User{
				ID:         1,
				GlobalRole: ptr.String(mobius.RoleObserver),
			},
			shouldFailGlobalRead: false,
			shouldFailTeamRead:   false,
			shouldFailWrite:      true,
		},
		{
			name: "team-admin-belongs-to-team",
			user: &mobius.User{
				ID: 1,
				Teams: []mobius.UserTeam{{
					Team: mobius.Team{ID: 1},
					Role: mobius.RoleAdmin,
				}},
			},
			shouldFailGlobalRead: true,
			shouldFailTeamRead:   false,
			shouldFailWrite:      true,
		},
		{
			name: "team-maintainer-belongs-to-team",
			user: &mobius.User{
				ID: 1,
				Teams: []mobius.UserTeam{{
					Team: mobius.Team{ID: 1},
					Role: mobius.RoleMaintainer,
				}},
			},
			shouldFailGlobalRead: true,
			shouldFailTeamRead:   false,
			shouldFailWrite:      true,
		},
		{
			name: "team-observer-belongs-to-team",
			user: &mobius.User{
				ID: 1,
				Teams: []mobius.UserTeam{{
					Team: mobius.Team{ID: 1},
					Role: mobius.RoleObserver,
				}},
			},
			shouldFailGlobalRead: true,
			shouldFailTeamRead:   false,
			shouldFailWrite:      true,
		},
		{
			name: "team-admin-does-not-belong-to-team",
			user: &mobius.User{
				ID: 1,
				Teams: []mobius.UserTeam{{
					Team: mobius.Team{ID: 2},
					Role: mobius.RoleAdmin,
				}},
			},
			shouldFailGlobalRead: true,
			shouldFailTeamRead:   true,
			shouldFailWrite:      true,
		},
		{
			name: "team-maintainer-does-not-belong-to-team",
			user: &mobius.User{
				ID: 1,
				Teams: []mobius.UserTeam{{
					Team: mobius.Team{ID: 2},
					Role: mobius.RoleMaintainer,
				}},
			},
			shouldFailGlobalRead: true,
			shouldFailTeamRead:   true,
			shouldFailWrite:      true,
		},
		{
			name: "team-observer-does-not-belong-to-team",
			user: &mobius.User{
				ID: 1,
				Teams: []mobius.UserTeam{{
					Team: mobius.Team{ID: 2},
					Role: mobius.RoleObserver,
				}},
			},
			shouldFailGlobalRead: true,
			shouldFailTeamRead:   true,
			shouldFailWrite:      true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := viewer.NewContext(ctx, viewer.Viewer{User: tc.user})
			premiumCtx := license.NewContext(ctx, &mobius.LicenseInfo{Tier: mobius.TierPremium})

			// List all software titles.
			_, _, _, err := svc.ListSoftwareTitles(ctx, mobius.SoftwareTitleListOptions{})
			checkAuthErr(t, tc.shouldFailGlobalRead, err)

			// List software for a team.
			_, _, _, err = svc.ListSoftwareTitles(premiumCtx, mobius.SoftwareTitleListOptions{
				TeamID: ptr.Uint(1),
			})
			checkAuthErr(t, tc.shouldFailTeamRead, err)

			// List software for a team should fail no matter what
			// with a non-premium context
			if !tc.shouldFailTeamRead {
				_, _, _, err = svc.ListSoftwareTitles(ctx, mobius.SoftwareTitleListOptions{
					TeamID: ptr.Uint(1),
				})
				require.ErrorContains(t, err, "Requires Mobius Premium license")
			}

			// Get a software title for a team
			_, err = svc.SoftwareTitleByID(ctx, 1, ptr.Uint(1))
			checkAuthErr(t, tc.shouldFailTeamRead, err)

			// Update a software title's name
			err = svc.UpdateSoftwareName(ctx, 1, "2 Chrome 2 Furious")
			checkAuthErr(t, tc.shouldFailWrite, err)
		})
	}
}

func TestSoftwareNameUpdate(t *testing.T) {
	ds := new(mock.Store)
	ds.SoftwareTitleByIDFunc = func(ctx context.Context, id uint, teamID *uint, tmFilter mobius.TeamFilter) (*mobius.SoftwareTitle, error) {
		return nil, &notFoundError{}
	}

	svc, ctx := newTestService(t, ds, nil, nil)
	ctx = viewer.NewContext(ctx, viewer.Viewer{User: &mobius.User{
		ID:         1,
		GlobalRole: ptr.String(mobius.RoleAdmin),
	}})

	// Title not found
	err := svc.UpdateSoftwareName(ctx, 1, "2 Chrome 2 Furious")
	require.ErrorContains(t, err, "not found")
	require.False(t, ds.UpdateHostSoftwareFuncInvoked)

	// Title found but doesn't have a bundle ID
	title := &mobius.SoftwareTitle{}
	ds.SoftwareTitleByIDFunc = func(ctx context.Context, id uint, teamID *uint, tmFilter mobius.TeamFilter) (*mobius.SoftwareTitle, error) {
		return title, nil
	}
	err = svc.UpdateSoftwareName(ctx, 1, "2 Chrome 2 Furious")
	require.ErrorContains(t, err, "bundle")
	require.False(t, ds.UpdateHostSoftwareFuncInvoked)

	// Title found with bundle ID but user didn't provide a name
	title = &mobius.SoftwareTitle{BundleIdentifier: ptr.String("foo")}
	err = svc.UpdateSoftwareName(ctx, 1, "")
	require.ErrorContains(t, err, "name")
	require.False(t, ds.UpdateHostSoftwareFuncInvoked)

	// Success case
	ds.UpdateSoftwareTitleNameFunc = func(ctx context.Context, id uint, name string) error {
		return nil
	}
	err = svc.UpdateSoftwareName(ctx, 1, "2 Chrome 2 Furious")
	require.NoError(t, err)
	require.True(t, ds.UpdateSoftwareTitleNameFuncInvoked)
}
