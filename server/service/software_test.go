package service

import (
	"context"
	"testing"

	"github.com/notawar/mobius/v4/server/contexts/viewer"
	"github.com/notawar/mobius/v4/server/mobius"
	"github.com/notawar/mobius/v4/server/mock"
	"github.com/notawar/mobius/v4/server/ptr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestService_ListSoftware(t *testing.T) {
	ds := new(mock.Store)

	var calledWithTeamID *uint
	var calledWithOpt mobius.SoftwareListOptions
	ds.ListSoftwareFunc = func(ctx context.Context, opt mobius.SoftwareListOptions) ([]mobius.Software, *mobius.PaginationMetadata, error) {
		calledWithTeamID = opt.TeamID
		calledWithOpt = opt
		return []mobius.Software{}, &mobius.PaginationMetadata{}, nil
	}

	user := &mobius.User{
		ID:         3,
		Email:      "foo@bar.com",
		GlobalRole: ptr.String(mobius.RoleAdmin),
	}

	svc, ctx := newTestService(t, ds, nil, nil)
	ctx = viewer.NewContext(ctx, viewer.Viewer{User: user})

	_, _, err := svc.ListSoftware(ctx, mobius.SoftwareListOptions{TeamID: ptr.Uint(42), ListOptions: mobius.ListOptions{PerPage: 77, Page: 4}})
	require.NoError(t, err)

	assert.True(t, ds.ListSoftwareFuncInvoked)
	assert.Equal(t, ptr.Uint(42), calledWithTeamID)
	// sort order defaults to hosts_count descending, automatically, if not explicitly provided
	assert.Equal(t, mobius.ListOptions{PerPage: 77, Page: 4, OrderKey: "hosts_count", OrderDirection: mobius.OrderDescending}, calledWithOpt.ListOptions)
	assert.True(t, calledWithOpt.WithHostCounts)

	// call again, this time with an explicit sort
	ds.ListSoftwareFuncInvoked = false
	_, _, err = svc.ListSoftware(ctx, mobius.SoftwareListOptions{TeamID: nil, ListOptions: mobius.ListOptions{PerPage: 11, Page: 2, OrderKey: "id", OrderDirection: mobius.OrderAscending}})
	require.NoError(t, err)

	assert.True(t, ds.ListSoftwareFuncInvoked)
	assert.Nil(t, calledWithTeamID)
	assert.Equal(t, mobius.ListOptions{PerPage: 11, Page: 2, OrderKey: "id", OrderDirection: mobius.OrderAscending}, calledWithOpt.ListOptions)
	assert.True(t, calledWithOpt.WithHostCounts)
}

func TestServiceSoftwareInventoryAuth(t *testing.T) {
	ds := new(mock.Store)

	ds.ListSoftwareFunc = func(ctx context.Context, opt mobius.SoftwareListOptions) ([]mobius.Software, *mobius.PaginationMetadata, error) {
		return []mobius.Software{}, &mobius.PaginationMetadata{}, nil
	}
	ds.CountSoftwareFunc = func(ctx context.Context, opt mobius.SoftwareListOptions) (int, error) {
		return 0, nil
	}
	ds.SoftwareByIDFunc = func(ctx context.Context, id uint, teamID *uint, includeCVEScores bool, tmFilter *mobius.TeamFilter) (*mobius.Software, error) {
		return &mobius.Software{}, nil
	}
	ds.TeamExistsFunc = func(ctx context.Context, teamID uint) (bool, error) { return true, nil }
	svc, ctx := newTestService(t, ds, nil, nil)

	for _, tc := range []struct {
		name                 string
		user                 *mobius.User
		shouldFailGlobalRead bool
		shouldFailTeamRead   bool
	}{
		{
			name: "global-admin",
			user: &mobius.User{
				ID:         1,
				GlobalRole: ptr.String(mobius.RoleAdmin),
			},
			shouldFailGlobalRead: false,
			shouldFailTeamRead:   false,
		},
		{
			name: "global-maintainer",
			user: &mobius.User{
				ID:         1,
				GlobalRole: ptr.String(mobius.RoleMaintainer),
			},
			shouldFailGlobalRead: false,
			shouldFailTeamRead:   false,
		},
		{
			name: "global-observer",
			user: &mobius.User{
				ID:         1,
				GlobalRole: ptr.String(mobius.RoleObserver),
			},
			shouldFailGlobalRead: false,
			shouldFailTeamRead:   false,
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
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := viewer.NewContext(ctx, viewer.Viewer{User: tc.user})

			// List all software.
			_, _, err := svc.ListSoftware(ctx, mobius.SoftwareListOptions{})
			checkAuthErr(t, tc.shouldFailGlobalRead, err)

			// Count all software.
			_, err = svc.CountSoftware(ctx, mobius.SoftwareListOptions{})
			checkAuthErr(t, tc.shouldFailGlobalRead, err)

			// List software for a team.
			_, _, err = svc.ListSoftware(ctx, mobius.SoftwareListOptions{
				TeamID: ptr.Uint(1),
			})
			checkAuthErr(t, tc.shouldFailTeamRead, err)

			// Count software for a team.
			_, err = svc.CountSoftware(ctx, mobius.SoftwareListOptions{
				TeamID: ptr.Uint(1),
			})
			checkAuthErr(t, tc.shouldFailTeamRead, err)

			_, err = svc.SoftwareByID(ctx, 1, ptr.Uint(1), false)
			checkAuthErr(t, tc.shouldFailTeamRead, err)
		})
	}
}
