package service

import (
	"context"
	"testing"
	"time"

	"github.com/notawar/mobius/v4/server/contexts/viewer"
	"github.com/notawar/mobius/v4/server/mobius"
	"github.com/notawar/mobius/v4/server/mock"
	"github.com/notawar/mobius/v4/server/ptr"
	"github.com/stretchr/testify/require"
)

func TestListVulnerabilities(t *testing.T) {
	ds := new(mock.Store)
	svc, ctx := newTestService(t, ds, nil, nil)
	ctx = viewer.NewContext(ctx, viewer.Viewer{User: &mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)}})

	ds.ListVulnerabilitiesFunc = func(cxt context.Context, opt mobius.VulnListOptions) ([]mobius.VulnerabilityWithMetadata, *mobius.PaginationMetadata, error) {
		return []mobius.VulnerabilityWithMetadata{
			{
				CVE: mobius.CVE{
					CVE:         "CVE-2019-1234",
					Description: ptr.StringPtr("A vulnerability"),
				},
				CreatedAt:  time.Now(),
				HostsCount: 10,
			},
		}, nil, nil
	}

	t.Run("no list options", func(t *testing.T) {
		_, _, err := svc.ListVulnerabilities(ctx, mobius.VulnListOptions{})
		require.NoError(t, err)
	})

	t.Run("can only sort by supported columns", func(t *testing.T) {
		// invalid order key
		opts := mobius.VulnListOptions{ListOptions: mobius.ListOptions{
			OrderKey: "invalid",
		}, ValidSortColumns: freeValidVulnSortColumns}

		_, _, err := svc.ListVulnerabilities(ctx, opts)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid order key")

		// valid order key
		opts.ListOptions.OrderKey = "cve"
		_, _, err = svc.ListVulnerabilities(ctx, opts)
		require.NoError(t, err)
	})
}

func TestVulnerabilitesAuth(t *testing.T) {
	ds := new(mock.Store)

	svc, ctx := newTestService(t, ds, nil, nil)

	ds.ListVulnerabilitiesFunc = func(cxt context.Context, opt mobius.VulnListOptions) ([]mobius.VulnerabilityWithMetadata, *mobius.PaginationMetadata, error) {
		return []mobius.VulnerabilityWithMetadata{}, &mobius.PaginationMetadata{}, nil
	}

	ds.VulnerabilityFunc = func(cxt context.Context, cve string, teamID *uint, includeCVEScores bool) (*mobius.VulnerabilityWithMetadata, error) {
		return &mobius.VulnerabilityWithMetadata{}, nil
	}

	ds.CountVulnerabilitiesFunc = func(cxt context.Context, opt mobius.VulnListOptions) (uint, error) {
		return 0, nil
	}

	ds.TeamExistsFunc = func(cxt context.Context, teamID uint) (bool, error) {
		return true, nil
	}

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
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx = viewer.NewContext(ctx, viewer.Viewer{User: tc.user})
			_, _, err := svc.ListVulnerabilities(ctx, mobius.VulnListOptions{})
			checkAuthErr(t, tc.shouldFailGlobalRead, err)

			_, _, err = svc.ListVulnerabilities(ctx, mobius.VulnListOptions{
				TeamID: ptr.Uint(1),
			})
			checkAuthErr(t, tc.shouldFailTeamRead, err)

			_, err = svc.CountVulnerabilities(ctx, mobius.VulnListOptions{})
			checkAuthErr(t, tc.shouldFailGlobalRead, err)

			_, err = svc.CountVulnerabilities(ctx, mobius.VulnListOptions{
				TeamID: ptr.Uint(1),
			})
			checkAuthErr(t, tc.shouldFailTeamRead, err)

			_, _, err = svc.Vulnerability(ctx, "CVE-2019-1234", nil, false)
			checkAuthErr(t, tc.shouldFailGlobalRead, err)

			_, _, err = svc.Vulnerability(ctx, "CVE-2019-1234", ptr.Uint(1), false)
			checkAuthErr(t, tc.shouldFailTeamRead, err)
		})
	}
}
