package service

import (
	"context"
	"testing"
	"time"

	"github.com/notawar/mobius/v4/server/contexts/viewer"
	"github.com/notawar/mobius/v4/server/mobius"
	"github.com/notawar/mobius/v4/server/mock"
	"github.com/notawar/mobius/v4/server/ptr"
)

func TestTeamScheduleAuth(t *testing.T) {
	ds := new(mock.Store)
	svc, ctx := newTestService(t, ds, nil, nil)

	ds.ListQueriesFunc = func(ctx context.Context, opt mobius.ListQueryOptions) ([]*mobius.Query, int, *mobius.PaginationMetadata, error) {
		return nil, 0, nil, nil
	}
	ds.QueryFunc = func(ctx context.Context, id uint) (*mobius.Query, error) {
		if id == 99 { // for testing modify and delete of a schedule
			return &mobius.Query{
				Name:   "foobar",
				Query:  "SELECT 1;",
				TeamID: ptr.Uint(1),
			}, nil
		}
		return &mobius.Query{ // for testing creation of a schedule
			Name:  "foobar",
			Query: "SELECT 1;",
			// TeamID is set to nil because a query must be global to be able to be
			// scheduled on a team by the deprecated APIs.
			TeamID: nil,
		}, nil
	}
	ds.SaveQueryFunc = func(ctx context.Context, query *mobius.Query, shouldDiscardResults bool, shouldDeleteStats bool) error {
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
	ds.NewQueryFunc = func(ctx context.Context, query *mobius.Query, opts ...mobius.OptionalArg) (*mobius.Query, error) {
		return &mobius.Query{}, nil
	}
	ds.DeleteQueryFunc = func(ctx context.Context, teamID *uint, name string) error {
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
			&mobius.User{
				GlobalRole: ptr.String(mobius.RoleAdmin),
			},
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
			false, // global observer can view all queries and scheduled queries.
		},
		{
			"global observer+",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleObserverPlus)},
			true,
			false, // global observer+ can view all queries and scheduled queries.
		},
		{
			"global gitops",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleGitOps)},
			false,
			false,
		},
		{
			"team admin, belongs to team",
			&mobius.User{
				Teams: []mobius.UserTeam{{
					Team: mobius.Team{ID: 1},
					Role: mobius.RoleAdmin,
				}},
			},
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
			"team observer+, belongs to team",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleObserverPlus}}},
			true,
			false,
		},
		{
			"team gitops, belongs to team",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleGitOps}}},
			false,
			false,
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
		{
			"team observer+, DOES NOT belong to team",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 2}, Role: mobius.RoleObserverPlus}}},
			true,
			true,
		},
		{
			"team gitops, DOES NOT belong to team",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 2}, Role: mobius.RoleGitOps}}},
			true,
			true,
		},
	}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			ctx := viewer.NewContext(ctx, viewer.Viewer{User: tt.user})

			_, err := svc.GetTeamScheduledQueries(ctx, 1, mobius.ListOptions{})
			checkAuthErr(t, tt.shouldFailRead, err)

			_, err = svc.TeamScheduleQuery(ctx, 1, &mobius.ScheduledQuery{Interval: 10})
			checkAuthErr(t, tt.shouldFailWrite, err)

			_, err = svc.ModifyTeamScheduledQueries(ctx, 1, 99, mobius.ScheduledQueryPayload{})
			checkAuthErr(t, tt.shouldFailWrite, err)

			err = svc.DeleteTeamScheduledQueries(ctx, 1, 99)
			checkAuthErr(t, tt.shouldFailWrite, err)
		})
	}
}
