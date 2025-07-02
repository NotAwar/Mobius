package service

import (
	"context"
	"testing"
	"time"

	"github.com/notawar/mobius/server/contexts/viewer"
	"github.com/notawar/mobius/server/mobius"
	"github.com/notawar/mobius/server/mock"
	"github.com/notawar/mobius/server/ptr"
)

func TestGlobalScheduleAuth(t *testing.T) {
	ds := new(mock.Store)
	svc, ctx := newTestService(t, ds, nil, nil)

	//
	// All global schedule query methods use queries datastore methods.
	//

	ds.QueryFunc = func(ctx context.Context, id uint) (*mobius.Query, error) {
		return &mobius.Query{
			Name:  "foobar",
			Query: "SELECT 1;",
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
	ds.ListQueriesFunc = func(ctx context.Context, opt mobius.ListQueryOptions) ([]*mobius.Query, int, *mobius.PaginationMetadata, error) {
		return nil, 0, nil, nil
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
			name:            "global admin",
			user:            &mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)},
			shouldFailWrite: false,
			shouldFailRead:  false,
		},
		{
			name:            "global maintainer",
			user:            &mobius.User{GlobalRole: ptr.String(mobius.RoleMaintainer)},
			shouldFailWrite: false,
			shouldFailRead:  false,
		},
		{
			name:            "global observer",
			user:            &mobius.User{GlobalRole: ptr.String(mobius.RoleObserver)},
			shouldFailWrite: true,
			shouldFailRead:  false,
		},
		{
			name:            "team admin",
			user:            &mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleAdmin}}},
			shouldFailWrite: true,
			shouldFailRead:  false,
		},
		{
			name:            "team maintainer",
			user:            &mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleMaintainer}}},
			shouldFailWrite: true,
			shouldFailRead:  false,
		},
		{
			name:            "team observer",
			user:            &mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleObserver}}},
			shouldFailWrite: true,
			shouldFailRead:  false,
		},
	}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			ctx := viewer.NewContext(ctx, viewer.Viewer{User: tt.user})

			_, err := svc.GetGlobalScheduledQueries(ctx, mobius.ListOptions{})
			checkAuthErr(t, tt.shouldFailRead, err)

			_, err = svc.GlobalScheduleQuery(ctx, &mobius.ScheduledQuery{
				Name:      "query",
				QueryName: "query",
				Interval:  10,
			})
			checkAuthErr(t, tt.shouldFailWrite, err)

			_, err = svc.ModifyGlobalScheduledQueries(ctx, 1, mobius.ScheduledQueryPayload{})
			checkAuthErr(t, tt.shouldFailWrite, err)

			err = svc.DeleteGlobalScheduledQueries(ctx, 1)
			checkAuthErr(t, tt.shouldFailWrite, err)
		})
	}
}
