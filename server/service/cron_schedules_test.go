package service

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/notawar/mobius/server/authz"
	"github.com/notawar/mobius/server/contexts/viewer"
	"github.com/notawar/mobius/server/mobius"
	"github.com/notawar/mobius/server/mock"
	"github.com/notawar/mobius/server/ptr"
	"github.com/notawar/mobius/server/service/schedule"
	"github.com/stretchr/testify/require"
)

func TestTriggerCronScheduleAuth(t *testing.T) {
	ds := new(mock.Store)

	svc, ctx := newTestService(t, ds, nil, nil, &TestServerOpts{StartCronSchedules: []TestNewScheduleFunc{
		func(ctx context.Context, ds mobius.Datastore) mobius.NewCronScheduleFunc {
			return func() (mobius.CronSchedule, error) {
				s := schedule.New(
					ctx, "test_sched", "id", 1*time.Second, schedule.NopLocker{}, schedule.NopStatsStore{},
					schedule.WithJob("test_job", func(ctx context.Context) error {
						return nil
					}),
				)
				return s, nil
			}
		},
	}})

	testCases := []struct {
		name       string
		user       *mobius.User
		shouldFail bool
	}{
		{
			"global admin",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)},
			false,
		},
		{
			"global maintainer",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleMaintainer)},
			true,
		},
		{
			"global observer",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleObserver)},
			true,
		},
		{
			"team admin",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleAdmin}}},
			true,
		},
		{
			"team maintainer",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleMaintainer}}},
			true,
		},
		{
			"team observer",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleObserver}}},
			true,
		},
		{
			"user",
			&mobius.User{ID: 777},
			true,
		},
	}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			ctx := viewer.NewContext(ctx, viewer.Viewer{User: tt.user})

			err := svc.TriggerCronSchedule(ctx, "test_sched")
			if tt.shouldFail {
				require.Error(t, err)
				require.Equal(t, (&authz.Forbidden{}).Error(), err.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestCronSchedulesService(t *testing.T) {
	ds := new(mock.Store)
	locker := schedule.SetupMockLocker("test_sched", "id", time.Now().Add(-1*time.Hour))
	statsStore := schedule.SetUpMockStatsStore("test_sched", mobius.CronStats{
		ID:        1,
		StatsType: mobius.CronStatsTypeScheduled,
		Name:      "test_sched",
		Instance:  "id",
		CreatedAt: time.Now().Add(-1 * time.Hour),
		UpdatedAt: time.Now().Add(-1 * time.Hour),
		Status:    mobius.CronStatsStatusCompleted,
	})
	jobsDone := uint32(0)
	startCh := make(chan struct{}, 1)

	svc, ctx := newTestService(t, ds, nil, nil, &TestServerOpts{StartCronSchedules: []TestNewScheduleFunc{
		func(ctx context.Context, ds mobius.Datastore) mobius.NewCronScheduleFunc {
			return func() (mobius.CronSchedule, error) {
				s := schedule.New(
					ctx, "test_sched", "id", 3*time.Second, locker, statsStore,
					schedule.WithJob("test_jobb", func(ctx context.Context) error {
						time.Sleep(100 * time.Millisecond)
						atomic.AddUint32(&jobsDone, 1)
						return nil
					}),
				)
				startCh <- struct{}{}
				return s, nil
			}
		},
	}})
	<-startCh
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	ctx = viewer.NewContext(ctx, viewer.Viewer{User: &mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)}})

	time.Sleep(10 * time.Millisecond)
	require.NoError(t, svc.TriggerCronSchedule(ctx, "test_sched")) // first trigger sent ok and will run successfully

	time.Sleep(10 * time.Millisecond)
	require.ErrorContains(t, svc.TriggerCronSchedule(ctx, "test_sched"), "conflicts with current status of test_sched") // error because first job is pending

	require.ErrorContains(t, svc.TriggerCronSchedule(ctx, "test_sched"), "conflicts with current status of test_sched") // error because first job is pending

	<-ticker.C
	require.Error(t, svc.TriggerCronSchedule(ctx, "test_sched_2")) // error because unrecognized name

	<-ticker.C
	time.Sleep(1500 * time.Millisecond)
	require.Equal(t, uint32(3), atomic.LoadUint32(&jobsDone)) // 2 regularly scheduled (at 3s and 6s) plus 1 triggered
}
