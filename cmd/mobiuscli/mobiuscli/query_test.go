package mobiuscli

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/notawar/mobius/cmd/mobiuscli/mobiuscli/testing_utils"
	"github.com/notawar/mobius/server/mobius"
	"github.com/notawar/mobius/server/live_query/live_query_mock"
	"github.com/notawar/mobius/server/pubsub"
	"github.com/notawar/mobius/server/service"
	kitlog "github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSavedLiveQuery(t *testing.T) {
	rs := pubsub.NewInmemQueryResults()
	lq := live_query_mock.New(t)

	logger := kitlog.NewJSONLogger(os.Stdout)
	logger = level.NewFilter(logger, level.AllowDebug())

	_, ds := testing_utils.RunServerWithMockedDS(t, &service.TestServerOpts{
		Rs:     rs,
		Lq:     lq,
		Logger: logger,
	})

	users, err := ds.ListUsersFunc(context.Background(), mobius.UserListOptions{})
	require.NoError(t, err)
	var admin *mobius.User
	for _, user := range users {
		if user.GlobalRole != nil && *user.GlobalRole == mobius.RoleAdmin {
			admin = user
		}
	}

	const queryName = "saved-query"
	const queryString = "select 42, * from time"
	query := mobius.Query{
		ID:    42,
		Name:  queryName,
		Query: queryString,
		Saved: true,
	}

	ds.HostIDsByIdentifierFunc = func(ctx context.Context, filter mobius.TeamFilter, hostIdentifiers []string) ([]uint, error) {
		if len(hostIdentifiers) == 1 && hostIdentifiers[0] == "1234" {
			return []uint{1234}, nil
		}
		return nil, nil
	}
	ds.LabelIDsByNameFunc = func(ctx context.Context, labels []string) (map[string]uint, error) {
		return nil, nil
	}
	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		return &mobius.AppConfig{}, nil
	}
	ds.ListQueriesFunc = func(ctx context.Context, opt mobius.ListQueryOptions) ([]*mobius.Query, int, *mobius.PaginationMetadata, error) {
		if opt.MatchQuery == queryName {
			return []*mobius.Query{&query}, 1, nil, nil
		}
		return []*mobius.Query{}, 0, nil, nil
	}
	ds.NewDistributedQueryCampaignFunc = func(ctx context.Context, camp *mobius.DistributedQueryCampaign) (*mobius.DistributedQueryCampaign, error) {
		camp.ID = 321
		return camp, nil
	}
	ds.NewDistributedQueryCampaignTargetFunc = func(ctx context.Context, target *mobius.DistributedQueryCampaignTarget) (*mobius.DistributedQueryCampaignTarget, error) {
		return target, nil
	}
	noHostsTargeted := false
	ds.HostIDsInTargetsFunc = func(ctx context.Context, filter mobius.TeamFilter, targets mobius.HostTargets) ([]uint, error) {
		if noHostsTargeted {
			return nil, nil
		}
		return []uint{1}, nil
	}
	ds.CountHostsInTargetsFunc = func(ctx context.Context, filter mobius.TeamFilter, targets mobius.HostTargets, now time.Time) (mobius.TargetMetrics, error) {
		return mobius.TargetMetrics{TotalHosts: 1, OnlineHosts: 1}, nil
	}

	lq.On("QueriesForHost", uint(1)).Return(
		map[string]string{
			"42": queryString,
		},
		nil,
	)
	lq.On("QueryCompletedByHost", "42", 99).Return(nil)
	lq.On("RunQuery", "321", queryString, []uint{1}).Return(nil)

	ds.DistributedQueryCampaignTargetIDsFunc = func(ctx context.Context, id uint) (targets *mobius.HostTargets, err error) {
		return &mobius.HostTargets{HostIDs: []uint{99}}, nil
	}
	ds.DistributedQueryCampaignFunc = func(ctx context.Context, id uint) (*mobius.DistributedQueryCampaign, error) {
		return &mobius.DistributedQueryCampaign{
			ID:     321,
			UserID: admin.ID,
		}, nil
	}
	ds.SaveDistributedQueryCampaignFunc = func(ctx context.Context, camp *mobius.DistributedQueryCampaign) error {
		return nil
	}
	ds.QueryFunc = func(ctx context.Context, id uint) (*mobius.Query, error) {
		return &query, nil
	}
	ds.IsSavedQueryFunc = func(ctx context.Context, queryID uint) (bool, error) {
		return true, nil
	}
	var GetLiveQueryStatsFuncWg sync.WaitGroup
	GetLiveQueryStatsFuncWg.Add(2)
	ds.GetLiveQueryStatsFunc = func(ctx context.Context, queryID uint, hostIDs []uint) ([]*mobius.LiveQueryStats, error) {
		stats := []*mobius.LiveQueryStats{
			{
				LastExecuted: time.Now(),
			},
		}
		GetLiveQueryStatsFuncWg.Done()
		return stats, nil
	}
	var UpdateLiveQueryStatsFuncWg sync.WaitGroup
	UpdateLiveQueryStatsFuncWg.Add(1)
	ds.UpdateLiveQueryStatsFunc = func(ctx context.Context, queryID uint, stats []*mobius.LiveQueryStats) error {
		UpdateLiveQueryStatsFuncWg.Done()
		return nil
	}
	var CalculateAggregatedPerfStatsPercentilesFuncWg sync.WaitGroup
	CalculateAggregatedPerfStatsPercentilesFuncWg.Add(1)
	ds.CalculateAggregatedPerfStatsPercentilesFunc = func(ctx context.Context, aggregate mobius.AggregatedStatsType, queryID uint) error {
		CalculateAggregatedPerfStatsPercentilesFuncWg.Done()
		return nil
	}

	go func() {
		time.Sleep(2 * time.Second)
		require.NoError(t, rs.WriteResult(
			mobius.DistributedQueryResult{
				DistributedQueryCampaignID: 321,
				Rows:                       []map[string]string{{"bing": "fds"}},
				Host: mobius.ResultHostData{
					ID:          99,
					Hostname:    "somehostname",
					DisplayName: "somehostname",
				},
				Stats: &mobius.Stats{
					WallTimeMs: 10,
					UserTime:   20,
					SystemTime: 30,
					Memory:     40,
				},
			},
		))
	}()

	// errors before requesting live query
	_, err = RunAppNoChecks([]string{"query", "--hosts", "", "--query-name", queryName})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "No hosts or labels targeted")

	expected := `{"host":"somehostname","rows":[{"bing":"fds","host_display_name":"somehostname","host_hostname":"somehostname"}]}
`
	// Note: runAppForTest never closes the WebSocket connection and does not exit,
	// so we are unable to see the activity data that is written after WebSocket disconnects.
	assert.Equal(t, expected, RunAppForTest(t, []string{"query", "--hosts", "1234", "--query-name", queryName}))

	// We need to use waitGroups to detect whether Database functions were called because this is an asynchronous test which will flag data races otherwise.
	c := make(chan struct{})
	go func() {
		defer close(c)
		GetLiveQueryStatsFuncWg.Wait()
		UpdateLiveQueryStatsFuncWg.Wait()
		CalculateAggregatedPerfStatsPercentilesFuncWg.Wait()
	}()
	select {
	case <-time.After(time.Second):
		require.Fail(
			t,
			"Expected invocation of one of these Database functions did not happen: GetLiveQueryStats, UpdateLiveQueryStats, or CalculateAggregatedPerfStatsPercentiles",
		)
	case <-c: // All good
	}

	// Test targeting no hosts (e.g. host does exist)
	noHostsTargeted = true
	_, err = RunAppNoChecks([]string{"query", "--hosts", "foobar", "--query-name", queryName})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "No hosts targeted")
}

func TestAdHocLiveQuery(t *testing.T) {
	rs := pubsub.NewInmemQueryResults()
	lq := live_query_mock.New(t)

	logger := kitlog.NewJSONLogger(os.Stdout)
	logger = level.NewFilter(logger, level.AllowDebug())

	_, ds := testing_utils.RunServerWithMockedDS(
		t, &service.TestServerOpts{
			Rs:     rs,
			Lq:     lq,
			Logger: logger,
		},
	)

	users, err := ds.ListUsersFunc(context.Background(), mobius.UserListOptions{})
	require.NoError(t, err)
	var admin *mobius.User
	for _, user := range users {
		if user.GlobalRole != nil && *user.GlobalRole == mobius.RoleAdmin {
			admin = user
		}
	}

	ds.HostIDsByIdentifierFunc = func(ctx context.Context, filter mobius.TeamFilter, hostIdentifiers []string) ([]uint, error) {
		return []uint{1234}, nil
	}
	ds.LabelIDsByNameFunc = func(ctx context.Context, labels []string) (map[string]uint, error) {
		return map[string]uint{"label1": uint(1)}, nil
	}

	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		return &mobius.AppConfig{}, nil
	}
	ds.NewQueryFunc = func(ctx context.Context, query *mobius.Query, opts ...mobius.OptionalArg) (*mobius.Query, error) {
		query.ID = 42
		return query, nil
	}
	ds.NewDistributedQueryCampaignFunc = func(ctx context.Context, camp *mobius.DistributedQueryCampaign) (
		*mobius.DistributedQueryCampaign, error,
	) {
		camp.ID = 321
		return camp, nil
	}
	ds.NewDistributedQueryCampaignTargetFunc = func(
		ctx context.Context, target *mobius.DistributedQueryCampaignTarget,
	) (*mobius.DistributedQueryCampaignTarget, error) {
		return target, nil
	}
	ds.HostIDsInTargetsFunc = func(ctx context.Context, filter mobius.TeamFilter, targets mobius.HostTargets) ([]uint, error) {
		return []uint{1}, nil
	}
	ds.CountHostsInTargetsFunc = func(
		ctx context.Context, filter mobius.TeamFilter, targets mobius.HostTargets, now time.Time,
	) (mobius.TargetMetrics, error) {
		return mobius.TargetMetrics{TotalHosts: 1, OnlineHosts: 1}, nil
	}

	lq.On("QueriesForHost", uint(1)).Return(
		map[string]string{
			"42": "select 42, * from time",
		},
		nil,
	)
	lq.On("QueryCompletedByHost", "42", 99).Return(nil)
	lq.On("RunQuery", "321", "select 42, * from time", []uint{1}).Return(nil)

	ds.DistributedQueryCampaignTargetIDsFunc = func(ctx context.Context, id uint) (targets *mobius.HostTargets, err error) {
		return &mobius.HostTargets{HostIDs: []uint{99}}, nil
	}
	ds.DistributedQueryCampaignFunc = func(ctx context.Context, id uint) (*mobius.DistributedQueryCampaign, error) {
		return &mobius.DistributedQueryCampaign{
			ID:     321,
			UserID: admin.ID,
		}, nil
	}
	ds.SaveDistributedQueryCampaignFunc = func(ctx context.Context, camp *mobius.DistributedQueryCampaign) error {
		return nil
	}
	ds.QueryFunc = func(ctx context.Context, id uint) (*mobius.Query, error) {
		return &mobius.Query{}, nil
	}
	ds.IsSavedQueryFunc = func(ctx context.Context, queryID uint) (bool, error) {
		return false, nil
	}

	go func() {
		time.Sleep(2 * time.Second)
		require.NoError(
			t, rs.WriteResult(
				mobius.DistributedQueryResult{
					DistributedQueryCampaignID: 321,
					Rows:                       []map[string]string{{"bing": "fds"}},
					Host: mobius.ResultHostData{
						ID:          99,
						Hostname:    "somehostname",
						DisplayName: "somehostname",
					},
					Stats: &mobius.Stats{
						WallTimeMs: 10,
						UserTime:   20,
						SystemTime: 30,
						Memory:     40,
					},
				},
			),
		)
	}()

	// test label not found
	_, err = RunAppNoChecks([]string{"query", "--hosts", "1234", "--labels", "iamnotalabel", "--query", "select 42, * from time"})
	assert.ErrorContains(t, err, "Invalid label name(s): iamnotalabel.")

	// test if some labels were not found
	_, err = RunAppNoChecks([]string{"query", "--labels", "label1, mac, windows", "--hosts", "1234", "--query",
		"select 42, * from time"})
	assert.ErrorContains(t, err, "Invalid label name(s): mac, windows.")

	expected := `{"host":"somehostname","rows":[{"bing":"fds","host_display_name":"somehostname","host_hostname":"somehostname"}]}
`
	assert.Equal(t, expected, RunAppForTest(t, []string{"query", "--hosts", "1234", "--query", "select 42, * from time"}))
}
