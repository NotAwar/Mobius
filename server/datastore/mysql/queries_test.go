package mysql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"sort"
	"testing"
	"time"

	"github.com/notawar/mobius/server/mobius"
	"github.com/notawar/mobius/server/ptr"
	"github.com/notawar/mobius/server/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestQueries(t *testing.T) {
	ds := CreateMySQLDS(t)

	cases := []struct {
		name string
		fn   func(t *testing.T, ds *Datastore)
	}{
		{"Apply", testQueriesApply},
		{"Delete", testQueriesDelete},
		{"GetByName", testQueriesGetByName},
		{"DeleteMany", testQueriesDeleteMany},
		{"Save", testQueriesSave},
		{"List", testQueriesList},
		{"LoadPacksForQueries", testQueriesLoadPacksForQueries},
		{"DuplicateNew", testQueriesDuplicateNew},
		{"ObserverCanRunQuery", testObserverCanRunQuery},
		{"ListQueriesFiltersByTeamID", testListQueriesFiltersByTeamID},
		{"ListQueriesFiltersByIsScheduled", testListQueriesFiltersByIsScheduled},
		{"ListScheduledQueriesForAgents", testListScheduledQueriesForAgents},
		{"IsSavedQuery", testIsSavedQuery},
		{"SaveQueryLabels", testSaveQueryLabels},
		{"ListScheduledQueriesForAgentsWithLabels", testListScheduledQueriesForAgentsWithLabels},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			defer TruncateTables(t, ds)
			c.fn(t, ds)
		})
	}
}

func testQueriesApply(t *testing.T, ds *Datastore) {
	test.AddAllHostsLabel(t, ds)

	// Add a user-defined label
	fooLabel, err := ds.NewLabel(
		context.Background(),
		&mobius.Label{
			Name:                "Foo",
			Query:               "select 1",
			LabelType:           mobius.LabelTypeRegular,
			LabelMembershipType: mobius.LabelMembershipTypeManual,
		},
	)
	require.NoError(t, err)

	barLabel, err := ds.NewLabel(
		context.Background(),
		&mobius.Label{
			Name:                "Bar",
			Query:               "select 1",
			LabelType:           mobius.LabelTypeRegular,
			LabelMembershipType: mobius.LabelMembershipTypeManual,
		},
	)
	require.NoError(t, err)

	zwass := test.NewUser(t, ds, "Zach", "zwass@mobius.co", true)
	groob := test.NewUser(t, ds, "Victor", "victor@mobius.co", true)

	expectedQueries := []*mobius.Query{
		{
			Name:               "foo",
			Description:        "get the foos",
			Query:              "select * from foo",
			ObserverCanRun:     true,
			Interval:           10,
			Platform:           "darwin",
			MinOsqueryVersion:  "5.2.1",
			AutomationsEnabled: true,
			Logging:            mobius.LoggingDifferential,
			DiscardData:        true,
			LabelsIncludeAny:   []mobius.LabelIdent{{LabelID: fooLabel.ID, LabelName: fooLabel.Name}},
		},
		{
			Name:        "bar",
			Description: "do some bars",
			Query:       "select baz from bar",
			Logging:     mobius.LoggingSnapshot,
			DiscardData: true,
		},
	}

	// Zach creates some queries
	err = ds.ApplyQueries(context.Background(), zwass.ID, expectedQueries, nil)
	require.NoError(t, err)

	queries, count, _, err := ds.ListQueries(context.Background(), mobius.ListQueryOptions{})
	require.NoError(t, err)
	require.Len(t, queries, len(expectedQueries))
	require.Equal(t, count, len(expectedQueries))

	test.QueryElementsMatch(t, expectedQueries, queries)

	// Check all queries were authored by zwass
	for _, q := range queries {
		require.Equal(t, &zwass.ID, q.AuthorID)
		require.Equal(t, zwass.Email, q.AuthorEmail)
		require.Equal(t, zwass.Name, q.AuthorName)
		require.True(t, q.Saved)
	}

	// Update the first query to have a different label
	expectedQueries[0].LabelsIncludeAny = []mobius.LabelIdent{{LabelID: barLabel.ID, LabelName: barLabel.Name}}

	err = ds.ApplyQueries(context.Background(), zwass.ID, expectedQueries, nil)
	require.NoError(t, err)

	queries, count, _, err = ds.ListQueries(context.Background(), mobius.ListQueryOptions{})
	require.NoError(t, err)
	require.Len(t, queries, len(expectedQueries))
	require.Equal(t, count, len(expectedQueries))

	test.QueryElementsMatch(t, expectedQueries, queries)

	// Victor modifies a query (but also pushes the same version of the
	// first query)
	expectedQueries[1].Query = "not really a valid query ;)"
	err = ds.ApplyQueries(context.Background(), groob.ID, expectedQueries, nil)
	require.NoError(t, err)

	queries, count, _, err = ds.ListQueries(context.Background(), mobius.ListQueryOptions{})
	require.NoError(t, err)
	require.Len(t, queries, len(expectedQueries))
	require.Equal(t, count, len(expectedQueries))

	test.QueryElementsMatch(t, expectedQueries, queries)

	// Check queries were authored by groob
	for _, q := range queries {
		assert.Equal(t, &groob.ID, q.AuthorID)
		require.Equal(t, groob.Email, q.AuthorEmail)
		require.Equal(t, groob.Name, q.AuthorName)
		require.True(t, q.Saved)
	}

	// Zach adds a third query (but does not re-apply the others)
	expectedQueries = append(expectedQueries,
		&mobius.Query{
			Name:        "trouble",
			Description: "Look out!",
			Query:       "select * from time",
			DiscardData: true,
			Logging:     mobius.LoggingDifferential,
		},
	)
	err = ds.ApplyQueries(context.Background(), zwass.ID, []*mobius.Query{expectedQueries[2]}, nil)
	require.NoError(t, err)

	queries, count, _, err = ds.ListQueries(context.Background(), mobius.ListQueryOptions{})
	require.NoError(t, err)
	require.Len(t, queries, len(expectedQueries))
	require.Equal(t, count, len(expectedQueries))

	test.QueryElementsMatch(t, expectedQueries, queries)

	for _, q := range queries {
		require.True(t, q.Saved)
		switch q.Name {
		case "foo", "bar":
			require.Equal(t, &groob.ID, q.AuthorID)
			require.Equal(t, groob.Email, q.AuthorEmail)
			require.Equal(t, groob.Name, q.AuthorName)
		default:
			require.Equal(t, &zwass.ID, q.AuthorID)
			require.Equal(t, zwass.Email, q.AuthorEmail)
			require.Equal(t, zwass.Name, q.AuthorName)
		}
	}

	// Zach tries to add a query with an invalid platform string
	invalidQueries := []*mobius.Query{
		{
			Name:               "foo",
			Description:        "get the foos",
			Query:              "select * from foo",
			ObserverCanRun:     true,
			Interval:           10,
			Platform:           "not valid",
			MinOsqueryVersion:  "5.2.1",
			AutomationsEnabled: true,
			Logging:            mobius.LoggingDifferential,
		},
	}
	err = ds.ApplyQueries(context.Background(), zwass.ID, invalidQueries, nil)
	require.ErrorIs(t, err, mobius.ErrQueryInvalidPlatform)
}

func testQueriesDelete(t *testing.T, ds *Datastore) {
	user := test.NewUser(t, ds, "Zach", "zwass@mobius.co", true)

	hostID := uint(1)
	query := &mobius.Query{
		Name:     "foo",
		Query:    "bar",
		AuthorID: &user.ID,
		Logging:  mobius.LoggingDifferential,
	}
	query, err := ds.NewQuery(context.Background(), query)
	require.NoError(t, err)
	require.NotNil(t, query)
	assert.NotEqual(t, query.ID, 0)
	lastExecuted := time.Now().Add(-time.Hour).Round(time.Second) // TIMESTAMP precision is seconds by default in MySQL
	err = ds.UpdateLiveQueryStats(
		context.Background(), query.ID, []*mobius.LiveQueryStats{
			{
				HostID:       hostID,
				Executions:   1,
				LastExecuted: lastExecuted,
			},
		},
	)
	require.NoError(t, err)
	// Check that the stats were saved correctly
	stats, err := ds.GetLiveQueryStats(context.Background(), query.ID, []uint{hostID})
	require.NoError(t, err)
	require.Len(t, stats, 1)
	assert.Equal(t, hostID, stats[0].HostID)
	assert.Equal(t, uint64(1), stats[0].Executions)
	assert.Equal(t, lastExecuted.UTC(), stats[0].LastExecuted.UTC())

	err = ds.CalculateAggregatedPerfStatsPercentiles(context.Background(), mobius.AggregatedStatsTypeScheduledQuery, query.ID)
	require.NoError(t, err)

	err = ds.DeleteQuery(context.Background(), query.TeamID, query.Name)
	require.NoError(t, err)

	require.NotEqual(t, query.ID, 0)
	_, err = ds.Query(context.Background(), query.ID)
	require.Error(t, err)
	require.True(t, mobius.IsNotFound(err))

	// Ensure stats were deleted.
	// The actual delete occurs asynchronously, so we for-loop.
	statsGone := make(chan bool)
	go func() {
		for {
			stats, err := ds.GetLiveQueryStats(context.Background(), query.ID, []uint{hostID})
			require.NoError(t, err)
			if len(stats) == 0 {
				_, err = GetAggregatedStats(context.Background(), ds, mobius.AggregatedStatsTypeScheduledQuery, query.ID)
				if errors.Is(err, sql.ErrNoRows) {
					statsGone <- true
					break
				}
			}
		}
	}()
	select {
	case <-statsGone:
	case <-time.After(10 * time.Second):
		t.Error("Timeout: stats not deleted for testQueriesDelete")
	}
}

func testQueriesGetByName(t *testing.T, ds *Datastore) {
	user := test.NewUser(t, ds, "Zach", "zwass@mobius.co", true)

	// Test we can get global queries by name
	globalQ := test.NewQuery(t, ds, nil, "q1", "select * from time", user.ID, true)

	actual, err := ds.QueryByName(context.Background(), nil, globalQ.Name)
	require.NoError(t, err)
	require.Nil(t, actual.TeamID)
	require.Equal(t, "q1", actual.Name)
	require.Equal(t, "select * from time", actual.Query)

	_, err = ds.QueryByName(context.Background(), nil, "xxx")
	require.Error(t, err)
	require.True(t, mobius.IsNotFound(err))

	// Test we can get queries in a team
	teamRocket, err := ds.NewTeam(context.Background(), &mobius.Team{
		Name:        "Team Rocket",
		Description: "Something cheesy",
	})
	require.NoError(t, err)

	teamRocketQ := test.NewQuery(t, ds, &teamRocket.ID, "q1", "select * from time", user.ID, true)

	actual, err = ds.QueryByName(context.Background(), &teamRocket.ID, teamRocketQ.Name)
	require.NoError(t, err)
	require.Equal(t, "q1", actual.Name)
	require.Equal(t, teamRocket.ID, *actual.TeamID)
	require.Equal(t, "select * from time", actual.Query)

	_, err = ds.QueryByName(context.Background(), &teamRocket.ID, "xxx")
	require.Error(t, err)
	require.True(t, mobius.IsNotFound(err))
}

func testQueriesDeleteMany(t *testing.T, ds *Datastore) {
	user := test.NewUser(t, ds, "Zach", "zwass@mobius.co", true)

	q1 := test.NewQuery(t, ds, nil, "q1", "select * from time", user.ID, true)
	q2 := test.NewQuery(t, ds, nil, "q2", "select * from processes", user.ID, true)
	q3 := test.NewQuery(t, ds, nil, "q3", "select 1", user.ID, true)
	q4 := test.NewQuery(t, ds, nil, "q4", "select * from osquery_info", user.ID, true)

	queries, count, _, err := ds.ListQueries(context.Background(), mobius.ListQueryOptions{})
	require.Nil(t, err)
	assert.Len(t, queries, 4)
	require.Equal(t, count, 4)

	// Add query stats
	hostIDs := []uint{10, 20}
	err = ds.UpdateLiveQueryStats(
		context.Background(), q1.ID, []*mobius.LiveQueryStats{
			{
				HostID:     hostIDs[0],
				Executions: 1,
			},
			{
				HostID:     hostIDs[1],
				Executions: 1,
			},
		},
	)
	require.NoError(t, err)
	err = ds.UpdateLiveQueryStats(
		context.Background(), q3.ID, []*mobius.LiveQueryStats{
			{
				HostID:     hostIDs[0],
				Executions: 1,
			},
		},
	)
	require.NoError(t, err)
	err = ds.CalculateAggregatedPerfStatsPercentiles(context.Background(), mobius.AggregatedStatsTypeScheduledQuery, q1.ID)
	require.NoError(t, err)
	err = ds.CalculateAggregatedPerfStatsPercentiles(context.Background(), mobius.AggregatedStatsTypeScheduledQuery, q3.ID)
	require.NoError(t, err)

	deleted, err := ds.DeleteQueries(context.Background(), []uint{q1.ID, q3.ID})
	require.Nil(t, err)
	assert.Equal(t, uint(2), deleted)

	queries, count, _, err = ds.ListQueries(context.Background(), mobius.ListQueryOptions{})
	require.Nil(t, err)
	assert.Len(t, queries, 2)
	assert.Equal(t, count, 2)

	// Ensure stats were deleted.
	// The actual delete occurs asynchronously, so we for-loop.
	statsGone := make(chan bool)
	go func() {
		for {
			stats, err := ds.GetLiveQueryStats(context.Background(), q1.ID, hostIDs)
			require.NoError(t, err)
			if len(stats) == 0 {
				_, err = GetAggregatedStats(context.Background(), ds, mobius.AggregatedStatsTypeScheduledQuery, q1.ID)
				if errors.Is(err, sql.ErrNoRows) {
					statsGone <- true
					break
				}
			}
		}
	}()
	select {
	case <-statsGone:
	case <-time.After(10 * time.Second):
		t.Error("Timeout: stats not deleted for testQueriesDeleteMany")
	}
	stats, err := ds.GetLiveQueryStats(context.Background(), q3.ID, hostIDs)
	require.NoError(t, err)
	require.Equal(t, 0, len(stats))
	_, err = GetAggregatedStats(context.Background(), ds, mobius.AggregatedStatsTypeScheduledQuery, q3.ID)
	require.ErrorIs(t, err, sql.ErrNoRows)

	deleted, err = ds.DeleteQueries(context.Background(), []uint{q2.ID})
	require.Nil(t, err)
	assert.Equal(t, uint(1), deleted)

	queries, count, _, err = ds.ListQueries(context.Background(), mobius.ListQueryOptions{})
	require.Nil(t, err)
	assert.Len(t, queries, 1)
	assert.Equal(t, count, 1)

	deleted, err = ds.DeleteQueries(context.Background(), []uint{q2.ID, q4.ID})
	require.Nil(t, err)
	assert.Equal(t, uint(1), deleted)

	queries, count, _, err = ds.ListQueries(context.Background(), mobius.ListQueryOptions{})
	require.Nil(t, err)
	assert.Len(t, queries, 0)
	assert.Equal(t, count, 0)
}

func testQueriesSave(t *testing.T, ds *Datastore) {
	user := test.NewUser(t, ds, "Zach", "zwass@mobius.co", true)

	query := &mobius.Query{
		Name:     "foo",
		Query:    "bar",
		AuthorID: &user.ID,
		Logging:  mobius.LoggingSnapshot,
	}
	query, err := ds.NewQuery(context.Background(), query)
	require.NoError(t, err)
	require.NotNil(t, query)
	require.NotEqual(t, 0, query.ID)

	team, err := ds.NewTeam(context.Background(), &mobius.Team{
		Name:        "some kind of nature",
		Description: "some kind of goal",
	})
	require.NoError(t, err)

	query.Query = "baz"
	query.ObserverCanRun = true
	query.TeamID = &team.ID
	query.Interval = 10
	query.Platform = "darwin"
	query.MinOsqueryVersion = "5.2.1"
	query.AutomationsEnabled = true
	query.Logging = mobius.LoggingDifferential
	query.DiscardData = true

	err = ds.SaveQuery(context.Background(), query, true, false)
	require.NoError(t, err)

	actual, err := ds.Query(context.Background(), query.ID)
	require.NoError(t, err)
	require.NotNil(t, actual)

	test.QueriesMatch(t, actual, query)

	require.Equal(t, "baz", actual.Query)
	require.Equal(t, "Zach", actual.AuthorName)
	require.Equal(t, "zwass@mobius.co", actual.AuthorEmail)

	// Now save again and delete old stats.
	// First we create stats which will be deleted.
	const hostID = 1
	err = ds.UpdateLiveQueryStats(
		context.Background(), query.ID, []*mobius.LiveQueryStats{
			{
				HostID:     hostID,
				Executions: 1,
			},
		},
	)
	require.NoError(t, err)
	err = ds.CalculateAggregatedPerfStatsPercentiles(context.Background(), mobius.AggregatedStatsTypeScheduledQuery, query.ID)
	require.NoError(t, err)
	// Update/save query.
	query.Query = "baz2"
	err = ds.SaveQuery(context.Background(), query, true, true)
	require.NoError(t, err)
	// Ensure stats were deleted.
	// The actual delete occurs asynchronously, so we for-loop.
	aggStatsGone := make(chan bool)
	go func() {
		for {
			actual, err = ds.Query(context.Background(), query.ID)
			require.NoError(t, err)
			require.NotNil(t, actual)
			if actual.AggregatedStats.TotalExecutions == nil {
				aggStatsGone <- true
				break
			}
		}
	}()
	select {
	case <-aggStatsGone:
	case <-time.After(10 * time.Second):
		t.Error("Timeout: aggregated stats not deleted for query")
	}
	test.QueriesMatch(t, query, actual)
	stats, err := ds.GetLiveQueryStats(context.Background(), query.ID, []uint{hostID})
	require.NoError(t, err)
	require.Equal(t, 0, len(stats))
	_, err = GetAggregatedStats(context.Background(), ds, mobius.AggregatedStatsTypeScheduledQuery, query.ID)
	require.ErrorIs(t, err, sql.ErrNoRows)
}

func testQueriesList(t *testing.T, ds *Datastore) {
	user := test.NewUser(t, ds, "Zach", "zwass@mobius.co", true)

	for i := 0; i < 10; i++ {
		// populate platform field of first 4 queries
		var p string
		switch i {
		case 0:
			p = "darwin"
		case 1:
			p = "windows"
		case 2:
			p = "linux"
		case 3:
			p = "darwin,windows,linux"
		}

		_, err := ds.NewQuery(context.Background(), &mobius.Query{
			Name:           fmt.Sprintf("name%02d", i),
			Query:          fmt.Sprintf("query%02d", i),
			Saved:          true,
			AuthorID:       &user.ID,
			DiscardData:    true,
			ObserverCanRun: rand.Intn(2) == 0, //nolint:gosec
			Logging:        mobius.LoggingSnapshot,
			Platform:       p,
		})
		require.Nil(t, err)
	}

	// One unsaved query should not be returned
	_, err := ds.NewQuery(context.Background(), &mobius.Query{
		Name:     "unsaved",
		Query:    "select * from time",
		Saved:    false,
		AuthorID: &user.ID,
		Logging:  mobius.LoggingSnapshot,
	})
	require.NoError(t, err)

	opts := mobius.ListQueryOptions{}
	opts.IncludeMetadata = true

	opts.Platform = ptr.String("darwin")
	// filtered by platform
	results, count, meta, err := ds.ListQueries(context.Background(), opts)
	require.NoError(t, err)
	require.Equal(t, 8, len(results))
	assert.Equal(t, count, 8)
	assert.False(t, meta.HasPreviousResults)
	assert.False(t, meta.HasNextResults)
	require.Equal(t, "darwin", results[0].Platform)
	require.Equal(t, "darwin,windows,linux", results[1].Platform)

	opts.Platform = ptr.String("windows")
	results, count, meta, err = ds.ListQueries(context.Background(), opts)
	require.NoError(t, err)
	require.Equal(t, 8, len(results))
	assert.Equal(t, count, 8)
	assert.False(t, meta.HasPreviousResults)
	assert.False(t, meta.HasNextResults)
	require.Equal(t, "windows", results[0].Platform)
	require.Equal(t, "darwin,windows,linux", results[1].Platform)

	opts.Platform = ptr.String("linux")
	results, count, meta, err = ds.ListQueries(context.Background(), opts)
	require.NoError(t, err)
	require.Equal(t, 8, len(results))
	assert.Equal(t, count, 8)
	assert.False(t, meta.HasPreviousResults)
	assert.False(t, meta.HasNextResults)
	require.Equal(t, "linux", results[0].Platform)
	require.Equal(t, "darwin,windows,linux", results[1].Platform)

	opts.Platform = ptr.String("lucas")
	results, count, meta, err = ds.ListQueries(context.Background(), opts)
	require.NoError(t, err)
	// only returns queries set to run on all platforms with platform == ""
	require.Equal(t, 6, len(results))
	assert.Equal(t, count, 6)
	assert.False(t, meta.HasPreviousResults)
	assert.False(t, meta.HasNextResults)

	opts.Platform = nil

	// paginated - beginning
	opts.PerPage = 3
	opts.Page = 0
	results, count, meta, err = ds.ListQueries(context.Background(), opts)
	require.NoError(t, err)
	require.Equal(t, 3, len(results))
	require.Equal(t, "Zach", results[0].AuthorName)
	require.Equal(t, "zwass@mobius.co", results[0].AuthorEmail)
	require.True(t, results[0].DiscardData)
	assert.Equal(t, count, 10)
	assert.False(t, meta.HasPreviousResults)
	assert.True(t, meta.HasNextResults)

	// paginated - middle
	opts.Page = 1
	results, count, meta, err = ds.ListQueries(context.Background(), opts)
	require.NoError(t, err)
	require.Equal(t, 3, len(results))
	require.Equal(t, "Zach", results[0].AuthorName)
	require.Equal(t, "zwass@mobius.co", results[0].AuthorEmail)
	require.True(t, results[0].DiscardData)
	assert.Equal(t, count, 10)
	assert.True(t, meta.HasPreviousResults)
	assert.True(t, meta.HasNextResults)

	// paginated - end
	opts.Page = 3
	results, count, meta, err = ds.ListQueries(context.Background(), opts)
	require.NoError(t, err)
	require.Equal(t, 1, len(results))
	require.Equal(t, "Zach", results[0].AuthorName)
	require.Equal(t, "zwass@mobius.co", results[0].AuthorEmail)
	require.True(t, results[0].DiscardData)
	assert.Equal(t, count, 10)
	assert.True(t, meta.HasPreviousResults)
	assert.False(t, meta.HasNextResults)

	// paginated - past end
	opts.Page = 4
	results, count, meta, err = ds.ListQueries(context.Background(), opts)
	require.NoError(t, err)
	require.Equal(t, 0, len(results))
	assert.Equal(t, count, 10)
	assert.True(t, meta.HasPreviousResults)
	assert.False(t, meta.HasNextResults)

	opts.PerPage = 0
	opts.Page = 0
	results, count, meta, err = ds.ListQueries(context.Background(), opts)
	require.NoError(t, err)
	require.Equal(t, 10, len(results))
	require.Equal(t, "Zach", results[0].AuthorName)
	require.Equal(t, "zwass@mobius.co", results[0].AuthorEmail)
	require.True(t, results[0].DiscardData)
	assert.Equal(t, count, 10)
	assert.False(t, meta.HasPreviousResults)
	assert.False(t, meta.HasNextResults)

	idWithAgg := results[0].ID

	_, err = ds.writer(context.Background()).Exec(
		`INSERT INTO aggregated_stats(id,global_stats,type,json_value) VALUES (?,?,?,?)`,
		idWithAgg, false, mobius.AggregatedStatsTypeScheduledQuery,
		`{"user_time_p50": 10.5777, "user_time_p95": 111.7308, "system_time_p50": 0.6936, "system_time_p95": 95.8654, "total_executions": 5038}`,
	)
	require.NoError(t, err)

	results, _, _, err = ds.ListQueries(context.Background(), opts)
	require.NoError(t, err)
	require.Equal(t, 10, len(results))

	foundAgg := false
	for _, q := range results {
		if q.ID == idWithAgg {
			foundAgg = true
			require.NotNil(t, q.SystemTimeP50)
			require.NotNil(t, q.SystemTimeP95)
			assert.Equal(t, 0.6936, *q.SystemTimeP50)
			assert.Equal(t, 95.8654, *q.SystemTimeP95)
		}
	}
	require.True(t, foundAgg)
}

func testQueriesLoadPacksForQueries(t *testing.T, ds *Datastore) {
	zwass := test.NewUser(t, ds, "Zach", "zwass@mobius.co", true)
	queries := []*mobius.Query{
		{Name: "q1", Query: "select * from time", Logging: mobius.LoggingSnapshot},
		{Name: "q2", Query: "select * from osquery_info", Logging: mobius.LoggingDifferential},
	}
	err := ds.ApplyQueries(context.Background(), zwass.ID, queries, nil)
	require.NoError(t, err)

	specs := []*mobius.PackSpec{
		{Name: "p1"},
		{Name: "p2"},
		{Name: "p3"},
	}
	err = ds.ApplyPackSpecs(context.Background(), specs)
	require.Nil(t, err)

	q0, err := ds.QueryByName(context.Background(), nil, queries[0].Name)
	require.Nil(t, err)
	assert.Empty(t, q0.Packs)

	q1, err := ds.QueryByName(context.Background(), nil, queries[1].Name)
	require.Nil(t, err)
	assert.Empty(t, q1.Packs)

	specs = []*mobius.PackSpec{
		{
			Name: "p2",
			Queries: []mobius.PackSpecQuery{
				{
					Name:      "q0",
					QueryName: queries[0].Name,
					Interval:  60,
				},
			},
		},
	}
	err = ds.ApplyPackSpecs(context.Background(), specs)
	require.Nil(t, err)

	q0, err = ds.QueryByName(context.Background(), nil, queries[0].Name)
	require.Nil(t, err)
	if assert.Len(t, q0.Packs, 1) {
		assert.Equal(t, "p2", q0.Packs[0].Name)
	}

	q1, err = ds.QueryByName(context.Background(), nil, queries[1].Name)
	require.Nil(t, err)
	assert.Empty(t, q1.Packs)

	specs = []*mobius.PackSpec{
		{
			Name: "p1",
			Queries: []mobius.PackSpecQuery{
				{
					QueryName: queries[1].Name,
					Interval:  60,
				},
			},
		},
		{
			Name: "p3",
			Queries: []mobius.PackSpecQuery{
				{
					QueryName: queries[1].Name,
					Interval:  60,
				},
			},
		},
	}
	err = ds.ApplyPackSpecs(context.Background(), specs)
	require.Nil(t, err)

	q0, err = ds.QueryByName(context.Background(), nil, queries[0].Name)
	require.Nil(t, err)
	if assert.Len(t, q0.Packs, 1) {
		assert.Equal(t, "p2", q0.Packs[0].Name)
	}

	q1, err = ds.QueryByName(context.Background(), nil, queries[1].Name)
	require.Nil(t, err)
	if assert.Len(t, q1.Packs, 2) {
		sort.Slice(q1.Packs, func(i, j int) bool { return q1.Packs[i].Name < q1.Packs[j].Name })
		assert.Equal(t, "p1", q1.Packs[0].Name)
		assert.Equal(t, "p3", q1.Packs[1].Name)
	}

	specs = []*mobius.PackSpec{
		{
			Name: "p3",
			Queries: []mobius.PackSpecQuery{
				{
					Name:      "q0",
					QueryName: queries[0].Name,
					Interval:  60,
				},
				{
					Name:      "q1",
					QueryName: queries[1].Name,
					Interval:  60,
				},
			},
		},
	}
	err = ds.ApplyPackSpecs(context.Background(), specs)
	require.Nil(t, err)

	q0, err = ds.QueryByName(context.Background(), nil, queries[0].Name)
	require.Nil(t, err)
	if assert.Len(t, q0.Packs, 2) {
		sort.Slice(q0.Packs, func(i, j int) bool { return q0.Packs[i].Name < q0.Packs[j].Name })
		assert.Equal(t, "p2", q0.Packs[0].Name)
		assert.Equal(t, "p3", q0.Packs[1].Name)
	}

	q1, err = ds.QueryByName(context.Background(), nil, queries[1].Name)
	require.Nil(t, err)
	if assert.Len(t, q1.Packs, 2) {
		sort.Slice(q1.Packs, func(i, j int) bool { return q1.Packs[i].Name < q1.Packs[j].Name })
		assert.Equal(t, "p1", q1.Packs[0].Name)
		assert.Equal(t, "p3", q1.Packs[1].Name)
	}
}

func testQueriesDuplicateNew(t *testing.T, ds *Datastore) {
	user := test.NewUser(t, ds, "Mike Arpaia", "mike@mobius.co", true)

	// The uniqueness of 'global' queries should be based on their name alone.
	globalQ1, err := ds.NewQuery(context.Background(), &mobius.Query{
		Name:     "foo",
		Query:    "select * from time;",
		AuthorID: &user.ID,
		Logging:  mobius.LoggingSnapshot,
	})
	require.NoError(t, err)
	require.NotZero(t, globalQ1.ID)
	_, err = ds.NewQuery(context.Background(), &mobius.Query{
		Name:    "foo",
		Query:   "select * from osquery_info;",
		Logging: mobius.LoggingSnapshot,
	})
	require.Contains(t, err.Error(), "already exists")

	// Check uniqueness constraint on queries that belong to a team
	team, err := ds.NewTeam(context.Background(), &mobius.Team{
		Name:        "some kind of nature",
		Description: "some kind of goal",
	})
	require.NoError(t, err)

	_, err = ds.NewQuery(context.Background(), &mobius.Query{
		Name:    "foo",
		Query:   "select * from osquery_info;",
		TeamID:  &team.ID,
		Logging: mobius.LoggingSnapshot,
	})
	require.NoError(t, err)

	_, err = ds.NewQuery(context.Background(), &mobius.Query{
		Name:    "foo",
		Query:   "select * from osquery_info;",
		TeamID:  &team.ID,
		Logging: mobius.LoggingSnapshot,
	})
	require.Contains(t, err.Error(), "already exists")
}

func testObserverCanRunQuery(t *testing.T, ds *Datastore) {
	_, err := ds.NewQuery(context.Background(), &mobius.Query{
		Name:           "canRunTrue",
		Query:          "select 1;",
		ObserverCanRun: true,
		Logging:        mobius.LoggingSnapshot,
	})
	require.NoError(t, err)

	_, err = ds.NewQuery(context.Background(), &mobius.Query{
		Name:           "canRunFalse",
		Query:          "select 1;",
		ObserverCanRun: false,
		Logging:        mobius.LoggingSnapshot,
	})
	require.NoError(t, err)

	_, err = ds.NewQuery(context.Background(), &mobius.Query{
		Name:    "canRunOmitted",
		Query:   "select 1;",
		Logging: mobius.LoggingSnapshot,
	})
	require.NoError(t, err)

	queries, _, _, err := ds.ListQueries(context.Background(), mobius.ListQueryOptions{})
	require.NoError(t, err)

	for _, q := range queries {
		canRun, err := ds.ObserverCanRunQuery(context.Background(), q.ID)
		require.NoError(t, err)
		require.Equal(t, q.ObserverCanRun, canRun)
	}
}

func testListQueriesFiltersByTeamID(t *testing.T, ds *Datastore) {
	globalQ1, err := ds.NewQuery(context.Background(), &mobius.Query{
		Name:    "query1",
		Query:   "select 1;",
		Saved:   true,
		Logging: mobius.LoggingSnapshot,
	})
	require.NoError(t, err)
	globalQ2, err := ds.NewQuery(context.Background(), &mobius.Query{
		Name:    "query2",
		Query:   "select 1;",
		Saved:   true,
		Logging: mobius.LoggingSnapshot,
	})
	require.NoError(t, err)
	globalQ3, err := ds.NewQuery(context.Background(), &mobius.Query{
		Name:    "query3",
		Query:   "select 1;",
		Saved:   true,
		Logging: mobius.LoggingSnapshot,
	})
	require.NoError(t, err)

	queries, count, _, err := ds.ListQueries(context.Background(), mobius.ListQueryOptions{})
	require.NoError(t, err)
	test.QueryElementsMatch(t, queries, []*mobius.Query{globalQ1, globalQ2, globalQ3})
	assert.Equal(t, count, 3)

	team, err := ds.NewTeam(context.Background(), &mobius.Team{
		Name:        "some kind of nature",
		Description: "some kind of goal",
	})
	require.NoError(t, err)

	teamQ1, err := ds.NewQuery(context.Background(), &mobius.Query{
		Name:    "query1",
		Query:   "select 1;",
		Saved:   true,
		TeamID:  &team.ID,
		Logging: mobius.LoggingSnapshot,
	})
	require.NoError(t, err)
	teamQ2, err := ds.NewQuery(context.Background(), &mobius.Query{
		Name:    "query2",
		Query:   "select 1;",
		Saved:   true,
		TeamID:  &team.ID,
		Logging: mobius.LoggingSnapshot,
	})
	require.NoError(t, err)
	teamQ3, err := ds.NewQuery(context.Background(), &mobius.Query{
		Name:    "query3",
		Query:   "select 1;",
		Saved:   true,
		TeamID:  &team.ID,
		Logging: mobius.LoggingSnapshot,
	})
	require.NoError(t, err)

	queries, count, _, err = ds.ListQueries(
		context.Background(),
		mobius.ListQueryOptions{
			TeamID: &team.ID,
		},
	)
	require.NoError(t, err)
	test.QueryElementsMatch(t, queries, []*mobius.Query{teamQ1, teamQ2, teamQ3})
	assert.Equal(t, count, 3)

	// test merge inherited
	queries, count, _, err = ds.ListQueries(
		context.Background(),
		mobius.ListQueryOptions{
			TeamID:         &team.ID,
			MergeInherited: true,
		},
	)
	require.NoError(t, err)
	test.QueryElementsMatch(t, queries, []*mobius.Query{globalQ1, globalQ2, globalQ3, teamQ1, teamQ2, teamQ3})
	assert.Equal(t, count, 6)

	// merge inherited ignored for global queries
	queries, count, _, err = ds.ListQueries(
		context.Background(),
		mobius.ListQueryOptions{
			MergeInherited: true,
		},
	)
	require.NoError(t, err)
	test.QueryElementsMatch(t, queries, []*mobius.Query{globalQ1, globalQ2, globalQ3})
	assert.Equal(t, count, 3)
}

func testListQueriesFiltersByIsScheduled(t *testing.T, ds *Datastore) {
	q1, err := ds.NewQuery(context.Background(), &mobius.Query{
		Name:     "query1",
		Query:    "select 1;",
		Saved:    true,
		Interval: 0,
		Logging:  mobius.LoggingSnapshot,
	})
	require.NoError(t, err)
	q2, err := ds.NewQuery(context.Background(), &mobius.Query{
		Name:               "query2",
		Query:              "select 1;",
		Saved:              true,
		Interval:           10,
		AutomationsEnabled: false,
		Logging:            mobius.LoggingSnapshot,
	})
	require.NoError(t, err)
	q3, err := ds.NewQuery(context.Background(), &mobius.Query{
		Name:               "query3",
		Query:              "select 1;",
		Saved:              true,
		Interval:           20,
		AutomationsEnabled: true,
		Logging:            mobius.LoggingSnapshot,
	})
	require.NoError(t, err)

	testCases := []struct {
		opts     mobius.ListQueryOptions
		expected []*mobius.Query
	}{
		{
			opts: mobius.ListQueryOptions{},

			expected: []*mobius.Query{q1, q2, q3},
		},
		{
			opts:     mobius.ListQueryOptions{IsScheduled: ptr.Bool(true)},
			expected: []*mobius.Query{q3},
		},
		{
			opts:     mobius.ListQueryOptions{IsScheduled: ptr.Bool(false)},
			expected: []*mobius.Query{q1, q2},
		},
	}

	for i, tCase := range testCases {
		queries, count, _, err := ds.ListQueries(
			context.Background(),
			tCase.opts,
		)
		require.NoError(t, err)
		test.QueryElementsMatch(t, queries, tCase.expected, i)
		assert.Equal(t, count, len(tCase.expected))

	}
}

func testListScheduledQueriesForAgents(t *testing.T, ds *Datastore) {
	ctx := context.Background()

	team, err := ds.NewTeam(context.Background(), &mobius.Team{
		Name:        "Team 1",
		Description: "Team 1",
	})
	require.NoError(t, err)

	for i, teamID := range []*uint{nil, &team.ID} {
		var teamIDStr string
		if teamID != nil {
			teamIDStr = fmt.Sprintf("%d", *teamID)
		}

		// Non saved queries should not be returned here.
		_, err = ds.NewQuery(context.Background(), &mobius.Query{
			Name:               fmt.Sprintf("%s query1", teamIDStr),
			Query:              "select 1;",
			Saved:              false,
			Interval:           10,
			AutomationsEnabled: false,
			TeamID:             teamID,
			DiscardData:        true,
			Logging:            mobius.LoggingSnapshot,
		})
		require.NoError(t, err)

		// Interval=0, AutomationsEnabled=0, DiscardData=0, Snapshot=0
		_, err := ds.NewQuery(context.Background(), &mobius.Query{
			Name:               fmt.Sprintf("%s query2", teamIDStr),
			Query:              "select 1;",
			Saved:              true,
			Interval:           0,
			TeamID:             teamID,
			AutomationsEnabled: false,
			DiscardData:        false,
			Logging:            mobius.LoggingDifferential,
		})
		require.NoError(t, err)

		// Interval=0, AutomationsEnabled=0, DiscardData=0, Snapshot=1
		_, err = ds.NewQuery(context.Background(), &mobius.Query{
			Name:               fmt.Sprintf("%s query3", teamIDStr),
			Query:              "select 1;",
			Saved:              true,
			Interval:           0,
			TeamID:             teamID,
			AutomationsEnabled: false,
			DiscardData:        false,
			Logging:            mobius.LoggingSnapshot,
		})
		require.NoError(t, err)

		// Interval=0, AutomationsEnabled=0, DiscardData=1, Snapshot=0
		_, err = ds.NewQuery(context.Background(), &mobius.Query{
			Name:               fmt.Sprintf("%s query4", teamIDStr),
			Query:              "select 1;",
			Saved:              true,
			Interval:           0,
			AutomationsEnabled: false,
			TeamID:             teamID,
			DiscardData:        true,
			Logging:            mobius.LoggingDifferential,
		})
		require.NoError(t, err)

		// Interval=0, AutomationsEnabled=0, DiscardData=1, Snapshot=1
		_, err = ds.NewQuery(context.Background(), &mobius.Query{
			Name:               fmt.Sprintf("%s query5", teamIDStr),
			Query:              "select 1;",
			Saved:              true,
			Interval:           0,
			AutomationsEnabled: false,
			TeamID:             teamID,
			DiscardData:        true,
			Logging:            mobius.LoggingSnapshot,
		})
		require.NoError(t, err)

		// Interval=0, AutomationsEnabled=1, DiscardData=0, Snapshot=0
		_, err = ds.NewQuery(context.Background(), &mobius.Query{
			Name:               fmt.Sprintf("%s query6", teamIDStr),
			Query:              "select 1;",
			Saved:              true,
			Interval:           0,
			AutomationsEnabled: true,
			TeamID:             teamID,
			DiscardData:        false,
			Logging:            mobius.LoggingDifferential,
		})
		require.NoError(t, err)

		// Interval=0, AutomationsEnabled=1, DiscardData=0, Snapshot=1
		_, err = ds.NewQuery(context.Background(), &mobius.Query{
			Name:               fmt.Sprintf("%s query7", teamIDStr),
			Query:              "select 1;",
			Saved:              true,
			Interval:           0,
			AutomationsEnabled: true,
			TeamID:             teamID,
			DiscardData:        false,
			Logging:            mobius.LoggingSnapshot,
		})
		require.NoError(t, err)

		// Interval=0, AutomationsEnabled=1, DiscardData=1, Snapshot=0
		_, err = ds.NewQuery(context.Background(), &mobius.Query{
			Name:               fmt.Sprintf("%s query8", teamIDStr),
			Query:              "select 1;",
			Saved:              true,
			Interval:           0,
			AutomationsEnabled: true,
			TeamID:             teamID,
			DiscardData:        true,
			Logging:            mobius.LoggingDifferential,
		})
		require.NoError(t, err)

		// Interval=0, AutomationsEnabled=1, DiscardData=1, Snapshot=1
		_, err = ds.NewQuery(context.Background(), &mobius.Query{
			Name:               fmt.Sprintf("%s query9", teamIDStr),
			Query:              "select 1;",
			Saved:              true,
			Interval:           0,
			AutomationsEnabled: true,
			TeamID:             teamID,
			DiscardData:        true,
			Logging:            mobius.LoggingSnapshot,
		})
		require.NoError(t, err)

		// Interval=1, AutomationsEnabled=0, DiscardData=0, Snapshot=0
		_, err = ds.NewQuery(context.Background(), &mobius.Query{
			Name:               fmt.Sprintf("%s query10", teamIDStr),
			Query:              "select 1;",
			Saved:              true,
			Interval:           10,
			AutomationsEnabled: false,
			TeamID:             teamID,
			DiscardData:        false,
			Logging:            mobius.LoggingDifferentialIgnoreRemovals,
		})
		require.NoError(t, err)

		// Interval=1, AutomationsEnabled=0, DiscardData=0, Snapshot=1
		q11, err := ds.NewQuery(context.Background(), &mobius.Query{
			Name:               fmt.Sprintf("%s query11", teamIDStr),
			Query:              "select 1;",
			Saved:              true,
			Interval:           10,
			AutomationsEnabled: false,
			TeamID:             teamID,
			DiscardData:        false,
			Logging:            mobius.LoggingSnapshot,
		})
		require.NoError(t, err)

		// Interval=1, AutomationsEnabled=0, DiscardData=1, Snapshot=0
		_, err = ds.NewQuery(context.Background(), &mobius.Query{
			Name:               fmt.Sprintf("%s query12", teamIDStr),
			Query:              "select 1;",
			Saved:              true,
			Interval:           10,
			AutomationsEnabled: false,
			TeamID:             teamID,
			DiscardData:        true,
			Logging:            mobius.LoggingDifferentialIgnoreRemovals,
		})
		require.NoError(t, err)

		// Interval=1, AutomationsEnabled=0, DiscardData=1, Snapshot=1
		_, err = ds.NewQuery(context.Background(), &mobius.Query{
			Name:               fmt.Sprintf("%s query13", teamIDStr),
			Query:              "select 1;",
			Saved:              true,
			Interval:           10,
			AutomationsEnabled: false,
			TeamID:             teamID,
			DiscardData:        true,
			Logging:            mobius.LoggingSnapshot,
		})
		require.NoError(t, err)

		// Interval=1, AutomationsEnabled=1, DiscardData=0, Snapshot=0
		q14, err := ds.NewQuery(context.Background(), &mobius.Query{
			Name:               fmt.Sprintf("%s query14", teamIDStr),
			Query:              "select 1;",
			Saved:              true,
			Interval:           10,
			AutomationsEnabled: true,
			TeamID:             teamID,
			DiscardData:        false,
			Logging:            mobius.LoggingDifferential,
		})
		require.NoError(t, err)

		// Interval=1, AutomationsEnabled=1, DiscardData=0, Snapshot=1
		q15, err := ds.NewQuery(context.Background(), &mobius.Query{
			Name:               fmt.Sprintf("%s query15", teamIDStr),
			Query:              "select 1;",
			Saved:              true,
			Interval:           10,
			AutomationsEnabled: true,
			TeamID:             teamID,
			DiscardData:        false,
			Logging:            mobius.LoggingSnapshot,
		})
		require.NoError(t, err)

		// Interval=1, AutomationsEnabled=1, DiscardData=1, Snapshot=0
		q16, err := ds.NewQuery(context.Background(), &mobius.Query{
			Name:               fmt.Sprintf("%s query16", teamIDStr),
			Query:              "select 1;",
			Saved:              true,
			Interval:           10,
			AutomationsEnabled: true,
			TeamID:             teamID,
			DiscardData:        true,
			Logging:            mobius.LoggingDifferential,
		})
		require.NoError(t, err)

		// Interval=1, AutomationsEnabled=1, DiscardData=1, Snapshot=1
		q17, err := ds.NewQuery(context.Background(), &mobius.Query{
			Name:               fmt.Sprintf("%s query17", teamIDStr),
			Query:              "select 1;",
			Saved:              true,
			Interval:           10,
			AutomationsEnabled: true,
			TeamID:             teamID,
			DiscardData:        true,
			Logging:            mobius.LoggingSnapshot,
		})
		require.NoError(t, err)

		queryReportsDisabled := false
		result, err := ds.ListScheduledQueriesForAgents(ctx, teamID, nil, queryReportsDisabled)
		require.NoError(t, err)
		sort.Slice(result, func(i, j int) bool {
			return result[i].ID < result[j].ID
		})
		test.QueryElementsMatch(t, result, []*mobius.Query{q11, q14, q15, q16, q17}, i)

		queryReportsDisabled = true
		result, err = ds.ListScheduledQueriesForAgents(ctx, teamID, nil, queryReportsDisabled)
		require.NoError(t, err)
		sort.Slice(result, func(i, j int) bool {
			return result[i].ID < result[j].ID
		})
		test.QueryElementsMatch(t, result, []*mobius.Query{q14, q15, q16, q17}, i)
	}
}

func testIsSavedQuery(t *testing.T, ds *Datastore) {
	user := test.NewUser(t, ds, "Zach", "zwass@mobius.co", true)

	// NOT saved query
	query := &mobius.Query{
		Name:     "foo",
		Query:    "bar",
		AuthorID: &user.ID,
		Logging:  mobius.LoggingSnapshot,
		Saved:    false,
	}
	query, err := ds.NewQuery(context.Background(), query)
	require.NoError(t, err)
	isSaved, err := ds.IsSavedQuery(context.Background(), query.ID)
	require.NoError(t, err)
	assert.False(t, isSaved)

	// Saved query
	query = &mobius.Query{
		Name:     "foo2",
		Query:    "bar",
		AuthorID: &user.ID,
		Logging:  mobius.LoggingSnapshot,
		Saved:    true,
	}
	query, err = ds.NewQuery(context.Background(), query)
	require.NoError(t, err)
	isSaved, err = ds.IsSavedQuery(context.Background(), query.ID)
	require.NoError(t, err)
	assert.True(t, isSaved)

	// error case
	_, err = ds.IsSavedQuery(context.Background(), math.MaxUint)
	require.Error(t, err)
}

func testSaveQueryLabels(t *testing.T, ds *Datastore) {
	ctx := context.Background()

	user := test.NewUser(t, ds, "Zach", "zwass@mobius.co", true)

	label1, err := ds.NewLabel(ctx, &mobius.Label{Name: "label1"})
	require.NoError(t, err)
	label2, err := ds.NewLabel(ctx, &mobius.Label{Name: "label2"})
	require.NoError(t, err)

	// Create query with label
	query1, err := ds.NewQuery(ctx, &mobius.Query{
		Name:     "query1",
		Query:    "SELECT 1",
		AuthorID: &user.ID,
		Logging:  mobius.LoggingSnapshot,
		Saved:    true,
		LabelsIncludeAny: []mobius.LabelIdent{
			{LabelName: label1.Name},
		},
	})
	require.NoError(t, err)
	require.Len(t, query1.LabelsIncludeAny, 1)
	require.Equal(t, label1.Name, query1.LabelsIncludeAny[0].LabelName)
	require.Equal(t, label1.ID, query1.LabelsIncludeAny[0].LabelID)

	// Change the label
	query1.LabelsIncludeAny = []mobius.LabelIdent{{LabelName: label2.Name}}
	err = ds.SaveQuery(ctx, query1, true, true)
	require.NoError(t, err)
	require.Len(t, query1.LabelsIncludeAny, 1)
	require.Equal(t, label2.Name, query1.LabelsIncludeAny[0].LabelName)
	require.Equal(t, label2.ID, query1.LabelsIncludeAny[0].LabelID)

	// Two labels
	query1.LabelsIncludeAny = []mobius.LabelIdent{{LabelName: label1.Name}, {LabelName: label2.Name}}
	err = ds.SaveQuery(ctx, query1, true, true)
	require.NoError(t, err)
	require.Len(t, query1.LabelsIncludeAny, 2)
	require.Equal(t, label1.Name, query1.LabelsIncludeAny[0].LabelName)
	require.Equal(t, label1.ID, query1.LabelsIncludeAny[0].LabelID)
	require.Equal(t, label2.Name, query1.LabelsIncludeAny[1].LabelName)
	require.Equal(t, label2.ID, query1.LabelsIncludeAny[1].LabelID)

	// Remove all labels
	query1.LabelsIncludeAny = []mobius.LabelIdent{}
	err = ds.SaveQuery(ctx, query1, true, true)
	require.NoError(t, err)
	require.Len(t, query1.LabelsIncludeAny, 0)
}

func testListScheduledQueriesForAgentsWithLabels(t *testing.T, ds *Datastore) {
	requireQueries := func(t *testing.T, queries []*mobius.Query, names []string) {
		require.Len(t, queries, len(names))
		for _, name := range names {
			found := false
			for _, query := range queries {
				if name == query.Name {
					found = true
					break
				}
			}
			if !found {
				foundNames := []string{}
				for _, query := range queries {
					foundNames = append(foundNames, query.Name)
				}
				require.Truef(t, found, "failed to find query %d in list %#v", name, foundNames)
			}
		}
	}

	ctx := context.Background()

	user := test.NewUser(t, ds, "Zach", "zwass@mobius.co", true)

	label1, err := ds.NewLabel(ctx, &mobius.Label{Name: "label1"})
	require.NoError(t, err)
	label2, err := ds.NewLabel(ctx, &mobius.Label{Name: "label2"})
	require.NoError(t, err)

	hostLabel1 := test.NewHost(t, ds, "host1", "10.0.0.1", "asdf", "host1", time.Now())
	err = ds.AddLabelsToHost(ctx, hostLabel1.ID, []uint{label1.ID})
	require.NoError(t, err)

	hostLabel2 := test.NewHost(t, ds, "host2", "10.0.0.2", "asdg", "host2", time.Now())
	err = ds.AddLabelsToHost(ctx, hostLabel2.ID, []uint{label2.ID})
	require.NoError(t, err)

	hostLabel1And2 := test.NewHost(t, ds, "host3", "10.0.0.3", "asdh", "host3", time.Now())
	err = ds.AddLabelsToHost(ctx, hostLabel1And2.ID, []uint{label1.ID, label2.ID})
	require.NoError(t, err)

	hostNoLabels := test.NewHost(t, ds, "host4", "10.0.0.4", "asdj", "host4", time.Now())

	queryLabel1, err := ds.NewQuery(ctx, &mobius.Query{
		Name:               "query1",
		Query:              "SELECT 1",
		DiscardData:        false,
		AutomationsEnabled: true,
		AuthorID:           &user.ID,
		Logging:            mobius.LoggingSnapshot,
		Interval:           10,
		Saved:              true,
		LabelsIncludeAny: []mobius.LabelIdent{
			{LabelName: label1.Name},
		},
	})
	require.NoError(t, err)

	queryLabel2, err := ds.NewQuery(ctx, &mobius.Query{
		Name:               "query2",
		Query:              "SELECT 1",
		DiscardData:        false,
		AutomationsEnabled: true,
		AuthorID:           &user.ID,
		Logging:            mobius.LoggingSnapshot,
		Interval:           10,
		Saved:              true,
		LabelsIncludeAny: []mobius.LabelIdent{
			{LabelName: label2.Name},
		},
	})
	require.NoError(t, err)

	queryLabel1And2, err := ds.NewQuery(ctx, &mobius.Query{
		Name:               "query3",
		Query:              "SELECT 1",
		DiscardData:        false,
		AutomationsEnabled: true,
		AuthorID:           &user.ID,
		Logging:            mobius.LoggingSnapshot,
		Interval:           10,
		Saved:              true,
		LabelsIncludeAny: []mobius.LabelIdent{
			{LabelName: label1.Name},
			{LabelName: label2.Name},
		},
	})
	require.NoError(t, err)

	queryNoLabel, err := ds.NewQuery(ctx, &mobius.Query{
		Name:               "query4",
		Query:              "SELECT 1",
		DiscardData:        false,
		AutomationsEnabled: true,
		AuthorID:           &user.ID,
		Logging:            mobius.LoggingSnapshot,
		Interval:           10,
		Saved:              true,
	})
	require.NoError(t, err)

	// No host specified, list all queries on team, regardless of tag
	queries, err := ds.ListScheduledQueriesForAgents(ctx, nil, nil, false)
	require.NoError(t, err)
	requireQueries(t, queries, []string{queryLabel1.Name, queryLabel2.Name, queryLabel1And2.Name, queryNoLabel.Name})

	// Label 1 queries
	queries, err = ds.ListScheduledQueriesForAgents(ctx, nil, &hostLabel1.ID, false)
	require.NoError(t, err)
	requireQueries(t, queries, []string{queryLabel1.Name, queryLabel1And2.Name, queryNoLabel.Name})

	// Label 2 queries
	queries, err = ds.ListScheduledQueriesForAgents(ctx, nil, &hostLabel2.ID, false)
	require.NoError(t, err)
	requireQueries(t, queries, []string{queryLabel2.Name, queryLabel1And2.Name, queryNoLabel.Name})

	// Labels 1 and 2 queries
	queries, err = ds.ListScheduledQueriesForAgents(ctx, nil, &hostLabel1And2.ID, false)
	require.NoError(t, err)
	requireQueries(t, queries, []string{queryLabel1.Name, queryLabel2.Name, queryLabel1And2.Name, queryNoLabel.Name})

	// No label queries
	queries, err = ds.ListScheduledQueriesForAgents(ctx, nil, &hostNoLabels.ID, false)
	require.NoError(t, err)
	requireQueries(t, queries, []string{queryNoLabel.Name})
}
