package cached_mysql

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/notawar/mobius/pkg/optjson"
	"github.com/notawar/mobius/server/contexts/ctxdb"
	"github.com/notawar/mobius/server/mobius"
	"github.com/notawar/mobius/server/mock"
	"github.com/notawar/mobius/server/ptr"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/require"
)

type nilCloner struct{}

func (n *nilCloner) Clone() (mobius.Cloner, error) {
	var nn *nilCloner
	return nn, nil
}

func TestClone(t *testing.T) {
	tests := []struct {
		name string
		src  mobius.Cloner
		want mobius.Cloner
	}{
		{
			name: "appconfig",
			src: &mobius.AppConfig{
				ServerSettings: mobius.ServerSettings{
					EnableAnalytics: true,
				},
			},
			want: &mobius.AppConfig{
				ServerSettings: mobius.ServerSettings{
					EnableAnalytics: true,
				},
			},
		},
		{
			name: "nil",
			src:  (*nilCloner)(nil),
			want: (*nilCloner)(nil),
		},
		{
			name: "appconfig with nested slice",
			src: &mobius.AppConfig{
				ServerSettings: mobius.ServerSettings{
					DebugHostIDs: []uint{1, 2, 3},
				},
			},
			want: &mobius.AppConfig{
				ServerSettings: mobius.ServerSettings{
					DebugHostIDs: []uint{1, 2, 3},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clone, err := tc.src.Clone()
			require.NoError(t, err)
			require.Equal(t, tc.want, clone)

			// ensure that writing to src does not alter the cloned value (i.e. that
			// the nested fields are deeply cloned too).
			if src, ok := tc.src.(*mobius.AppConfig); ok {
				if len(src.ServerSettings.DebugHostIDs) > 0 {
					src.ServerSettings.DebugHostIDs[0] = 999
					require.NotEqual(t, src.ServerSettings.DebugHostIDs, clone.(*mobius.AppConfig).ServerSettings.DebugHostIDs)
				}
			}
		})
	}
}

func TestCachedAppConfig(t *testing.T) {
	t.Parallel()

	mockedDS := new(mock.Store)
	ds := New(mockedDS)

	var appConfigSet *mobius.AppConfig
	mockedDS.NewAppConfigFunc = func(ctx context.Context, info *mobius.AppConfig) (*mobius.AppConfig, error) {
		appConfigSet = info
		return info, nil
	}
	mockedDS.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		return appConfigSet, nil
	}
	mockedDS.SaveAppConfigFunc = func(ctx context.Context, info *mobius.AppConfig) error {
		appConfigSet = info
		return nil
	}
	_, err := ds.NewAppConfig(context.Background(), &mobius.AppConfig{
		Features: mobius.Features{
			AdditionalQueries: ptr.RawMessage(json.RawMessage(`"TestCachedAppConfig"`)),
		},
	})
	require.NoError(t, err)

	t.Run("NewAppConfig", func(t *testing.T) {
		data, err := ds.AppConfig(context.Background())
		require.NoError(t, err)

		require.NotEmpty(t, data)
		require.Equal(t, json.RawMessage(`"TestCachedAppConfig"`), *data.Features.AdditionalQueries)
	})

	t.Run("AppConfig", func(t *testing.T) {
		require.False(t, mockedDS.AppConfigFuncInvoked)
		ac, err := ds.AppConfig(context.Background())
		require.NoError(t, err)
		require.False(t, mockedDS.AppConfigFuncInvoked)

		require.Equal(t, ptr.RawMessage(json.RawMessage(`"TestCachedAppConfig"`)), ac.Features.AdditionalQueries)
	})

	t.Run("SaveAppConfig", func(t *testing.T) {
		require.NoError(t, ds.SaveAppConfig(context.Background(), &mobius.AppConfig{
			Features: mobius.Features{
				AdditionalQueries: ptr.RawMessage(json.RawMessage(`"NewSAVED"`)),
			},
		}))

		require.True(t, mockedDS.SaveAppConfigFuncInvoked)

		ac, err := ds.AppConfig(context.Background())
		require.NoError(t, err)
		require.NotNil(t, ac.Features.AdditionalQueries)
		require.Equal(t, json.RawMessage(`"NewSAVED"`), *ac.Features.AdditionalQueries)
	})

	t.Run("External SaveAppConfig gets caught", func(t *testing.T) {
		mockedDS.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
			return &mobius.AppConfig{
				Features: mobius.Features{
					AdditionalQueries: ptr.RawMessage(json.RawMessage(`"SavedSomewhereElse"`)),
				},
			}, nil
		}

		time.Sleep(2 * time.Second)

		ac, err := ds.AppConfig(context.Background())
		require.NoError(t, err)
		require.NotNil(t, ac.Features.AdditionalQueries)
		require.Equal(t, json.RawMessage(`"SavedSomewhereElse"`), *ac.Features.AdditionalQueries)
	})
}

func TestBypassAppConfig(t *testing.T) {
	t.Parallel()

	mockedDS := new(mock.Store)
	ds := New(mockedDS, WithAppConfigExpiration(time.Minute))

	var appConfigSet *mobius.AppConfig
	mockedDS.NewAppConfigFunc = func(ctx context.Context, info *mobius.AppConfig) (*mobius.AppConfig, error) {
		appConfigSet = info
		return info, nil
	}
	mockedDS.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		return appConfigSet, nil
	}
	mockedDS.SaveAppConfigFunc = func(ctx context.Context, info *mobius.AppConfig) error {
		appConfigSet = info
		return nil
	}

	// calling NewAppConfig initializes the cache
	_, err := ds.NewAppConfig(context.Background(), &mobius.AppConfig{
		OrgInfo: mobius.OrgInfo{
			OrgName: "A",
		},
	})
	require.NoError(t, err)

	ctx := context.Background()

	// used the cached value
	ac, err := ds.AppConfig(ctx)
	require.NoError(t, err)
	require.Equal(t, "A", ac.OrgInfo.OrgName)
	require.False(t, mockedDS.AppConfigFuncInvoked)

	// update and save it, calls the DB
	ac.OrgInfo.OrgName = "B"
	err = ds.SaveAppConfig(ctx, ac)
	require.NoError(t, err)
	require.True(t, mockedDS.SaveAppConfigFuncInvoked)
	mockedDS.SaveAppConfigFuncInvoked = false

	// read it back, uses the cache
	ac, err = ds.AppConfig(ctx)
	require.NoError(t, err)
	require.Equal(t, "B", ac.OrgInfo.OrgName)
	require.False(t, mockedDS.AppConfigFuncInvoked)

	// simulate a database change from another process, not via the cached_mysql store
	ac.OrgInfo.OrgName = "C"
	err = mockedDS.SaveAppConfig(ctx, ac)
	require.NoError(t, err)

	// reading it via the store uses the old cached value
	ac, err = ds.AppConfig(ctx)
	require.NoError(t, err)
	require.Equal(t, "B", ac.OrgInfo.OrgName)
	require.False(t, mockedDS.AppConfigFuncInvoked)

	// force-bypassing the cache gets the updated value
	ctx = ctxdb.BypassCachedMysql(ctx, true)
	ac, err = ds.AppConfig(ctx)
	require.NoError(t, err)
	require.Equal(t, "C", ac.OrgInfo.OrgName)
	require.True(t, mockedDS.AppConfigFuncInvoked)
	mockedDS.AppConfigFuncInvoked = false

	// bypassing the cache to read AppConfig did update the cache, so if we don't
	// bypass it anymore, it now gets the updated value from the cache
	ctx = ctxdb.BypassCachedMysql(ctx, false)
	ac, err = ds.AppConfig(ctx)
	require.NoError(t, err)
	require.Equal(t, "C", ac.OrgInfo.OrgName)
	require.False(t, mockedDS.AppConfigFuncInvoked)
}

func TestCachedPacksforHost(t *testing.T) {
	t.Parallel()

	mockedDS := new(mock.Store)
	ds := New(mockedDS, WithPacksExpiration(100*time.Millisecond))

	dbPacks := []*mobius.Pack{
		{
			ID:   1,
			Name: "test-pack-1",
		},
		{
			ID:   2,
			Name: "test-pack-2",
		},
	}
	called := 0
	mockedDS.ListPacksForHostFunc = func(ctx context.Context, hid uint) (packs []*mobius.Pack, err error) {
		called++
		return dbPacks, nil
	}

	// first call gets the result from the DB
	packs, err := ds.ListPacksForHost(context.Background(), 1)
	require.NoError(t, err)
	require.Equal(t, dbPacks, packs)
	require.Same(t, dbPacks[0], packs[0])
	require.Equal(t, 1, called)

	// change "stored" dbPacks.
	dbPacks = []*mobius.Pack{
		{
			ID:   1,
			Name: "test-pack-1",
		},
		{
			ID:   3,
			Name: "test-pack-3",
		},
	}

	// this call gets it from the cache
	packs2, err := ds.ListPacksForHost(context.Background(), 1)
	require.NoError(t, err)
	require.Equal(t, packs, packs2)         // returns the old cached value
	require.NotSame(t, packs[0], packs2[0]) // have been cloned
	require.Equal(t, 1, called)

	time.Sleep(200 * time.Millisecond)

	// this call gets it from the DB again since the cache expired
	packs3, err := ds.ListPacksForHost(context.Background(), 1)
	require.NoError(t, err)
	require.Equal(t, dbPacks, packs3)
	require.Same(t, dbPacks[0], packs3[0])
	require.Equal(t, 2, called)
}

func TestCachedListScheduledQueriesInPack(t *testing.T) {
	t.Parallel()

	mockedDS := new(mock.Store)
	ds := New(mockedDS, WithScheduledQueriesExpiration(100*time.Millisecond))

	dbScheduledQueries := mobius.ScheduledQueryList{
		{
			ID:   1,
			Name: "test-schedule-1",
		},
		{
			ID:   2,
			Name: "test-schedule-2",
		},
	}
	called := 0
	mockedDS.ListScheduledQueriesInPackFunc = func(ctx context.Context, packID uint) (mobius.ScheduledQueryList, error) {
		called++
		return dbScheduledQueries, nil
	}

	// this initial call gets the result from the DB
	scheduledQueries, err := ds.ListScheduledQueriesInPack(context.Background(), 1)
	require.NoError(t, err)
	require.Equal(t, dbScheduledQueries, scheduledQueries)
	require.Same(t, dbScheduledQueries[0], scheduledQueries[0])
	require.Equal(t, 1, called)

	// change "stored" dbScheduledQueries.
	dbScheduledQueries = mobius.ScheduledQueryList{
		{
			ID:   3,
			Name: "test-schedule-3",
		},
	}

	// this call gets it from the cache
	scheduledQueries2, err := ds.ListScheduledQueriesInPack(context.Background(), 1)
	require.NoError(t, err)
	require.Equal(t, scheduledQueries2, scheduledQueries)
	require.NotSame(t, scheduledQueries[0], scheduledQueries2[0]) // has been cloned
	require.Equal(t, 1, called)

	time.Sleep(200 * time.Millisecond)

	// this call gets it from the DB again, since the cache expired
	scheduledQueries3, err := ds.ListScheduledQueriesInPack(context.Background(), 1)
	require.NoError(t, err)
	require.Equal(t, dbScheduledQueries, scheduledQueries3)
	require.Same(t, dbScheduledQueries[0], scheduledQueries3[0])
	require.Equal(t, 2, called)
}

func TestCachedTeamAgentOptions(t *testing.T) {
	t.Parallel()

	mockedDS := new(mock.Store)
	ds := New(mockedDS, WithTeamAgentOptionsExpiration(100*time.Millisecond))

	testOptions := json.RawMessage(`
{
  "config": {
    "options": {
      "logger_plugin": "tls",
      "pack_delimiter": "/",
      "logger_tls_period": 10,
      "distributed_plugin": "tls",
      "disable_distributed": false,
      "logger_tls_endpoint": "/api/osquery/log",
      "distributed_interval": 10,
      "distributed_tls_max_attempts": 3
    },
    "decorators": {
      "load": [
        "SELECT uuid AS host_uuid FROM system_info;",
        "SELECT hostname AS hostname FROM system_info;"
      ]
    }
  },
  "overrides": {}
}
`)

	testTeam := &mobius.Team{
		ID:        1,
		CreatedAt: time.Now(),
		Name:      "test",
		Config: mobius.TeamConfig{
			AgentOptions: &testOptions,
		},
	}

	deleted := false
	mockedDS.TeamAgentOptionsFunc = func(ctx context.Context, teamID uint) (*json.RawMessage, error) {
		if deleted {
			return nil, errors.New("not found")
		}
		return &testOptions, nil
	}
	mockedDS.SaveTeamFunc = func(ctx context.Context, team *mobius.Team) (*mobius.Team, error) {
		return team, nil
	}
	mockedDS.DeleteTeamFunc = func(ctx context.Context, teamID uint) error {
		deleted = true
		return nil
	}

	// initial call reads from the DB
	options, err := ds.TeamAgentOptions(context.Background(), 1)
	require.NoError(t, err)
	require.JSONEq(t, string(testOptions), string(*options))
	require.Same(t, &testOptions, options)
	require.True(t, mockedDS.TeamAgentOptionsFuncInvoked)
	mockedDS.TeamAgentOptionsFuncInvoked = false

	// subsequent call reads from the cache
	options, err = ds.TeamAgentOptions(context.Background(), 1)
	require.NoError(t, err)
	require.JSONEq(t, string(testOptions), string(*options))
	require.NotSame(t, &testOptions, options)
	require.False(t, mockedDS.TeamAgentOptionsFuncInvoked)

	// saving a team updates agent options in cache
	updateOptions := json.RawMessage(`
{}
`)
	updateTeam := &mobius.Team{
		ID:        testTeam.ID,
		CreatedAt: testTeam.CreatedAt,
		Name:      testTeam.Name,
		Config: mobius.TeamConfig{
			AgentOptions: &updateOptions,
		},
	}

	_, err = ds.SaveTeam(context.Background(), updateTeam)
	require.NoError(t, err)
	require.True(t, mockedDS.SaveTeamFuncInvoked)
	mockedDS.SaveTeamFuncInvoked = false

	// reading reads it from the cache with the updated data
	options, err = ds.TeamAgentOptions(context.Background(), testTeam.ID)
	require.NoError(t, err)
	require.JSONEq(t, string(updateOptions), string(*options))
	require.NotSame(t, &updateOptions, options)
	require.False(t, mockedDS.TeamAgentOptionsFuncInvoked)

	// deleting a team removes the agent options from the cache
	err = ds.DeleteTeam(context.Background(), testTeam.ID)
	require.NoError(t, err)
	require.True(t, mockedDS.DeleteTeamFuncInvoked)
	mockedDS.DeleteTeamFuncInvoked = false

	// reading hits the DB as the cached item was removed
	_, err = ds.TeamAgentOptions(context.Background(), testTeam.ID)
	require.Error(t, err)
	require.True(t, mockedDS.TeamAgentOptionsFuncInvoked)
}

func TestCachedTeamFeatures(t *testing.T) {
	t.Parallel()

	mockedDS := new(mock.Store)
	ds := New(mockedDS, WithTeamFeaturesExpiration(100*time.Millisecond))

	ao := json.RawMessage(`{}`)
	aq := json.RawMessage(`{"foo": "bar"}`)
	testFeatures := mobius.Features{
		EnableHostUsers:         false,
		EnableSoftwareInventory: true,
		AdditionalQueries:       &aq,
		DetailQueryOverrides:    map[string]*string{"a": ptr.String("A"), "b": ptr.String("B")},
	}

	testTeam := mobius.Team{
		ID:        1,
		CreatedAt: time.Now(),
		Name:      "test",
		Config: mobius.TeamConfig{
			Features:     testFeatures,
			AgentOptions: &ao,
		},
	}

	deleted := false
	mockedDS.TeamFeaturesFunc = func(ctx context.Context, teamID uint) (*mobius.Features, error) {
		if deleted {
			return nil, errors.New("not found")
		}
		return &testFeatures, nil
	}
	mockedDS.SaveTeamFunc = func(ctx context.Context, team *mobius.Team) (*mobius.Team, error) {
		return team, nil
	}
	mockedDS.DeleteTeamFunc = func(ctx context.Context, teamID uint) error {
		deleted = true
		return nil
	}

	// get it the first time, it will populate the cache
	features, err := ds.TeamFeatures(context.Background(), 1)
	require.NoError(t, err)
	require.Equal(t, testFeatures, *features)
	require.Same(t, &testFeatures, features)
	require.True(t, mockedDS.TeamFeaturesFuncInvoked)
	mockedDS.TeamFeaturesFuncInvoked = false

	// get it again, will retrieve it from the cache
	features, err = ds.TeamFeatures(context.Background(), 1)
	require.NoError(t, err)
	require.Equal(t, testFeatures, *features)
	require.NotSame(t, &testFeatures, features)
	require.False(t, mockedDS.TeamFeaturesFuncInvoked)

	// changing e.g. the DetailQueryOverrides map doesn't affect the stored value
	ptrA := features.DetailQueryOverrides["a"]
	*ptrA = "AAA"
	features.DetailQueryOverrides["c"] = ptr.String("C")
	require.NotEqual(t, testFeatures.DetailQueryOverrides, features.DetailQueryOverrides)

	// saving a team updates features in cache
	aq = json.RawMessage(`{"bar": "baz"}`)
	updateFeatures := mobius.Features{
		EnableHostUsers:         true,
		EnableSoftwareInventory: false,
		AdditionalQueries:       &aq,
		DetailQueryOverrides:    map[string]*string{"c": ptr.String("C")},
	}
	updateTeam := &mobius.Team{
		ID:        testTeam.ID,
		CreatedAt: testTeam.CreatedAt,
		Name:      testTeam.Name,
		Config: mobius.TeamConfig{
			Features:     updateFeatures,
			AgentOptions: &ao,
		},
	}

	_, err = ds.SaveTeam(context.Background(), updateTeam)
	require.NoError(t, err)
	require.True(t, mockedDS.SaveTeamFuncInvoked)
	mockedDS.SaveTeamFuncInvoked = false

	// this call gets it from the cache and gets the updated value set by SaveTeam
	features, err = ds.TeamFeatures(context.Background(), testTeam.ID)
	require.NoError(t, err)
	require.Equal(t, updateFeatures, *features)
	require.NotSame(t, &updateFeatures, features)
	require.False(t, mockedDS.TeamFeaturesFuncInvoked)

	// deleting a team removes the features from the cache
	err = ds.DeleteTeam(context.Background(), testTeam.ID)
	require.NoError(t, err)

	// reading hits the DB as the cached item was removed
	_, err = ds.TeamFeatures(context.Background(), testTeam.ID)
	require.Error(t, err)
	require.True(t, mockedDS.TeamFeaturesFuncInvoked)
}

func TestCachedTeamMDMConfig(t *testing.T) {
	t.Parallel()

	mockedDS := new(mock.Store)
	ds := New(mockedDS, WithTeamMDMConfigExpiration(100*time.Millisecond))
	ao := json.RawMessage(`{}`)

	testMDMConfig := mobius.TeamMDM{
		EnableDiskEncryption: true,
		MacOSUpdates: mobius.AppleOSUpdateSettings{
			MinimumVersion: optjson.SetString("10.10.10"),
			Deadline:       optjson.SetString("1992-03-01"),
		},
		MacOSSettings: mobius.MacOSSettings{
			CustomSettings:                 []mobius.MDMProfileSpec{{Path: "a"}, {Path: "b"}},
			DeprecatedEnableDiskEncryption: ptr.Bool(false),
		},
		MacOSSetup: mobius.MacOSSetup{
			BootstrapPackage: optjson.SetString("bootstrap"),
		},
	}

	testTeam := mobius.Team{
		ID:        1,
		CreatedAt: time.Now(),
		Name:      "test",
		Config: mobius.TeamConfig{
			MDM:          testMDMConfig,
			AgentOptions: &ao,
		},
	}

	deleted := false
	mockedDS.TeamMDMConfigFunc = func(ctx context.Context, teamID uint) (*mobius.TeamMDM, error) {
		if deleted {
			return nil, errors.New("not found")
		}
		return &testMDMConfig, nil
	}
	mockedDS.SaveTeamFunc = func(ctx context.Context, team *mobius.Team) (*mobius.Team, error) {
		return team, nil
	}
	mockedDS.DeleteTeamFunc = func(ctx context.Context, teamID uint) error {
		deleted = true
		return nil
	}

	// get the team's config, will load it into cache
	mdmConfig, err := ds.TeamMDMConfig(context.Background(), 1)
	require.NoError(t, err)
	require.Equal(t, testMDMConfig, *mdmConfig)
	require.Same(t, &testMDMConfig, mdmConfig)
	require.True(t, mockedDS.TeamMDMConfigFuncInvoked)
	mockedDS.TeamMDMConfigFuncInvoked = false

	// get it again, will get it from cache
	mdmConfig, err = ds.TeamMDMConfig(context.Background(), 1)
	require.NoError(t, err)
	require.Equal(t, testMDMConfig, *mdmConfig)
	require.NotSame(t, &testMDMConfig, mdmConfig)
	require.False(t, mockedDS.TeamMDMConfigFuncInvoked)

	// changing some deep value doesn't affect the stored value
	mdmConfig.MacOSSettings.CustomSettings[0] = mobius.MDMProfileSpec{Path: "c"}
	require.NotEqual(t, testMDMConfig, *mdmConfig)

	// saving a team updates config in cache
	updateMDMConfig := mobius.TeamMDM{
		MacOSUpdates: mobius.AppleOSUpdateSettings{
			MinimumVersion: optjson.SetString("13.13.13"),
			Deadline:       optjson.SetString("2022-03-01"),
		},
		MacOSSettings: mobius.MacOSSettings{
			CustomSettings:                 nil,
			DeprecatedEnableDiskEncryption: ptr.Bool(true),
		},
	}
	updateTeam := &mobius.Team{
		ID:        testTeam.ID,
		CreatedAt: testTeam.CreatedAt,
		Name:      testTeam.Name,
		Config: mobius.TeamConfig{
			MDM:          updateMDMConfig,
			AgentOptions: &ao,
		},
	}

	_, err = ds.SaveTeam(context.Background(), updateTeam)
	require.NoError(t, err)
	require.True(t, mockedDS.SaveTeamFuncInvoked)
	mockedDS.SaveTeamFuncInvoked = false

	// this call gets it from the cache, with the updated value set by SaveTeam
	mdmConfig, err = ds.TeamMDMConfig(context.Background(), testTeam.ID)
	require.NoError(t, err)
	require.Equal(t, updateMDMConfig, *mdmConfig)
	require.NotSame(t, &updateMDMConfig, mdmConfig)
	require.False(t, mockedDS.TeamMDMConfigFuncInvoked)

	// deleting a team removes the config from the cache
	err = ds.DeleteTeam(context.Background(), testTeam.ID)
	require.NoError(t, err)

	// reading hits the DB as the cached item was removed
	_, err = ds.TeamMDMConfig(context.Background(), testTeam.ID)
	require.Error(t, err)
	require.True(t, mockedDS.TeamMDMConfigFuncInvoked)
}

func TestCachedQueryByName(t *testing.T) {
	t.Parallel()

	mockedDS := new(mock.Store)
	ds := New(mockedDS, WithQueryByNameExpiration(100*time.Millisecond))

	testQuery := &mobius.Query{
		ID:     1,
		TeamID: ptr.Uint(1),
		Packs:  []mobius.Pack{{ID: 2, Name: "a"}},
	}
	mockedDS.QueryByNameFunc = func(ctx context.Context, teamID *uint, name string) (*mobius.Query, error) {
		return testQuery, nil
	}

	// first call gets the result from the DB
	query1, err := ds.QueryByName(context.Background(), nil, "q")
	require.NoError(t, err)
	require.Equal(t, testQuery, query1)
	require.Same(t, testQuery, query1)
	require.True(t, mockedDS.QueryByNameFuncInvoked)
	mockedDS.QueryByNameFuncInvoked = false

	// change "stored" query.
	testQuery = &mobius.Query{
		ID:     1,
		TeamID: ptr.Uint(2),
		Packs:  []mobius.Pack{{ID: 3, Name: "b"}},
	}

	// this call gets it from the cache
	query2, err := ds.QueryByName(context.Background(), nil, "q")
	require.NoError(t, err)
	require.Equal(t, query1, query2)   // returns the old cached value
	require.NotSame(t, query1, query2) // have been cloned
	require.False(t, mockedDS.QueryByNameFuncInvoked)

	// a deep change doesn't alter the stored value
	query2.Packs[0].Name = "Z"
	require.NotEqual(t, query1, query2)

	time.Sleep(200 * time.Millisecond)

	// this call gets it from the DB again since the cache expired
	query3, err := ds.QueryByName(context.Background(), nil, "q")
	require.NoError(t, err)
	require.Equal(t, testQuery, query3)
	require.Same(t, testQuery, query3)
	require.True(t, mockedDS.QueryByNameFuncInvoked)
}

func TestCachedResultCountForQuery(t *testing.T) {
	t.Parallel()

	mockedDS := new(mock.Store)
	ds := New(mockedDS, WithQueryResultsCountExpiration(100*time.Millisecond))

	testCount := 1
	mockedDS.ResultCountForQueryFunc = func(ctx context.Context, queryID uint) (int, error) {
		return testCount, nil
	}

	// first call gets the result from the DB
	c1, err := ds.ResultCountForQuery(context.Background(), 1)
	require.NoError(t, err)
	require.Equal(t, testCount, c1)
	require.True(t, mockedDS.ResultCountForQueryFuncInvoked)
	mockedDS.ResultCountForQueryFuncInvoked = false

	// change "stored" count.
	testCount = 2

	// this call gets it from the cache
	c2, err := ds.ResultCountForQuery(context.Background(), 1)
	require.NoError(t, err)
	require.Equal(t, c1, c2) // returns the old cached value
	require.False(t, mockedDS.ResultCountForQueryFuncInvoked)

	time.Sleep(200 * time.Millisecond)

	// this call gets it from the DB again since the cache expired
	c3, err := ds.ResultCountForQuery(context.Background(), 1)
	require.NoError(t, err)
	require.Equal(t, testCount, c3)
	require.True(t, mockedDS.ResultCountForQueryFuncInvoked)
}

func TestGetAllMDMConfigAssetsByName(t *testing.T) {
	t.Parallel()

	mockedDS := new(mock.Store)
	ds := New(mockedDS)

	assetNames := []mobius.MDMAssetName{"asset1", "asset2", "asset3"}
	assetMap := map[mobius.MDMAssetName]mobius.MDMConfigAsset{
		"asset1": {Name: "asset1", Value: []byte("value1")},
		"asset2": {Name: "asset2", Value: []byte("value2")},
		"asset3": {Name: "asset2", Value: []byte("value3")},
	}
	assetHashes := map[mobius.MDMAssetName]string{
		"asset1": "hash1",
		"asset2": "hash2",
		"asset3": "hash3",
	}

	mockedDS.GetAllMDMConfigAssetsHashesFunc = func(ctx context.Context, assetNames []mobius.MDMAssetName) (map[mobius.MDMAssetName]string, error) {
		result := map[mobius.MDMAssetName]string{}
		for _, n := range assetNames {
			result[n] = assetHashes[n]
		}
		return result, nil
	}

	mockedDS.GetAllMDMConfigAssetsByNameFunc = func(ctx context.Context, assetNames []mobius.MDMAssetName,
		_ sqlx.QueryerContext) (map[mobius.MDMAssetName]mobius.MDMConfigAsset, error) {
		result := map[mobius.MDMAssetName]mobius.MDMConfigAsset{}
		for _, n := range assetNames {
			result[n] = assetMap[n]
		}
		return result, nil
	}

	// returns cached assets if hashes match
	result, err := ds.GetAllMDMConfigAssetsByName(context.Background(), []mobius.MDMAssetName{"asset1", "asset2"}, nil)
	require.NoError(t, err)

	require.True(t, mockedDS.GetAllMDMConfigAssetsByNameFuncInvoked)
	require.True(t, mockedDS.GetAllMDMConfigAssetsHashesFuncInvoked)
	mockedDS.GetAllMDMConfigAssetsByNameFuncInvoked = false
	mockedDS.GetAllMDMConfigAssetsHashesFuncInvoked = false
	require.Equal(t, assetMap["asset1"], result["asset1"])
	require.Equal(t, assetMap["asset2"], result["asset2"])
	require.NotContains(t, result, "asset3")

	result, err = ds.GetAllMDMConfigAssetsByName(context.Background(), []mobius.MDMAssetName{"asset1", "asset2"}, nil)
	require.NoError(t, err)
	require.False(t, mockedDS.GetAllMDMConfigAssetsByNameFuncInvoked)
	require.True(t, mockedDS.GetAllMDMConfigAssetsHashesFuncInvoked)
	mockedDS.GetAllMDMConfigAssetsByNameFuncInvoked = false
	mockedDS.GetAllMDMConfigAssetsHashesFuncInvoked = false
	require.Equal(t, assetMap["asset1"], result["asset1"])
	require.Equal(t, assetMap["asset2"], result["asset2"])
	require.NotContains(t, result, "asset3")
	mockedDS.GetAllMDMConfigAssetsByNameFuncInvoked = false
	mockedDS.GetAllMDMConfigAssetsHashesFuncInvoked = false

	// fetches missing assets from the db
	result, err = ds.GetAllMDMConfigAssetsByName(context.Background(), []mobius.MDMAssetName{"asset1", "asset2", "asset3"}, nil)
	require.NoError(t, err)
	require.Equal(t, assetMap["asset1"], result["asset1"])
	require.Equal(t, assetMap["asset2"], result["asset2"])
	require.Equal(t, assetMap["asset3"], result["asset3"])
	require.True(t, mockedDS.GetAllMDMConfigAssetsByNameFuncInvoked)
	require.True(t, mockedDS.GetAllMDMConfigAssetsHashesFuncInvoked)
	mockedDS.GetAllMDMConfigAssetsByNameFuncInvoked = false
	mockedDS.GetAllMDMConfigAssetsHashesFuncInvoked = false

	// fetches updated assets from the db
	assetHashes["asset1"] = "newhash"
	assetMap["asset1"] = mobius.MDMConfigAsset{Name: "asset1", Value: []byte("newvalue")}
	result, err = ds.GetAllMDMConfigAssetsByName(context.Background(), assetNames, nil)
	require.NoError(t, err)
	require.Equal(t, assetMap["asset1"], result["asset1"])
	require.Equal(t, assetMap["asset2"], result["asset2"])
	require.Equal(t, assetMap["asset3"], result["asset3"])
	require.True(t, mockedDS.GetAllMDMConfigAssetsByNameFuncInvoked)
	require.True(t, mockedDS.GetAllMDMConfigAssetsHashesFuncInvoked)
	mockedDS.GetAllMDMConfigAssetsByNameFuncInvoked = false
	mockedDS.GetAllMDMConfigAssetsHashesFuncInvoked = false

	// passes errors fetching assets from downstream
	mockedDS.GetAllMDMConfigAssetsByNameFunc = func(ctx context.Context, assetNames []mobius.MDMAssetName,
		_ sqlx.QueryerContext) (map[mobius.MDMAssetName]mobius.MDMConfigAsset, error) {
		return nil, errors.New("error fetching assets")
	}

	_, err = ds.GetAllMDMConfigAssetsByName(context.Background(), []mobius.MDMAssetName{"not exists"}, nil)
	require.Error(t, err)
	require.Equal(t, "error fetching assets", err.Error())

	// passes errors fetching hashes from downstream
	mockedDS.GetAllMDMConfigAssetsHashesFunc = func(ctx context.Context, assetNames []mobius.MDMAssetName) (map[mobius.MDMAssetName]string, error) {
		return nil, errors.New("error fetching hashes")
	}

	_, err = ds.GetAllMDMConfigAssetsByName(context.Background(), []mobius.MDMAssetName{"not exists"}, nil)
	require.Error(t, err)
	require.Equal(t, "error fetching hashes", err.Error())
}
