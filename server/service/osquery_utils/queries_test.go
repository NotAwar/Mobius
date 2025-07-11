package osquery_utils

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/notawar/mobius/server/datastore/mysql/common_mysql"

	"github.com/WatchBeam/clock"
	"github.com/notawar/mobius/server/config"
	"github.com/notawar/mobius/server/contexts/publicip"
	"github.com/notawar/mobius/server/mobius"
	apple_mdm "github.com/notawar/mobius/server/mdm/apple"
	"github.com/notawar/mobius/server/mdm/microsoft/syncml"
	"github.com/notawar/mobius/server/mock"
	"github.com/notawar/mobius/server/ptr"
	"github.com/notawar/mobius/server/service/async"
	"github.com/go-kit/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/maps"
)

func TestDetailQueryNetworkInterfaces(t *testing.T) {
	var initialHost mobius.Host
	host := initialHost

	ingest := GetDetailQueries(context.Background(), config.MobiusConfig{}, nil, nil, Integrations{})["network_interface_unix"].IngestFunc

	assert.NoError(t, ingest(context.Background(), log.NewNopLogger(), &host, nil))
	assert.Equal(t, initialHost, host)

	var rows []map[string]string
	require.NoError(t, json.Unmarshal([]byte(`
[
  {"address":"10.0.1.2","mac":"bc:d0:74:4b:10:6d"}
]`),
		&rows,
	))

	assert.NoError(t, ingest(context.Background(), log.NewNopLogger(), &host, rows))
	assert.Equal(t, "10.0.1.2", host.PrimaryIP)
	assert.Equal(t, "bc:d0:74:4b:10:6d", host.PrimaryMac)

	rows = make([]map[string]string, 1)
	require.NoError(
		t, json.Unmarshal(
			[]byte(`
[
  {"address":"fd7a:115c:a1e0::d401:6637","mac":"b2:a2:e4:62:0f:1e"}
]`),
			&rows,
		),
	)
	assert.NoError(t, ingest(context.Background(), log.NewNopLogger(), &host, rows))
	assert.Equal(t, "fd7a:115c:a1e0::d401:6637", host.PrimaryIP)
	assert.Equal(t, "b2:a2:e4:62:0f:1e", host.PrimaryMac)
}

func TestDetailQueryScheduledQueryStats(t *testing.T) {
	host := mobius.Host{ID: 1}
	ds := new(mock.Store)
	task := async.NewTask(ds, nil, clock.C, config.OsqueryConfig{EnableAsyncHostProcessing: "false"})

	var gotPackStats []mobius.PackStats
	ds.SaveHostPackStatsFunc = func(ctx context.Context, teamID *uint, hostID uint, stats []mobius.PackStats) error {
		if hostID != host.ID {
			return errors.New("not found")
		}
		gotPackStats = stats
		return nil
	}

	ingest := GetDetailQueries(context.Background(), config.MobiusConfig{App: config.AppConfig{EnableScheduledQueryStats: true}}, nil, nil, Integrations{})["scheduled_query_stats"].DirectTaskIngestFunc

	ctx := context.Background()
	assert.NoError(t, ingest(ctx, log.NewNopLogger(), &host, task, nil))
	assert.Len(t, host.PackStats, 0)

	resJSON := `
[
  {
    "average_memory":"33",
    "delimiter":"/",
    "denylisted":"0",
    "executions":"1",
    "interval":"33",
    "last_executed":"1620325191",
    "name":"pack/pack-2/time",
    "output_size":"",
    "query":"SELECT * FROM time",
    "system_time":"100",
    "user_time":"60",
    "wall_time":"180"
  },
  {
    "average_memory":"8000",
    "delimiter":"/",
    "denylisted":"0",
    "executions":"164",
    "interval":"30",
    "last_executed":"1620325191",
    "name":"pack/test/osquery info",
    "output_size":"1337",
    "query":"SELECT * FROM osquery_info",
    "system_time":"150",
    "user_time":"180",
    "wall_time_ms":"0"
  },
  {
    "average_memory":"50400",
    "delimiter":"/",
    "denylisted":"1",
    "executions":"188",
    "interval":"30",
    "last_executed":"1620325203",
    "name":"pack/test/processes?",
    "output_size":"",
    "query":"SELECT * FROM processes",
    "system_time":"140",
    "user_time":"190",
    "wall_time":"1111",
    "wall_time_ms":"1"
  },
  {
    "average_memory":"0",
    "delimiter":"/",
    "denylisted":"0",
    "executions":"1",
    "interval":"3600",
    "last_executed":"1620323381",
    "name":"pack/test/processes?-1",
    "output_size":"",
    "query":"SELECT * FROM processes",
    "system_time":"0",
    "user_time":"0",
    "wall_time_ms":"0"
  },
  {
    "average_memory":"0",
    "delimiter":"/",
    "denylisted":"0",
    "executions":"105",
    "interval":"47",
    "last_executed":"1620325190",
    "name":"pack/test/time",
    "output_size":"",
    "query":"SELECT * FROM time",
    "system_time":"70",
    "user_time":"50",
    "wall_time_ms":"1"
  }
]
`

	var rows []map[string]string
	require.NoError(t, json.Unmarshal([]byte(resJSON), &rows))

	assert.NoError(t, ingest(ctx, log.NewNopLogger(), &host, task, rows))
	assert.Len(t, gotPackStats, 2)
	sort.Slice(gotPackStats, func(i, j int) bool {
		return gotPackStats[i].PackName < gotPackStats[j].PackName
	})
	assert.Equal(t, gotPackStats[0].PackName, "pack-2")
	assert.ElementsMatch(t, gotPackStats[0].QueryStats,
		[]mobius.ScheduledQueryStats{
			{
				ScheduledQueryName: "time",
				PackName:           "pack-2",
				AverageMemory:      33,
				Denylisted:         false,
				Executions:         1,
				Interval:           33,
				LastExecuted:       time.Unix(1620325191, 0).UTC(),
				OutputSize:         0,
				SystemTime:         100,
				UserTime:           60,
				WallTimeMs:         180 * 1000,
			},
		},
	)
	assert.Equal(t, gotPackStats[1].PackName, "test")
	assert.ElementsMatch(t, gotPackStats[1].QueryStats,
		[]mobius.ScheduledQueryStats{
			{
				ScheduledQueryName: "osquery info",
				PackName:           "test",
				AverageMemory:      8000,
				Denylisted:         false,
				Executions:         164,
				Interval:           30,
				LastExecuted:       time.Unix(1620325191, 0).UTC(),
				OutputSize:         1337,
				SystemTime:         150,
				UserTime:           180,
				WallTimeMs:         0,
			},
			{
				ScheduledQueryName: "processes?",
				PackName:           "test",
				AverageMemory:      50400,
				Denylisted:         true,
				Executions:         188,
				Interval:           30,
				LastExecuted:       time.Unix(1620325203, 0).UTC(),
				OutputSize:         0,
				SystemTime:         140,
				UserTime:           190,
				WallTimeMs:         1,
			},
			{
				ScheduledQueryName: "processes?-1",
				PackName:           "test",
				AverageMemory:      0,
				Denylisted:         false,
				Executions:         1,
				Interval:           3600,
				LastExecuted:       time.Unix(1620323381, 0).UTC(),
				OutputSize:         0,
				SystemTime:         0,
				UserTime:           0,
				WallTimeMs:         0,
			},
			{
				ScheduledQueryName: "time",
				PackName:           "test",
				AverageMemory:      0,
				Denylisted:         false,
				Executions:         105,
				Interval:           47,
				LastExecuted:       time.Unix(1620325190, 0).UTC(),
				OutputSize:         0,
				SystemTime:         70,
				UserTime:           50,
				WallTimeMs:         1,
			},
		},
	)

	assert.NoError(t, ingest(ctx, log.NewNopLogger(), &host, task, nil))
	assert.Len(t, gotPackStats, 0)
}

func sortedKeysCompare(t *testing.T, m map[string]DetailQuery, expectedKeys []string) {
	var keys []string
	for key := range m {
		keys = append(keys, key)
	}
	assert.ElementsMatch(t, keys, expectedKeys)
}

func TestGetDetailQueries(t *testing.T) {
	queriesNoConfig := GetDetailQueries(context.Background(), config.MobiusConfig{}, nil, nil, Integrations{})

	baseQueries := []string{
		"network_interface_unix",
		"network_interface_windows",
		"network_interface_chrome",
		"os_version",
		"os_version_windows",
		"osquery_flags",
		"osquery_info",
		"system_info",
		"uptime",
		"disk_space_unix",
		"disk_space_windows",
		"mdm",
		"mdm_windows",
		"munki_info",
		"google_chrome_profiles",
		"battery",
		"os_windows",
		"os_unix_like",
		"os_chrome",
		"windows_update_history",
		"kubequery_info",
		"orbit_info",
		"disk_encryption_darwin",
		"disk_encryption_linux",
		"disk_encryption_windows",
		"chromeos_profile_user_info",
		"certificates_darwin",
	}

	require.Len(t, queriesNoConfig, len(baseQueries))
	sortedKeysCompare(t, queriesNoConfig, baseQueries)

	queriesWithoutWinOSVuln := GetDetailQueries(context.Background(), config.MobiusConfig{Vulnerabilities: config.VulnerabilitiesConfig{DisableWinOSVulnerabilities: true}}, nil, nil, Integrations{})
	require.Len(t, queriesWithoutWinOSVuln, 26)

	queriesWithUsers := GetDetailQueries(context.Background(), config.MobiusConfig{App: config.AppConfig{EnableScheduledQueryStats: true}}, nil, &mobius.Features{EnableHostUsers: true}, Integrations{})
	qs := baseQueries
	qs = append(qs, "users", "users_chrome", "scheduled_query_stats")
	require.Len(t, queriesWithUsers, len(qs))
	sortedKeysCompare(t, queriesWithUsers, qs)

	queriesWithUsersAndSoftware := GetDetailQueries(context.Background(), config.MobiusConfig{App: config.AppConfig{EnableScheduledQueryStats: true}}, nil, &mobius.Features{EnableHostUsers: true, EnableSoftwareInventory: true}, Integrations{})
	qs = baseQueries
	qs = append(qs, "users", "users_chrome", "software_macos", "software_linux", "software_windows", "software_vscode_extensions",
		"software_chrome", "software_python_packages", "software_python_packages_with_users_dir", "scheduled_query_stats", "software_macos_firefox", "software_macos_codesign")
	require.Len(t, queriesWithUsersAndSoftware, len(qs))
	sortedKeysCompare(t, queriesWithUsersAndSoftware, qs)

	// test that appropriate mdm queries are added based on app config
	var mdmQueriesBase, mdmQueriesWindows []string
	for k, q := range mdmQueries {
		switch {
		case slices.Equal(q.Platforms, []string{"windows"}):
			mdmQueriesWindows = append(mdmQueriesWindows, k)
		default:
			mdmQueriesBase = append(mdmQueriesBase, k)
		}
	}
	ac := mobius.AppConfig{}
	ac.MDM.EnabledAndConfigured = true
	// windows mdm is disabled by default, windows mdm queries should not be present
	gotQueries := GetDetailQueries(context.Background(), config.MobiusConfig{}, &ac, nil, Integrations{})
	wantQueries := baseQueries
	wantQueries = append(wantQueries, mdmQueriesBase...)
	require.Len(t, gotQueries, len(wantQueries))
	sortedKeysCompare(t, gotQueries, wantQueries)
	// enable windows mdm, windows mdm queries should be present
	ac.MDM.WindowsEnabledAndConfigured = true
	gotQueries = GetDetailQueries(context.Background(), config.MobiusConfig{}, &ac, nil, Integrations{})
	wantQueries = append(wantQueries, mdmQueriesWindows...)
	require.Len(t, gotQueries, len(wantQueries))
	sortedKeysCompare(t, gotQueries, wantQueries)
}

func TestDetailQueriesOSVersionUnixLike(t *testing.T) {
	var initialHost mobius.Host
	host := initialHost

	ingest := GetDetailQueries(context.Background(), config.MobiusConfig{}, nil, nil, Integrations{})["os_version"].IngestFunc

	assert.NoError(t, ingest(context.Background(), log.NewNopLogger(), &host, nil))
	assert.Equal(t, initialHost, host)

	// Rolling release for archlinux
	var rows []map[string]string
	require.NoError(t, json.Unmarshal([]byte(`
[{
    "hostname": "kube2",
    "arch": "x86_64",
    "build": "rolling",
    "codename": "",
    "major": "0",
    "minor": "0",
    "name": "Arch Linux",
    "patch": "0",
    "platform": "arch",
    "platform_like": "",
    "version": ""
}]`),
		&rows,
	))

	assert.NoError(t, ingest(context.Background(), log.NewNopLogger(), &host, rows))
	assert.Equal(t, "Arch Linux rolling", host.OSVersion)

	// Simulate a linux with a proper version
	require.NoError(t, json.Unmarshal([]byte(`
[{
    "hostname": "kube2",
    "arch": "x86_64",
    "build": "rolling",
    "codename": "",
    "major": "1",
    "minor": "2",
    "name": "Arch Linux",
    "patch": "3",
    "platform": "arch",
    "platform_like": "",
    "version": ""
}]`),
		&rows,
	))

	assert.NoError(t, ingest(context.Background(), log.NewNopLogger(), &host, rows))
	assert.Equal(t, "Arch Linux 1.2.3", host.OSVersion)

	// Simulate Ubuntu host with incorrect `patch` number
	require.NoError(t, json.Unmarshal([]byte(`
[{
    "hostname": "kube2",
    "arch": "x86_64",
    "build": "",
    "codename": "bionic",
    "major": "18",
    "minor": "4",
    "name": "Ubuntu",
    "patch": "0",
    "platform": "ubuntu",
    "platform_like": "debian",
    "version": "18.04.5 LTS (Bionic Beaver)"
}]`),
		&rows,
	))

	assert.NoError(t, ingest(context.Background(), log.NewNopLogger(), &host, rows))
	assert.Equal(t, "Ubuntu 18.04.5 LTS", host.OSVersion)
}

func TestDetailQueriesOSVersionWindows(t *testing.T) {
	var initialHost mobius.Host
	host := initialHost

	ingest := GetDetailQueries(context.Background(), config.MobiusConfig{}, nil, nil, Integrations{})["os_version_windows"].IngestFunc

	assert.NoError(t, ingest(context.Background(), log.NewNopLogger(), &host, nil))
	assert.Equal(t, initialHost, host)

	var rows []map[string]string
	require.NoError(t, json.Unmarshal([]byte(`
[{
    "hostname": "WinBox",
    "arch": "64-bit",
    "build": "22000",
    "codename": "Microsoft Windows 11 Enterprise",
    "major": "10",
    "minor": "0",
    "name": "Microsoft Windows 11 Enterprise",
    "patch": "",
    "platform": "windows",
    "platform_like": "windows",
    "version": "10.0.22000",
	"display_version": "21H2",
	"release_id": ""
}]`),
		&rows,
	))

	assert.NoError(t, ingest(context.Background(), log.NewNopLogger(), &host, rows))
	assert.Equal(t, "Windows 11 Enterprise 21H2 10.0.22000", host.OSVersion)

	require.NoError(t, json.Unmarshal([]byte(`
[{
    "hostname": "WinBox",
    "arch": "64-bit",
    "build": "17763",
    "codename": "Microsoft Windows 10 Enterprise LTSC",
    "major": "10",
    "minor": "0",
    "name": "Microsoft Windows 10 Enterprise LTSC",
    "patch": "",
    "platform": "windows",
    "platform_like": "windows",
    "version": "10.0.17763",
	"display_version": "",
	"release_id": "1809"
}]`),
		&rows,
	))

	assert.NoError(t, ingest(context.Background(), log.NewNopLogger(), &host, rows))
	assert.Equal(t, "Windows 10 Enterprise LTSC 10.0.17763", host.OSVersion)
}

func TestDetailQueriesOSVersionChrome(t *testing.T) {
	var initialHost mobius.Host
	host := initialHost

	ingest := GetDetailQueries(context.Background(), config.MobiusConfig{}, nil, nil, Integrations{})["os_version"].IngestFunc

	assert.NoError(t, ingest(context.Background(), log.NewNopLogger(), &host, nil))
	assert.Equal(t, initialHost, host)

	var rows []map[string]string
	require.NoError(t, json.Unmarshal([]byte(`
[{
    "hostname": "chromeo",
    "arch": "x86_64",
    "build": "chrome-build",
    "codename": "",
    "major": "1",
    "minor": "3",
    "name": "chromeos",
    "patch": "7",
    "platform": "chrome",
    "platform_like": "chrome",
    "version": "1.3.3.7"
}]`),
		&rows,
	))

	assert.NoError(t, ingest(context.Background(), log.NewNopLogger(), &host, rows))
	assert.Equal(t, "chromeos 1.3.3.7", host.OSVersion)
}

func TestDirectIngestMDMMac(t *testing.T) {
	ds := new(mock.Store)
	var host mobius.Host

	cases := []struct {
		name       string
		got        map[string]string
		wantParams []any
		wantErr    string
		enrollRef  string
	}{
		{
			"empty server URL",
			map[string]string{
				"enrolled":           "false",
				"installed_from_dep": "",
				"server_url":         "",
			},
			[]any{false, false, "", false, mobius.UnknownMDMName},
			"",
			"",
		},
		{
			"with Mobius payload identifier",
			map[string]string{
				"enrolled":           "true",
				"installed_from_dep": "true",
				"server_url":         "https://test.example.com",
				"payload_identifier": apple_mdm.MobiusPayloadIdentifier,
			},
			[]any{false, true, "https://test.example.com", true, mobius.WellKnownMDMMobius},
			"",
			"",
		},
		{
			"with a query string on the server URL",
			map[string]string{
				"enrolled":           "true",
				"installed_from_dep": "true",
				"server_url":         "https://jamf.com/1/some/path?one=1&two=2",
			},
			[]any{false, true, "https://jamf.com/1/some/path", true, mobius.WellKnownMDMJamf},
			"",
			"",
		},
		{
			"with invalid installed_from_dep",
			map[string]string{
				"enrolled":           "true",
				"installed_from_dep": "invalid",
				"server_url":         "https://jamf.com/1/some/path?one=1&two=2",
			},
			[]any{},
			"parsing installed_from_dep",
			"",
		},
		{
			"with invalid enrolled",
			map[string]string{
				"enrolled":           "invalid",
				"installed_from_dep": "false",
				"server_url":         "https://jamf.com/1/some/path?one=1&two=2",
			},
			[]any{},
			"parsing enrolled",
			"",
		},
		{
			"with invalid server_url",
			map[string]string{
				"enrolled":           "false",
				"installed_from_dep": "false",
				"server_url":         "ht tp://foo.com",
			},
			[]any{},
			"parsing server_url",
			"",
		},
		{
			"with invalid enrollment reference",
			map[string]string{
				"enrolled":           "true",
				"installed_from_dep": "true",
				"server_url":         "https://test.example.com?enroll_reference=foobar",
				"payload_identifier": apple_mdm.MobiusPayloadIdentifier,
			},
			[]any{false, true, "https://test.example.com", true, mobius.WellKnownMDMMobius},
			"",
			"foobar",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
				return &mobius.AppConfig{
					MDM: mobius.MDM{
						MacOSSetup: mobius.MacOSSetup{
							EnableEndUserAuthentication: true,
						},
					},
				}, nil
			}
			ds.SetOrUpdateMDMDataFunc = func(ctx context.Context, hostID uint, isServer, enrolled bool, serverURL string, installedFromDep bool, name string, mobiusEnrollmentRef string) error {
				require.Equal(t, isServer, c.wantParams[0])
				require.Equal(t, enrolled, c.wantParams[1])
				require.Equal(t, serverURL, c.wantParams[2])
				require.Equal(t, installedFromDep, c.wantParams[3])
				require.Equal(t, name, c.wantParams[4])
				require.Equal(t, mobiusEnrollmentRef, c.enrollRef)
				return nil
			}

			err := directIngestMDMMac(context.Background(), log.NewNopLogger(), &host, ds, []map[string]string{c.got})
			if c.wantErr != "" {
				require.ErrorContains(t, err, c.wantErr)
				require.False(t, ds.SetOrUpdateMDMDataFuncInvoked)
			} else {
				require.True(t, ds.SetOrUpdateMDMDataFuncInvoked)
				require.NoError(t, err)
			}
			ds.SetOrUpdateMDMDataFuncInvoked = false
		})
	}
}

func TestDirectIngestMDMMobiusEnrollRef(t *testing.T) {
	ds := new(mock.Store)
	var host mobius.Host

	generateRows := func(serverURL, payloadIdentifier string) []map[string]string {
		return []map[string]string{
			{
				"enrolled":           "true",
				"installed_from_dep": "true",
				"server_url":         serverURL,
				"payload_identifier": payloadIdentifier,
			},
		}
	}

	type testCase struct {
		name          string
		mdmData       []map[string]string
		wantServerURL string
		wantEnrollRef string
	}

	for _, tc := range []testCase{
		{
			name:          "Mobius enroll_reference",
			mdmData:       generateRows("https://test.example.com?enroll_reference=test-reference", apple_mdm.MobiusPayloadIdentifier),
			wantServerURL: "https://test.example.com",
			wantEnrollRef: "test-reference",
		},
		{
			name:          "Mobius no enroll_reference",
			mdmData:       generateRows("https://test.example.com", apple_mdm.MobiusPayloadIdentifier),
			wantServerURL: "https://test.example.com",
			wantEnrollRef: "",
		},
		{
			name:          "Mobius enrollment_reference",
			mdmData:       generateRows("https://test.example.com?enrollment_reference=test-reference", apple_mdm.MobiusPayloadIdentifier),
			wantServerURL: "https://test.example.com",
			wantEnrollRef: "test-reference",
		},
		{
			name:          "Mobius enroll_reference with other query params",
			mdmData:       generateRows("https://test.example.com?token=abcdefg&enroll_reference=test-reference", apple_mdm.MobiusPayloadIdentifier),
			wantServerURL: "https://test.example.com",
			wantEnrollRef: "test-reference",
		},
		{
			name:          "non-Mobius enroll_reference",
			mdmData:       generateRows("https://test.example.com?enroll_reference=test-reference", "com.unknown.mdm"),
			wantServerURL: "https://test.example.com",
			wantEnrollRef: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ds.SetOrUpdateMDMDataFunc = func(ctx context.Context, hostID uint, isServer, enrolled bool, serverURL string, installedFromDep bool, name string, mobiusEnrollmentRef string) error {
				require.False(t, isServer)
				require.True(t, enrolled)
				require.True(t, installedFromDep)

				require.Equal(t, tc.wantServerURL, serverURL)
				require.Equal(t, tc.wantEnrollRef, mobiusEnrollmentRef)
				if tc.wantEnrollRef != "" {
					require.NotContains(t, serverURL, tc.wantEnrollRef) // query string is removed
				}
				if tc.mdmData[0]["payload_identifier"] == apple_mdm.MobiusPayloadIdentifier {
					require.Equal(t, name, mobius.WellKnownMDMMobius)
				} else {
					require.Equal(t, name, mobius.UnknownMDMName)
				}

				return nil
			}
			ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
				return &mobius.AppConfig{
					MDM: mobius.MDM{
						MacOSSetup: mobius.MacOSSetup{
							EnableEndUserAuthentication: true,
						},
					},
				}, nil
			}

			err := directIngestMDMMac(context.Background(), log.NewNopLogger(), &host, ds, tc.mdmData)
			require.NoError(t, err)
			require.True(t, ds.SetOrUpdateMDMDataFuncInvoked)
			ds.SetOrUpdateMDMDataFuncInvoked = false
		})
	}

	t.Run("end user authentication disabled", func(t *testing.T) {
		// Test that email isn't set when end user authentication is disabled
		ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
			return &mobius.AppConfig{
				MDM: mobius.MDM{
					MacOSSetup: mobius.MacOSSetup{
						EnableEndUserAuthentication: false,
					},
				},
			}, nil
		}
		ds.SetOrUpdateMDMDataFunc = func(ctx context.Context, hostID uint, isServer, enrolled bool, serverURL string, installedFromDep bool, name string, mobiusEnrollmentRef string) error {
			require.False(t, isServer)
			require.True(t, enrolled)
			require.True(t, installedFromDep)
			require.Equal(t, "https://test.example.com", serverURL)
			require.Equal(t, "test-reference", mobiusEnrollmentRef)
			require.Equal(t, mobius.WellKnownMDMMobius, name)

			return nil
		}

		t.Run("no team", func(t *testing.T) {
			err := directIngestMDMMac(context.Background(), log.NewNopLogger(), &host, ds, generateRows("https://test.example.com?enroll_reference=test-reference", apple_mdm.MobiusPayloadIdentifier))
			require.NoError(t, err)
			require.True(t, ds.SetOrUpdateMDMDataFuncInvoked)
			ds.SetOrUpdateMDMDataFuncInvoked = false
		})

		t.Run("team", func(t *testing.T) {
			host.TeamID = ptr.Uint(1)
			err := directIngestMDMMac(context.Background(), log.NewNopLogger(), &host, ds, generateRows("https://test.example.com?enroll_reference=test-reference", apple_mdm.MobiusPayloadIdentifier))
			require.NoError(t, err)
			require.True(t, ds.SetOrUpdateMDMDataFuncInvoked)
			ds.SetOrUpdateMDMDataFuncInvoked = false
		})
	})
}

func TestDirectIngestMDMWindows(t *testing.T) {
	ds := new(mock.Store)
	cases := []struct {
		name                 string
		data                 []map[string]string
		wantEnrolled         bool
		wantInstalledFromDep bool
		wantIsServer         bool
		wantServerURL        string
		wantMDMSolName       string
	}{
		{
			name: "off empty server URL",
			data: []map[string]string{
				{
					"discovery_service_url": "",
					"aad_resource_id":       "https://example.com",
					"provider_id":           "Some_ID",
					"installation_type":     "Client",
				},
			},
			wantEnrolled:         false,
			wantInstalledFromDep: false,
			wantIsServer:         false,
			wantServerURL:        "",
		},
		{
			name: "off missing aad_resource_id and server url",
			data: []map[string]string{
				{
					"provider_id":       "Some_ID",
					"installation_type": "Client",
				},
			},
			wantEnrolled:         false,
			wantInstalledFromDep: false,
			wantIsServer:         false,
			wantServerURL:        "",
		},
		{
			name:                 "off no rows",
			data:                 []map[string]string{},
			wantEnrolled:         false,
			wantInstalledFromDep: false,
			wantIsServer:         false,
			wantServerURL:        "",
		},
		{
			name: "on automatic",
			data: []map[string]string{
				{
					"discovery_service_url": "https://example.com",
					"aad_resource_id":       "https://example.com",
					"provider_id":           "Some_ID",
					"installation_type":     "Client",
				},
			},
			wantEnrolled:         true,
			wantInstalledFromDep: true,
			wantIsServer:         false,
			wantServerURL:        "https://example.com",
		},
		{
			name: "on manual",
			data: []map[string]string{
				{
					"discovery_service_url": "https://example.com",
					"aad_resource_id":       "",
					"provider_id":           "Local_Management",
					"installation_type":     "Client",
				},
			},
			wantEnrolled:         true,
			wantInstalledFromDep: false,
			wantIsServer:         false,
			wantServerURL:        "https://example.com",
		},
		{
			name: "on manual missing aad_resource_id",
			data: []map[string]string{
				{
					"discovery_service_url": "https://example.com",
					"provider_id":           "Some_ID",
					"installation_type":     "Client",
				},
			},
			wantEnrolled:         true,
			wantInstalledFromDep: false,
			wantIsServer:         false,
			wantServerURL:        "https://example.com",
		},
		{
			name: "is_server",
			data: []map[string]string{
				{
					"discovery_service_url": "https://example.com",
					"aad_resource_id":       "https://example.com",
					"provider_id":           "Some_ID",
					"installation_type":     "Windows SeRvEr 99.9",
				},
			},
			wantEnrolled:         true,
			wantInstalledFromDep: true,
			wantIsServer:         true,
			wantServerURL:        "https://example.com",
		},

		// Test that names are being calculated correctly

		{
			name: "on manual jumpcloud",
			data: []map[string]string{
				{
					"discovery_service_url": "https://jumpcloud.com",
					"aad_resource_id":       "",
					"provider_id":           "Local_Management",
					"installation_type":     "Client",
				},
			},
			wantEnrolled:         true,
			wantInstalledFromDep: false,
			wantIsServer:         false,
			wantServerURL:        "https://jumpcloud.com",
			wantMDMSolName:       mobius.WellKnownMDMJumpCloud,
		},
		{
			name: "on manual airwatch",
			data: []map[string]string{
				{
					"discovery_service_url": "https://airwatch.com",
					"aad_resource_id":       "",
					"provider_id":           "Local_Management",
					"installation_type":     "Client",
				},
			},
			wantEnrolled:         true,
			wantInstalledFromDep: false,
			wantIsServer:         false,
			wantServerURL:        "https://airwatch.com",
			wantMDMSolName:       mobius.WellKnownMDMVMWare,
		},
		{
			name: "on manual awmdm",
			data: []map[string]string{
				{
					"discovery_service_url": "https://awmdm.com",
					"aad_resource_id":       "",
					"provider_id":           "Local_Management",
					"installation_type":     "Client",
				},
			},
			wantEnrolled:         true,
			wantInstalledFromDep: false,
			wantIsServer:         false,
			wantServerURL:        "https://awmdm.com",
			wantMDMSolName:       mobius.WellKnownMDMVMWare,
		},
		{
			name: "on manual microsoft",
			data: []map[string]string{
				{
					"discovery_service_url": "https://microsoft.com",
					"aad_resource_id":       "",
					"provider_id":           "Local_Management",
					"installation_type":     "Client",
				},
			},
			wantEnrolled:         true,
			wantInstalledFromDep: false,
			wantIsServer:         false,
			wantServerURL:        "https://microsoft.com",
			wantMDMSolName:       mobius.WellKnownMDMIntune,
		},
		{
			name: "on manual mobiusmdm cloud hosted",
			data: []map[string]string{
				{
					"discovery_service_url": "https://mobiusmdm.com",
					"aad_resource_id":       "",
					"provider_id":           "Local_Management",
					"installation_type":     "Client",
				},
			},
			wantEnrolled:         true,
			wantInstalledFromDep: false,
			wantIsServer:         false,
			wantServerURL:        "https://mobiusmdm.com",
			wantMDMSolName:       mobius.WellKnownMDMMobius,
		},

		{
			name: "on manual mobiusmdm self hosted",
			data: []map[string]string{
				{
					"discovery_service_url": "https://myinstall.local",
					"aad_resource_id":       "",
					"provider_id":           "Mobius",
					"installation_type":     "Client",
				},
			},
			wantEnrolled:         true,
			wantInstalledFromDep: false,
			wantIsServer:         false,
			wantServerURL:        "https://myinstall.local",
			wantMDMSolName:       mobius.WellKnownMDMMobius,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ds.SetOrUpdateMDMDataFunc = func(ctx context.Context, hostID uint, isServer, enrolled bool, serverURL string, installedFromDep bool, name string, mobiusEnrollmentRef string) error {
				require.Equal(t, c.wantEnrolled, enrolled)
				require.Equal(t, c.wantInstalledFromDep, installedFromDep)
				require.Equal(t, c.wantIsServer, isServer)
				require.Equal(t, c.wantServerURL, serverURL)
				require.Equal(t, c.wantMDMSolName, name)
				require.Empty(t, mobiusEnrollmentRef)
				return nil
			}
		})
		err := directIngestMDMWindows(context.Background(), log.NewNopLogger(), &mobius.Host{}, ds, c.data)
		require.NoError(t, err)
		require.True(t, ds.SetOrUpdateMDMDataFuncInvoked)
		ds.SetOrUpdateMDMDataFuncInvoked = false
	}
}

func TestDirectIngestChromeProfiles(t *testing.T) {
	ds := new(mock.Store)
	ds.ReplaceHostDeviceMappingFunc = func(ctx context.Context, hostID uint, mapping []*mobius.HostDeviceMapping, source string) error {
		require.Equal(t, hostID, uint(1))
		require.Equal(t, mapping, []*mobius.HostDeviceMapping{
			{HostID: hostID, Email: "test@example.com", Source: "google_chrome_profiles"},
			{HostID: hostID, Email: "test+2@example.com", Source: "google_chrome_profiles"},
		})
		require.Equal(t, source, "google_chrome_profiles")
		return nil
	}

	host := mobius.Host{
		ID: 1,
	}

	err := directIngestChromeProfiles(context.Background(), log.NewNopLogger(), &host, ds, []map[string]string{
		{"email": "test@example.com"},
		{"email": "test+2@example.com"},
	})

	require.NoError(t, err)
	require.True(t, ds.ReplaceHostDeviceMappingFuncInvoked)
}

func TestDirectIngestBattery(t *testing.T) {
	tests := []struct {
		name            string
		input           map[string]string
		expectedBattery *mobius.HostBattery
	}{
		{
			name:            "max_capacity >= 80%, cycleCount < 1000",
			input:           map[string]string{"serial_number": "a", "cycle_count": "2", "designed_capacity": "3000", "max_capacity": "2400"},
			expectedBattery: &mobius.HostBattery{HostID: uint(1), SerialNumber: "a", CycleCount: 2, Health: batteryStatusGood},
		},
		{
			name:            "max_capacity < 50%",
			input:           map[string]string{"serial_number": "b", "cycle_count": "3", "designed_capacity": "3000", "max_capacity": "2399"},
			expectedBattery: &mobius.HostBattery{HostID: uint(1), SerialNumber: "b", CycleCount: 3, Health: batteryStatusDegraded},
		},
		{
			name:            "missing max_capacity",
			input:           map[string]string{"serial_number": "c", "cycle_count": "4", "designed_capacity": "3000", "max_capacity": ""},
			expectedBattery: &mobius.HostBattery{HostID: uint(1), SerialNumber: "c", CycleCount: 4, Health: batteryStatusUnknown},
		},
		{
			name:            "missing designed_capacity and max_capacity",
			input:           map[string]string{"serial_number": "d", "cycle_count": "5", "designed_capacity": "", "max_capacity": ""},
			expectedBattery: &mobius.HostBattery{HostID: uint(1), SerialNumber: "d", CycleCount: 5, Health: batteryStatusUnknown},
		},
		{
			name:            "missing designed_capacity",
			input:           map[string]string{"serial_number": "e", "cycle_count": "6", "designed_capacity": "", "max_capacity": "2000"},
			expectedBattery: &mobius.HostBattery{HostID: uint(1), SerialNumber: "e", CycleCount: 6, Health: batteryStatusUnknown},
		},
		{
			name:            "invalid designed_capacity and max_capacity",
			input:           map[string]string{"serial_number": "f", "cycle_count": "7", "designed_capacity": "foo", "max_capacity": "bar"},
			expectedBattery: &mobius.HostBattery{HostID: uint(1), SerialNumber: "f", CycleCount: 7, Health: batteryStatusUnknown},
		},
		{
			name:            "cycleCount >= 1000",
			input:           map[string]string{"serial_number": "g", "cycle_count": "1000", "designed_capacity": "3000", "max_capacity": "2400"},
			expectedBattery: &mobius.HostBattery{HostID: uint(1), SerialNumber: "g", CycleCount: 1000, Health: batteryStatusDegraded},
		},
		{
			name:            "cycleCount >= 1000 with degraded health",
			input:           map[string]string{"serial_number": "h", "cycle_count": "1001", "designed_capacity": "3000", "max_capacity": "2399"},
			expectedBattery: &mobius.HostBattery{HostID: uint(1), SerialNumber: "h", CycleCount: 1001, Health: batteryStatusDegraded},
		},
		{
			name:            "missing cycle_count",
			input:           map[string]string{"serial_number": "i", "cycle_count": "", "designed_capacity": "3000", "max_capacity": "2400"},
			expectedBattery: &mobius.HostBattery{HostID: uint(1), SerialNumber: "i", CycleCount: 0, Health: batteryStatusGood},
		},
		{
			name:            "missing cycle_count with degraded health",
			input:           map[string]string{"serial_number": "j", "cycle_count": "", "designed_capacity": "3000", "max_capacity": "2399"},
			expectedBattery: &mobius.HostBattery{HostID: uint(1), SerialNumber: "j", CycleCount: 0, Health: batteryStatusDegraded},
		},
		{
			name:            "invalid cycle_count",
			input:           map[string]string{"serial_number": "k", "cycle_count": "foo", "designed_capacity": "3000", "max_capacity": "2400"},
			expectedBattery: &mobius.HostBattery{HostID: uint(1), SerialNumber: "k", CycleCount: 0, Health: batteryStatusGood},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ds := new(mock.Store)

			ds.ReplaceHostBatteriesFunc = func(ctx context.Context, id uint, mappings []*mobius.HostBattery) error {
				require.Len(t, mappings, 1)
				require.Equal(t, tt.expectedBattery, mappings[0])
				return nil
			}

			host := mobius.Host{
				ID: 1,
			}

			err := directIngestBattery(context.Background(), log.NewNopLogger(), &host, ds, []map[string]string{tt.input})
			require.NoError(t, err)
			require.True(t, ds.ReplaceHostBatteriesFuncInvoked)
		})
	}
}

func TestDirectIngestOSWindows(t *testing.T) {
	ds := new(mock.Store)

	testCases := []struct {
		expected mobius.OperatingSystem
		data     []map[string]string
	}{
		{
			expected: mobius.OperatingSystem{
				Name:           "Microsoft Windows 11 Enterprise 21H2",
				Version:        "10.0.22000.795",
				Arch:           "64-bit",
				KernelVersion:  "10.0.22000.795",
				DisplayVersion: "21H2",
			},
			data: []map[string]string{
				{"name": "Microsoft Windows 11 Enterprise", "display_version": "21H2", "version": "10.0.22000.795", "arch": "64-bit"},
			},
		},
		{
			expected: mobius.OperatingSystem{
				Name:           "Microsoft Windows 10 Enterprise", // no display_version
				Version:        "10.0.17763.2183",
				Arch:           "64-bit",
				KernelVersion:  "10.0.17763.2183",
				DisplayVersion: "",
			},
			data: []map[string]string{
				{"name": "Microsoft Windows 10 Enterprise", "display_version": "", "version": "10.0.17763.2183", "arch": "64-bit"},
			},
		},
	}

	host := mobius.Host{ID: 1}

	for _, tt := range testCases {
		ds.UpdateHostOperatingSystemFunc = func(ctx context.Context, hostID uint, hostOS mobius.OperatingSystem) error {
			require.Equal(t, host.ID, hostID)
			require.Equal(t, tt.expected, hostOS)
			return nil
		}

		err := directIngestOSWindows(context.Background(), log.NewNopLogger(), &host, ds, tt.data)
		require.NoError(t, err)

		require.True(t, ds.UpdateHostOperatingSystemFuncInvoked)
		ds.UpdateHostOperatingSystemFuncInvoked = false
	}
}

func TestDirectIngestOSUnixLike(t *testing.T) {
	ds := new(mock.Store)

	for i, tc := range []struct {
		data     []map[string]string
		expected mobius.OperatingSystem
	}{
		{
			data: []map[string]string{
				{
					"name":           "macOS",
					"version":        "12.5",
					"major":          "12",
					"minor":          "5",
					"patch":          "0",
					"build":          "21G72",
					"arch":           "x86_64",
					"kernel_version": "21.6.0",
				},
			},
			expected: mobius.OperatingSystem{
				Name:          "macOS",
				Version:       "12.5.0",
				Arch:          "x86_64",
				KernelVersion: "21.6.0",
			},
		},
		// macOS with Rapid Security Response version
		{
			data: []map[string]string{
				{
					"name":           "macOS",
					"version":        "13.4.1",
					"major":          "13",
					"minor":          "4",
					"patch":          "1",
					"build":          "22F82",
					"arch":           "arm64",
					"kernel_version": "21.6.0",
					"extra":          "(c) ",
				},
			},
			expected: mobius.OperatingSystem{
				Name:          "macOS",
				Version:       "13.4.1 (c)",
				Arch:          "arm64",
				KernelVersion: "21.6.0",
			},
		},
		{
			data: []map[string]string{
				{
					"name":           "Ubuntu",
					"version":        "20.04.2 LTS (Focal Fossa)",
					"major":          "20",
					"minor":          "4",
					"patch":          "0",
					"build":          "",
					"arch":           "x86_64",
					"kernel_version": "5.10.76-linuxkit",
				},
			},
			expected: mobius.OperatingSystem{
				Name:          "Ubuntu",
				Version:       "20.04.2 LTS",
				Arch:          "x86_64",
				KernelVersion: "5.10.76-linuxkit",
			},
		},
		{
			data: []map[string]string{
				{
					"name":           "CentOS Linux",
					"version":        "CentOS Linux release 7.9.2009 (Core)",
					"major":          "7",
					"minor":          "9",
					"patch":          "2009",
					"build":          "",
					"arch":           "x86_64",
					"kernel_version": "5.10.76-linuxkit",
				},
			},
			expected: mobius.OperatingSystem{
				Name:          "CentOS Linux",
				Version:       "7.9.2009",
				Arch:          "x86_64",
				KernelVersion: "5.10.76-linuxkit",
			},
		},
		{
			data: []map[string]string{
				{
					"name":           "Debian GNU/Linux",
					"version":        "10 (buster)",
					"major":          "10",
					"minor":          "0",
					"patch":          "0",
					"build":          "",
					"arch":           "x86_64",
					"kernel_version": "5.10.76-linuxkit",
				},
			},
			expected: mobius.OperatingSystem{
				Name:          "Debian GNU/Linux",
				Version:       "10.0.0",
				Arch:          "x86_64",
				KernelVersion: "5.10.76-linuxkit",
			},
		},
		{
			data: []map[string]string{
				{
					"name":           "CentOS Linux",
					"version":        "CentOS Linux release 7.9.2009 (Core)",
					"major":          "7",
					"minor":          "9",
					"patch":          "2009",
					"build":          "",
					"arch":           "x86_64",
					"kernel_version": "5.10.76-linuxkit",
				},
			},
			expected: mobius.OperatingSystem{
				Name:          "CentOS Linux",
				Version:       "7.9.2009",
				Arch:          "x86_64",
				KernelVersion: "5.10.76-linuxkit",
			},
		},
	} {
		t.Run(tc.expected.Name, func(t *testing.T) {
			ds.UpdateHostOperatingSystemFunc = func(ctx context.Context, hostID uint, hostOS mobius.OperatingSystem) error {
				require.Equal(t, uint(i), hostID) //nolint:gosec // dismiss G115
				require.Equal(t, tc.expected, hostOS)
				return nil
			}

			err := directIngestOSUnixLike(context.Background(), log.NewNopLogger(), &mobius.Host{ID: uint(i)}, //nolint:gosec // dismiss G115
				ds, tc.data)

			require.NoError(t, err)
			require.True(t, ds.UpdateHostOperatingSystemFuncInvoked)
			ds.UpdateHostOperatingSystemFuncInvoked = false
		})
	}
}

func TestAppConfigReplaceQuery(t *testing.T) {
	queries := GetDetailQueries(context.Background(), config.MobiusConfig{}, nil, &mobius.Features{EnableHostUsers: true}, Integrations{})
	originalQuery := queries["users"].Query

	replacementMap := make(map[string]*string)
	replacementMap["users"] = ptr.String("select 1 from blah")
	queries = GetDetailQueries(context.Background(), config.MobiusConfig{}, nil, &mobius.Features{EnableHostUsers: true, DetailQueryOverrides: replacementMap}, Integrations{})
	assert.NotEqual(t, originalQuery, queries["users"].Query)
	assert.Equal(t, "select 1 from blah", queries["users"].Query)

	replacementMap["users"] = nil
	queries = GetDetailQueries(context.Background(), config.MobiusConfig{}, nil, &mobius.Features{EnableHostUsers: true, DetailQueryOverrides: replacementMap}, Integrations{})
	_, exists := queries["users"]
	assert.False(t, exists)

	// put the query back again
	replacementMap["users"] = ptr.String("select 1 from blah")
	queries = GetDetailQueries(context.Background(), config.MobiusConfig{}, nil, &mobius.Features{EnableHostUsers: true, DetailQueryOverrides: replacementMap}, Integrations{})
	assert.NotEqual(t, originalQuery, queries["users"].Query)
	assert.Equal(t, "select 1 from blah", queries["users"].Query)

	// empty strings are also ignored
	replacementMap["users"] = ptr.String("")
	queries = GetDetailQueries(context.Background(), config.MobiusConfig{}, nil, &mobius.Features{EnableHostUsers: true, DetailQueryOverrides: replacementMap}, Integrations{})
	_, exists = queries["users"]
	assert.False(t, exists)
}

func TestDirectIngestSoftware(t *testing.T) {
	ds := new(mock.Store)
	ctx := context.Background()
	logger := log.NewNopLogger()
	host := mobius.Host{ID: uint(1)}

	t.Run("ingesting installed software path", func(t *testing.T) {
		data := []map[string]string{
			{
				"name":              "Software 1",
				"version":           "12.5.0",
				"source":            "apps",
				"bundle_identifier": "com.bundle.com",
				"vendor":            "EvilCorp",
				"installed_path":    "",
			},
			{
				"name":              "Software 2",
				"version":           "0.0.1",
				"source":            "apps",
				"bundle_identifier": "coms.widgets.com",
				"vendor":            "widgets",
				"installed_path":    "/tmp/some_path",
			},
		}

		ds.UpdateHostSoftwareFunc = func(ctx context.Context, hostID uint, software []mobius.Software) (*mobius.UpdateHostSoftwareDBResult, error) {
			return nil, nil
		}

		t.Run("errors are reported back", func(t *testing.T) {
			ds.UpdateHostSoftwareInstalledPathsFunc = func(ctx context.Context, hostID uint, sPaths map[string]struct{}, result *mobius.UpdateHostSoftwareDBResult) error {
				return errors.New("some error")
			}
			require.Error(t, directIngestSoftware(ctx, logger, &host, ds, data), "some error")
			ds.UpdateHostSoftwareInstalledPathsFuncInvoked = false
		})

		t.Run("only entries with installed_path set are persisted", func(t *testing.T) {
			var calledWith map[string]struct{}
			ds.UpdateHostSoftwareInstalledPathsFunc = func(ctx context.Context, hostID uint, sPaths map[string]struct{}, result *mobius.UpdateHostSoftwareDBResult) error {
				calledWith = make(map[string]struct{})
				for k, v := range sPaths {
					calledWith[k] = v
				}
				return nil
			}

			require.NoError(t, directIngestSoftware(ctx, logger, &host, ds, data))
			require.True(t, ds.UpdateHostSoftwareFuncInvoked)

			require.Len(t, calledWith, 1)
			require.Contains(t, strings.Join(maps.Keys(calledWith), " "), fmt.Sprintf("%s%s%s%s%s%s", data[1]["installed_path"], mobius.SoftwareFieldSeparator, "", mobius.SoftwareFieldSeparator, mobius.SoftwareFieldSeparator, data[1]["name"]))

			ds.UpdateHostSoftwareInstalledPathsFuncInvoked = false
		})
	})

	t.Run("vendor gets truncated", func(t *testing.T) {
		for _, tc := range []struct {
			data     []map[string]string
			expected string
		}{
			{
				data: []map[string]string{
					{
						"name":              "Software 1",
						"version":           "12.5",
						"source":            "My backyard",
						"bundle_identifier": "",
						"vendor":            "Mobius",
					},
				},
				expected: "Mobius",
			},
			{
				data: []map[string]string{
					{
						"name":              "Software 1",
						"version":           "12.5",
						"source":            "My backyard",
						"bundle_identifier": "",
						"vendor":            `oFZTwTV5WxJt02EVHEBcnhLzuJ8wnxKwfbabPWy7yTSiQbabEcAGDVmoXKZEZJLWObGD0cVfYptInHYgKjtDeDsBh2a8669EnyAqyBECXbFjSh1111`,
					},
				},
				expected: `oFZTwTV5WxJt02EVHEBcnhLzuJ8wnxKwfbabPWy7yTSiQbabEcAGDVmoXKZEZJLWObGD0cVfYptInHYgKjtDeDsBh2a8669EnyAqyBECXbFjSh1...`,
			},
		} {
			ds.UpdateHostSoftwareFunc = func(ctx context.Context, hostID uint, software []mobius.Software) (*mobius.UpdateHostSoftwareDBResult, error) {
				require.Len(t, software, 1)
				require.Equal(t, tc.expected, software[0].Vendor)
				return nil, nil
			}

			ds.UpdateHostSoftwareInstalledPathsFunc = func(ctx context.Context, hostID uint, sPaths map[string]struct{}, result *mobius.UpdateHostSoftwareDBResult) error {
				// NOP - This functionality is tested elsewhere
				return nil
			}

			require.NoError(t, directIngestSoftware(ctx, logger, &host, ds, tc.data))
			require.True(t, ds.UpdateHostSoftwareFuncInvoked)
			ds.UpdateHostSoftwareFuncInvoked = false
		}
	})

	t.Run("cdhash_sha256", func(t *testing.T) {
		data := []map[string]string{
			{
				"name":              "Software 1",
				"version":           "12.5.0",
				"source":            "apps",
				"bundle_identifier": "com.bundle.com",
				"vendor":            "EvilCorp",
				"installed_path":    "/Applications/Software1.app",
				"team_identifier":   "corp1",
				"cdhash_sha256":     "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			},
			{
				"name":              "Software 2",
				"version":           "0.0.1",
				"source":            "apps",
				"bundle_identifier": "coms.widgets.com",
				"vendor":            "widgets",
				"team_identifier":   "corp2",
				"installed_path":    "/Applications/Software2.app",
			},
		}
		var dataAsSoftware []mobius.Software
		for _, entry := range data {
			software := mobius.Software{
				Name:             entry["name"],
				Version:          entry["version"],
				Source:           entry["source"],
				BundleIdentifier: entry["bundle_identifier"],
				Vendor:           entry["vendor"],
			}
			dataAsSoftware = append(dataAsSoftware, software)
		}

		ds.UpdateHostSoftwareFunc = func(ctx context.Context, hostID uint, software []mobius.Software) (*mobius.UpdateHostSoftwareDBResult, error) {
			return nil, nil
		}
		ds.UpdateHostSoftwareInstalledPathsFunc = func(ctx context.Context, hostID uint, sPaths map[string]struct{}, result *mobius.UpdateHostSoftwareDBResult) error {
			require.Len(t, sPaths, 2)
			require.Contains(t, sPaths,
				fmt.Sprintf(
					"%s%s%s%s%s%s%s",
					data[0]["installed_path"],
					mobius.SoftwareFieldSeparator,
					data[0]["team_identifier"],
					mobius.SoftwareFieldSeparator,
					data[0]["cdhash_sha256"],
					mobius.SoftwareFieldSeparator,
					dataAsSoftware[0].ToUniqueStr(),
				),
			)
			require.Contains(t, sPaths,
				fmt.Sprintf(
					"%s%s%s%s%s%s",
					data[1]["installed_path"],
					mobius.SoftwareFieldSeparator,
					data[1]["team_identifier"],
					mobius.SoftwareFieldSeparator,
					mobius.SoftwareFieldSeparator,
					dataAsSoftware[1].ToUniqueStr(),
				),
			)
			return nil
		}

		require.NoError(t, directIngestSoftware(ctx, logger, &host, ds, data))
		require.True(t, ds.UpdateHostSoftwareInstalledPathsFuncInvoked)
		ds.UpdateHostSoftwareInstalledPathsFuncInvoked = false
	})
}

func TestDirectIngestWindowsUpdateHistory(t *testing.T) {
	ds := new(mock.Store)
	ds.InsertWindowsUpdatesFunc = func(ctx context.Context, hostID uint, updates []mobius.WindowsUpdate) error {
		require.Len(t, updates, 6)
		require.ElementsMatch(t, []mobius.WindowsUpdate{
			{KBID: 2267602, DateEpoch: 1657929207},
			{KBID: 890830, DateEpoch: 1658226954},
			{KBID: 5013887, DateEpoch: 1658225364},
			{KBID: 5005463, DateEpoch: 1658225225},
			{KBID: 5010472, DateEpoch: 1658224963},
			{KBID: 4052623, DateEpoch: 1657929544},
		}, updates)
		return nil
	}

	host := mobius.Host{
		ID: 1,
	}

	payload := []map[string]string{
		{"date": "1659392951", "title": "Security Intelligence Update for Microsoft Defender Antivirus - KB2267602 (Version 1.371.1239.0)"},
		{"date": "1658271402", "title": "Security Intelligence Update for Microsoft Defender Antivirus - KB2267602 (Version 1.371.442.0)"},
		{"date": "1658228495", "title": "Security Intelligence Update for Microsoft Defender Antivirus - KB2267602 (Version 1.371.415.0)"},
		{"date": "1658226954", "title": "Windows Malicious Software Removal Tool x64 - v5.103 (KB890830)"},
		{"date": "1658225364", "title": "2022-06 Cumulative Update for .NET Framework 3.5 and 4.8 for Windows 10 Version 21H2 for x64 (KB5013887)"},
		{"date": "1658225225", "title": "2022-04 Update for Windows 10 Version 21H2 for x64-based Systems (KB5005463)"},
		{"date": "1658224963", "title": "2022-02 Cumulative Update Preview for .NET Framework 3.5 and 4.8 for Windows 10 Version 21H2 for x64 (KB5010472)"},
		{"date": "1658222131", "title": "Security Intelligence Update for Microsoft Defender Antivirus - KB2267602 (Version 1.371.400.0)"},
		{"date": "1658189063", "title": "Security Intelligence Update for Microsoft Defender Antivirus - KB2267602 (Version 1.371.376.0)"},
		{"date": "1658185542", "title": "Security Intelligence Update for Microsoft Defender Antivirus - KB2267602 (Version 1.371.386.0)"},
		{"date": "1657929544", "title": "Update for Microsoft Defender Antivirus antimalware platform - KB4052623 (Version 4.18.2205.7)"},
		{"date": "1657929207", "title": "Security Intelligence Update for Microsoft Defender Antivirus - KB2267602 (Version 1.371.203.0)"},
	}

	err := directIngestWindowsUpdateHistory(context.Background(), log.NewNopLogger(), &host, ds, payload)
	require.NoError(t, err)
	require.True(t, ds.InsertWindowsUpdatesFuncInvoked)
}

func TestIngestKubequeryInfo(t *testing.T) {
	err := ingestKubequeryInfo(context.Background(), log.NewNopLogger(), &mobius.Host{}, nil)
	require.Error(t, err)
	err = ingestKubequeryInfo(context.Background(), log.NewNopLogger(), &mobius.Host{}, []map[string]string{})
	require.Error(t, err)
	err = ingestKubequeryInfo(context.Background(), log.NewNopLogger(), &mobius.Host{}, []map[string]string{
		{
			"cluster_name": "foo",
		},
	})
	require.NoError(t, err)
}

func TestDirectDiskEncryption(t *testing.T) {
	ds := new(mock.Store)
	var expectEncrypted bool
	ds.SetOrUpdateHostDisksEncryptionFunc = func(ctx context.Context, id uint, encrypted bool) error {
		assert.Equal(t, expectEncrypted, encrypted)
		return nil
	}

	host := mobius.Host{
		ID: 1,
	}

	// set to true (osquery returned a row)
	expectEncrypted = true
	err := directIngestDiskEncryption(context.Background(), log.NewNopLogger(), &host, ds, []map[string]string{
		{"col1": "1"},
	})
	require.NoError(t, err)
	require.True(t, ds.SetOrUpdateHostDisksEncryptionFuncInvoked)
	ds.SetOrUpdateHostDisksEncryptionFuncInvoked = false

	// set to false (osquery returned nothing)
	expectEncrypted = false
	err = directIngestDiskEncryption(context.Background(), log.NewNopLogger(), &host, ds, []map[string]string{})
	require.NoError(t, err)
	require.True(t, ds.SetOrUpdateHostDisksEncryptionFuncInvoked)
	ds.SetOrUpdateHostDisksEncryptionFuncInvoked = false
}

func TestDirectIngestDiskEncryptionLinux(t *testing.T) {
	ds := new(mock.Store)
	var expectEncrypted bool
	ds.SetOrUpdateHostDisksEncryptionFunc = func(ctx context.Context, id uint, encrypted bool) error {
		assert.Equal(t, expectEncrypted, encrypted)
		return nil
	}
	host := mobius.Host{
		ID: 1,
	}

	expectEncrypted = false
	err := directIngestDiskEncryptionLinux(context.Background(), log.NewNopLogger(), &host, ds, []map[string]string{})
	require.NoError(t, err)
	require.True(t, ds.SetOrUpdateHostDisksEncryptionFuncInvoked)
	ds.SetOrUpdateHostDisksEncryptionFuncInvoked = false

	expectEncrypted = true
	err = directIngestDiskEncryptionLinux(context.Background(), log.NewNopLogger(), &host, ds, []map[string]string{
		{"path": "/etc/hosts", "encrypted": "0"},
		{"path": "/tmp", "encrypted": "0"},
		{"path": "/", "encrypted": "1"},
	})
	require.NoError(t, err)
	require.True(t, ds.SetOrUpdateHostDisksEncryptionFuncInvoked)
}

func TestDirectIngestDiskEncryptionKeyDarwin(t *testing.T) {
	ds := new(mock.Store)
	ctx := context.Background()
	logger := log.NewNopLogger()
	host := &mobius.Host{ID: 1}

	var wantKey string

	mockFileLines := func(wantKey string, wantEncrypted string) []map[string]string {
		var output []map[string]string
		scanner := bufio.NewScanner(bytes.NewBuffer([]byte(wantKey)))
		scanner.Split(bufio.ScanLines)

		for scanner.Scan() {
			line := scanner.Text()
			item := make(map[string]string)
			item["hex_line"] = hex.EncodeToString([]byte(line))
			item["encrypted"] = wantEncrypted
			output = append(output, item)
		}
		return output
	}

	mockFilevaultPRK := func(wantKey string, wantEncrypted string) []map[string]string {
		return []map[string]string{
			{"filevault_key": base64.StdEncoding.EncodeToString([]byte(wantKey)), "encrypted": wantEncrypted},
		}
	}

	ds.SetOrUpdateHostDiskEncryptionKeyFunc = func(ctx context.Context, incomingHost *mobius.Host, encryptedBase64Key, clientError string,
		decryptable *bool,
	) error {
		if base64.StdEncoding.EncodeToString([]byte(wantKey)) != encryptedBase64Key {
			return errors.New("key mismatch")
		}
		if host.ID != incomingHost.ID {
			return errors.New("host ID mismatch")
		}
		if encryptedBase64Key == "" && (decryptable == nil || *decryptable == true) {
			return errors.New("decryptable should be false if the key is empty")
		}
		return nil
	}

	t.Run("empty key", func(t *testing.T) {
		err := directIngestDiskEncryptionKeyFileLinesDarwin(ctx, logger, host, ds, []map[string]string{})
		require.NoError(t, err)
		require.False(t, ds.SetOrUpdateHostDiskEncryptionKeyFuncInvoked)

		err = directIngestDiskEncryptionKeyFileDarwin(ctx, logger, host, ds, []map[string]string{})
		require.NoError(t, err)
		require.False(t, ds.SetOrUpdateHostDiskEncryptionKeyFuncInvoked)

		err = directIngestDiskEncryptionKeyFileLinesDarwin(ctx, logger, host, ds, []map[string]string{{"encrypted": "0"}})
		require.NoError(t, err)
		require.False(t, ds.SetOrUpdateHostDiskEncryptionKeyFuncInvoked)

		err = directIngestDiskEncryptionKeyFileDarwin(ctx, logger, host, ds, []map[string]string{{"encrypted": "0"}})
		require.NoError(t, err)
		require.False(t, ds.SetOrUpdateHostDiskEncryptionKeyFuncInvoked)

		err = directIngestDiskEncryptionKeyFileLinesDarwin(ctx, logger, host, ds, []map[string]string{{"encrypted": "1"}})
		require.NoError(t, err)
		require.True(t, ds.SetOrUpdateHostDiskEncryptionKeyFuncInvoked)
		ds.SetOrUpdateHostDiskEncryptionKeyFuncInvoked = false

		err = directIngestDiskEncryptionKeyFileDarwin(ctx, logger, host, ds, []map[string]string{{"encrypted": "1"}})
		require.NoError(t, err)
		require.True(t, ds.SetOrUpdateHostDiskEncryptionKeyFuncInvoked)
		ds.SetOrUpdateHostDiskEncryptionKeyFuncInvoked = false

		err = directIngestDiskEncryptionKeyFileLinesDarwin(ctx, logger, host, ds, []map[string]string{{"encrypted": "1", "hex_line": ""}})
		require.NoError(t, err)
		require.True(t, ds.SetOrUpdateHostDiskEncryptionKeyFuncInvoked)
		ds.SetOrUpdateHostDiskEncryptionKeyFuncInvoked = false

		err = directIngestDiskEncryptionKeyFileDarwin(ctx, logger, host, ds, []map[string]string{{"encrypted": "1", "filevault_key": ""}})
		require.NoError(t, err)
		require.True(t, ds.SetOrUpdateHostDiskEncryptionKeyFuncInvoked)
		ds.SetOrUpdateHostDiskEncryptionKeyFuncInvoked = false
	})

	t.Run("key contains new lines and carriage return", func(t *testing.T) {
		wantKey = "This is only a \n\r\n\n test."

		err := directIngestDiskEncryptionKeyFileLinesDarwin(ctx, logger, host, ds, mockFileLines(wantKey, "1"))
		// it is a known limitation with the current file_lines implementation that causes this to fail
		// because it relies on bufio.ScanLines, which drops "\r" from "\r\n"
		require.ErrorContains(t, err, "key mismatch")
		require.True(t, ds.SetOrUpdateHostDiskEncryptionKeyFuncInvoked)
		ds.SetOrUpdateHostDiskEncryptionKeyFuncInvoked = false

		err = directIngestDiskEncryptionKeyFileDarwin(ctx, logger, host, ds, mockFilevaultPRK(wantKey, "1"))
		// filevault_prk does not have the scan lines limitation
		require.NoError(t, err)
		require.True(t, ds.SetOrUpdateHostDiskEncryptionKeyFuncInvoked)
		ds.SetOrUpdateHostDiskEncryptionKeyFuncInvoked = false
	})

	t.Run("key contains new lines", func(t *testing.T) {
		wantKey = "This is only a \n\n\n test."

		err := directIngestDiskEncryptionKeyFileLinesDarwin(ctx, logger, host, ds, mockFileLines(wantKey, "1"))
		// new lines are not a problem if they are not preceded by carriage return
		require.NoError(t, err)
		require.True(t, ds.SetOrUpdateHostDiskEncryptionKeyFuncInvoked)
		ds.SetOrUpdateHostDiskEncryptionKeyFuncInvoked = false

		err = directIngestDiskEncryptionKeyFileDarwin(ctx, logger, host, ds, mockFilevaultPRK(wantKey, "1"))
		// filevault_prk does not have the scan lines limitation
		require.NoError(t, err)
		require.True(t, ds.SetOrUpdateHostDiskEncryptionKeyFuncInvoked)
		ds.SetOrUpdateHostDiskEncryptionKeyFuncInvoked = false
	})
}

func TestDirectIngestHostMacOSProfiles(t *testing.T) {
	ds := new(mock.Store)
	ctx := context.Background()
	logger := log.NewNopLogger()
	h := &mobius.Host{ID: 1}

	toRows := func(profs []*mobius.HostMacOSProfile) []map[string]string {
		rows := make([]map[string]string, len(profs))
		for i, p := range profs {
			rows[i] = map[string]string{
				"identifier":   p.Identifier,
				"display_name": p.DisplayName,
				"install_date": p.InstallDate.Format("2006-01-02 15:04:05 -0700"),
			}
		}
		return rows
	}

	var installedProfiles []*mobius.HostMacOSProfile
	ds.GetHostMDMProfilesExpectedForVerificationFunc = func(ctx context.Context, host *mobius.Host) (map[string]*mobius.ExpectedMDMProfile, error) {
		require.Equal(t, h.ID, host.ID)
		expected := make(map[string]*mobius.ExpectedMDMProfile, len(installedProfiles))
		for _, p := range installedProfiles {
			expected[p.Identifier] = &mobius.ExpectedMDMProfile{
				Identifier:          p.Identifier,
				EarliestInstallDate: p.InstallDate,
			}
		}
		return expected, nil
	}
	ds.UpdateHostMDMProfilesVerificationFunc = func(ctx context.Context, host *mobius.Host, toVerify, toFailed, toRetry []string) error {
		require.Equal(t, h.UUID, host.UUID)
		require.Equal(t, len(installedProfiles), len(toVerify))
		require.Len(t, toFailed, 0)
		require.Len(t, toRetry, 0)
		for _, p := range installedProfiles {
			require.Contains(t, toVerify, p.Identifier)
		}
		return nil
	}

	// expect no error: happy path
	installedProfiles = []*mobius.HostMacOSProfile{
		{
			Identifier:  "com.example.test",
			DisplayName: "Test Profile",
			InstallDate: time.Now().Truncate(time.Second),
		},
	}
	rows := toRows(installedProfiles)
	require.NoError(t, directIngestMacOSProfiles(ctx, logger, h, ds, rows))

	// expect no error: identifer or display name is empty
	installedProfiles = append(installedProfiles, &mobius.HostMacOSProfile{
		Identifier:  "",
		DisplayName: "",
		InstallDate: time.Now().Truncate(time.Second),
	})
	rows = toRows(installedProfiles)
	require.NoError(t, directIngestMacOSProfiles(ctx, logger, h, ds, rows))

	// expect no error: empty rows
	require.NoError(t, directIngestMacOSProfiles(ctx, logger, h, ds, []map[string]string{}))

	// expect error: install date format is not "2006-01-02 15:04:05 -0700"
	rows[0]["install_date"] = time.Now().Format(time.UnixDate)
	require.ErrorContains(t, directIngestMacOSProfiles(ctx, logger, h, ds, rows), "parsing time")
}

func TestDirectIngestMDMDeviceIDWindows(t *testing.T) {
	ds := new(mock.Store)
	ctx := context.Background()
	logger := log.NewNopLogger()
	host := &mobius.Host{ID: 1, UUID: "mdm-windows-hw-uuid"}

	ds.UpdateMDMWindowsEnrollmentsHostUUIDFunc = func(ctx context.Context, hostUUID string, deviceID string) error {
		require.NotEmpty(t, deviceID)
		require.Equal(t, host.UUID, hostUUID)
		return nil
	}

	// if no rows, assume the registry key is not present (i.e. mdm is turned off) and do nothing
	require.NoError(t, directIngestMDMDeviceIDWindows(ctx, logger, host, ds, []map[string]string{}))
	require.False(t, ds.UpdateMDMWindowsEnrollmentsHostUUIDFuncInvoked)

	// if multiple rows, expect error
	require.Error(t, directIngestMDMDeviceIDWindows(ctx, logger, host, ds, []map[string]string{
		{"name": "mdm-windows-hostname", "data": "mdm-windows-device-id"},
		{"name": "mdm-windows-hostname2", "data": "mdm-windows-device-id2"},
	}))
	require.False(t, ds.UpdateMDMWindowsEnrollmentsHostUUIDFuncInvoked)

	// happy path
	require.NoError(t, directIngestMDMDeviceIDWindows(ctx, logger, host, ds, []map[string]string{
		{"name": "mdm-windows-hostname", "data": "mdm-windows-device-id"},
	}))
	require.True(t, ds.UpdateMDMWindowsEnrollmentsHostUUIDFuncInvoked)
}

func TestDirectIngestWindowsProfiles(t *testing.T) {
	ctx := context.Background()
	logger := log.NewNopLogger()
	ds := new(mock.Store)

	for _, tc := range []struct {
		hostProfiles []*mobius.ExpectedMDMProfile
		want         string
	}{
		{nil, ""},
		{
			[]*mobius.ExpectedMDMProfile{
				{Name: "N1", RawProfile: syncml.ForTestWithData([]syncml.TestCommand{})},
			},
			"",
		},
		{
			[]*mobius.ExpectedMDMProfile{
				{Name: "N1", RawProfile: syncml.ForTestWithData([]syncml.TestCommand{{Verb: "Replace", LocURI: "L1", Data: "D1"}})},
			},
			"SELECT raw_mdm_command_output FROM mdm_bridge WHERE mdm_command_input = '<SyncBody><Get><CmdID>1255198959</CmdID><Item><Target><LocURI>L1</LocURI></Target></Item></Get></SyncBody>';",
		},
		{
			[]*mobius.ExpectedMDMProfile{
				{Name: "N1", RawProfile: syncml.ForTestWithData([]syncml.TestCommand{{Verb: "Add", LocURI: "L1", Data: "D1"}})},
			},
			"SELECT raw_mdm_command_output FROM mdm_bridge WHERE mdm_command_input = '<SyncBody><Get><CmdID>1255198959</CmdID><Item><Target><LocURI>L1</LocURI></Target></Item></Get></SyncBody>';",
		},
		{
			[]*mobius.ExpectedMDMProfile{
				{Name: "N1", RawProfile: syncml.ForTestWithData([]syncml.TestCommand{{Verb: "Replace", LocURI: "L1", Data: "D1"}})},
				{Name: "N2", RawProfile: syncml.ForTestWithData([]syncml.TestCommand{{Verb: "Add", LocURI: "L2", Data: "D2"}})},
				{Name: "N3", RawProfile: syncml.ForTestWithData([]syncml.TestCommand{{Verb: "Replace", LocURI: "L3", Data: "D3"}, {Verb: "Add", LocURI: "L3.1", Data: "D3.1"}})},
			},
			"SELECT raw_mdm_command_output FROM mdm_bridge WHERE mdm_command_input = '<SyncBody><Get><CmdID>1255198959</CmdID><Item><Target><LocURI>L1</LocURI></Target></Item></Get><Get><CmdID>2736786183</CmdID><Item><Target><LocURI>L2</LocURI></Target></Item></Get><Get><CmdID>894211447</CmdID><Item><Target><LocURI>L3</LocURI></Target></Item></Get><Get><CmdID>3410477854</CmdID><Item><Target><LocURI>L3.1</LocURI></Target></Item></Get></SyncBody>';",
		},
	} {

		ds.GetHostMDMProfilesExpectedForVerificationFunc = func(ctx context.Context, host *mobius.Host) (map[string]*mobius.ExpectedMDMProfile, error) {
			result := map[string]*mobius.ExpectedMDMProfile{}
			for _, p := range tc.hostProfiles {
				result[p.Name] = p
			}
			return result, nil
		}
		ds.ExpandEmbeddedSecretsFunc = func(ctx context.Context, secret string) (string, error) {
			return secret, nil
		}

		gotQuery, _ := buildConfigProfilesWindowsQuery(ctx, logger, &mobius.Host{}, ds)
		if tc.want != "" {
			require.Contains(t, gotQuery, "SELECT raw_mdm_command_output FROM mdm_bridge WHERE mdm_command_input =")
			re := regexp.MustCompile(`'<(.*?)>'`)
			gotMatches := re.FindStringSubmatch(gotQuery)
			require.NotEmpty(t, gotMatches)
			wantMatches := re.FindStringSubmatch(tc.want)
			require.NotEmpty(t, wantMatches)

			var extractedStruct, expectedStruct mobius.SyncBody
			err := xml.Unmarshal([]byte(gotMatches[0]), &extractedStruct)
			require.NoError(t, err)

			err = xml.Unmarshal([]byte(wantMatches[0]), &expectedStruct)
			require.NoError(t, err)

			require.ElementsMatch(t, expectedStruct.Get, extractedStruct.Get)
		} else {
			require.Equal(t, gotQuery, tc.want)
		}
	}
}

func TestShouldRemoveSoftware(t *testing.T) {
	tests := []struct {
		name string
		want bool
		s    *mobius.Software
		h    *mobius.Host
	}{
		{
			name: "parallels windows software on MacOS host",
			want: true,
			h:    &mobius.Host{Platform: "darwin"},
			s:    &mobius.Software{BundleIdentifier: "com.parallels.winapp.notepad", Name: "Notepad.app"},
		},
		{
			name: "regular macos software",
			want: false,
			h:    &mobius.Host{Platform: "darwin"},
			s:    &mobius.Software{BundleIdentifier: "com.apple.dock", Name: "Dock.app"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, shouldRemoveSoftware(tt.h, tt.s))
		})
	}
}

func TestIngestNetworkInterface(t *testing.T) {
	t.Parallel()

	// NOTE: It was decided that we should allow ingesting private IPs on the PublicIP field,
	// see https://github.com/notawar/mobius/issues/11102.
	for _, tc := range []struct {
		name  string
		ip    string
		valid bool
	}{
		{"public IPv6", "598b:6910:e935:63ff:54db:1753:9c01:4c84", true},
		{"private IPv6", "fd42:fdaa:1234:5678::1a2b", true},
		{"public IPv4", "190.18.97.12", true},
		{"private IPv4", "127.0.0.1", true},
		{"IP could not be determined", "", true},
		{"invalid value ends up in the context", "invalid-ip", false},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			h := mobius.Host{PublicIP: "190.18.97.3"} // set to some old value that should always be overridden
			err := ingestNetworkInterface(publicip.NewContext(context.Background(), tc.ip), log.NewNopLogger(), &h, nil)
			require.NoError(t, err)
			if tc.valid {
				require.Equal(t, tc.ip, h.PublicIP)
			} else {
				require.Empty(t, h.PublicIP)
			}
		})
	}

	t.Run("primaryIP and primaryMAC", func(t *testing.T) {
		h := mobius.Host{PublicIP: "190.18.97.3"} // set to some old value that should always be overridden
		ip := "10.0.0.1"
		var b bytes.Buffer
		logger := log.NewLogfmtLogger(&b)

		// Happy path
		rows := []map[string]string{
			{"address": "address", "mac": "mac"},
		}
		err := ingestNetworkInterface(publicip.NewContext(context.Background(), ip), logger, &h, rows)
		require.NoError(t, err)
		assert.Equal(t, ip, h.PublicIP)
		assert.Equal(t, "mac", h.PrimaryMac)
		assert.Equal(t, "address", h.PrimaryIP)
		assert.Empty(t, b.String())

		// No rows
		b.Reset()
		h = mobius.Host{PublicIP: "190.18.97.3"}
		err = ingestNetworkInterface(publicip.NewContext(context.Background(), ip), logger, &h, []map[string]string{})
		require.NoError(t, err)
		assert.Equal(t, ip, h.PublicIP)
		assert.Empty(t, h.PrimaryMac)
		assert.Empty(t, h.PrimaryIP)
		assert.Contains(t, b.String(), "did not find a private IP address")

		// Too many rows
		b.Reset()
		h = mobius.Host{PublicIP: "190.18.97.3"}
		rows = []map[string]string{
			{"address": "address", "mac": "mac"},
			{"address": "address2", "mac": "mac2"},
		}
		err = ingestNetworkInterface(publicip.NewContext(context.Background(), ip), logger, &h, rows)
		require.NoError(t, err)
		assert.Equal(t, ip, h.PublicIP)
		assert.Empty(t, h.PrimaryMac)
		assert.Empty(t, h.PrimaryIP)
		assert.Contains(t, b.String(), "expected single result")
	})
}

func TestDirectIngestHostCertificates(t *testing.T) {
	ds := new(mock.Store)
	ctx := context.Background()
	logger := log.NewNopLogger()
	host := &mobius.Host{ID: 1, UUID: "host-uuid"}

	row1 := map[string]string{
		"ca":                "0",
		"common_name":       "Cert 1 Common Name",
		"issuer":            "/C=US/O=Issuer 1 Inc./CN=Issuer 1 Common Name",
		"subject":           "/C=US/O=Subject 1 Inc./OU=Subject 1 Org Unit/CN=Subject 1 Common Name",
		"key_algorithm":     "rsaEncryption",
		"key_strength":      "2048",
		"key_usage":         "Data Encipherment, Key Encipherment, Digital Signature",
		"serial":            "123abc",
		"signing_algorithm": "sha256WithRSAEncryption",
		"not_valid_after":   "1822755797",
		"not_valid_before":  "1770228826",
		"sha1":              "9c1e9c00d8120c1a9d96274d2a17c38ffa30fd31",
		"source":            "user",
		"path":              "/Users/mna/Library/Keychains/login.keychain-db",
	}

	// row2 will not be ingeted because of the issue field containing an extra /
	row2 := map[string]string{
		"ca":                "1",
		"common_name":       "Cert 2 Common Name",
		"issuer":            `/C=US/O=Issuer 2 Inc.\/foobar/CN=Issuer 2 Common Name`,
		"subject":           "/C=US/O=Subject 1 Inc./OU=Subject 1 Org Unit/CN=Subject 1 Common Name",
		"key_algorithm":     "rsaEncryption",
		"key_strength":      "2048",
		"key_usage":         "Data Encipherment, Key Encipherment, Digital Signature",
		"serial":            "123abcd",
		"signing_algorithm": "sha256WithRSAEncryption",
		"not_valid_after":   "1822755797",
		"not_valid_before":  "1770228826",
		"sha1":              "9c1e9c00d8120c1a9d96274d2a17c38ffa30fd32",
		"source":            "system",
		"path":              "/Library/Keychains/System.keychain",
	}

	ds.UpdateHostCertificatesFunc = func(ctx context.Context, hostID uint, hostUUID string, certs []*mobius.HostCertificateRecord) error {
		require.Equal(t, host.ID, hostID)
		require.Equal(t, host.UUID, hostUUID)
		require.Len(t, certs, 1)
		require.Equal(t, "9c1e9c00d8120c1a9d96274d2a17c38ffa30fd31", hex.EncodeToString(certs[0].SHA1Sum))
		require.Equal(t, "Cert 1 Common Name", certs[0].CommonName)
		require.Equal(t, "Subject 1 Common Name", certs[0].SubjectCommonName)
		require.Equal(t, "Subject 1 Inc.", certs[0].SubjectOrganization)
		require.Equal(t, "Subject 1 Org Unit", certs[0].SubjectOrganizationalUnit)
		require.Equal(t, "US", certs[0].SubjectCountry)
		require.Equal(t, "Issuer 1 Common Name", certs[0].IssuerCommonName)
		require.Equal(t, "Issuer 1 Inc.", certs[0].IssuerOrganization)
		require.Empty(t, certs[0].IssuerOrganizationalUnit)
		require.Equal(t, "US", certs[0].IssuerCountry)
		require.Equal(t, "rsaEncryption", certs[0].KeyAlgorithm)
		require.Equal(t, 2048, certs[0].KeyStrength)
		require.Equal(t, "Data Encipherment, Key Encipherment, Digital Signature", certs[0].KeyUsage)
		require.Equal(t, "123abc", certs[0].Serial)
		require.Equal(t, "sha256WithRSAEncryption", certs[0].SigningAlgorithm)
		require.Equal(t, int64(1822755797), certs[0].NotValidAfter.Unix())
		require.Equal(t, int64(1770228826), certs[0].NotValidBefore.Unix())
		require.False(t, certs[0].CertificateAuthority)
		require.EqualValues(t, "user", certs[0].Source)
		require.Equal(t, "mna", certs[0].Username)

		return nil
	}

	err := directIngestHostCertificates(ctx, logger, host, ds, []map[string]string{row2, row1})
	require.NoError(t, err)
	require.True(t, ds.UpdateHostCertificatesFuncInvoked)
}

func TestGenerateSQLForAllExists(t *testing.T) {
	// Combine two queries
	query1 := "SELECT 1 WHERE foo = bar"
	query2 := "SELECT 1 WHERE baz = qux"
	sql := generateSQLForAllExists(query1, query2)
	assert.Equal(t, "SELECT 1 WHERE EXISTS (SELECT 1 WHERE foo = bar) AND EXISTS (SELECT 1 WHERE baz = qux)", sql)

	// Default
	sql = generateSQLForAllExists()
	require.Equal(t, "SELECT 0 LIMIT 0", sql)

	// sanitize semicolons from subqueries
	query1 = "SELECT 1 WHERE foo = bar;"
	query2 = "SELECT 1 WHERE baz = qux;"
	sql = generateSQLForAllExists(query1, query2)
	assert.Equal(t, "SELECT 1 WHERE EXISTS (SELECT 1 WHERE foo = bar) AND EXISTS (SELECT 1 WHERE baz = qux)", sql)

	// sanitize only trailing semicolons
	query1 = "SELECT 1 WHERE foo = 'ba;r';"
	query2 = "SELECT 1 WHERE baz = 'qu;x';;; "
	sql = generateSQLForAllExists(query1, query2)
	assert.Equal(t, "SELECT 1 WHERE EXISTS (SELECT 1 WHERE foo = 'ba;r') AND EXISTS (SELECT 1 WHERE baz = 'qu;x')", sql)
}

func TestLuksVerifyQueryDiscovery(t *testing.T) {
	lsblkTbl := "SELECT 1 FROM osquery_registry WHERE active = true AND registry = 'table' AND name = 'lsblk'"
	cryptsetupLuksSaltTbl := "SELECT 1 FROM osquery_registry WHERE active = true AND registry = 'table' AND name = 'cryptsetup_luks_salt'"

	require.Equal(t,
		fmt.Sprintf("SELECT 1 WHERE EXISTS (%s) AND EXISTS (%s);", lsblkTbl, cryptsetupLuksSaltTbl),
		luksVerifyQuery.Discovery,
	)
}

func TestLuksVerifyQueryIngester(t *testing.T) {
	decrypter := func(encrypted string) (string, error) {
		return encrypted, nil
	}
	ctx := context.Background()
	logger := log.NewNopLogger()

	nonLUKSHost := &mobius.Host{ID: 1, Platform: "skynet"}
	luksHost := &mobius.Host{ID: 1, Platform: "ubuntu"}

	testCases := []struct {
		name         string
		rows         []map[string]string
		err          error
		host         *mobius.Host
		setUp        func(t *testing.T, ds *mock.Store)
		expectations func(t *testing.T, ds *mock.Store, err error)
	}{
		{
			name: "No results",
			expectations: func(t *testing.T, ds *mock.Store, err error) {
				require.NoError(t, err)
				require.False(t, ds.GetHostDiskEncryptionKeyFuncInvoked)
				require.False(t, ds.DeleteLUKSDataFuncInvoked)
			},
		},
		{
			name: "host is not LUKS capable",
			host: nonLUKSHost,
			rows: []map[string]string{
				{
					"key_slot": "0",
					"salt":     "some salty bits",
				},
			},
			expectations: func(t *testing.T, ds *mock.Store, err error) {
				require.NoError(t, err)
				require.False(t, ds.GetHostDiskEncryptionKeyFuncInvoked)
				require.False(t, ds.DeleteLUKSDataFuncInvoked)
			},
		},
		{
			name: "disk encryption entry not found on DB",
			host: luksHost,
			rows: []map[string]string{
				{
					"key_slot": "0",
					"salt":     "some salty bits",
				},
			},
			setUp: func(t *testing.T, ds *mock.Store) {
				ds.GetHostDiskEncryptionKeyFunc = func(ctx context.Context, hostID uint) (*mobius.HostDiskEncryptionKey, error) {
					require.Equal(t, uint(1), hostID)
					return nil, common_mysql.NotFound("HostDiskEncryptionKey")
				}
			},
			expectations: func(t *testing.T, ds *mock.Store, err error) {
				require.NoError(t, err)
				require.False(t, ds.DeleteLUKSDataFuncInvoked)
			},
		},
		{
			name: "error is thrown while getting the host disk encryption key",
			host: luksHost,
			rows: []map[string]string{
				{
					"key_slot": "0",
					"salt":     "some salty bits",
				},
			},
			setUp: func(t *testing.T, ds *mock.Store) {
				ds.GetHostDiskEncryptionKeyFunc = func(ctx context.Context, hostID uint) (*mobius.HostDiskEncryptionKey, error) {
					require.Equal(t, uint(1), hostID)
					return nil, errors.New("some error")
				}
			},
			expectations: func(t *testing.T, ds *mock.Store, err error) {
				require.Error(t, err)
				require.False(t, ds.DeleteLUKSDataFuncInvoked)
			},
		},
		{
			name: "stored key matches the one reported",
			host: luksHost,
			rows: []map[string]string{
				{
					"key_slot": "0",
					"salt":     "some salty bits",
				},
			},
			setUp: func(t *testing.T, ds *mock.Store) {
				ds.GetHostDiskEncryptionKeyFunc = func(ctx context.Context, hostID uint) (*mobius.HostDiskEncryptionKey, error) {
					require.Equal(t, uint(1), hostID)
					return &mobius.HostDiskEncryptionKey{
						KeySlot:             ptr.Uint(0),
						Base64EncryptedSalt: "some salty bits",
					}, nil
				}
			},
			expectations: func(t *testing.T, ds *mock.Store, err error) {
				require.NoError(t, err)
				require.False(t, ds.DeleteLUKSDataFuncInvoked)
			},
		},
		{
			name: "stored key does not match the one reported",
			host: luksHost,
			rows: []map[string]string{
				{
					"key_slot": "0",
					"salt":     "some sour bits",
				},
				{
					"key_slot": "1",
					"salt":     "some spicy bits",
				},
			},
			setUp: func(t *testing.T, ds *mock.Store) {
				ds.GetHostDiskEncryptionKeyFunc = func(ctx context.Context, hostID uint) (*mobius.HostDiskEncryptionKey, error) {
					require.Equal(t, uint(1), hostID)
					return &mobius.HostDiskEncryptionKey{
						KeySlot:             ptr.Uint(0),
						Base64EncryptedSalt: base64.StdEncoding.EncodeToString([]byte("some salty bits")),
					}, nil
				}
				ds.DeleteLUKSDataFunc = func(ctx context.Context, hostID uint, keySlot uint) error {
					require.Equal(t, uint(1), hostID)
					return nil
				}
			},
			expectations: func(t *testing.T, ds *mock.Store, err error) {
				require.NoError(t, err)
				require.True(t, ds.DeleteLUKSDataFuncInvoked)
			},
		},
	}

	sut := luksVerifyQueryIngester(decrypter)
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ds := new(mock.Store)
			if tc.setUp != nil {
				tc.setUp(t, ds)
			}
			tc.expectations(t, ds, sut(ctx, logger, tc.host, ds, tc.rows))
		})
	}
}

func TestUserIngestNoUID(t *testing.T) {
	ctx := context.Background()
	host := mobius.Host{ID: 1}
	ds := new(mock.Store)
	savedUsers := 0

	ds.SaveHostUsersFunc = func(ctx context.Context, hostID uint, users []mobius.HostUser) error {
		savedUsers = len(users)
		return nil
	}

	input := []map[string]string{
		{"uid": "1000", "shell": "/bin/sh"},
		// Missing uid
		{"shell": "/bin/sh"},
	}

	err := usersQuery.DirectIngestFunc(ctx, nil, &host, ds, input)
	require.NoError(t, err)
	// Saved the good user, ignored the one missing a uid
	require.Equal(t, 1, savedUsers)
}
