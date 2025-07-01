package mobiuscli

import (
	"context"
	"testing"
	"time"

	"github.com/notawar/mobius/v4/cmd/mobiuscli/mobiuscli/testing_utils"
	"github.com/notawar/mobius set/v4/server/mobius"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHostTransferFlagChecks(t *testing.T) {
	testing_utils.RunServerWithMockedDS(t)

	RunAppCheckErr(t,
		[]string{"hosts", "transfer", "--team", "team1", "--hosts", "host1", "--label", "AAA"},
		"--hosts cannot be used along side any other flag",
	)
	RunAppCheckErr(t,
		[]string{"hosts", "transfer", "--team", "team1"},
		"You need to define either --hosts, or one or more of --label, --status, --search_query",
	)
}

func TestHostsTransferByHosts(t *testing.T) {
	_, ds := testing_utils.RunServerWithMockedDS(t)

	ds.HostByIdentifierFunc = func(ctx context.Context, identifier string) (*mobius.Host, error) {
		require.Equal(t, "host1", identifier)
		return &mobius.Host{ID: 42}, nil
	}

	ds.TeamByNameFunc = func(ctx context.Context, name string) (*mobius.Team, error) {
		require.Equal(t, "team1", name)
		return &mobius.Team{ID: 99, Name: "team1"}, nil
	}

	ds.AddHostsToTeamFunc = func(ctx context.Context, teamID *uint, hostIDs []uint) error {
		require.NotNil(t, teamID)
		require.Equal(t, uint(99), *teamID)
		require.Equal(t, []uint{42}, hostIDs)
		return nil
	}

	ds.BulkSetPendingMDMHostProfilesFunc = func(ctx context.Context, hostIDs, teamIDs []uint, profileUUIDs, uuids []string,
	) (updates mobius.MDMProfilesUpdates, err error) {
		return mobius.MDMProfilesUpdates{}, nil
	}

	ds.ListMDMAppleDEPSerialsInHostIDsFunc = func(ctx context.Context, hostIDs []uint) ([]string, error) {
		return nil, nil
	}

	ds.TeamFunc = func(ctx context.Context, tid uint) (*mobius.Team, error) {
		return &mobius.Team{ID: tid, Name: "team1"}, nil
	}

	ds.NewActivityFunc = func(
		ctx context.Context, user *mobius.User, activity mobius.ActivityDetails, details []byte, createdAt time.Time,
	) error {
		require.IsType(t, mobius.ActivityTypeTransferredHostsToTeam{}, activity)
		return nil
	}

	ds.ListHostsLiteByIDsFunc = func(ctx context.Context, ids []uint) ([]*mobius.Host, error) {
		return nil, nil
	}

	assert.Equal(t, "", RunAppForTest(t, []string{"hosts", "transfer", "--team", "team1", "--hosts", "host1"}))
	assert.True(t, ds.AddHostsToTeamFuncInvoked)
	assert.True(t, ds.NewActivityFuncInvoked)

	// Now, transfer out of the team.
	ds.AddHostsToTeamFunc = func(ctx context.Context, teamID *uint, hostIDs []uint) error {
		assert.Nil(t, teamID)
		assert.Equal(t, []uint{42}, hostIDs)
		return nil
	}
	ds.NewActivityFuncInvoked = false
	ds.AddHostsToTeamFuncInvoked = false
	assert.Equal(t, "", RunAppForTest(t, []string{"hosts", "transfer", "--team", "", "--hosts", "host1"}))
	assert.True(t, ds.AddHostsToTeamFuncInvoked)
	assert.True(t, ds.NewActivityFuncInvoked)
}

func TestHostsTransferByLabel(t *testing.T) {
	_, ds := testing_utils.RunServerWithMockedDS(t)

	ds.HostByIdentifierFunc = func(ctx context.Context, identifier string) (*mobius.Host, error) {
		require.Equal(t, "host1", identifier)
		return &mobius.Host{ID: 42}, nil
	}

	ds.TeamByNameFunc = func(ctx context.Context, name string) (*mobius.Team, error) {
		require.Equal(t, "team1", name)
		return &mobius.Team{ID: 99, Name: "team1"}, nil
	}

	ds.LabelIDsByNameFunc = func(ctx context.Context, labels []string) (map[string]uint, error) {
		require.Equal(t, []string{"label1"}, labels)
		return map[string]uint{"label1": uint(11)}, nil
	}

	ds.ListHostsInLabelFunc = func(ctx context.Context, filter mobius.TeamFilter, lid uint, opt mobius.HostListOptions) ([]*mobius.Host, error) {
		require.Equal(t, mobius.HostStatus(""), opt.StatusFilter)
		require.Equal(t, uint(11), lid)
		return []*mobius.Host{{ID: 32}, {ID: 12}}, nil
	}

	ds.AddHostsToTeamFunc = func(ctx context.Context, teamID *uint, hostIDs []uint) error {
		require.NotNil(t, teamID)
		require.Equal(t, uint(99), *teamID)
		require.Equal(t, []uint{32, 12}, hostIDs)
		return nil
	}

	ds.BulkSetPendingMDMHostProfilesFunc = func(ctx context.Context, hostIDs, teamIDs []uint, profileUUIDs, uuids []string,
	) (updates mobius.MDMProfilesUpdates, err error) {
		return mobius.MDMProfilesUpdates{}, nil
	}

	ds.ListMDMAppleDEPSerialsInHostIDsFunc = func(ctx context.Context, hostIDs []uint) ([]string, error) {
		return nil, nil
	}

	ds.TeamFunc = func(ctx context.Context, tid uint) (*mobius.Team, error) {
		return &mobius.Team{ID: tid, Name: "team1"}, nil
	}

	ds.NewActivityFunc = func(
		ctx context.Context, user *mobius.User, activity mobius.ActivityDetails, details []byte, createdAt time.Time,
	) error {
		require.IsType(t, mobius.ActivityTypeTransferredHostsToTeam{}, activity)
		return nil
	}

	ds.ListHostsLiteByIDsFunc = func(ctx context.Context, ids []uint) ([]*mobius.Host, error) {
		return nil, nil
	}

	assert.Equal(t, "", RunAppForTest(t, []string{"hosts", "transfer", "--team", "team1", "--label", "label1"}))
	require.True(t, ds.NewActivityFuncInvoked)
	assert.True(t, ds.AddHostsToTeamFuncInvoked)

	// Now, transfer out of the team.
	ds.AddHostsToTeamFunc = func(ctx context.Context, teamID *uint, hostIDs []uint) error {
		assert.Nil(t, teamID)
		require.Equal(t, []uint{32, 12}, hostIDs)
		return nil
	}
	ds.NewActivityFuncInvoked = false
	ds.AddHostsToTeamFuncInvoked = false
	assert.Equal(t, "", RunAppForTest(t, []string{"hosts", "transfer", "--team", "", "--label", "label1"}))
	assert.True(t, ds.AddHostsToTeamFuncInvoked)
	assert.True(t, ds.NewActivityFuncInvoked)
}

func TestHostsTransferByStatus(t *testing.T) {
	_, ds := testing_utils.RunServerWithMockedDS(t)

	ds.HostByIdentifierFunc = func(ctx context.Context, identifier string) (*mobius.Host, error) {
		require.Equal(t, "host1", identifier)
		return &mobius.Host{ID: 42}, nil
	}

	ds.TeamByNameFunc = func(ctx context.Context, name string) (*mobius.Team, error) {
		require.Equal(t, "team1", name)
		return &mobius.Team{ID: 99, Name: "team1"}, nil
	}

	ds.LabelIDsByNameFunc = func(ctx context.Context, labels []string) (map[string]uint, error) {
		require.Equal(t, []string{"label1"}, labels)
		return map[string]uint{"label1": uint(11)}, nil
	}

	ds.ListHostsFunc = func(ctx context.Context, filter mobius.TeamFilter, opt mobius.HostListOptions) ([]*mobius.Host, error) {
		require.Equal(t, mobius.StatusOnline, opt.StatusFilter)
		return []*mobius.Host{{ID: 32}, {ID: 12}}, nil
	}

	ds.AddHostsToTeamFunc = func(ctx context.Context, teamID *uint, hostIDs []uint) error {
		require.NotNil(t, teamID)
		require.Equal(t, uint(99), *teamID)
		require.Equal(t, []uint{32, 12}, hostIDs)
		return nil
	}

	ds.BulkSetPendingMDMHostProfilesFunc = func(ctx context.Context, hostIDs, teamIDs []uint, profileUUIDs, uuids []string,
	) (updates mobius.MDMProfilesUpdates, err error) {
		return mobius.MDMProfilesUpdates{}, nil
	}

	ds.ListMDMAppleDEPSerialsInHostIDsFunc = func(ctx context.Context, hostIDs []uint) ([]string, error) {
		return nil, nil
	}

	ds.TeamFunc = func(ctx context.Context, tid uint) (*mobius.Team, error) {
		return &mobius.Team{ID: tid, Name: "team1"}, nil
	}

	ds.NewActivityFunc = func(
		ctx context.Context, user *mobius.User, activity mobius.ActivityDetails, details []byte, createdAt time.Time,
	) error {
		require.IsType(t, mobius.ActivityTypeTransferredHostsToTeam{}, activity)
		return nil
	}

	ds.ListHostsLiteByIDsFunc = func(ctx context.Context, ids []uint) ([]*mobius.Host, error) {
		return nil, nil
	}

	assert.Equal(t, "", RunAppForTest(t,
		[]string{"hosts", "transfer", "--team", "team1", "--status", "online"}))
	require.True(t, ds.NewActivityFuncInvoked)
}

func TestHostsTransferByStatusAndSearchQuery(t *testing.T) {
	_, ds := testing_utils.RunServerWithMockedDS(t)

	ds.HostByIdentifierFunc = func(ctx context.Context, identifier string) (*mobius.Host, error) {
		require.Equal(t, "host1", identifier)
		return &mobius.Host{ID: 42}, nil
	}

	ds.TeamByNameFunc = func(ctx context.Context, name string) (*mobius.Team, error) {
		require.Equal(t, "team1", name)
		return &mobius.Team{ID: 99, Name: "team1"}, nil
	}

	ds.LabelIDsByNameFunc = func(ctx context.Context, labels []string) (map[string]uint, error) {
		require.Equal(t, []string{"label1"}, labels)
		return map[string]uint{"label1": uint(11)}, nil
	}

	ds.ListHostsFunc = func(ctx context.Context, filter mobius.TeamFilter, opt mobius.HostListOptions) ([]*mobius.Host, error) {
		require.Equal(t, mobius.StatusOnline, opt.StatusFilter)
		require.Equal(t, "somequery", opt.MatchQuery)
		return []*mobius.Host{{ID: 32}, {ID: 12}}, nil
	}

	ds.AddHostsToTeamFunc = func(ctx context.Context, teamID *uint, hostIDs []uint) error {
		require.NotNil(t, teamID)
		require.Equal(t, uint(99), *teamID)
		require.Equal(t, []uint{32, 12}, hostIDs)
		return nil
	}

	ds.BulkSetPendingMDMHostProfilesFunc = func(ctx context.Context, hostIDs, teamIDs []uint, profileUUIDs, uuids []string,
	) (updates mobius.MDMProfilesUpdates, err error) {
		return mobius.MDMProfilesUpdates{}, nil
	}

	ds.ListMDMAppleDEPSerialsInHostIDsFunc = func(ctx context.Context, hostIDs []uint) ([]string, error) {
		return nil, nil
	}

	ds.TeamFunc = func(ctx context.Context, tid uint) (*mobius.Team, error) {
		return &mobius.Team{ID: tid, Name: "team1"}, nil
	}

	ds.NewActivityFunc = func(
		ctx context.Context, user *mobius.User, activity mobius.ActivityDetails, details []byte, createdAt time.Time,
	) error {
		require.IsType(t, mobius.ActivityTypeTransferredHostsToTeam{}, activity)
		return nil
	}

	ds.ListHostsLiteByIDsFunc = func(ctx context.Context, ids []uint) ([]*mobius.Host, error) {
		return nil, nil
	}

	assert.Equal(t, "", RunAppForTest(t,
		[]string{"hosts", "transfer", "--team", "team1", "--status", "online", "--search_query", "somequery"}))
	require.True(t, ds.NewActivityFuncInvoked)
}
