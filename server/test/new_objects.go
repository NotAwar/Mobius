package test

import (
	"context"
	"testing"
	"time"

	"github.com/notawar/mobius/server"

	"github.com/notawar/mobius/server/mobius"
	"github.com/notawar/mobius/server/ptr"
	"github.com/stretchr/testify/require"
)

func NewQueryWithSchedule(t *testing.T, ds mobius.Datastore, teamID *uint, name, q string, authorID uint, saved bool, interval uint, automationsEnabled bool) *mobius.Query {
	authorPtr := &authorID
	if authorID == 0 {
		authorPtr = nil
	}
	query, err := ds.NewQuery(context.Background(), &mobius.Query{
		Name:               name,
		Query:              q,
		AuthorID:           authorPtr,
		Saved:              saved,
		TeamID:             teamID,
		Interval:           interval,
		AutomationsEnabled: automationsEnabled,
		Logging:            mobius.LoggingSnapshot,
	})
	require.NoError(t, err)

	// Loading gives us the timestamps
	query, err = ds.Query(context.Background(), query.ID)
	require.NoError(t, err)

	return query
}

func NewQuery(t *testing.T, ds mobius.Datastore, teamID *uint, name, q string, authorID uint, saved bool) *mobius.Query {
	return NewQueryWithSchedule(t, ds, teamID, name, q, authorID, saved, 0, false)
}

func NewPack(t *testing.T, ds mobius.Datastore, name string) *mobius.Pack {
	err := ds.ApplyPackSpecs(context.Background(), []*mobius.PackSpec{{Name: name}})
	require.Nil(t, err)

	// Loading gives us the timestamps
	pack, ok, err := ds.PackByName(context.Background(), name)
	require.True(t, ok)
	require.NoError(t, err)

	return pack
}

func NewCampaign(t *testing.T, ds mobius.Datastore, queryID uint, status mobius.DistributedQueryStatus, now time.Time) *mobius.DistributedQueryCampaign {
	campaign, err := ds.NewDistributedQueryCampaign(context.Background(), &mobius.DistributedQueryCampaign{
		UpdateCreateTimestamps: mobius.UpdateCreateTimestamps{
			CreateTimestamp: mobius.CreateTimestamp{
				CreatedAt: now,
			},
		},
		QueryID: queryID,
		Status:  status,
	})
	require.NoError(t, err)

	// Loading gives us the timestamps
	campaign, err = ds.DistributedQueryCampaign(context.Background(), campaign.ID)
	require.NoError(t, err)

	return campaign
}

func AddHostToCampaign(t *testing.T, ds mobius.Datastore, campaignID, hostID uint) {
	_, err := ds.NewDistributedQueryCampaignTarget(
		context.Background(),
		&mobius.DistributedQueryCampaignTarget{
			Type:                       mobius.TargetHost,
			TargetID:                   hostID,
			DistributedQueryCampaignID: campaignID,
		})
	require.NoError(t, err)
}

func AddLabelToCampaign(t *testing.T, ds mobius.Datastore, campaignID, labelID uint) {
	_, err := ds.NewDistributedQueryCampaignTarget(
		context.Background(),
		&mobius.DistributedQueryCampaignTarget{
			Type:                       mobius.TargetLabel,
			TargetID:                   labelID,
			DistributedQueryCampaignID: campaignID,
		})
	require.NoError(t, err)
}

func AddAllHostsLabel(t *testing.T, ds mobius.Datastore) {
	_, err := ds.NewLabel(
		context.Background(),
		&mobius.Label{
			Name:                "All Hosts",
			Query:               "select 1",
			LabelType:           mobius.LabelTypeBuiltIn,
			LabelMembershipType: mobius.LabelMembershipTypeManual,
		},
	)
	require.NoError(t, err)
}

func AddBuiltinLabels(t *testing.T, ds mobius.Datastore) {
	builtins := []*mobius.Label{
		{
			Name:                "All Hosts",
			Query:               "select 1",
			LabelType:           mobius.LabelTypeBuiltIn,
			LabelMembershipType: mobius.LabelMembershipTypeDynamic,
		},
		{
			Name:                "macOS",
			Query:               "select 1 from os_version where platform = 'darwin';",
			LabelType:           mobius.LabelTypeBuiltIn,
			LabelMembershipType: mobius.LabelMembershipTypeDynamic,
		},
		{
			Name:                "Ubuntu Linux",
			Query:               "select 1 from os_version where platform = 'ubuntu';",
			LabelType:           mobius.LabelTypeBuiltIn,
			LabelMembershipType: mobius.LabelMembershipTypeDynamic,
		},
		{
			Name:                "CentOS Linux",
			Query:               "select 1 from os_version where platform = 'centos' or name like '%centos%';",
			LabelType:           mobius.LabelTypeBuiltIn,
			LabelMembershipType: mobius.LabelMembershipTypeDynamic,
		},
		{
			Name:                "MS Windows",
			Query:               "select 1 from os_version where platform = 'windows';",
			LabelType:           mobius.LabelTypeBuiltIn,
			LabelMembershipType: mobius.LabelMembershipTypeDynamic,
		},
		{
			Name:                "Red Hat Linux",
			Query:               "SELECT 1 FROM os_version WHERE name LIKE '%red hat%'",
			LabelType:           mobius.LabelTypeBuiltIn,
			LabelMembershipType: mobius.LabelMembershipTypeDynamic,
		},
		{
			Name:                "All Linux",
			Query:               "SELECT 1 FROM osquery_info WHERE build_platform LIKE '%ubuntu%' OR build_distro LIKE '%centos%';",
			LabelType:           mobius.LabelTypeBuiltIn,
			LabelMembershipType: mobius.LabelMembershipTypeDynamic,
		},
		{
			Name:                "chrome",
			Query:               "select 1 from os_version where platform = 'chrome';",
			LabelType:           mobius.LabelTypeBuiltIn,
			LabelMembershipType: mobius.LabelMembershipTypeDynamic,
		},
		{
			Name:                mobius.BuiltinLabelMacOS14Plus,
			Query:               "select 1 from os_version where platform = 'darwin' and major >= 14;",
			LabelType:           mobius.LabelTypeBuiltIn,
			LabelMembershipType: mobius.LabelMembershipTypeDynamic,
		},
		{
			Name:                "iOS",
			Platform:            "ios",
			Query:               "",
			LabelType:           mobius.LabelTypeBuiltIn,
			LabelMembershipType: mobius.LabelMembershipTypeManual,
		},
		{
			Name:                "iPadOS",
			Platform:            "ipados",
			Query:               "",
			LabelType:           mobius.LabelTypeBuiltIn,
			LabelMembershipType: mobius.LabelMembershipTypeManual,
		},
		{
			Name:                "Fedora Linux",
			Platform:            "rhel",
			Query:               "select 1 from os_version where name = 'Fedora Linux';",
			LabelType:           mobius.LabelTypeBuiltIn,
			LabelMembershipType: mobius.LabelMembershipTypeDynamic,
		},
		{
			Name:                "Android",
			Platform:            "android",
			Query:               "",
			LabelType:           mobius.LabelTypeBuiltIn,
			LabelMembershipType: mobius.LabelMembershipTypeManual,
		},
	}

	names := mobius.ReservedLabelNames()
	require.Equal(t, len(builtins), len(names))
	storedByName := map[string]*mobius.Label{}
	for _, b := range builtins {
		stored, err := ds.NewLabel(context.Background(), b)
		require.NoError(t, err)
		storedByName[stored.Name] = stored
	}
	require.Len(t, storedByName, len(builtins))

	for name := range names {
		_, ok := storedByName[name]
		require.True(t, ok, "expected label %s to be created", name)
	}
}

// NewHostOption is an Option for the NewHost function.
type NewHostOption func(*mobius.Host)

// WithComputerName sets the ComputerName in NewHost.
func WithComputerName(s string) NewHostOption {
	return func(h *mobius.Host) {
		h.ComputerName = s
	}
}

func WithPlatform(s string) NewHostOption {
	return func(h *mobius.Host) {
		h.Platform = s
	}
}

func WithOSVersion(s string) NewHostOption {
	return func(h *mobius.Host) {
		h.OSVersion = s
	}
}

func WithTeamID(teamID uint) NewHostOption {
	return func(h *mobius.Host) {
		h.TeamID = &teamID
	}
}

func NewHost(tb testing.TB, ds mobius.Datastore, name, ip, key, uuid string, now time.Time, options ...NewHostOption) *mobius.Host {
	osqueryHostID, _ := server.GenerateRandomText(10)
	h := &mobius.Host{
		Hostname:        name,
		NodeKey:         &key,
		UUID:            uuid,
		DetailUpdatedAt: now,
		LabelUpdatedAt:  now,
		PolicyUpdatedAt: now,
		SeenTime:        now,
		OsqueryHostID:   &osqueryHostID,
		Platform:        "darwin",
		PublicIP:        ip,
		PrimaryIP:       ip,
	}
	for _, o := range options {
		o(h)
	}
	h, err := ds.NewHost(context.Background(), h)
	require.NoError(tb, err)
	require.NotZero(tb, h.ID)
	require.NoError(tb, ds.MarkHostsSeen(context.Background(), []uint{h.ID}, now))

	return h
}

func NewUser(t *testing.T, ds mobius.Datastore, name, email string, admin bool) *mobius.User {
	role := mobius.RoleObserver
	if admin {
		role = mobius.RoleAdmin
	}
	u, err := ds.NewUser(context.Background(), &mobius.User{
		Password:   []byte("garbage"),
		Salt:       "garbage",
		Name:       name,
		Email:      email,
		GlobalRole: &role,
	})

	require.NoError(t, err)
	require.NotZero(t, u.ID)

	return u
}

func NewScheduledQuery(t *testing.T, ds mobius.Datastore, pid, qid, interval uint, snapshot, removed bool, name string) *mobius.ScheduledQuery {
	sq, err := ds.NewScheduledQuery(context.Background(), &mobius.ScheduledQuery{
		Name:     name,
		PackID:   pid,
		QueryID:  qid,
		Interval: interval,
		Snapshot: &snapshot,
		Removed:  &removed,
		Platform: ptr.String("darwin"),
	})
	require.NoError(t, err)
	require.NotZero(t, sq.ID)

	return sq
}
