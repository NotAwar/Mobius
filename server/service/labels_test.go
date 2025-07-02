package service

import (
	"context"
	"testing"
	"time"

	authz_ctx "github.com/notawar/mobius/server/contexts/authz"
	"github.com/notawar/mobius/server/contexts/viewer"
	"github.com/notawar/mobius/server/datastore/mysql"
	"github.com/notawar/mobius/server/datastore/mysql/common_mysql/testing_utils"
	"github.com/notawar/mobius/server/mobius"
	"github.com/notawar/mobius/server/mock"
	"github.com/notawar/mobius/server/ptr"
	"github.com/notawar/mobius/server/test"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLabelsAuth(t *testing.T) {
	ds := new(mock.Store)
	svc, ctx := newTestService(t, ds, nil, nil)

	ds.NewLabelFunc = func(ctx context.Context, lbl *mobius.Label, opts ...mobius.OptionalArg) (*mobius.Label, error) {
		return lbl, nil
	}
	ds.SaveLabelFunc = func(ctx context.Context, lbl *mobius.Label, filter mobius.TeamFilter) (*mobius.Label, []uint, error) {
		return lbl, nil, nil
	}
	ds.DeleteLabelFunc = func(ctx context.Context, nm string) error {
		return nil
	}
	ds.ApplyLabelSpecsFunc = func(ctx context.Context, specs []*mobius.LabelSpec) error {
		return nil
	}
	ds.LabelFunc = func(ctx context.Context, id uint, filter mobius.TeamFilter) (*mobius.Label, []uint, error) {
		return &mobius.Label{}, nil, nil
	}
	ds.ListLabelsFunc = func(ctx context.Context, filter mobius.TeamFilter, opts mobius.ListOptions) ([]*mobius.Label, error) {
		return nil, nil
	}
	ds.LabelsSummaryFunc = func(ctx context.Context) ([]*mobius.LabelSummary, error) {
		return nil, nil
	}
	ds.ListHostsInLabelFunc = func(ctx context.Context, filter mobius.TeamFilter, lid uint, opts mobius.HostListOptions) ([]*mobius.Host, error) {
		return nil, nil
	}
	ds.GetLabelSpecsFunc = func(ctx context.Context) ([]*mobius.LabelSpec, error) {
		return nil, nil
	}
	ds.GetLabelSpecFunc = func(ctx context.Context, name string) (*mobius.LabelSpec, error) {
		return &mobius.LabelSpec{}, nil
	}

	testCases := []struct {
		name            string
		user            *mobius.User
		shouldFailWrite bool
		shouldFailRead  bool
	}{
		{
			"global admin",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)},
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
			false,
		},
		{
			"team maintainer",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleMaintainer}}},
			false,
			false,
		},
		{
			"team observer",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleObserver}}},
			true,
			false,
		},
	}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			ctx := viewer.NewContext(ctx, viewer.Viewer{User: tt.user})

			_, _, err := svc.NewLabel(ctx, mobius.LabelPayload{Name: t.Name(), Query: `SELECT 1`})
			checkAuthErr(t, tt.shouldFailWrite, err)

			_, _, err = svc.ModifyLabel(ctx, 1, mobius.ModifyLabelPayload{})
			checkAuthErr(t, tt.shouldFailWrite, err)

			err = svc.ApplyLabelSpecs(ctx, []*mobius.LabelSpec{})
			checkAuthErr(t, tt.shouldFailWrite, err)

			_, _, err = svc.GetLabel(ctx, 1)
			checkAuthErr(t, tt.shouldFailRead, err)

			_, err = svc.GetLabelSpecs(ctx)
			checkAuthErr(t, tt.shouldFailRead, err)

			_, err = svc.GetLabelSpec(ctx, "abc")
			checkAuthErr(t, tt.shouldFailRead, err)

			_, err = svc.ListLabels(ctx, mobius.ListOptions{})
			checkAuthErr(t, tt.shouldFailRead, err)

			_, err = svc.LabelsSummary((ctx))
			checkAuthErr(t, tt.shouldFailRead, err)

			_, err = svc.ListHostsInLabel(ctx, 1, mobius.HostListOptions{})
			checkAuthErr(t, tt.shouldFailRead, err)

			err = svc.DeleteLabel(ctx, "abc")
			checkAuthErr(t, tt.shouldFailWrite, err)

			err = svc.DeleteLabelByID(ctx, 1)
			checkAuthErr(t, tt.shouldFailWrite, err)
		})
	}
}

func TestLabelsWithDS(t *testing.T) {
	ds := mysql.CreateMySQLDS(t)

	cases := []struct {
		name string
		fn   func(t *testing.T, ds *mysql.Datastore)
	}{
		{"GetLabel", testLabelsGetLabel},
		{"ListLabels", testLabelsListLabels},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			defer mysql.TruncateTables(t, ds)
			c.fn(t, ds)
		})
	}
}

func testLabelsGetLabel(t *testing.T, ds *mysql.Datastore) {
	svc, ctx := newTestService(t, ds, nil, nil)

	label := &mobius.Label{
		Name:  "foo",
		Query: "select * from foo;",
	}
	label, err := ds.NewLabel(ctx, label)
	assert.Nil(t, err)
	assert.NotZero(t, label.ID)

	labelVerify, _, err := svc.GetLabel(test.UserContext(ctx, test.UserAdmin), label.ID)
	assert.Nil(t, err)
	assert.Equal(t, label.ID, labelVerify.ID)
	assert.Nil(t, label.AuthorID)
}

func testLabelsListLabels(t *testing.T, ds *mysql.Datastore) {
	svc, ctx := newTestService(t, ds, nil, nil)
	require.NoError(t, ds.MigrateData(context.Background()))

	labels, err := svc.ListLabels(test.UserContext(ctx, test.UserAdmin), mobius.ListOptions{Page: 0, PerPage: 1000})
	require.NoError(t, err)
	require.Len(t, labels, 8)

	labelsSummary, err := svc.LabelsSummary(test.UserContext(ctx, test.UserAdmin))
	require.NoError(t, err)
	require.Len(t, labelsSummary, 8)
}

func TestApplyLabelSpecsWithBuiltInLabels(t *testing.T) {
	t.Parallel()
	ds := new(mock.Store)
	user := &mobius.User{
		ID:         3,
		Email:      "foo@bar.com",
		GlobalRole: ptr.String(mobius.RoleAdmin),
	}
	svc, ctx := newTestService(t, ds, nil, nil)
	ctx = viewer.NewContext(ctx, viewer.Viewer{User: user})
	name := "foo"
	description := "bar"
	query := "select * from foo;"
	platform := ""
	labelType := mobius.LabelTypeBuiltIn
	labelMembershipType := mobius.LabelMembershipTypeDynamic
	spec := &mobius.LabelSpec{
		Name:                name,
		Description:         description,
		Query:               query,
		LabelType:           labelType,
		LabelMembershipType: labelMembershipType,
	}

	ds.LabelsByNameFunc = func(ctx context.Context, names []string) (map[string]*mobius.Label, error) {
		return map[string]*mobius.Label{
			name: {
				Name:                name,
				Description:         description,
				Query:               query,
				Platform:            platform,
				LabelType:           labelType,
				LabelMembershipType: labelMembershipType,
			},
		}, nil
	}

	// all good
	err := svc.ApplyLabelSpecs(ctx, []*mobius.LabelSpec{spec})
	require.NoError(t, err)

	const errorMessage = "cannot modify or add built-in label"
	// not ok -- built-in label name doesn't exist
	name = "not-foo"
	err = svc.ApplyLabelSpecs(ctx, []*mobius.LabelSpec{spec})
	assert.ErrorContains(t, err, errorMessage)
	name = "foo"

	// not ok -- description does not match
	description = "not-bar"
	err = svc.ApplyLabelSpecs(ctx, []*mobius.LabelSpec{spec})
	assert.ErrorContains(t, err, errorMessage)
	description = "bar"

	// not ok -- query does not match
	query = "select * from not-foo;"
	err = svc.ApplyLabelSpecs(ctx, []*mobius.LabelSpec{spec})
	assert.ErrorContains(t, err, errorMessage)
	query = "select * from foo;"

	// not ok -- label type does not match
	labelType = mobius.LabelTypeRegular
	err = svc.ApplyLabelSpecs(ctx, []*mobius.LabelSpec{spec})
	assert.ErrorContains(t, err, errorMessage)
	labelType = mobius.LabelTypeBuiltIn

	// not ok -- label membership type does not match
	labelMembershipType = mobius.LabelMembershipTypeManual
	err = svc.ApplyLabelSpecs(ctx, []*mobius.LabelSpec{spec})
	assert.ErrorContains(t, err, errorMessage)
	labelMembershipType = mobius.LabelMembershipTypeDynamic

	// not ok -- DB error
	ds.LabelsByNameFunc = func(ctx context.Context, names []string) (map[string]*mobius.Label, error) {
		return nil, assert.AnError
	}
	err = svc.ApplyLabelSpecs(ctx, []*mobius.LabelSpec{spec})
	assert.ErrorIs(t, err, assert.AnError)
}

func TestLabelsWithReplica(t *testing.T) {
	opts := &testing_utils.DatastoreTestOptions{DummyReplica: true}
	ds := mysql.CreateMySQLDSWithOptions(t, opts)
	defer ds.Close()

	svc, ctx := newTestService(t, ds, nil, nil)
	user, err := ds.NewUser(ctx, &mobius.User{
		Name:       "Adminboi",
		Password:   []byte("p4ssw0rd.123"),
		Email:      "admin@example.com",
		GlobalRole: ptr.String(mobius.RoleAdmin),
	})
	require.NoError(t, err)
	ctx = viewer.NewContext(ctx, viewer.Viewer{User: user})

	// create a couple hosts
	h1, err := ds.NewHost(ctx, &mobius.Host{
		Hostname:        "host1",
		HardwareSerial:  uuid.NewString(),
		UUID:            uuid.NewString(),
		Platform:        "darwin",
		LastEnrolledAt:  time.Now(),
		DetailUpdatedAt: time.Now(),
	})
	require.NoError(t, err)
	h2, err := ds.NewHost(ctx, &mobius.Host{
		Hostname:        "host2",
		HardwareSerial:  uuid.NewString(),
		UUID:            uuid.NewString(),
		Platform:        "darwin",
		LastEnrolledAt:  time.Now(),
		DetailUpdatedAt: time.Now(),
	})
	require.NoError(t, err)
	// make the newly-created hosts available to the reader
	opts.RunReplication()

	lbl, hostIDs, err := svc.NewLabel(ctx, mobius.LabelPayload{Name: "label1", Hosts: []string{"host1", "host2"}})
	require.NoError(t, err)
	require.ElementsMatch(t, []uint{h1.ID, h2.ID}, hostIDs)
	require.Equal(t, 2, lbl.HostCount)
	require.Equal(t, user.ID, *lbl.AuthorID)

	// make the newly-created label available to the reader
	opts.RunReplication("labels", "label_membership")

	lbl, hostIDs, err = svc.ModifyLabel(ctx, lbl.ID, mobius.ModifyLabelPayload{Hosts: []string{"host1"}})
	require.NoError(t, err)
	require.ElementsMatch(t, []uint{h1.ID}, hostIDs)
	require.Equal(t, 1, lbl.HostCount)
	require.Equal(t, user.ID, *lbl.AuthorID)

	// reading this label without replication returns the old data as it only uses the reader
	lbl, hostIDs, err = svc.GetLabel(ctx, lbl.ID)
	require.NoError(t, err)
	require.ElementsMatch(t, []uint{h1.ID, h2.ID}, hostIDs)
	require.Equal(t, 2, lbl.HostCount)
	require.Equal(t, user.ID, *lbl.AuthorID)

	// running the replication makes the updated data available
	opts.RunReplication("labels", "label_membership")

	lbl, hostIDs, err = svc.GetLabel(ctx, lbl.ID)
	require.NoError(t, err)
	require.ElementsMatch(t, []uint{h1.ID}, hostIDs)
	require.Equal(t, 1, lbl.HostCount)
	require.Equal(t, user.ID, *lbl.AuthorID)
}

func TestBatchValidateLabels(t *testing.T) {
	ds := new(mock.Store)
	svc, ctx := newTestService(t, ds, nil, nil)

	t.Run("no auth context", func(t *testing.T) {
		_, err := svc.BatchValidateLabels(context.Background(), nil)
		require.ErrorContains(t, err, "Authentication required")
	})

	authCtx := authz_ctx.AuthorizationContext{}
	ctx = authz_ctx.NewContext(ctx, &authCtx)

	t.Run("no auth checked", func(t *testing.T) {
		_, err := svc.BatchValidateLabels(ctx, nil)
		require.ErrorContains(t, err, "Authentication required")
	})

	// validator requires that an authz check has been performed upstream so we'll set it now for
	// the rest of the tests
	authCtx.SetChecked()

	mockLabels := map[string]uint{
		"foo": 1,
		"bar": 2,
		"baz": 3,
	}

	mockLabelIdent := func(name string, id uint) mobius.LabelIdent {
		return mobius.LabelIdent{LabelID: id, LabelName: name}
	}

	ds.LabelIDsByNameFunc = func(ctx context.Context, names []string) (map[string]uint, error) {
		res := make(map[string]uint)
		if names == nil {
			return res, nil
		}
		for _, name := range names {
			if id, ok := mockLabels[name]; ok {
				res[name] = id
			}
		}
		return res, nil
	}

	testCases := []struct {
		name         string
		labelNames   []string
		expectLabels map[string]mobius.LabelIdent
		expectError  string
	}{
		{
			"no labels",
			nil,
			nil,
			"",
		},
		{
			"include labels",
			[]string{"foo", "bar"},
			map[string]mobius.LabelIdent{
				"foo": mockLabelIdent("foo", 1),
				"bar": mockLabelIdent("bar", 2),
			},
			"",
		},
		{
			"non-existent label",
			[]string{"foo", "qux"},
			nil,
			"some or all the labels provided don't exist",
		},
		{
			"duplicate label",
			[]string{"foo", "foo"},
			map[string]mobius.LabelIdent{
				"foo": mockLabelIdent("foo", 1),
			},
			"",
		},
		{
			"empty slice",
			[]string{},
			nil,
			"",
		},
		{
			"empty string",
			[]string{""},
			nil,
			"some or all the labels provided don't exist",
		},
	}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			got, err := svc.BatchValidateLabels(ctx, tt.labelNames)
			if tt.expectError != "" {
				require.Contains(t, err.Error(), tt.expectError)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expectLabels, got)
			}
		})
	}
}

func TestNewManualLabel(t *testing.T) {
	ds := new(mock.Store)
	svc, ctx := newTestService(t, ds, nil, nil)
	ctx = viewer.NewContext(ctx, viewer.Viewer{User: &mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)}})

	ds.NewLabelFunc = func(ctx context.Context, lbl *mobius.Label, opts ...mobius.OptionalArg) (*mobius.Label, error) {
		lbl.ID = 1
		lbl.LabelMembershipType = mobius.LabelMembershipTypeManual
		return lbl, nil
	}
	ds.HostIDsByIdentifierFunc = func(ctx context.Context, filter mobius.TeamFilter, hostnames []string) ([]uint, error) {
		return []uint{99, 100}, nil
	}

	t.Run("using hostnames", func(t *testing.T) {
		ds.UpdateLabelMembershipByHostIDsFunc = func(ctx context.Context, labelID uint, hostIds []uint, teamFilter mobius.TeamFilter) (*mobius.Label, []uint, error) {
			require.Equal(t, uint(1), labelID)
			require.Equal(t, []uint{99, 100}, hostIds)
			return nil, nil, nil
		}
		_, _, err := svc.NewLabel(ctx, mobius.LabelPayload{
			Name:  "foo",
			Hosts: []string{"host1", "host2"},
		})
		require.NoError(t, err)
	})

	t.Run("using IDs", func(t *testing.T) {
		ds.UpdateLabelMembershipByHostIDsFunc = func(ctx context.Context, labelID uint, hostIds []uint, teamFilter mobius.TeamFilter) (*mobius.Label, []uint, error) {
			require.Equal(t, uint(1), labelID)
			require.Equal(t, []uint{1, 2}, hostIds)
			return nil, nil, nil
		}
		_, _, err := svc.NewLabel(ctx, mobius.LabelPayload{
			Name:    "foo",
			HostIDs: []uint{1, 2},
		})
		require.NoError(t, err)
	})
}

func TestModifyManualLabel(t *testing.T) {
	ds := new(mock.Store)
	svc, ctx := newTestService(t, ds, nil, nil)
	ctx = viewer.NewContext(ctx, viewer.Viewer{User: &mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)}})

	ds.LabelFunc = func(ctx context.Context, lid uint, teamFilter mobius.TeamFilter) (*mobius.Label, []uint, error) {
		return &mobius.Label{
			ID:                  lid,
			LabelMembershipType: mobius.LabelMembershipTypeManual,
		}, nil, nil
	}
	ds.HostIDsByIdentifierFunc = func(ctx context.Context, filter mobius.TeamFilter, hostnames []string) ([]uint, error) {
		return []uint{99, 100}, nil
	}
	ds.SaveLabelFunc = func(ctx context.Context, lbl *mobius.Label, filter mobius.TeamFilter) (*mobius.Label, []uint, error) {
		return nil, nil, nil
	}

	t.Run("using hostnames", func(t *testing.T) {
		ds.UpdateLabelMembershipByHostIDsFunc = func(ctx context.Context, labelID uint, hostIds []uint, teamFilter mobius.TeamFilter) (*mobius.Label, []uint, error) {
			require.Equal(t, uint(1), labelID)
			require.Equal(t, []uint{99, 100}, hostIds)
			return nil, nil, nil
		}
		_, _, err := svc.ModifyLabel(ctx, 1, mobius.ModifyLabelPayload{
			Hosts: []string{"host1", "host2"},
		})
		require.NoError(t, err)
	})

	t.Run("using IDs", func(t *testing.T) {
		ds.UpdateLabelMembershipByHostIDsFunc = func(ctx context.Context, labelID uint, hostIds []uint, teamFilter mobius.TeamFilter) (*mobius.Label, []uint, error) {
			require.Equal(t, uint(1), labelID)
			require.Equal(t, []uint{1, 2}, hostIds)
			return nil, nil, nil
		}
		_, _, err := svc.ModifyLabel(ctx, 1, mobius.ModifyLabelPayload{
			HostIDs: []uint{1, 2},
		})
		require.NoError(t, err)
	})
}
