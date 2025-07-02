package service

import (
	"context"
	"testing"
	"time"

	"github.com/notawar/mobius/server/authz"
	"github.com/notawar/mobius/server/contexts/viewer"
	"github.com/notawar/mobius/server/datastore/mysql"
	"github.com/notawar/mobius/server/mobius"
	"github.com/notawar/mobius/server/mock"
	"github.com/notawar/mobius/server/ptr"
	"github.com/notawar/mobius/server/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetPack(t *testing.T) {
	ds := new(mock.Store)
	svc, ctx := newTestService(t, ds, nil, nil)

	ds.PackFunc = func(ctx context.Context, id uint) (*mobius.Pack, error) {
		return &mobius.Pack{
			ID:      1,
			TeamIDs: []uint{1},
		}, nil
	}

	pack, err := svc.GetPack(test.UserContext(ctx, test.UserAdmin), 1)
	require.NoError(t, err)
	require.Equal(t, uint(1), pack.ID)

	_, err = svc.GetPack(test.UserContext(ctx, test.UserNoRoles), 1)
	require.Error(t, err)
	require.Contains(t, err.Error(), authz.ForbiddenErrorMessage)
}

func TestNewPackSavesTargets(t *testing.T) {
	ds := new(mock.Store)
	svc, ctx := newTestService(t, ds, nil, nil)

	ds.NewPackFunc = func(ctx context.Context, pack *mobius.Pack, opts ...mobius.OptionalArg) (*mobius.Pack, error) {
		return pack, nil
	}
	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		return &mobius.AppConfig{}, nil
	}
	ds.NewActivityFunc = func(
		ctx context.Context, user *mobius.User, activity mobius.ActivityDetails, details []byte, createdAt time.Time,
	) error {
		return nil
	}

	packPayload := mobius.PackPayload{
		Name:     ptr.String("foo"),
		HostIDs:  &[]uint{123},
		LabelIDs: &[]uint{456},
		TeamIDs:  &[]uint{789},
	}
	pack, err := svc.NewPack(test.UserContext(ctx, test.UserAdmin), packPayload)
	require.NoError(t, err)

	require.Len(t, pack.HostIDs, 1)
	require.Len(t, pack.LabelIDs, 1)
	require.Len(t, pack.TeamIDs, 1)
	assert.Equal(t, uint(123), pack.HostIDs[0])
	assert.Equal(t, uint(456), pack.LabelIDs[0])
	assert.Equal(t, uint(789), pack.TeamIDs[0])
	assert.True(t, ds.NewPackFuncInvoked)
	assert.True(t, ds.NewActivityFuncInvoked)
}

func TestPacksWithDS(t *testing.T) {
	ds := mysql.CreateMySQLDS(t)

	cases := []struct {
		name string
		fn   func(t *testing.T, ds *mysql.Datastore)
	}{
		{"ListPacks", testPacksListPacks},
		{"DeletePack", testPacksDeletePack},
		{"DeletePackByID", testPacksDeletePackByID},
		{"ApplyPackSpecs", testPacksApplyPackSpecs},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			defer mysql.TruncateTables(t, ds)
			c.fn(t, ds)
		})
	}
}

func testPacksListPacks(t *testing.T, ds *mysql.Datastore) {
	svc, ctx := newTestService(t, ds, nil, nil)

	queries, err := svc.ListPacks(test.UserContext(ctx, test.UserAdmin), mobius.PackListOptions{IncludeSystemPacks: false})
	require.NoError(t, err)
	assert.Len(t, queries, 0)

	_, err = ds.NewPack(ctx, &mobius.Pack{
		Name: "foo",
	})
	require.NoError(t, err)

	queries, err = svc.ListPacks(test.UserContext(ctx, test.UserAdmin), mobius.PackListOptions{IncludeSystemPacks: false})
	require.NoError(t, err)
	assert.Len(t, queries, 1)
}

func testPacksDeletePack(t *testing.T, ds *mysql.Datastore) {
	test.AddAllHostsLabel(t, ds)

	users := createTestUsers(t, ds)
	user := users["admin1@example.com"]

	type args struct {
		ctx  context.Context
		name string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "delete pack that doesn't exist",
			args: args{
				ctx:  test.UserContext(context.Background(), &user),
				name: "foo",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, _ := newTestService(t, ds, nil, nil)
			if err := svc.DeletePack(tt.args.ctx, tt.args.name); (err != nil) != tt.wantErr {
				t.Errorf("DeletePack() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func testPacksDeletePackByID(t *testing.T, ds *mysql.Datastore) {
	test.AddAllHostsLabel(t, ds)

	type args struct {
		ctx context.Context
		id  uint
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "cannot delete pack that doesn't exists",
			args: args{
				ctx: test.UserContext(context.Background(), test.UserAdmin),
				id:  123456,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, _ := newTestService(t, ds, nil, nil)
			if err := svc.DeletePackByID(tt.args.ctx, tt.args.id); (err != nil) != tt.wantErr {
				t.Errorf("DeletePackByID() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func testPacksApplyPackSpecs(t *testing.T, ds *mysql.Datastore) {
	test.AddAllHostsLabel(t, ds)

	users := createTestUsers(t, ds)
	user := users["admin1@example.com"]

	type args struct {
		ctx   context.Context
		specs []*mobius.PackSpec
	}
	tests := []struct {
		name    string
		args    args
		want    []*mobius.PackSpec
		wantErr bool
	}{
		{
			name: "cannot modify global pack",
			args: args{
				ctx: test.UserContext(context.Background(), &user),
				specs: []*mobius.PackSpec{
					{Name: "Foo Pack", Description: "Foo Desc", Platform: "MacOS"},
					{Name: "Bar Pack", Description: "Bar Desc", Platform: "MacOS"},
				},
			},
			want: []*mobius.PackSpec{
				{Name: "Foo Pack", Description: "Foo Desc", Platform: "MacOS"},
				{Name: "Bar Pack", Description: "Bar Desc", Platform: "MacOS"},
			},
			wantErr: false,
		},
		{
			name: "cannot modify team pack",
			args: args{
				ctx: test.UserContext(context.Background(), &user),
				specs: []*mobius.PackSpec{
					{Name: "Test", Description: "Test Desc", Platform: "linux"},
				},
			},
			want: []*mobius.PackSpec{
				{Name: "Test", Description: "Test Desc", Platform: "linux"},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, _ := newTestService(t, ds, nil, nil)
			got, err := svc.ApplyPackSpecs(tt.args.ctx, tt.args.specs)
			if (err != nil) != tt.wantErr {
				t.Errorf("ApplyPackSpecs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			require.Equal(t, tt.want, got)
		})
	}
}

func TestUserIsGitOpsOnly(t *testing.T) {
	for _, tc := range []struct {
		name       string
		user       *mobius.User
		expectedFn func(value bool, err error) bool
	}{
		{
			name: "missing user in context",
			user: nil,
			expectedFn: func(value bool, err error) bool {
				return err != nil && !value
			},
		},
		{
			name: "no roles",
			user: &mobius.User{},
			expectedFn: func(value bool, err error) bool {
				return err != nil && !value
			},
		},
		{
			name: "global gitops",
			user: &mobius.User{
				GlobalRole: ptr.String(mobius.RoleGitOps),
			},
			expectedFn: func(value bool, err error) bool {
				return err == nil && value
			},
		},
		{
			name: "global non-gitops",
			user: &mobius.User{
				GlobalRole: ptr.String(mobius.RoleObserver),
			},
			expectedFn: func(value bool, err error) bool {
				return err == nil && !value
			},
		},
		{
			name: "team gitops",
			user: &mobius.User{
				GlobalRole: nil,
				Teams: []mobius.UserTeam{
					{
						Team: mobius.Team{ID: 1},
						Role: mobius.RoleGitOps,
					},
				},
			},
			expectedFn: func(value bool, err error) bool {
				return err == nil && value
			},
		},
		{
			name: "multiple team gitops",
			user: &mobius.User{
				GlobalRole: nil,
				Teams: []mobius.UserTeam{
					{
						Team: mobius.Team{ID: 1},
						Role: mobius.RoleGitOps,
					},
					{
						Team: mobius.Team{ID: 2},
						Role: mobius.RoleGitOps,
					},
				},
			},
			expectedFn: func(value bool, err error) bool {
				return err == nil && value
			},
		},
		{
			name: "multiple teams, not all gitops",
			user: &mobius.User{
				GlobalRole: nil,
				Teams: []mobius.UserTeam{
					{
						Team: mobius.Team{ID: 1},
						Role: mobius.RoleObserver,
					},
					{
						Team: mobius.Team{ID: 2},
						Role: mobius.RoleGitOps,
					},
				},
			},
			expectedFn: func(value bool, err error) bool {
				return err == nil && !value
			},
		},
		{
			name: "multiple teams, none gitops",
			user: &mobius.User{
				GlobalRole: nil,
				Teams: []mobius.UserTeam{
					{
						Team: mobius.Team{ID: 1},
						Role: mobius.RoleObserver,
					},
					{
						Team: mobius.Team{ID: 2},
						Role: mobius.RoleMaintainer,
					},
				},
			},
			expectedFn: func(value bool, err error) bool {
				return err == nil && !value
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := userIsGitOpsOnly(viewer.NewContext(context.Background(), viewer.Viewer{User: tc.user}))
			require.True(t, tc.expectedFn(actual, err))
		})
	}
}
