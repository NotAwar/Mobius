package service

import (
	"context"
	"os"
	"testing"

	"github.com/notawar/mobius/v4/server/authz"
	"github.com/notawar/mobius set/v4/server/contexts/viewer"
	"github.com/notawar/mobius set/v4/server/mobius"
	android_mock "github.com/notawar/mobius set/v4/server/mdm/android/mock"
	ds_mock "github.com/notawar/mobius set/v4/server/mock"
	"github.com/notawar/mobius set/v4/server/ptr"
	kitlog "github.com/go-kit/log"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestEnterprisesAuth(t *testing.T) {
	androidAPIClient := android_mock.Client{}
	androidAPIClient.InitCommonMocks()
	logger := kitlog.NewLogfmtLogger(os.Stdout)
	mobiusDS := InitCommonDSMocks()
	mobiusSvc := mockService{}
	svc, err := NewServiceWithClient(logger, mobiusDS, &androidAPIClient, &mobiusSvc)
	require.NoError(t, err)

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
			true,
			true,
		},
		{
			"global gitops",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleGitOps)},
			true,
			true,
		},
		{
			"global observer",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleObserver)},
			true,
			true,
		},
		{
			"global observer+",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleObserverPlus)},
			true,
			true,
		},
		{
			"team admin",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleAdmin}}},
			true,
			true,
		},
		{
			"team maintainer",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleMaintainer}}},
			true,
			true,
		},
		{
			"team observer",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleObserver}}},
			true,
			true,
		},
		{
			"team observer+",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleObserverPlus}}},
			true,
			true,
		},
	}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			ctx := viewer.NewContext(context.Background(), viewer.Viewer{User: tt.user})

			_, err := svc.GetEnterprise(ctx)
			checkAuthErr(t, tt.shouldFailRead, err)

			err = svc.DeleteEnterprise(ctx)
			checkAuthErr(t, tt.shouldFailWrite, err)

			_, err = svc.EnterpriseSignup(ctx)
			checkAuthErr(t, tt.shouldFailWrite, err)

			ctx, cancel := context.WithCancel(ctx)
			defer cancel()
			_, err = svc.EnterpriseSignupSSE(ctx)
			checkAuthErr(t, tt.shouldFailRead, err)

		})
	}

	t.Run("unauthorized", func(t *testing.T) {
		err := svc.EnterpriseSignupCallback(context.Background(), "signup_token", "token")
		checkAuthErr(t, false, err)
		err = svc.EnterpriseSignupCallback(context.Background(), "bad_token", "token")
		checkAuthErr(t, true, err)
	})
}

func checkAuthErr(t *testing.T, shouldFail bool, err error) {
	t.Helper()
	if shouldFail {
		require.Error(t, err)
		var forbiddenError *authz.Forbidden
		require.ErrorAs(t, err, &forbiddenError)
	} else {
		require.NoError(t, err)
	}
}

func InitCommonDSMocks() mobius.AndroidDatastore {
	ds := AndroidMockDS{}
	ds.Datastore.InitCommonMocks()

	ds.Store.AppConfigFunc = func(_ context.Context) (*mobius.AppConfig, error) {
		return &mobius.AppConfig{}, nil
	}
	ds.Store.SetAndroidEnabledAndConfiguredFunc = func(_ context.Context, configured bool) error {
		return nil
	}
	ds.Store.UserOrDeletedUserByIDFunc = func(ctx context.Context, id uint) (*mobius.User, error) {
		return &mobius.User{ID: id}, nil
	}
	ds.Store.GetAllMDMConfigAssetsByNameFunc = func(ctx context.Context, assetNames []mobius.MDMAssetName,
		queryerContext sqlx.QueryerContext) (map[mobius.MDMAssetName]mobius.MDMConfigAsset, error) {
		result := make(map[mobius.MDMAssetName]mobius.MDMConfigAsset, len(assetNames))
		for _, name := range assetNames {
			result[name] = mobius.MDMConfigAsset{Value: []byte("value")}
		}
		return result, nil
	}
	ds.Store.InsertOrReplaceMDMConfigAssetFunc = func(ctx context.Context, asset mobius.MDMConfigAsset) error {
		return nil
	}
	ds.Store.DeleteMDMConfigAssetsByNameFunc = func(ctx context.Context, assetNames []mobius.MDMAssetName) error {
		return nil
	}
	ds.Store.BulkSetAndroidHostsUnenrolledFunc = func(ctx context.Context) error {
		return nil
	}
	return &ds
}

type AndroidMockDS struct {
	android_mock.Datastore
	ds_mock.Store
}

type mockService struct {
	mock.Mock
	mobius.Service
}

// NewActivity mocks the mobius.Service method.
func (m *mockService) NewActivity(_ context.Context, _ *mobius.User, _ mobius.ActivityDetails) error {
	return nil
}
