package android

import (
	"os"
	"testing"

	"github.com/notawar/mobius/server/mobius"
	android_mock "github.com/notawar/mobius/server/mdm/android/mock"
	android_service "github.com/notawar/mobius/server/mdm/android/service"
	"github.com/notawar/mobius/server/service"
	"github.com/notawar/mobius/server/service/integrationtest"
	"github.com/notawar/mobius/server/service/middleware/endpoint_utils"
	"github.com/go-kit/log"
	"github.com/stretchr/testify/require"
)

type Suite struct {
	integrationtest.BaseSuite
	AndroidProxy *android_mock.Client
}

func SetUpSuite(t *testing.T, uniqueTestName string) *Suite {
	ds, redisPool, mobiusCfg, mobiusSvc, ctx := integrationtest.SetUpMySQLAndRedisAndService(t, uniqueTestName)
	logger := log.NewLogfmtLogger(os.Stdout)
	proxy := android_mock.Client{}
	proxy.InitCommonMocks()
	androidSvc, err := android_service.NewServiceWithClient(
		logger,
		ds,
		&proxy,
		mobiusSvc,
	)
	require.NoError(t, err)
	androidSvc.(*android_service.Service).AllowLocalhostServerURL = true
	users, server := service.RunServerForTestsWithServiceWithDS(t, ctx, ds, mobiusSvc, &service.TestServerOpts{
		License: &mobius.LicenseInfo{
			Tier: mobius.TierFree,
		},
		MobiusConfig:   &mobiusCfg,
		Pool:          redisPool,
		Logger:        logger,
		FeatureRoutes: []endpoint_utils.HandlerRoutesFunc{android_service.GetRoutes(mobiusSvc, androidSvc)},
	})

	s := &Suite{
		BaseSuite: integrationtest.BaseSuite{
			Logger:   logger,
			DS:       ds,
			MobiusCfg: mobiusCfg,
			Users:    users,
			Server:   server,
		},
		AndroidProxy: &proxy,
	}

	integrationtest.SetUpServerURL(t, ds, server)

	s.Token = s.GetTestAdminToken(t)
	return s
}
