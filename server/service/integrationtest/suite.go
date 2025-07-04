package integrationtest

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/notawar/mobius/server/config"
	"github.com/notawar/mobius/server/datastore/mysql"
	"github.com/notawar/mobius/server/datastore/redis/redistest"
	"github.com/notawar/mobius/server/mobius"
	"github.com/notawar/mobius/server/service"
	"github.com/notawar/mobius/server/test"
	"github.com/go-kit/log"
	"github.com/stretchr/testify/require"
)

type BaseSuite struct {
	Logger   log.Logger
	MobiusCfg config.MobiusConfig
	Server   *httptest.Server
	DS       *mysql.Datastore
	Users    map[string]mobius.User
	Token    string

	cachedAdminToken string
}

func (s *BaseSuite) GetTestAdminToken(t *testing.T) string {
	// because the login endpoint is rate-limited, use the cached admin token
	// if available (if for some reason a test needs to logout the admin user,
	// then set cachedAdminToken = "" so that a new token is retrieved).
	if s.cachedAdminToken == "" {
		s.cachedAdminToken = s.GetTestToken(t, service.TestAdminUserEmail, test.GoodPassword)
	}
	return s.cachedAdminToken
}

func (s *BaseSuite) GetTestToken(t *testing.T, email string, password string) string {
	return service.GetToken(t, email, password, s.Server.URL)
}

func SetUpServerURL(t *testing.T, ds *mysql.Datastore, server *httptest.Server) {
	appConf, err := ds.AppConfig(t.Context())
	require.NoError(t, err)
	appConf.ServerSettings.ServerURL = server.URL
	err = ds.SaveAppConfig(t.Context(), appConf)
	require.NoError(t, err)
}

func SetUpMySQLAndRedisAndService(t *testing.T, uniqueTestName string, opts ...*service.TestServerOpts) (*mysql.Datastore, mobius.RedisPool,
	config.MobiusConfig,
	mobius.Service, context.Context) {
	ds := mysql.CreateMySQLDS(t)
	test.AddAllHostsLabel(t, ds)

	// Set up the required fields on AppConfig
	appConf, err := ds.AppConfig(testContext())
	require.NoError(t, err)
	appConf.OrgInfo.OrgName = "MobiusTest"
	appConf.ServerSettings.ServerURL = "https://example.org"
	err = ds.SaveAppConfig(testContext(), appConf)
	require.NoError(t, err)

	redisPool := redistest.SetupRedis(t, uniqueTestName, false, false, false)

	mobiusCfg := config.TestConfig()
	mobiusSvc, ctx := service.NewTestService(t, ds, mobiusCfg, opts...)
	return ds, redisPool, mobiusCfg, mobiusSvc, ctx
}

func testContext() context.Context {
	return context.Background()
}
