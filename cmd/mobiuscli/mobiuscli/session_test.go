package mobiuscli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/notawar/mobius/cmd/mobiuscli/mobiuscli/testing_utils"
	"github.com/notawar/mobius/server/mobius"
	"github.com/notawar/mobius/server/service"
	"github.com/stretchr/testify/require"
)

func TestEarlySessionCheck(t *testing.T) {
	_, ds := testing_utils.RunServerWithMockedDS(t)
	ds.ListQueriesFunc = func(ctx context.Context, opt mobius.ListQueryOptions) ([]*mobius.Query, int, *mobius.PaginationMetadata, error) {
		return nil, 0, nil, nil
	}
	ds.SessionByKeyFunc = func(ctx context.Context, key string) (*mobius.Session, error) {
		return nil, errors.New("invalid session")
	}

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config")
	config := `contexts:
  default:
    tls-skip-verify: true
    token: phIEGWGzKxXui1uZYFBXFwZ1Wv1iMxl79gbqMbOmMxgyZP2O5jga5qyhvEjzlGsdM7ax93iDqjnVSu9Fi8q1/w==`
	err := os.WriteFile(configPath, []byte(config), configFilePerms)
	require.NoError(t, err)

	_, err = RunAppNoChecks([]string{"get", "queries", "--config", configPath})
	require.ErrorIs(t, err, service.ErrUnauthenticated)
}
