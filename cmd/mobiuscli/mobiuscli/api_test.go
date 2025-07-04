package mobiuscli

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/notawar/mobius/cmd/mobiuscli/mobiuscli/testing_utils"
	"github.com/notawar/mobius/server/config"
	"github.com/notawar/mobius/server/mobius"
	"github.com/notawar/mobius/server/service"
	"github.com/stretchr/testify/require"
)

// TestRunApiCommand checks that the usage of `api` command works as expected
func TestRunApiCommand(t *testing.T) {
	cfg := config.TestConfig()
	_, ds := testing_utils.RunServerWithMockedDS(t, &service.TestServerOpts{
		License:     &mobius.LicenseInfo{Tier: mobius.TierPremium, Expiration: time.Now().Add(24 * time.Hour)},
		MobiusConfig: &cfg,
	})

	created_at, err := time.Parse(time.RFC3339, "1999-03-10T02:45:06.371Z")
	require.NoError(t, err)

	type testCase struct {
		name         string
		args         []string
		expectOutput string
		expectErrMsg string
	}

	expectedScripts := `{
  "meta": {
    "has_next_results": false,
    "has_previous_results": false
  },
  "scripts": [
    {
      "id": 23,
      "team_id": null,
      "name": "get_my_device_page.sh",
      "created_at": "%s",
      "updated_at": "%s"
    }
  ]
}
`

	expectedEmptyScripts := `{
  "meta": {
    "has_next_results": false,
    "has_previous_results": false
  },
  "scripts": []
}
`

	cases := []testCase{
		{
			name: "get scripts",
			args: []string{"scripts"},
			expectOutput: fmt.Sprintf(
				expectedScripts,
				created_at.Format(time.RFC3339Nano),
				created_at.Format(time.RFC3339Nano)),
		},
		{
			name: "get /scripts",
			args: []string{"/scripts"},
			expectOutput: fmt.Sprintf(
				expectedScripts,
				created_at.Format(time.RFC3339Nano),
				created_at.Format(time.RFC3339Nano)),
		},
		{
			name: "get scripts full path",
			args: []string{"/api/v1/mobius/scripts"},
			expectOutput: fmt.Sprintf(
				expectedScripts,
				created_at.Format(time.RFC3339Nano),
				created_at.Format(time.RFC3339Nano)),
		},
		{
			name: "get scripts full path missing /",
			args: []string{"api/v1/mobius/scripts"},
			expectOutput: fmt.Sprintf(
				expectedScripts,
				created_at.Format(time.RFC3339Nano),
				created_at.Format(time.RFC3339Nano)),
		},
		{
			name:         "get scripts team",
			args:         []string{"-F", "team_id=1", "scripts"},
			expectOutput: expectedEmptyScripts,
		},
		{
			name:         "get scripts team no cache",
			args:         []string{"-H", "cache-control:no-cache", "-F", "team_id=1", "scripts"},
			expectOutput: expectedEmptyScripts,
		},
		{
			name:         "get typo",
			args:         []string{"vresion"},
			expectErrMsg: "Got non 2XX return of 404",
		},
	}

	setupDS := func(t *testing.T, c testCase) {
		ds.ListScriptsFunc = func(ctx context.Context, teamID *uint, opt mobius.ListOptions) ([]*mobius.Script, *mobius.PaginationMetadata, error) {
			if teamID == nil {
				ret := []*mobius.Script{
					&mobius.Script{
						ID:        23,
						Name:      "get_my_device_page.sh",
						CreatedAt: created_at,
						UpdatedAt: created_at,
					},
				}
				page := mobius.PaginationMetadata{}
				return ret, &page, nil
			}
			return []*mobius.Script{}, &mobius.PaginationMetadata{}, nil
		}
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			setupDS(t, c)
			args := []string{"api"}

			args = append(args, c.args...)

			b, err := RunAppNoChecks(args)
			if c.expectErrMsg != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), c.expectErrMsg)
			} else {
				require.NoError(t, err)
			}
			if c.expectOutput != "" {
				out := b.String()
				require.NoError(t, err)
				require.NotEmpty(t, out)
				require.Equal(t, c.expectOutput, out)
			} else {
				require.Empty(t, b.String())
			}
		})
	}

}
