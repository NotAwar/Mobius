package goval_dictionary

import (
	"github.com/notawar/mobius/server/mobius"
	"github.com/notawar/mobius/server/vulnerabilities/oval"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestSync(t *testing.T) {
	t.Run("#whatToDownload", func(t *testing.T) {
		osVersions := mobius.OSVersions{
			CountsUpdatedAt: time.Now(),
			OSVersions: []mobius.OSVersion{
				{
					HostsCount: 1,
					Platform:   "ubuntu",
					Name:       "Ubuntu 20.4.0",
				},
				{
					HostsCount: 1,
					Platform:   "amzn",
					Name:       "Amazon Linux 2.0.0",
				},
			},
		}

		result := whatToDownload(&osVersions)
		require.Len(t, result, 1)
		require.Contains(t, result, oval.NewPlatform("amzn", "Amazon Linux 2.0.0"))
		require.NotContains(t, result, oval.NewPlatform("ubuntu", "Ubuntu 20.4.0"))
	})
}
