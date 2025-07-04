package upgrade

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUpgradeAToB(t *testing.T) {
	versionA := os.Getenv("MOBIUS_VERSION_A")
	if versionA == "" {
		t.Skip("Missing environment variable MOBIUS_VERSION_A")
	}

	versionB := os.Getenv("MOBIUS_VERSION_B")
	if versionB == "" {
		t.Skip("Missing environment variable MOBIUS_VERSION_B")
	}

	f := NewMobius(t, versionA)

	hostname, err := enrollHost(t, f)
	require.NoError(t, err)
	t.Logf("first host %s enrolled successfully", hostname)

	err = f.Upgrade(versionA, versionB)
	require.NoError(t, err)

	// enroll another host with the new version
	hostname, err = enrollHost(t, f)
	require.NoError(t, err)
	t.Logf("second host %s enrolled successfully", hostname)
}
