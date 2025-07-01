package _package

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/notawar/mobius/v4/cmd/mobiuscli/mobiuscli"
	"github.com/notawar/mobius set/v4/orbit/pkg/packaging"
	"github.com/notawar/mobius set/v4/orbit/pkg/update"
	"github.com/notawar/mobius set/v4/pkg/nettest"
	"github.com/stretchr/testify/require"
)

func TestPackage(t *testing.T) {
	nettest.Run(t)

	updateOpt := update.DefaultOptions
	updateOpt.RootDirectory = t.TempDir()
	updatesData, err := packaging.InitializeUpdates(updateOpt)
	require.NoError(t, err)

	// --type is required
	mobiuscli.RunAppCheckErr(t, []string{"package", "deb"}, "Required flag \"type\" not set")

	// if you provide -mobius-url & --enroll-secret are required together
	mobiuscli.RunAppCheckErr(t, []string{"package", "--type=deb", "--mobius-url=https://localhost:8080"},
		"--enroll-secret and --mobius-url must be provided together")
	mobiuscli.RunAppCheckErr(t, []string{"package", "--type=deb", "--enroll-secret=foobar"}, "--enroll-secret and --mobius-url must be provided together")

	// --insecure and --mobius-certificate are mutually exclusive
	mobiuscli.RunAppCheckErr(t, []string{"package", "--type=deb", "--insecure", "--mobius-certificate=test123"},
		"--insecure and --mobius-certificate may not be provided together")

	// Test invalid PEM file provided in --mobius-certificate.
	certDir := t.TempDir()
	mobiusCertificate := filepath.Join(certDir, "mobius.pem")
	err = os.WriteFile(mobiusCertificate, []byte("undefined"), os.FileMode(0o644))
	require.NoError(t, err)
	mobiuscli.RunAppCheckErr(t, []string{"package", "--type=deb", fmt.Sprintf("--mobius-certificate=%s", mobiusCertificate)},
		fmt.Sprintf("failed to read mobius server certificate %q: invalid PEM file", mobiusCertificate))

	if runtime.GOOS != "linux" {
		mobiuscli.RunAppCheckErr(t, []string{"package", "--type=msi", "--native-tooling"}, "native tooling is only available in Linux")
	}

	t.Run("deb", func(t *testing.T) {
		mobiuscli.RunAppForTest(t, []string{"package", "--type=deb", "--insecure", "--disable-open-folder"})
		info, err := os.Stat(fmt.Sprintf("mobius-osquery_%s_amd64.deb", updatesData.OrbitVersion))
		require.NoError(t, err)
		require.Greater(t, info.Size(), int64(0)) // TODO verify contents
	})

	t.Run("--use-sytem-configuration can't be used on installers that aren't pkg", func(t *testing.T) {
		for _, p := range []string{"deb", "msi", "rpm", ""} {
			mobiuscli.RunAppCheckErr(
				t,
				[]string{"package", fmt.Sprintf("--type=%s", p), "--use-system-configuration"},
				"--use-system-configuration is only available for pkg installers",
			)
		}
	})

	// mobius-osquery.msi
	// runAppForTest(t, []string{"package", "--type=msi", "--insecure"}) TODO: this is currently failing on Github runners due to permission issues
	// info, err = os.Stat("orbit-osquery_0.0.3.msi")
	// require.NoError(t, err)
	// require.Greater(t, info.Size(), int64(0))

	// runAppForTest(t, []string{"package", "--type=pkg", "--insecure"}) TODO: had a hard time getting xar installed on Ubuntu
}
