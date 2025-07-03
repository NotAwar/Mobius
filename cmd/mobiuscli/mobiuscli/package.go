package mobiuscli

import (
	"crypto/tls"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/notawar/mobius/orbit/pkg/packaging"
	"github.com/notawar/mobius/orbit/pkg/update"
	"github.com/notawar/mobius/pkg/filepath_windows"
	"github.com/notawar/mobius/server/mobius"
	"github.com/rs/zerolog"
	zlog "github.com/rs/zerolog/log"
	"github.com/skratchdot/open-golang/open"
	"github.com/urfave/cli/v2"
)

var (
	opt               packaging.Options
	disableOpenFolder bool
)

func packageCommand() *cli.Command {
	return &cli.Command{
		Name:        "package",
		Aliases:     nil,
		Usage:       "Create a mobiusdaemon agent",
		Description: "An easy way to create fully boot-strapped installer packages for Windows, macOS, or Linux",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "type",
				Usage:    "Type of package to build",
				Required: true,
			},
			&cli.StringFlag{
				Name:        "arch",
				Usage:       "Target CPU Architecture for the installer package (Only supported with '--type' deb, rpm, or msi)",
				Destination: &opt.Architecture,
				Value:       "amd64",
			},
			&cli.StringFlag{
				Name:        "enroll-secret",
				Usage:       "Enroll secret for authenticating to Mobius server",
				Destination: &opt.EnrollSecret,
			},
			&cli.StringFlag{
				Name:        "mobius-url",
				Usage:       "URL (host:port) of Mobius server",
				Destination: &opt.MobiusURL,
			},
			&cli.StringFlag{
				Name:        "mobius-certificate",
				Usage:       "Path to the Mobius server certificate chain",
				Destination: &opt.MobiusCertificate,
			},
			&cli.StringFlag{
				Name:        "mobius-tls-client-certificate",
				Usage:       "Path to a TLS client certificate to use when connecting to the Mobius server. This functionality is licensed under the Mobius EE License. Usage requires a current Mobius EE subscription.",
				Destination: &opt.MobiusTLSClientCertificate,
			},
			&cli.StringFlag{
				Name:        "mobius-tls-client-key",
				Usage:       "Path to a TLS client private key to use when connecting to the Mobius server. This functionality is licensed under the Mobius EE License. Usage requires a current Mobius EE subscription.",
				Destination: &opt.MobiusTLSClientKey,
			},
			&cli.StringFlag{
				Name:        "mobius-desktop-alternative-browser-host",
				Usage:       "Alternative host:port to use for Mobius Desktop in the browser (this may be required when using TLS client authentication in the Mobius server)",
				Destination: &opt.MobiusDesktopAlternativeBrowserHost,
			},
			&cli.StringFlag{
				Name:        "identifier",
				Usage:       "Identifier for package product",
				Value:       "com.mobiusmdm.orbit",
				Destination: &opt.Identifier,
			},
			&cli.BoolFlag{
				Name:        "insecure",
				Usage:       "Disable TLS certificate verification",
				Destination: &opt.Insecure,
			},
			&cli.BoolFlag{
				Name:        "service",
				Usage:       "Install orbit/osquery with a persistence service (launchd, systemd, etc.)",
				Value:       true,
				Destination: &opt.StartService,
			},
			&cli.StringFlag{
				Name:        "sign-identity",
				Usage:       "Identity to use for macOS codesigning",
				Destination: &opt.SignIdentity,
			},
			&cli.BoolFlag{
				Name:        "notarize",
				Usage:       "Whether to notarize macOS packages",
				Destination: &opt.Notarize,
			},
			&cli.StringFlag{
				Name:        "osqueryd-channel",
				Usage:       "Update channel of osqueryd to use",
				Value:       "stable",
				Destination: &opt.OsquerydChannel,
			},
			&cli.StringFlag{
				Name:        "desktop-channel",
				Usage:       "Update channel of desktop to use",
				Value:       "stable",
				Destination: &opt.DesktopChannel,
			},
			&cli.StringFlag{
				Name:        "orbit-channel",
				Usage:       "Update channel of Orbit to use",
				Value:       "stable",
				Destination: &opt.OrbitChannel,
			},
			&cli.BoolFlag{
				Name:        "disable-updates",
				Usage:       "Disable auto updates on the generated package",
				Destination: &opt.DisableUpdates,
			},
			&cli.StringFlag{
				Name:        "update-url",
				Usage:       "URL for update server",
				Value:       update.DefaultURL,
				Destination: &opt.UpdateURL,
			},
			&cli.StringFlag{
				Name:        "update-roots",
				Usage:       "Root key JSON metadata for update server (from mobiuscli updates roots)",
				Destination: &opt.UpdateRoots,
			},
			&cli.StringFlag{
				Name:        "update-tls-certificate",
				Usage:       "Path to the update server TLS certificate chain",
				Destination: &opt.UpdateTLSServerCertificate,
			},
			&cli.StringFlag{
				Name:        "update-tls-client-certificate",
				Usage:       "Path to a TLS client certificate to use when connecting to the update server. This functionality is licensed under the Mobius EE License. Usage requires a current Mobius EE subscription.",
				Destination: &opt.UpdateTLSClientCertificate,
			},
			&cli.StringFlag{
				Name:        "update-tls-client-key",
				Usage:       "Path to a TLS client private key to use when connecting to the update server. This functionality is licensed under the Mobius EE License. Usage requires a current Mobius EE subscription.",
				Destination: &opt.UpdateTLSClientKey,
			},
			&cli.StringFlag{
				Name:        "osquery-flagfile",
				Usage:       "Flagfile to package and provide to osquery",
				Destination: &opt.OsqueryFlagfile,
			},
			&cli.BoolFlag{
				Name:        "debug",
				Usage:       "Enable debug logging in orbit",
				Destination: &opt.Debug,
			},
			&cli.BoolFlag{
				Name:  "verbose",
				Usage: "Log detailed information when building the package",
			},
			&cli.BoolFlag{
				Name:        "mobius-desktop",
				Usage:       "Include the Mobius Desktop Application in the package",
				Destination: &opt.Desktop,
			},
			&cli.DurationFlag{
				Name:        "update-interval",
				Usage:       "Interval that Orbit will use to check for new updates (10s, 1h, etc.)",
				Value:       15 * time.Minute,
				Destination: &opt.OrbitUpdateInterval,
			},
			&cli.BoolFlag{
				Name:        "disable-open-folder",
				Usage:       "Disable opening the folder at the end",
				Destination: &disableOpenFolder,
			},
			&cli.BoolFlag{
				Name:        "native-tooling",
				Usage:       "Build the package using native tooling (only available in Linux)",
				EnvVars:     []string{"MOBIUSCTL_NATIVE_TOOLING"},
				Destination: &opt.NativeTooling,
			},
			&cli.StringFlag{
				Name:        "local-wix-dir",
				Usage:       "Use a local WiX directory instead of containerized tooling",
				Destination: &opt.LocalWixDir,
			},
			&cli.StringFlag{
				Name:        "macos-devid-pem-content",
				Usage:       "Dev ID certificate keypair content in PEM format",
				EnvVars:     []string{"MOBIUSCTL_MACOS_DEVID_PEM_CONTENT"},
				Destination: &opt.MacOSDevIDCertificateContent,
			},
			&cli.StringFlag{
				Name:        "app-store-connect-api-key-id",
				Usage:       "App Store Connect API key used for notarization",
				EnvVars:     []string{"MOBIUSCTL_APP_STORE_CONNECT_API_KEY_ID"},
				Destination: &opt.AppStoreConnectAPIKeyID,
			},
			&cli.StringFlag{
				Name:        "app-store-connect-api-key-issuer",
				Usage:       "Issuer of the App Store Connect API key",
				EnvVars:     []string{"MOBIUSCTL_APP_STORE_CONNECT_API_KEY_ISSUER"},
				Destination: &opt.AppStoreConnectAPIKeyIssuer,
			},
			&cli.StringFlag{
				Name:        "app-store-connect-api-key-content",
				Usage:       "Contents of the .p8 App Store Connect API key",
				EnvVars:     []string{"MOBIUSCTL_APP_STORE_CONNECT_API_KEY_CONTENT"},
				Destination: &opt.AppStoreConnectAPIKeyContent,
			},
			&cli.BoolFlag{
				Name:        "use-system-configuration",
				Usage:       "Try to read --mobius-url and --enroll-secret using configuration in the host (currently only macOS profiles are supported)",
				EnvVars:     []string{"MOBIUSCTL_USE_SYSTEM_CONFIGURATION"},
				Destination: &opt.UseSystemConfiguration,
			},
			&cli.BoolFlag{
				Name:        "enable-scripts",
				Usage:       "Enable script execution",
				EnvVars:     []string{"MOBIUSCTL_ENABLE_SCRIPTS"},
				Destination: &opt.EnableScripts,
			},
			&cli.StringFlag{
				Name:        "host-identifier",
				Usage:       "Sets the host identifier that orbit and osquery will use when enrolling to Mobius. Options: 'uuid' and 'instance' (requires Mobius >= v4.42.0)",
				Value:       "uuid",
				EnvVars:     []string{"MOBIUSCTL_HOST_IDENTIFIER"},
				Destination: &opt.HostIdentifier,
			},
			&cli.StringFlag{
				Name:        "end-user-email",
				Usage:       "End user's email that populates human to host mapping in Mobius (only available on Windows and Linux)",
				EnvVars:     []string{"MOBIUSCTL_END_USER_EMAIL"},
				Destination: &opt.EndUserEmail,
			},
			&cli.BoolFlag{
				Name:        "disable-keystore",
				Usage:       "Disables the use of the keychain on macOS and Credentials Manager on Windows",
				EnvVars:     []string{"MOBIUSCTL_DISABLE_KEYSTORE"},
				Destination: &opt.DisableKeystore,
			},
			&cli.StringFlag{
				Name:        "osquery-db",
				Usage:       "Sets a custom osquery database directory, it must be an absolute path (requires orbit >= v1.22.0)",
				EnvVars:     []string{"MOBIUSCTL_OSQUERY_DB"},
				Destination: &opt.OsqueryDB,
			},
			&cli.StringFlag{
				Name:        "outfile",
				Usage:       "Output file for the generated package",
				Value:       "",
				Destination: &opt.CustomOutfile,
			},
		},
		Action: func(c *cli.Context) error {
			if opt.MobiusURL != "" || opt.EnrollSecret != "" {
				if opt.MobiusURL == "" || opt.EnrollSecret == "" {
					return errors.New("--enroll-secret and --mobius-url must be provided together")
				}
			}

			if opt.Insecure && opt.MobiusCertificate != "" {
				return errors.New("--insecure and --mobius-certificate may not be provided together")
			}

			if opt.Insecure && opt.UpdateTLSServerCertificate != "" {
				return errors.New("--insecure and --update-tls-certificate may not be provided together")
			}

			if opt.HostIdentifier != "uuid" && opt.HostIdentifier != "instance" {
				return fmt.Errorf("--host-identifier=%s is not supported, currently supported values are 'uuid' and 'instance'", opt.HostIdentifier)
			}

			// Perform checks on the provided mobius client certificate and key.
			if (opt.MobiusTLSClientCertificate != "") != (opt.MobiusTLSClientKey != "") {
				return errors.New("must specify both mobius-tls-client-certificate and mobius-tls-client-key")
			}
			if opt.MobiusTLSClientKey != "" {
				if _, err := tls.LoadX509KeyPair(opt.MobiusTLSClientCertificate, opt.MobiusTLSClientKey); err != nil {
					return fmt.Errorf("error loading mobius client certificate and key: %w", err)
				}
			}

			// Perform checks on the provided update client certificate and key.
			if (opt.UpdateTLSClientCertificate != "") != (opt.UpdateTLSClientKey != "") {
				return errors.New("must specify both update-tls-client-certificate and update-tls-client-key")
			}
			if opt.UpdateTLSClientKey != "" {
				if _, err := tls.LoadX509KeyPair(opt.UpdateTLSClientCertificate, opt.UpdateTLSClientKey); err != nil {
					return fmt.Errorf("error loading update client certificate and key: %w", err)
				}
			}

			if opt.OsqueryDB != "" && !isAbsolutePath(opt.OsqueryDB, c.String("type")) {
				return fmt.Errorf("--osquery-db must be an absolute path: %q", opt.OsqueryDB)
			}

			if runtime.GOOS == "windows" && c.String("type") != "msi" {
				return errors.New("Windows can only build MSI packages.")
			}

			if opt.NativeTooling && runtime.GOOS != "linux" {
				return errors.New("native tooling is only available in Linux")
			}

			if opt.LocalWixDir != "" && runtime.GOOS != "windows" && runtime.GOOS != "darwin" {
				return errors.New(
					`Could not use local WiX to generate an osquery installer. This option is only available on Windows and macOS.
				Visit https://wixtoolset.org/ for more information about how to use WiX.`)
			}

			if opt.EndUserEmail != "" {
				if !mobius.IsLooseEmail(opt.EndUserEmail) {
					return errors.New("Invalid email address specified for --end-user-email.")
				}

				switch c.String("type") {
				case "msi", "deb", "rpm":
					// ok
				default:
					return errors.New("Can only set --end-user-email when building an MSI, DEB, or RPM package.")
				}
			}

			if opt.MobiusCertificate != "" {
				err := checkPEMCertificate(opt.MobiusCertificate)
				if err != nil {
					return fmt.Errorf("failed to read mobius server certificate %q: %w", opt.MobiusCertificate, err)
				}
			}

			if opt.UpdateTLSServerCertificate != "" {
				err := checkPEMCertificate(opt.UpdateTLSServerCertificate)
				if err != nil {
					return fmt.Errorf("failed to read update server certificate %q: %w", opt.UpdateTLSServerCertificate, err)
				}
			}

			if opt.UseSystemConfiguration && c.String("type") != "pkg" {
				return errors.New("--use-system-configuration is only available for pkg installers")
			}

			if opt.CustomOutfile != "" {
				switch c.String("type") {
				case "deb":
					if !strings.HasSuffix(opt.CustomOutfile, ".deb") {
						return errors.New("output file must end with .deb for DEB packages")
					}
				case "rpm":
					if !strings.HasSuffix(opt.CustomOutfile, ".rpm") {
						return errors.New("output file must end with .rpm for RPM packages")
					}
				case "msi":
					if !strings.HasSuffix(opt.CustomOutfile, ".msi") {
						return errors.New("output file must end with .msi for MSI packages")
					}
				case "pkg":
					if !strings.HasSuffix(opt.CustomOutfile, ".pkg") {
						return errors.New("output file must end with .pkg for PKG packages")
					}
				default:
					return fmt.Errorf("unsupported package type %q for custom outfile", c.String("type"))
				}
			}

			linuxPackage := false
			switch c.String("type") {
			case "deb", "rpm":
				linuxPackage = true
			}
			windowsPackage := c.String("type") == "msi"

			if opt.Architecture != packaging.ArchAmd64 && !(linuxPackage || windowsPackage) {
				return fmt.Errorf("can't use '--arch' with '--type %s'", c.String("type"))
			}

			if opt.Architecture != packaging.ArchAmd64 && opt.Architecture != packaging.ArchArm64 {
				return errors.New("arch must be one of ('amd64', 'arm64')")
			}

			var buildFunc func(packaging.Options) (string, error)
			switch c.String("type") {
			case "pkg":
				opt.NativePlatform = "darwin"
				buildFunc = packaging.BuildPkg
			case "deb":
				if opt.Architecture == packaging.ArchAmd64 {
					opt.NativePlatform = "linux"
				} else {
					opt.NativePlatform = "linux-arm64"
				}
				buildFunc = packaging.BuildDeb
			case "rpm":
				if opt.Architecture == packaging.ArchAmd64 {
					opt.NativePlatform = "linux"
				} else {
					opt.NativePlatform = "linux-arm64"
				}
				buildFunc = packaging.BuildRPM
			case "msi":
				if opt.Architecture == packaging.ArchAmd64 {
					opt.NativePlatform = "windows"
				} else {
					opt.NativePlatform = "windows-arm64"
				}
				buildFunc = packaging.BuildMSI
			default:
				return errors.New("type must be one of ('pkg', 'deb', 'rpm', 'msi')")
			}

			// disable detailed logging unless verbose is set
			if !c.Bool("verbose") {
				zlog.Logger = zerolog.Nop()
			}

			fmt.Println("Generating your mobiusdaemon agent...")
			path, err := buildFunc(opt)
			if err != nil {
				return err
			}

			path, _ = filepath.Abs(path)
			fmt.Printf(`
Success! You generated mobiusdaemon at %s

To add hosts to Mobius, install mobiusdaemon.
Learn how: https://mobiusmdm.com/learn-more-about/enrolling-hosts
`, path)
			if !disableOpenFolder {
				open.Start(filepath.Dir(path)) //nolint:errcheck
			}
			return nil
		},
	}
}

func checkPEMCertificate(path string) error {
	cert, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if p, _ := pem.Decode(cert); p == nil {
		return errors.New("invalid PEM file")
	}
	return nil
}

// isAbsolutePath returns whether a path is absolute.
// It does not make use of filepath.IsAbs to support
// checking Windows paths from Go code running in unix.
func isAbsolutePath(path, pkgType string) bool {
	if pkgType == "msi" {
		return filepath_windows.IsAbs(path)
	}
	return strings.HasPrefix(path, "/") // this is the unix implementation of filepath.IsAbs
}
