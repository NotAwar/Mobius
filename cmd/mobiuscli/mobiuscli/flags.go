package mobiuscli

import "github.com/urfave/cli/v2"

const (
	outfileFlagName          = "outfile"
	debugFlagName            = "debug"
	mobiusCertificateFlagName = "mobius-certificate"
	stdoutFlagName           = "stdout"
)

func outfileFlag() cli.Flag {
	return &cli.StringFlag{
		Name:    outfileFlagName,
		Value:   "",
		EnvVars: []string{"OUTFILE"},
		Usage:   "Path to output file",
	}
}

func getOutfile(c *cli.Context) string {
	return c.String(outfileFlagName)
}

func debugFlag() cli.Flag {
	return &cli.BoolFlag{
		Name:    debugFlagName,
		EnvVars: []string{"DEBUG"},
		Usage:   "Enable debug http request logging",
	}
}

func getDebug(c *cli.Context) bool {
	return c.Bool(debugFlagName)
}

func mobiusCertificateFlag() cli.Flag {
	return &cli.StringFlag{
		Name:    mobiusCertificateFlagName,
		EnvVars: []string{"MOBIUS_CERTIFICATE"},
		Usage:   "Path of the TLS mobius certificate, can be used to provide additional connection debugging information",
	}
}

func getMobiusCertificate(c *cli.Context) string {
	return c.String(mobiusCertificateFlagName)
}

func stdoutFlag() cli.Flag {
	return &cli.BoolFlag{
		Name:    stdoutFlagName,
		EnvVars: []string{"STDOUT"},
		Usage:   "Print contents to stdout",
	}
}

func getStdout(c *cli.Context) bool {
	return c.Bool(stdoutFlagName)
}

func byHostIdentifier() cli.Flag {
	return &cli.StringFlag{
		Name:  "host",
		Usage: "Filter MDM commands by host specified by hostname, UUID, or serial number.",
	}
}

func byMDMCommandRequestType() cli.Flag {
	return &cli.StringFlag{
		Name:  "type",
		Usage: "Filter MDM commands by type.",
	}
}
