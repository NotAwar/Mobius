package mobiuscli

import (
	"encoding/json"
	"fmt"

	"github.com/notawar/mobius/mobius-server/server/mobius"
	"github.com/urfave/cli/v2"
)

func licenseCommand() *cli.Command {
	return &cli.Command{
		Name:  "license",
		Usage: "License operations",
		Subcommands: []*cli.Command{
			licenseStatusCommand(),
		},
	}
}

func licenseStatusCommand() *cli.Command {
	return &cli.Command{
		Name:  "status",
		Usage: "Show current license status",
		Flags: []cli.Flag{
			jsonFlag(),
			yamlFlag(),
			configFlag(),
			contextFlag(),
			debugFlag(),
		},
		Action: func(c *cli.Context) error {
			client, err := clientFromCLI(c)
			if err != nil {
				return err
			}
			lic, err := client.GetLicenseStatus()
			if err != nil {
				return err
			}
			if lic == nil {
				fmt.Fprintln(c.App.Writer, "No license configured")
				return nil
			}

			spec := specGeneric{
				Kind:    "License",
				Version: mobius.ApiVersion,
				Spec:    lic,
			}

			if c.Bool(jsonFlagName) {
				b, _ := json.Marshal(spec)
				fmt.Fprintf(c.App.Writer, "%s\n", b)
				return nil
			}
			return printYaml(spec, c.App.Writer)
		},
	}
}
