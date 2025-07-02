package mobiuscli

import (
	"errors"
	"fmt"
	"os"

	"github.com/notawar/mobius/server/contexts/ctxerr"
	"github.com/notawar/mobius/server/service"
	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/ssh/terminal"
)

func setupCommand() *cli.Command {
	var (
		flEmail    string
		flName     string
		flPassword string
		flOrgName  string
	)
	return &cli.Command{
		Name:      "setup",
		Usage:     "Set up a Mobius instance",
		UsageText: `mobiuscli setup [options]`,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "email",
				EnvVars:     []string{"EMAIL"},
				Value:       "",
				Destination: &flEmail,
				Usage:       "Email of the admin user to create (required)",
				Required:    true,
			},
			&cli.StringFlag{
				Name:        "name",
				EnvVars:     []string{"NAME"},
				Value:       "",
				Destination: &flName,
				Usage:       "Name or nickname of the admin user to create (required)",
				Required:    true,
			},
			&cli.StringFlag{
				Name:        "password",
				EnvVars:     []string{"PASSWORD"},
				Value:       "",
				Destination: &flPassword,
				Usage:       "Password for the admin user (recommended to use interactive entry)",
			},
			&cli.StringFlag{
				Name:        "org-name",
				EnvVars:     []string{"ORG_NAME"},
				Value:       "",
				Destination: &flOrgName,
				Usage:       "Name of the organization (required)",
				Required:    true,
			},
			configFlag(),
			contextFlag(),
			debugFlag(),
		},
		Action: func(c *cli.Context) error {
			mobius, err := unauthenticatedClientFromCLI(c)
			if err != nil {
				return err
			}

			if flPassword == "" {
				fmt.Print("Password: ")
				passBytes, err := terminal.ReadPassword(int(os.Stdin.Fd()))
				if err != nil {
					return fmt.Errorf("error reading password: %w", err)
				}
				fmt.Println()
				flPassword = string(passBytes)

				fmt.Print("Confirm Password: ")
				passBytes, err = terminal.ReadPassword(int(os.Stdin.Fd()))
				if err != nil {
					return fmt.Errorf("error reading password confirmation: %w", err)
				}
				fmt.Println()
				if flPassword != string(passBytes) {
					return errors.New("passwords do not match")
				}

			}

			token, err := mobius.Setup(flEmail, flName, flPassword, flOrgName)
			if err != nil {
				root := ctxerr.Cause(err)
				switch root.(type) { //nolint:gocritic // ignore singleCaseSwitch
				case service.SetupAlreadyErr:
					return err
				}
				return fmt.Errorf("error setting up Mobius: %w", err)
			}

			configPath, context := c.String("config"), c.String("context")

			if err := setConfigValue(configPath, context, "email", flEmail); err != nil {
				return fmt.Errorf("error setting email for the current context: %w", err)
			}

			if err := setConfigValue(configPath, context, "token", token); err != nil {
				return fmt.Errorf("error setting token for the current context: %w", err)
			}

			fmt.Println("Mobius Device Management Inc. periodically collects information about your instance.\nSending usage statistics from your Mobius instance is optional and can be disabled in settings.")
			fmt.Println("[+] Mobius setup successful and context configured!")

			return nil
		},
	}
}
