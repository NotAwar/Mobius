package mobiuscli

import (
	"errors"
	"io"

	mobiuscli "github.com/notawar/mobius/mobiuscli"
	"github.com/notawar/mobius/server/version"
	"github.com/urfave/cli/v2"
)

const (
	defaultFileMode = 0o600
)

func CreateApp(
	reader io.Reader,
	stdout io.Writer,
	stderr io.Writer,
	exitErrHandler cli.ExitErrHandlerFunc,
) *cli.App {
	app := cli.NewApp()
	app.Name = "mobiuscli"
	app.Usage = "CLI for operating Mobius"
	app.Version = version.Version().Version
	app.ExitErrHandler = exitErrHandler
	cli.VersionPrinter = func(c *cli.Context) {
		version.PrintFull()
	}
	app.Reader = reader
	app.Writer = stdout
	app.ErrWriter = stderr

	app.Commands = []*cli.Command{
		apiCommand(),
		applyCommand(),
		deleteCommand(),
		setupCommand(),
		loginCommand(),
		logoutCommand(),
		queryCommand(),
		getCommand(),
		{
			Name:  "config",
			Usage: "Modify Mobius server connection settings",
			Subcommands: []*cli.Command{
				configSetCommand(),
				configGetCommand(),
			},
		},
		convertCommand(),
		goqueryCommand(),
		userCommand(),
		debugCommand(),
		previewCommand(),
		eemobiuscli.UpdatesCommand(),
		hostsCommand(),
		vulnerabilityDataStreamCommand(),
		packageCommand(),
		generateCommand(),
		{
			// It's become common for folks to unintentionally install mobiuscli when they actually
			// need the Mobius server. This is hopefully a more helpful error message.
			Name:  "prepare",
			Usage: "This is not the binary you're looking for. Please use the mobius server binary for prepare commands.",
			Action: func(c *cli.Context) error {
				return errors.New("This is not the binary you're looking for. Please use the mobius server binary for prepare commands.")
			},
		},
		triggerCommand(),
		mdmCommand(),
		upgradePacksCommand(),
		runScriptCommand(),
		gitopsCommand(),
		generateGitopsCommand(),
	}
	return app
}
