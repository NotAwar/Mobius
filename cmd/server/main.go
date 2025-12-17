package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"mobius/internal/api"
	"mobius/internal/cnpg"
	"mobius/internal/deploy"
	"mobius/internal/docker"
	"mobius/internal/headscale"
	"mobius/internal/kind"
	"mobius/internal/tui"
	"mobius/internal/ui"
	"mobius/pkg/branding"

	"github.com/sirupsen/logrus"
)

// tuiHook is a logrus hook that forwards logs to the TUI
type tuiHook struct {
	tui *tui.Program
}

func (h *tuiHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

func (h *tuiHook) Fire(entry *logrus.Entry) error {
	msg := entry.Message
	switch entry.Level {
	case logrus.ErrorLevel, logrus.FatalLevel, logrus.PanicLevel:
		h.tui.Error(msg)
	case logrus.WarnLevel:
		h.tui.Warning(msg)
	case logrus.InfoLevel:
		h.tui.Info(msg)
	default:
		h.tui.Info(msg)
	}
	return nil
}

func main() {
	// Pre-authenticate sudo before starting TUI (dockerd needs root)
	boxStyle := branding.NewBoxStyle(50)
	titleStyle := branding.NewTitleStyle(50)
	successStyle := branding.StyleSuccess
	errorStyle := branding.StyleError

	setupBox := boxStyle.Render(
		titleStyle.Render("🚀 "+branding.AppName+" Server Setup") + "\n\n" +
			"Docker daemon requires root access.\n" +
			"Please enter your password when prompted.",
	)
	fmt.Println("\n" + setupBox + "\n")

	authCmd := exec.Command("sudo", "true")
	authCmd.Stdin = os.Stdin
	authCmd.Stdout = os.Stdout
	authCmd.Stderr = os.Stderr
	if err := authCmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "\n"+errorStyle.Render("✗ Failed to authenticate: %v")+"\n", err)
		os.Exit(1)
	}

	fmt.Println("\n" + successStyle.Render("✓ Authentication successful") + "\n")

	// Start TUI
	tuiProgram := tui.Start()
	defer tuiProgram.Quit()

	// Setup logrus logger with TUI hook
	logger := logrus.New()
	logger.SetOutput(io.Discard) // Don't output to stdout
	logger.AddHook(&tuiHook{tui: tuiProgram})
	logger.SetLevel(logrus.InfoLevel)

	// Verify Docker is available (OS-independent)
	tuiProgram.Info("Initializing Mobius server...")
	dockerDaemon, err := docker.Start(tui.NewLogger(tuiProgram))
	if err != nil {
		errMsg := err.Error()
		// Check if this is the "restart needed" message
		if strings.Contains(errMsg, "Setup complete!") || strings.Contains(errMsg, "restart Mobius") {
			tuiProgram.Success("Initial setup completed successfully!")
			tuiProgram.Info("Please run the server again to start Mobius")
			tuiProgram.Info("Press Ctrl+C to exit")
		} else {
			tuiProgram.Error(fmt.Sprintf("Failed to start Docker: %v", err))
			tuiProgram.Error("Press Ctrl+C to exit")
		}
		// Keep TUI alive to show error
		signChn := make(chan os.Signal, 1)
		signal.Notify(signChn, syscall.SIGINT, syscall.SIGTERM)
		<-signChn
		return
	}
	defer dockerDaemon.Stop()

	// Get absolute path for config files
	kubeconfigPath, _ := filepath.Abs("configs/cluster/kubeconfig")

	// Create KIND cluster (without config file for now - using defaults)
	tuiProgram.Info("Creating Kubernetes cluster...")
	cluster := kind.NewCluster(logger, kind.Config{
		Name:           "mobius-cluster",
		ConfigPath:     "", // Empty to use defaults
		KubeconfigPath: kubeconfigPath,
	})

	if err := cluster.Create(); err != nil {
		tuiProgram.Error(fmt.Sprintf("Failed to create cluster: %v", err))
		return
	}

	// Ensure cluster cleanup always happens
	defer func() {
		tuiProgram.Info("Deleting cluster...")
		if err := cluster.Delete(); err != nil {
			tuiProgram.Warning(fmt.Sprintf("Failed to delete cluster: %v", err))
		}
		dockerDaemon.Stop()
	}()

	tuiProgram.Success("Mobius cluster is running!")
	tuiProgram.Info(fmt.Sprintf("Kubeconfig: %s", kubeconfigPath))

	// Get workspace root for UI path
	workspaceRoot, _ := filepath.Abs(".")

	// Initialize deployer
	deployer := deploy.NewDeployer(kubeconfigPath, logger)

	// Deploy CloudNativePG operator
	tuiProgram.Info("Deploying CloudNativePG operator...")
	cnpgConfig := cnpg.DefaultConfig()
	cnpgDeployer := cnpg.NewDeployer(deployer, logger, cnpgConfig)
	if err := cnpgDeployer.Deploy(); err != nil {
		tuiProgram.Error(fmt.Sprintf("Failed to deploy CNPG: %v", err))
	} else {
		tuiProgram.Success("CloudNativePG operator deployed successfully")
	}

	// Ensure CNPG cleanup
	defer func() {
		tuiProgram.Info("Uninstalling CloudNativePG...")
		if err := cnpgDeployer.Uninstall(); err != nil {
			tuiProgram.Warning(fmt.Sprintf("Failed to uninstall CNPG: %v", err))
		}
	}()

	// Deploy Headscale
	tuiProgram.Info("Deploying Headscale VPN...")
	headscaleConfig := headscale.DefaultConfig()
	headscaleDeployer := headscale.NewDeployer(deployer, logger, headscaleConfig)
	if err := headscaleDeployer.Deploy(); err != nil {
		tuiProgram.Error(fmt.Sprintf("Failed to deploy Headscale: %v", err))
	} else {
		tuiProgram.Success("Headscale deployed successfully")
	}

	// Ensure Headscale cleanup
	defer func() {
		tuiProgram.Info("Uninstalling Headscale...")
		if err := headscaleDeployer.Uninstall(); err != nil {
			tuiProgram.Warning(fmt.Sprintf("Failed to uninstall Headscale: %v", err))
		}
	}()

	// Start API server
	tuiProgram.Info("Starting API server...")
	apiConfig := api.Config{
		Port:       "3000",
		Kubeconfig: kubeconfigPath,
	}
	apiServer := api.NewServer(logger, apiConfig)
	if err := apiServer.Start(); err != nil {
		tuiProgram.Error(fmt.Sprintf("Failed to start API server: %v", err))
	} else {
		tuiProgram.Success(fmt.Sprintf("API server running at http://localhost:%s", apiConfig.Port))
	}

	// Ensure API server cleanup
	defer func() {
		tuiProgram.Info("Stopping API server...")
		if err := apiServer.Stop(); err != nil {
			tuiProgram.Warning(fmt.Sprintf("Failed to stop API server: %v", err))
		}
	}()

	// Deploy Svelte UI
	tuiProgram.Info("Deploying UI...")
	uiConfig := ui.DefaultConfig(workspaceRoot)
	uiDeployer := ui.NewDeployer(deployer, logger, uiConfig)
	if err := uiDeployer.Deploy(); err != nil {
		tuiProgram.Error(fmt.Sprintf("Failed to deploy UI: %v", err))
	} else {
		tuiProgram.Success("UI deployed successfully")
	}

	// Ensure UI cleanup
	defer func() {
		tuiProgram.Info("Uninstalling UI...")
		if err := uiDeployer.Uninstall(); err != nil {
			tuiProgram.Warning(fmt.Sprintf("Failed to uninstall UI: %v", err))
		}
	}()

	// Setup signal handling
	signChn := make(chan os.Signal, 1)
	signal.Notify(signChn, syscall.SIGINT, syscall.SIGTERM)

	// Wait for shutdown signal
	<-signChn
	tuiProgram.Info("Shutdown signal received, cleaning up...")
}
