package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

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
	// Prompt for sudo early (needed for embedded dockerd)
	boxStyle := branding.NewBoxStyle(50)
	titleStyle := branding.NewTitleStyle(50)
	successStyle := branding.StyleSuccess

	setupBox := boxStyle.Render(
		titleStyle.Render("🚀 "+branding.AppName+" Server Setup") + "\n\n" +
			"Embedded Docker requires sudo access.\n" +
			"Please enter your password when prompted.",
	)
	fmt.Println("\n" + setupBox + "\n")

	// Pre-authenticate sudo
	authCmd := exec.Command("sudo", "true")
	authCmd.Stdin = os.Stdin
	authCmd.Stdout = os.Stdout
	authCmd.Stderr = os.Stderr
	if err := authCmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "\n✗ Failed to authenticate: %v\n", err)
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

	// Start Docker daemon (embedded or connect to existing)
	tuiProgram.Info("Initializing Mobius server...")
	dockerDaemon, err := docker.Start(tui.NewLogger(tuiProgram))
	if err != nil {
		tuiProgram.Error(fmt.Sprintf("Failed to start Docker: %v", err))
		tuiProgram.Error("Press Ctrl+C to exit")
		// Keep TUI alive to show error
		signChn := make(chan os.Signal, 1)
		signal.Notify(signChn, syscall.SIGINT, syscall.SIGTERM)
		<-signChn
		return
	}
	defer dockerDaemon.Stop()

	// Ensure kubectl is installed
	tuiProgram.Info("Checking kubectl availability...")
	kubectlPath, err := docker.EnsureKubectl(tui.NewLogger(tuiProgram))
	if err != nil {
		tuiProgram.Error(fmt.Sprintf("Failed to ensure kubectl: %v", err))
		tuiProgram.Error("Press Ctrl+C to exit")
		signChn := make(chan os.Signal, 1)
		signal.Notify(signChn, syscall.SIGINT, syscall.SIGTERM)
		<-signChn
		return
	}

	// Add kubectl to PATH if it's not in system PATH
	if filepath.Dir(kubectlPath) != "/usr/bin" && filepath.Dir(kubectlPath) != "/usr/local/bin" {
		newPath := filepath.Dir(kubectlPath) + ":" + os.Getenv("PATH")
		os.Setenv("PATH", newPath)
		tuiProgram.Info(fmt.Sprintf("Added %s to PATH", filepath.Dir(kubectlPath)))
	}

	// Get absolute path for config files
	kubeconfigPath, _ := filepath.Abs("configs/cluster/kubeconfig")

	// Create KIND cluster (without config file for now - using defaults)
	tuiProgram.Info("Creating Kubernetes cluster...")
	cluster := kind.NewCluster(logger, kind.Config{
		Name:           "mobius-cluster",
		ConfigPath:     "", // Empty to use defaults
		KubeconfigPath: kubeconfigPath,
		DockerHost:     dockerDaemon.GetSocketPath(), // Use embedded Docker socket
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
	}()

	tuiProgram.Success("Mobius cluster is running!")
	tuiProgram.Info(fmt.Sprintf("Kubeconfig: %s", kubeconfigPath))

	// Get workspace root for UI path
	workspaceRoot, _ := filepath.Abs(".")

	// Initialize deployer
	deployer := deploy.NewDeployer(kubeconfigPath, logger)

	// Wait for Kubernetes API server to be ready
	tuiProgram.Info("Waiting for Kubernetes API server...")
	if err := deployer.WaitForAPIServer(30 * time.Second); err != nil {
		tuiProgram.Error(fmt.Sprintf("API server failed to become ready: %v", err))
		tuiProgram.Warning("Continuing anyway, services may fail to deploy...")
	} else {
		tuiProgram.Success("Kubernetes API server is ready!")
	}

	// Deploy services concurrently for better performance
	var wg sync.WaitGroup
	var cnpgDeployer *cnpg.Deployer
	var headscaleDeployer *headscale.Deployer
	var apiServer *api.Server
	var uiDeployer *ui.Deployer
	
	// Use channels to collect errors
	cnpgErr := make(chan error, 1)
	apiErr := make(chan error, 1)
	uiErr := make(chan error, 1)

	// Deploy CNPG first (required for Headscale)
	wg.Add(1)
	go func() {
		defer wg.Done()
		tuiProgram.Info("Deploying CloudNativePG operator...")
		cnpgConfig := cnpg.DefaultConfig()
		cnpgDeployer = cnpg.NewDeployer(deployer, logger, cnpgConfig)
		if err := cnpgDeployer.Deploy(); err != nil {
			tuiProgram.Error(fmt.Sprintf("Failed to deploy CNPG: %v", err))
			cnpgErr <- err
		} else {
			tuiProgram.Success("CloudNativePG operator deployed successfully")
			cnpgErr <- nil
		}
	}()

	// Start API server in parallel
	wg.Add(1)
	go func() {
		defer wg.Done()
		tuiProgram.Info("Starting API server on port 3001...")
		apiConfig := api.Config{
			Port:       "3001",
			Kubeconfig: kubeconfigPath,
		}
		apiServer = api.NewServer(logger, apiConfig)
		if err := apiServer.Start(); err != nil {
			tuiProgram.Error(fmt.Sprintf("Failed to start API server: %v", err))
			tuiProgram.Info("Tip: Kill any process using port 3001 first")
			apiErr <- err
		} else {
			tuiProgram.Success(fmt.Sprintf("API server running at http://localhost:%s", apiConfig.Port))
			apiErr <- nil
		}
	}()

	// Wait for CNPG and API to be ready
	wg.Wait()
	
	// Check for critical errors
	tuiProgram.Info("Checking CNPG deployment status...")
	if err := <-cnpgErr; err != nil {
		tuiProgram.Error(fmt.Sprintf("CNPG deployment failed: %v", err))
		tuiProgram.Error("Cannot continue without CNPG")
		return
	}
	tuiProgram.Info("Checking API server status...")
	if err := <-apiErr; err != nil {
		tuiProgram.Error(fmt.Sprintf("API server failed to start: %v", err))
		tuiProgram.Error("Cannot continue without API server")
		return
	}
	tuiProgram.Success("Core services (CNPG + API) are running!")

	// Now deploy Headscale (requires CNPG to be running)
	tuiProgram.Info("Deploying Headscale VPN with PostgreSQL...")
	headscaleConfig := headscale.DefaultConfig()
	headscaleDeployer = headscale.NewDeployer(deployer, logger, headscaleConfig)
	if err := headscaleDeployer.Deploy(); err != nil {
		tuiProgram.Warning(fmt.Sprintf("Headscale deployment skipped: %v", err))
		tuiProgram.Info("Server will continue without Headscale VPN")
	} else {
		tuiProgram.Success("Headscale deployed successfully with PostgreSQL")
	}

	// Deploy UI after other services are ready
	go func() {
		tuiProgram.Info("Deploying UI...")
		uiConfig := ui.DefaultConfig(workspaceRoot)
		uiDeployer = ui.NewDeployer(deployer, logger, uiConfig)
		if err := uiDeployer.Deploy(); err != nil {
			tuiProgram.Error(fmt.Sprintf("Failed to deploy UI: %v", err))
			uiErr <- err
		} else {
			tuiProgram.Success("UI deployed successfully")
			
			// Show prominent access message
			successBox := branding.NewBoxStyle(60)
			titleStyle := branding.StyleTitle
			accessMsg := successStyle.Render("✓ Mobius is ready!") + "\n\n" +
				"Access your dashboard at:\n" +
				titleStyle.Render(fmt.Sprintf("  http://localhost:%d", uiConfig.ServicePort)) + "\n\n" +
				"Press Ctrl+C to stop the server."
			fmt.Println("\n" + successBox.Render(accessMsg))
			
			uiErr <- nil
		}
	}()
	
	// Wait for UI to deploy (or fail)
	select {
	case err := <-uiErr:
		if err != nil {
			tuiProgram.Warning("UI deployment failed, but server will continue")
		}
	case <-time.After(10 * time.Minute):
		tuiProgram.Warning("UI deployment timed out after 10 minutes")
	}

	// Ensure cleanup happens in reverse order
	defer func() {
		if uiDeployer != nil {
			tuiProgram.Info("Uninstalling UI...")
			if err := uiDeployer.Uninstall(); err != nil {
				tuiProgram.Warning(fmt.Sprintf("Failed to uninstall UI: %v", err))
			}
		}
		if apiServer != nil {
			tuiProgram.Info("Stopping API server...")
			if err := apiServer.Stop(); err != nil {
				tuiProgram.Warning(fmt.Sprintf("Failed to stop API server: %v", err))
			}
		}
		if headscaleDeployer != nil {
			tuiProgram.Info("Uninstalling Headscale...")
			if err := headscaleDeployer.Uninstall(); err != nil {
				tuiProgram.Warning(fmt.Sprintf("Failed to uninstall Headscale: %v", err))
			}
		}
		if cnpgDeployer != nil {
			tuiProgram.Info("Uninstalling CloudNativePG...")
			if err := cnpgDeployer.Uninstall(); err != nil {
				tuiProgram.Warning(fmt.Sprintf("Failed to uninstall CNPG: %v", err))
			}
		}
	}()

	// Setup signal handling
	signChn := make(chan os.Signal, 1)
	signal.Notify(signChn, syscall.SIGINT, syscall.SIGTERM)

	// Wait for shutdown signal
	<-signChn
	tuiProgram.Info("Shutdown signal received, cleaning up...")
}
