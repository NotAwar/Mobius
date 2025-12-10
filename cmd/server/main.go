package main

import (
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"mobius/internal/deploy"
	"mobius/internal/docker"
	"mobius/internal/headscale"
	"mobius/internal/kind"
	"mobius/internal/ui"

	"github.com/sirupsen/logrus"
)

func main() {
	// Setup logger
	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})
	logger.SetOutput(os.Stdout)
	logger.SetLevel(logrus.TraceLevel)

	// Verify Docker is available (OS-independent)
	logger.Info("Initializing Mobius server...")
	dockerDaemon, err := docker.Start(logger)
	if err != nil {
		logger.Fatalf("Failed to start Docker: %v", err)
	}
	defer dockerDaemon.Stop()

	// Get absolute path for config files
	kubeconfigPath, _ := filepath.Abs("configs/cluster/kubeconfig")

	// Create KIND cluster (without config file for now - using defaults)
	cluster := kind.NewCluster(logger, kind.Config{
		Name:           "mobius-cluster",
		ConfigPath:     "", // Empty to use defaults
		KubeconfigPath: kubeconfigPath,
	})

	if err := cluster.Create(); err != nil {
		logger.Fatalf("Failed to create cluster: %v", err)
	}

	// Ensure cluster cleanup always happens
	defer func() {
		logger.Info("Deleting cluster...")
		if err := cluster.Delete(); err != nil {
			logger.Warnf("Failed to delete cluster: %v", err)
		}
		dockerDaemon.Stop()
	}()

	logger.Info("=================================================================")
	logger.Info("Mobius server is running!")
	logger.Info("=================================================================")
	logger.Infof("Kubeconfig: %s", kubeconfigPath)
	logger.Info("Press Ctrl+C to stop")
	logger.Info("=================================================================")

	// Get workspace root for UI path
	workspaceRoot, _ := filepath.Abs(".")

	// Deploy Headscale
	deployer := deploy.NewDeployer(kubeconfigPath, logger)
	headscaleConfig := headscale.DefaultConfig()
	headscaleDeployer := headscale.NewDeployer(deployer, logger, headscaleConfig)
	if err := headscaleDeployer.Deploy(); err != nil {
		logger.Errorf("Failed to deploy Headscale: %v", err)
	}

	// Ensure Headscale cleanup
	defer func() {
		logger.Info("Uninstalling Headscale...")
		if err := headscaleDeployer.Uninstall(); err != nil {
			logger.Warnf("Failed to uninstall Headscale: %v", err)
		}
	}()

	// Deploy Svelte UI
	uiConfig := ui.DefaultConfig(workspaceRoot)
	uiDeployer := ui.NewDeployer(deployer, logger, uiConfig)
	if err := uiDeployer.Deploy(); err != nil {
		logger.Errorf("Failed to deploy UI: %v", err)
	}

	// Ensure UI cleanup
	defer func() {
		logger.Info("Uninstalling UI...")
		if err := uiDeployer.Uninstall(); err != nil {
			logger.Warnf("Failed to uninstall UI: %v", err)
		}
	}()

	// Setup signal handling
	signChn := make(chan os.Signal, 1)
	signal.Notify(signChn, syscall.SIGINT, syscall.SIGTERM)

	// Wait for shutdown signal
	<-signChn
	logger.Info("Shutdown signal received, cleaning up...")
	logger.Info("Cleanup completed")
}
