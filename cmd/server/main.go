package main

import (
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"mobius/internal/deploy"
	"mobius/internal/docker"
	"mobius/internal/kind"

	cmd "github.com/go-cmd/cmd"
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

	// Ensure cleanup on exit
	defer func() {
		if err := cluster.Delete(); err != nil {
			logger.Warnf("Failed to delete cluster: %v", err)
		}
	}()

	logger.Info("=================================================================")
	logger.Info("Mobius server is running!")
	logger.Info("=================================================================")
	logger.Infof("Kubeconfig: %s", kubeconfigPath)
	logger.Info("Press Ctrl+C to stop")
	logger.Info("=================================================================")

	// Deploy Headscale
	deployer := deploy.NewDeployer(kubeconfigPath, logger)

	// Create namespace for Headscale
	if err := deployer.CreateNamespace("headscale"); err != nil {
		logger.Warnf("Failed to create namespace: %v", err)
	}

	// Clone Headscale chart
	logger.Info("Cloning Headscale Helm chart from GitHub...")
	chartTmpDir := "/tmp/headscale-helm-chart"
	cloneCmd := cmd.NewCmd("git", "clone", "https://github.com/IvanLapchenko/headscale-helm-chart.git", chartTmpDir)
	cloneStatus := <-cloneCmd.Start()
	if cloneStatus.Exit != 0 {
		// Clean up old clone if exists
		cleanCmd := cmd.NewCmd("rm", "-rf", chartTmpDir)
		<-cleanCmd.Start()
		// Try cloning again
		cloneCmd = cmd.NewCmd("git", "clone", "https://github.com/IvanLapchenko/headscale-helm-chart.git", chartTmpDir)
		cloneStatus = <-cloneCmd.Start()
		if cloneStatus.Exit != 0 {
			logger.Errorf("Failed to clone Headscale chart: %v", cloneStatus.Stderr)
		}
	}

	// Install Headscale Helm chart from cloned directory
	// Disable ingresses for local development
	helmValues := map[string]string{
		"ingressApi.enabled": "false",
		"ingressUI.enabled":  "false",
	}
	
	if err := deployer.HelmInstall(
		"headscale",
		chartTmpDir,
		"headscale",
		helmValues,
		nil, // No values files for now
	); err != nil {
		logger.Errorf("Failed to install Headscale: %v", err)
	} else {
		logger.Info("Headscale installed successfully!")
		logger.Info("Headscale is running in the cluster!")
		logger.Info("To access Headscale, use: kubectl port-forward -n headscale svc/headscale 8080:8080")
	}

	// Setup signal handling
	signChn := make(chan os.Signal, 1)
	signal.Notify(signChn, syscall.SIGINT, syscall.SIGTERM)

	// Wait for shutdown signal
	<-signChn
	logger.Info("Shutdown signal received, cleaning up...")
}
