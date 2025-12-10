package main

import (
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"mobius/internal/docker"
	"mobius/internal/kind"
	"mobius/internal/privileges"

	"github.com/sirupsen/logrus"
)

func main() {
	// Setup logger
	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})
	logger.SetOutput(os.Stdout)
	logger.SetLevel(logrus.TraceLevel)

	// Check and elevate privileges if needed
	privileges.CheckAndElevate(logger)

	// Start Docker daemon
	logger.Info("Initializing Mobius server...")
	dockerDaemon, err := docker.Start(logger)
	if err != nil {
		logger.Fatalf("Failed to start Docker daemon: %s", privileges.FormatErrorMessage(err))
	}
	defer dockerDaemon.Stop()

	// Get absolute path for config files
	configPath, _ := filepath.Abs("../../configs/cluster/config.yaml")
	kubeconfigPath, _ := filepath.Abs("../../configs/cluster/kubeconfig")

	// Create KIND cluster
	cluster := kind.NewCluster(logger, kind.Config{
		Name:           "mobius-cluster",
		ConfigPath:     configPath,
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

	// TODO: Add your deployment logic here
	// Example:
	// deployer := deploy.NewDeployer(kubeconfigPath, logger)
	// if err := deployer.CreateNamespace("mobius-system"); err != nil {
	//     logger.Warnf("Failed to create namespace: %v", err)
	// }
	// if err := deployer.Apply("deployments/mdm-server.yaml"); err != nil {
	//     logger.Errorf("Failed to deploy MDM server: %v", err)
	// }

	// Setup signal handling
	signChn := make(chan os.Signal, 1)
	signal.Notify(signChn, syscall.SIGINT, syscall.SIGTERM)

	// Wait for shutdown signal
	<-signChn
	logger.Info("Shutdown signal received, cleaning up...")
}
