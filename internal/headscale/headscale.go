package headscale

import (
	"fmt"
	"os"

	cmd "github.com/go-cmd/cmd"
	"github.com/sirupsen/logrus"
	"mobius/internal/deploy"
)

const (
	chartRepoURL = "https://github.com/IvanLapchenko/headscale-helm-chart.git"
	chartTmpDir  = "/tmp/headscale-helm-chart"
	namespace    = "headscale"
	releaseName  = "headscale"
)

// Config holds Headscale deployment configuration
type Config struct {
	// Namespace to deploy into
	Namespace string
	// ReleaseName for the Helm release
	ReleaseName string
	// DisableIngress disables both API and UI ingresses
	DisableIngress bool
	// CustomValues for Helm chart
	CustomValues map[string]string
}

// DefaultConfig returns the default Headscale configuration
func DefaultConfig() Config {
	return Config{
		Namespace:      namespace,
		ReleaseName:    releaseName,
		DisableIngress: true, // Default to disabled for local development
		CustomValues:   make(map[string]string),
	}
}

// Deployer handles Headscale deployment
type Deployer struct {
	config   Config
	deployer *deploy.Deployer
	logger   *logrus.Logger
}

// NewDeployer creates a new Headscale deployer
func NewDeployer(deployer *deploy.Deployer, logger *logrus.Logger, config Config) *Deployer {
	return &Deployer{
		config:   config,
		deployer: deployer,
		logger:   logger,
	}
}

// Deploy deploys Headscale to the cluster
func (h *Deployer) Deploy() error {
	// Create namespace
	if err := h.deployer.CreateNamespace(h.config.Namespace); err != nil {
		return fmt.Errorf("failed to create namespace: %w", err)
	}

	// Clone the chart repository
	if err := h.cloneChart(); err != nil {
		return fmt.Errorf("failed to clone chart: %w", err)
	}

	// Prepare Helm values
	helmValues := h.prepareValues()

	// Install the chart
	h.logger.Infof("Installing Helm chart: %s as release %s in namespace %s", chartTmpDir, h.config.ReleaseName, h.config.Namespace)
	if err := h.deployer.HelmInstall(h.config.ReleaseName, chartTmpDir, h.config.Namespace, helmValues, nil); err != nil {
		return fmt.Errorf("failed to install helm chart: %w", err)
	}

	h.logger.Info("Headscale installed successfully!")
	h.logger.Info("Headscale is running in the cluster!")
	h.logger.Infof("To access Headscale, use: kubectl port-forward -n %s svc/%s 8080:8080", h.config.Namespace, h.config.ReleaseName)

	return nil
}

// cloneChart clones the Headscale Helm chart from GitHub
func (h *Deployer) cloneChart() error {
	h.logger.Info("Cloning Headscale Helm chart from GitHub...")

	// Remove existing directory if it exists
	if _, err := os.Stat(chartTmpDir); err == nil {
		if err := os.RemoveAll(chartTmpDir); err != nil {
			return fmt.Errorf("failed to remove existing chart directory: %w", err)
		}
	}

	// Clone the repository
	cloneCmd := cmd.NewCmd("git", "clone", chartRepoURL, chartTmpDir)
	status := <-cloneCmd.Start()

	if status.Exit != 0 {
		return fmt.Errorf("failed to clone chart repository: %s", status.Stderr)
	}

	return nil
}

// prepareValues prepares Helm values for installation
func (h *Deployer) prepareValues() map[string]string {
	helmValues := make(map[string]string)

	// Disable ingresses for local development by default
	if h.config.DisableIngress {
		helmValues["ingressApi.enabled"] = "false"
		helmValues["ingressUI.enabled"] = "false"
	}

	// Merge custom values
	for k, v := range h.config.CustomValues {
		helmValues[k] = v
	}

	return helmValues
}

// Uninstall removes Headscale from the cluster
func (h *Deployer) Uninstall() error {
	h.logger.Infof("Uninstalling Headscale from namespace %s...", h.config.Namespace)
	
	if err := h.deployer.HelmUninstall(h.config.ReleaseName, h.config.Namespace); err != nil {
		return fmt.Errorf("failed to uninstall Headscale: %w", err)
	}

	h.logger.Info("Headscale uninstalled successfully")
	return nil
}
