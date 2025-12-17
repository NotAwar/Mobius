package cnpg

import (
	"fmt"

	"mobius/internal/deploy"

	"github.com/sirupsen/logrus"
)

const (
	chartRepoName = "cnpg"
	chartRepoURL  = "https://cloudnative-pg.github.io/charts"
	chartName     = "cnpg/cloudnative-pg"
	namespace     = "cnpg-system"
	releaseName   = "cnpg"
)

// Config holds cnpg deployment configuration
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

// DefaultConfig returns the default cnpg configuration
func DefaultConfig() Config {
	return Config{
		Namespace:      namespace,
		ReleaseName:    releaseName,
		DisableIngress: true, // Default to disabled for local development
		CustomValues:   make(map[string]string),
	}
}

// Deployer handles cnpg deployment
type Deployer struct {
	config   Config
	deployer *deploy.Deployer
	logger   *logrus.Logger
}

// NewDeployer creates a new cnpg deployer
func NewDeployer(deployer *deploy.Deployer, logger *logrus.Logger, config Config) *Deployer {
	return &Deployer{
		config:   config,
		deployer: deployer,
		logger:   logger,
	}
}

// Deploy deploys CloudNativePG operator to the cluster
func (h *Deployer) Deploy() error {
	// Create namespace
	if err := h.deployer.CreateNamespace(h.config.Namespace); err != nil {
		return fmt.Errorf("failed to create namespace: %w", err)
	}

	// Add Helm repository
	if err := h.addHelmRepo(); err != nil {
		return fmt.Errorf("failed to add helm repo: %w", err)
	}

	// Prepare Helm values
	helmValues := h.prepareValues()

	// Install the chart
	h.logger.Infof("Installing CloudNativePG operator as release %s in namespace %s", h.config.ReleaseName, h.config.Namespace)
	if err := h.deployer.HelmInstall(h.config.ReleaseName, chartName, h.config.Namespace, helmValues, nil); err != nil {
		return fmt.Errorf("failed to install helm chart: %w", err)
	}

	h.logger.Info("CloudNativePG operator installed successfully!")
	h.logger.Info("CloudNativePG is running in the cluster!")

	return nil
}

// addHelmRepo adds the CloudNativePG Helm repository
func (h *Deployer) addHelmRepo() error {
	h.logger.Info("Adding CloudNativePG Helm repository...")

	if err := h.deployer.HelmRepoAdd(chartRepoName, chartRepoURL); err != nil {
		return fmt.Errorf("failed to add helm repository: %w", err)
	}

	h.logger.Info("Updating Helm repositories...")
	if err := h.deployer.HelmRepoUpdate(); err != nil {
		return fmt.Errorf("failed to update helm repositories: %w", err)
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

// Uninstall removes CloudNativePG operator from the cluster
func (h *Deployer) Uninstall() error {
	h.logger.Infof("Uninstalling CloudNativePG from namespace %s...", h.config.Namespace)

	if err := h.deployer.HelmUninstall(h.config.ReleaseName, h.config.Namespace); err != nil {
		return fmt.Errorf("failed to uninstall CloudNativePG: %w", err)
	}

	h.logger.Info("CloudNativePG uninstalled successfully")
	return nil
}
