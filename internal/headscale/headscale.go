package headscale

import (
	"fmt"
	"os"
	"time"

	"mobius/internal/deploy"

	"github.com/sirupsen/logrus"
)

const (
	// Using OCI-based Helm chart from Codeberg
	chartName   = "oci://codeberg.org/wrenix/helm-charts/headscale"
	namespace   = "headscale"
	releaseName = "headscale"
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

	// Deploy PostgreSQL cluster for Headscale
	h.logger.Info("Creating PostgreSQL database for Headscale...")
	
	// Wait for CNPG webhook to be ready (needed for cluster creation)
	h.logger.Info("Waiting for CNPG webhook service...")
	time.Sleep(30 * time.Second)
	
	postgresManifest := "configs/headscale/postgres.yaml"
	if err := h.deployer.Apply(postgresManifest); err != nil {
		return fmt.Errorf("failed to create PostgreSQL cluster: %w", err)
	}

	// Wait for PostgreSQL to be ready
	h.logger.Info("Waiting for PostgreSQL database...")
	time.Sleep(20 * time.Second)

	// Prepare Helm values
	helmValues := h.prepareValues()
	
	// Use values file if it exists
	valuesFile := "configs/headscale/values.yaml"
	var valuesFiles []string
	if _, err := os.Stat(valuesFile); err == nil {
		valuesFiles = append(valuesFiles, valuesFile)
		h.logger.Info("Using Headscale values file: configs/headscale/values.yaml")
	} else {
		h.logger.Warn("No custom values file found, using default Helm values")
	}

	// Install the chart (OCI charts don't need repo add)
	h.logger.Infof("Installing Helm chart: %s as release %s in namespace %s", chartName, h.config.ReleaseName, h.config.Namespace)
	h.logger.Info("Note: This may take a few minutes to download and install...")
	
	if err := h.deployer.HelmInstall(h.config.ReleaseName, chartName, h.config.Namespace, helmValues, valuesFiles); err != nil {
		// Provide detailed error information
		h.logger.Errorf("Failed to install Headscale Helm chart: %v", err)
		h.logger.Error("Possible causes:")
		h.logger.Error("  1. Helm chart repository (codeberg.org) may be unreachable")
		h.logger.Error("  2. OCI registry authentication may be required")
		h.logger.Error("  3. Chart version may not exist or be incompatible")
		h.logger.Error("  4. RBAC permissions may be insufficient")
		h.logger.Info("You can manually install Headscale later if needed")
		return fmt.Errorf("failed to install helm chart %s: %w", chartName, err)
	}

	h.logger.Info("Headscale installed successfully!")
	h.logger.Info("Headscale is running in the cluster!")
	h.logger.Infof("To access Headscale, use: kubectl port-forward -n %s svc/%s 8080:8080", h.config.Namespace, h.config.ReleaseName)

	return nil
}

// Note: OCI charts (oci://) don't require adding repositories
// The chart is pulled directly from the OCI registry

// prepareValues prepares Helm values for installation
func (h *Deployer) prepareValues() map[string]string {
	helmValues := make(map[string]string)

	// Disable ingresses for local development by default
	if h.config.DisableIngress {
		helmValues["ingressApi.enabled"] = "false"
		helmValues["ingressUI.enabled"] = "false"
	}

	// Configure key generation - disable cert-manager integration for local dev
	helmValues["headscale.certmanager.enabled"] = "false"
	
	// Use SQLite for simplicity in local development
	helmValues["headscale.config.database.type"] = "sqlite"
	
	// Ensure keys are created automatically
	helmValues["headscale.keys.create"] = "true"

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
