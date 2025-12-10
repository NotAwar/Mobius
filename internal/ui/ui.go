package ui

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"mobius/internal/deploy"

	cmd "github.com/go-cmd/cmd"
	"github.com/sirupsen/logrus"
)

const (
	namespace   = "mobius-ui"
	releaseName = "mobius-ui"
	serviceName = "mobius-ui"
	servicePort = 8081
)

// Config holds UI deployment configuration
type Config struct {
	// Namespace to deploy into
	Namespace string
	// ReleaseName for the Helm release
	ReleaseName string
	// ServiceName for the Kubernetes service
	ServiceName string
	// ServicePort for the UI service
	ServicePort int
	// UIPath is the path to the UI directory (archive/ui/web)
	UIPath string
	// BuildUI determines whether to build the UI before deploying
	BuildUI bool
	// CustomValues for Kubernetes deployment
	CustomValues map[string]string
}

// DefaultConfig returns the default UI configuration
func DefaultConfig(workspaceRoot string) Config {
	return Config{
		Namespace:    namespace,
		ReleaseName:  releaseName,
		ServiceName:  serviceName,
		ServicePort:  servicePort,
		UIPath:       filepath.Join(workspaceRoot, "archive", "ui", "web"),
		BuildUI:      true,
		CustomValues: make(map[string]string),
	}
}

// Deployer handles UI deployment
type Deployer struct {
	config         Config
	deployer       *deploy.Deployer
	logger         *logrus.Logger
	portForwardCmd *cmd.Cmd
}

// NewDeployer creates a new UI deployer
func NewDeployer(deployer *deploy.Deployer, logger *logrus.Logger, config Config) *Deployer {
	return &Deployer{
		config:   config,
		deployer: deployer,
		logger:   logger,
	}
}

// Deploy deploys the Svelte UI to the cluster
func (u *Deployer) Deploy() error {
	// Build the Docker image
	if u.config.BuildUI {
		if err := u.buildDockerImage(); err != nil {
			return fmt.Errorf("failed to build Docker image: %w", err)
		}
	}

	// Create namespace
	if err := u.deployer.CreateNamespace(u.config.Namespace); err != nil {
		return fmt.Errorf("failed to create namespace: %w", err)
	}

	// Create Kubernetes manifests
	manifestPath, err := u.generateManifests()
	if err != nil {
		return fmt.Errorf("failed to generate manifests: %w", err)
	}
	defer os.RemoveAll(filepath.Dir(manifestPath))

	// Apply the manifests
	u.logger.Infof("Deploying UI to namespace %s", u.config.Namespace)
	if err := u.deployer.Apply(manifestPath); err != nil {
		return fmt.Errorf("failed to apply manifests: %w", err)
	}

	u.logger.Info("Mobius UI deployed successfully!")

	// Wait for deployment to be ready
	u.logger.Info("Waiting for UI deployment to be ready...")
	if err := u.deployer.WaitForDeployment(u.config.Namespace, u.config.ServiceName, 5*time.Minute); err != nil {
		return fmt.Errorf("failed to wait for deployment: %w", err)
	}

	// Start port-forwarding automatically
	if err := u.startPortForward(); err != nil {
		return fmt.Errorf("failed to start port-forward: %w", err)
	}

	u.logger.Infof("UI is now accessible at: http://localhost:%d", u.config.ServicePort)

	return nil
}

// buildDockerImage builds the Docker image and loads it into KIND
func (u *Deployer) buildDockerImage() error {
	u.logger.Info("Building Svelte UI Docker image...")

	imageName := "mobius-ui:latest"

	// Build the Docker image
	buildCmd := cmd.NewCmd("docker", "build", "-t", imageName, ".")
	buildCmd.Dir = u.config.UIPath
	status := <-buildCmd.Start()

	if status.Exit != 0 {
		return fmt.Errorf("docker build failed: %s", status.Stderr)
	}

	u.logger.Info("Loading image into KIND cluster...")
	// Load the image into KIND
	loadCmd := cmd.NewCmd("kind", "load", "docker-image", imageName, "--name", "mobius-cluster")
	loadStatus := <-loadCmd.Start()

	if loadStatus.Exit != 0 {
		return fmt.Errorf("kind load failed: %s", loadStatus.Stderr)
	}

	u.logger.Info("UI Docker image built and loaded successfully")
	return nil
}

// generateManifests creates Kubernetes deployment and service manifests
func (u *Deployer) generateManifests() (string, error) {
	// Create a temporary directory for manifests
	tmpDir, err := os.MkdirTemp("", "mobius-ui-manifests-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temp dir: %w", err)
	}

	manifestPath := filepath.Join(tmpDir, "ui-deployment.yaml")

	manifest := fmt.Sprintf(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: %s
  namespace: %s
  labels:
    app: %s
spec:
  replicas: 1
  selector:
    matchLabels:
      app: %s
  template:
    metadata:
      labels:
        app: %s
    spec:
      containers:
      - name: ui
        image: mobius-ui:latest
        imagePullPolicy: IfNotPresent
        ports:
        - name: http
          containerPort: 80
---
apiVersion: v1
kind: Service
metadata:
  name: %s
  namespace: %s
  labels:
    app: %s
spec:
  type: ClusterIP
  selector:
    app: %s
  ports:
  - name: ui-port
    port: %d
    targetPort: http
    protocol: TCP
`,
		u.config.ReleaseName, u.config.Namespace, u.config.ServiceName,
		u.config.ServiceName,
		u.config.ServiceName,
		u.config.ServiceName, u.config.Namespace, u.config.ServiceName,
		u.config.ServiceName,
		u.config.ServicePort,
	)

	if err := os.WriteFile(manifestPath, []byte(manifest), 0644); err != nil {
		return "", fmt.Errorf("failed to write manifest: %w", err)
	}

	return manifestPath, nil
}

// startPortForward starts a port-forward to the UI service
func (u *Deployer) startPortForward() error {
	u.logger.Infof("Starting port-forward to UI service on port %d...", u.config.ServicePort)

	// Map local port to service port (service then routes to container port 80)
	portMapping := fmt.Sprintf("%d:%d", u.config.ServicePort, u.config.ServicePort)
	u.portForwardCmd = cmd.NewCmd(
		"kubectl", "port-forward",
		"-n", u.config.Namespace,
		fmt.Sprintf("svc/%s", u.config.ServiceName),
		portMapping,
	)
	u.portForwardCmd.Env = append(os.Environ(), fmt.Sprintf("KUBECONFIG=%s", u.deployer.GetKubeconfig()))

	// Start in background
	statusChan := u.portForwardCmd.Start()

	// Start a goroutine to log if port-forward fails
	go func() {
		status := <-statusChan
		if status.Exit != 0 {
			u.logger.Warnf("Port-forward exited with code %d: %s", status.Exit, status.Stderr)
		}
	}()

	u.logger.Info("Port-forward started successfully")
	return nil
}

// stopPortForward stops the port-forward process
func (u *Deployer) stopPortForward() {
	if u.portForwardCmd != nil {
		u.logger.Info("Stopping port-forward...")
		if err := u.portForwardCmd.Stop(); err != nil {
			u.logger.Warnf("Failed to stop port-forward: %v", err)
		}
	}
}

// Uninstall removes the UI from the cluster
func (u *Deployer) Uninstall() error {
	u.logger.Infof("Uninstalling UI from namespace %s...", u.config.Namespace)

	// Stop port-forward first
	u.stopPortForward()

	// Delete the deployment
	deleteCmd := cmd.NewCmd("kubectl", "delete", "namespace", u.config.Namespace)
	deleteCmd.Env = append(os.Environ(), fmt.Sprintf("KUBECONFIG=%s", u.deployer.GetKubeconfig()))
	status := <-deleteCmd.Start()

	if status.Exit != 0 {
		return fmt.Errorf("failed to delete namespace: %s", status.Stderr)
	}

	u.logger.Info("UI uninstalled successfully")
	return nil
}
