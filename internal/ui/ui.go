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
	servicePort = 3000 // Standard port for easy access
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
		UIPath:       filepath.Join(workspaceRoot, "web"),
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
	if err := u.deployer.WaitForDeployment(u.config.Namespace, u.config.ServiceName, 2*time.Minute); err != nil {
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

	// Build the Docker image with explicit context and progress output
	buildCmd := cmd.NewCmd("docker", "build", "--progress=plain", "-t", imageName, ".")
	buildCmd.Dir = u.config.UIPath
	
	// Stream output for better visibility
	statusChan := buildCmd.Start()
	go func() {
		for buildCmd.Status().Runtime > 0 {
			status := buildCmd.Status()
			for _, line := range status.Stdout {
				u.logger.Debug(line)
			}
			for _, line := range status.Stderr {
				u.logger.Warn(line)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()
	
	status := <-statusChan
	if status.Exit != 0 {
		// Collect full error output
		errMsg := "unknown error"
		if len(status.Stderr) > 0 {
			// Get last few lines of stderr for context
			startIdx := len(status.Stderr) - 5
			if startIdx < 0 {
				startIdx = 0
			}
			errMsg = fmt.Sprintf("%v", status.Stderr[startIdx:])
		}
		return fmt.Errorf("docker build failed: %s", errMsg)
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
          containerPort: 3000
        env:
        - name: PORT
          value: "3000"
        - name: ORIGIN
          value: "http://localhost:%d"
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
		u.config.ServicePort, // ORIGIN env var
		u.config.ServiceName, u.config.Namespace, u.config.ServiceName,
		u.config.ServiceName,
		u.config.ServicePort,
	)

	if err := os.WriteFile(manifestPath, []byte(manifest), 0644); err != nil {
		return "", fmt.Errorf("failed to write manifest: %w", err)
	}

	return manifestPath, nil
}

// startPortForward starts a port-forward to the UI service with retry logic
func (u *Deployer) startPortForward() error {
	u.logger.Infof("Starting port-forward to UI service on port %d...", u.config.ServicePort)

	// Start port-forward with auto-retry on failure
	go u.maintainPortForward()

	// Give it a moment to start
	time.Sleep(2 * time.Second)

	u.logger.Info("Port-forward started successfully")
	return nil
}

// maintainPortForward keeps the port-forward running with automatic restarts
func (u *Deployer) maintainPortForward() {
	maxRetries := 10
	retryDelay := 5 * time.Second
	retryCount := 0

	for {
		// Map local port to service port
		portMapping := fmt.Sprintf("%d:%d", u.config.ServicePort, u.config.ServicePort)
		u.portForwardCmd = cmd.NewCmd(
			"kubectl", "port-forward",
			"-n", u.config.Namespace,
			fmt.Sprintf("svc/%s", u.config.ServiceName),
			portMapping,
		)
		u.portForwardCmd.Env = append(os.Environ(), fmt.Sprintf("KUBECONFIG=%s", u.deployer.GetKubeconfig()))

		// Start port-forward
		statusChan := u.portForwardCmd.Start()

		// Wait for exit
		status := <-statusChan

		if status.Exit != 0 {
			retryCount++
			u.logger.Warnf("Port-forward exited with code %d (retry %d/%d): %v", status.Exit, retryCount, maxRetries, status.Stderr)

			if retryCount >= maxRetries {
				u.logger.Errorf("Port-forward failed after %d retries, giving up", maxRetries)
				return
			}

			// Exponential backoff: 5s, 10s, 20s, etc (max 60s)
			backoff := retryDelay * time.Duration(retryCount)
			if backoff > 60*time.Second {
				backoff = 60 * time.Second
			}

			u.logger.Infof("Retrying port-forward in %v...", backoff)
			time.Sleep(backoff)
		} else {
			// Successful exit (user stopped?), reset retry count
			u.logger.Info("Port-forward stopped gracefully")
			return
		}
	}
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
