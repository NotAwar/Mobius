package deploy

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/sirupsen/logrus"
)

// Deployer handles deploying applications to the Kubernetes cluster
type Deployer struct {
	kubeconfig string
	logger     *logrus.Logger
}

// NewDeployer creates a new deployer instance
func NewDeployer(kubeconfig string, logger *logrus.Logger) *Deployer {
	return &Deployer{
		kubeconfig: kubeconfig,
		logger:     logger,
	}
}

// Apply applies a Kubernetes manifest file
func (d *Deployer) Apply(manifestPath string) error {
	d.logger.Infof("Applying manifest: %s", manifestPath)

	cmd := exec.Command("kubectl", "apply", "-f", manifestPath)
	cmd.Env = append(os.Environ(), fmt.Sprintf("KUBECONFIG=%s", d.kubeconfig))
	cmd.Stdout = d.logger.Writer()
	cmd.Stderr = d.logger.Writer()

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to apply manifest %s: %w", manifestPath, err)
	}

	d.logger.Infof("Successfully applied: %s", manifestPath)
	return nil
}

// WaitForDeployment waits for a deployment to be ready
func (d *Deployer) WaitForDeployment(namespace, name string, timeout time.Duration) error {
	d.logger.Infof("Waiting for deployment %s/%s to be ready...", namespace, name)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "kubectl", "wait",
		"--for=condition=available",
		"--timeout="+timeout.String(),
		"-n", namespace,
		"deployment/"+name,
	)
	cmd.Env = append(os.Environ(), fmt.Sprintf("KUBECONFIG=%s", d.kubeconfig))

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("deployment %s/%s did not become ready: %w", namespace, name, err)
	}

	d.logger.Infof("Deployment %s/%s is ready", namespace, name)
	return nil
}

// CreateNamespace creates a Kubernetes namespace if it doesn't exist
func (d *Deployer) CreateNamespace(name string) error {
	d.logger.Infof("Creating namespace: %s", name)

	cmd := exec.Command("kubectl", "create", "namespace", name)
	cmd.Env = append(os.Environ(), fmt.Sprintf("KUBECONFIG=%s", d.kubeconfig))

	// Ignore error if namespace already exists
	if err := cmd.Run(); err != nil {
		// Check if it's just because it already exists
		checkCmd := exec.Command("kubectl", "get", "namespace", name)
		checkCmd.Env = append(os.Environ(), fmt.Sprintf("KUBECONFIG=%s", d.kubeconfig))
		if checkErr := checkCmd.Run(); checkErr != nil {
			return fmt.Errorf("failed to create namespace %s: %w", name, err)
		}
		d.logger.Infof("Namespace %s already exists", name)
		return nil
	}

	d.logger.Infof("Created namespace: %s", name)
	return nil
}

// GetPods lists pods in a namespace
func (d *Deployer) GetPods(namespace string) ([]byte, error) {
	cmd := exec.Command("kubectl", "get", "pods", "-n", namespace, "-o", "wide")
	cmd.Env = append(os.Environ(), fmt.Sprintf("KUBECONFIG=%s", d.kubeconfig))

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to get pods in namespace %s: %w", namespace, err)
	}

	return output, nil
}
