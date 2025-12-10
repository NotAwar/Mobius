package deploy

import (
	"context"
	"fmt"
	"os"
	"time"

	cmd "github.com/go-cmd/cmd"
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

	kubectlCmd := cmd.NewCmd("kubectl", "apply", "-f", manifestPath)
	kubectlCmd.Env = append(os.Environ(), fmt.Sprintf("KUBECONFIG=%s", d.kubeconfig))
	status := <-kubectlCmd.Start()

	if status.Exit != 0 {
		return fmt.Errorf("failed to apply manifest %s: %s", manifestPath, status.Stderr)
	}

	d.logger.Infof("Successfully applied: %s", manifestPath)
	return nil
}

// WaitForDeployment waits for a deployment to be ready
func (d *Deployer) WaitForDeployment(namespace, name string, timeout time.Duration) error {
	d.logger.Infof("Waiting for deployment %s/%s to be ready...", namespace, name)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	kubectlCmd := cmd.NewCmd("kubectl", "wait",
		"--for=condition=available",
		"--timeout="+timeout.String(),
		"-n", namespace,
		"deployment/"+name,
	)
	kubectlCmd.Env = append(os.Environ(), fmt.Sprintf("KUBECONFIG=%s", d.kubeconfig))

	// Run with context timeout
	statusChan := kubectlCmd.Start()
	select {
	case <-ctx.Done():
		return fmt.Errorf("timeout waiting for deployment %s/%s", namespace, name)
	case status := <-statusChan:
		if status.Exit != 0 {
			return fmt.Errorf("deployment %s/%s did not become ready: %s", namespace, name, status.Stderr)
		}
	}

	d.logger.Infof("Deployment %s/%s is ready", namespace, name)
	return nil
}

// CreateNamespace creates a Kubernetes namespace if it doesn't exist
func (d *Deployer) CreateNamespace(name string) error {
	d.logger.Infof("Creating namespace: %s", name)

	kubectlCmd := cmd.NewCmd("kubectl", "create", "namespace", name)
	kubectlCmd.Env = append(os.Environ(), fmt.Sprintf("KUBECONFIG=%s", d.kubeconfig))
	status := <-kubectlCmd.Start()

	// Ignore error if namespace already exists
	if status.Exit != 0 {
		// Check if it's just because it already exists
		checkCmd := cmd.NewCmd("kubectl", "get", "namespace", name)
		checkCmd.Env = append(os.Environ(), fmt.Sprintf("KUBECONFIG=%s", d.kubeconfig))
		checkStatus := <-checkCmd.Start()
		if checkStatus.Exit != 0 {
			return fmt.Errorf("failed to create namespace %s: %s", name, status.Stderr)
		}
		d.logger.Infof("Namespace %s already exists", name)
		return nil
	}

	d.logger.Infof("Created namespace: %s", name)
	return nil
}

// GetPods lists pods in a namespace
func (d *Deployer) GetPods(namespace string) ([]byte, error) {
	kubectlCmd := cmd.NewCmd("kubectl", "get", "pods", "-n", namespace, "-o", "wide")
	kubectlCmd.Env = append(os.Environ(), fmt.Sprintf("KUBECONFIG=%s", d.kubeconfig))
	status := <-kubectlCmd.Start()

	if status.Exit != 0 {
		return nil, fmt.Errorf("failed to get pods in namespace %s: %s", namespace, status.Stderr)
	}

	// Combine stdout into single output
	output := []byte{}
	for _, line := range status.Stdout {
		output = append(output, []byte(line+"\n")...)
	}
	return output, nil
}

// HelmInstall installs a Helm chart
// Parameters:
//   - releaseName: Name of the Helm release
//   - chartPath: Path to the chart (can be local path or chart name from repo)
//   - namespace: Kubernetes namespace to install into
//   - values: Optional map of values to override (can be nil)
//   - valuesFiles: Optional list of values files to use (can be nil)
func (d *Deployer) HelmInstall(releaseName, chartPath, namespace string, values map[string]string, valuesFiles []string) error {
	d.logger.Infof("Installing Helm chart: %s as release %s in namespace %s", chartPath, releaseName, namespace)

	args := []string{"install", releaseName, chartPath, "-n", namespace, "--create-namespace"}

	// Add values files
	for _, vf := range valuesFiles {
		args = append(args, "-f", vf)
	}

	// Add individual value overrides
	for key, val := range values {
		args = append(args, "--set", fmt.Sprintf("%s=%s", key, val))
	}

	helmCmd := cmd.NewCmd("helm", args...)
	helmCmd.Env = append(os.Environ(), fmt.Sprintf("KUBECONFIG=%s", d.kubeconfig))
	
	// Stream output in real-time
	statusChan := helmCmd.Start()
	go func() {
		for helmCmd.Status().Runtime > 0 {
			status := helmCmd.Status()
			for _, line := range status.Stdout {
				d.logger.Info(line)
			}
			for _, line := range status.Stderr {
				d.logger.Warn(line)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()
	
	status := <-statusChan
	if status.Exit != 0 {
		return fmt.Errorf("failed to install helm chart %s: %s", chartPath, status.Stderr)
	}

	d.logger.Infof("Successfully installed Helm release: %s", releaseName)
	return nil
}

// HelmUpgrade upgrades an existing Helm release or installs it if it doesn't exist
func (d *Deployer) HelmUpgrade(releaseName, chartPath, namespace string, values map[string]string, valuesFiles []string) error {
	d.logger.Infof("Upgrading Helm release: %s in namespace %s", releaseName, namespace)

	args := []string{"upgrade", "--install", releaseName, chartPath, "-n", namespace, "--create-namespace"}

	// Add values files
	for _, vf := range valuesFiles {
		args = append(args, "-f", vf)
	}

	// Add individual value overrides
	for key, val := range values {
		args = append(args, "--set", fmt.Sprintf("%s=%s", key, val))
	}

	helmCmd := cmd.NewCmd("helm", args...)
	helmCmd.Env = append(os.Environ(), fmt.Sprintf("KUBECONFIG=%s", d.kubeconfig))
	status := <-helmCmd.Start()

	if status.Exit != 0 {
		return fmt.Errorf("failed to upgrade helm release %s: %s", releaseName, status.Stderr)
	}

	d.logger.Infof("Successfully upgraded Helm release: %s", releaseName)
	return nil
}

// HelmUninstall uninstalls a Helm release
func (d *Deployer) HelmUninstall(releaseName, namespace string) error {
	d.logger.Infof("Uninstalling Helm release: %s from namespace %s", releaseName, namespace)

	helmCmd := cmd.NewCmd("helm", "uninstall", releaseName, "-n", namespace)
	helmCmd.Env = append(os.Environ(), fmt.Sprintf("KUBECONFIG=%s", d.kubeconfig))
	status := <-helmCmd.Start()

	if status.Exit != 0 {
		return fmt.Errorf("failed to uninstall helm release %s: %s", releaseName, status.Stderr)
	}

	d.logger.Infof("Successfully uninstalled Helm release: %s", releaseName)
	return nil
}

// HelmList lists all Helm releases in a namespace
func (d *Deployer) HelmList(namespace string) ([]byte, error) {
	args := []string{"list", "-n", namespace, "-o", "json"}

	helmCmd := cmd.NewCmd("helm", args...)
	helmCmd.Env = append(os.Environ(), fmt.Sprintf("KUBECONFIG=%s", d.kubeconfig))
	status := <-helmCmd.Start()

	if status.Exit != 0 {
		return nil, fmt.Errorf("failed to list helm releases in namespace %s: %s", namespace, status.Stderr)
	}

	// Combine stdout into single output
	output := []byte{}
	for _, line := range status.Stdout {
		output = append(output, []byte(line+"\n")...)
	}
	return output, nil
}

// HelmRepoAdd adds a Helm repository
func (d *Deployer) HelmRepoAdd(repoName, repoURL string) error {
	d.logger.Infof("Adding Helm repo: %s (%s)", repoName, repoURL)

	helmCmd := cmd.NewCmd("helm", "repo", "add", repoName, repoURL)
	status := <-helmCmd.Start()

	if status.Exit != 0 {
		return fmt.Errorf("failed to add helm repo %s: %s", repoName, status.Stderr)
	}

	d.logger.Infof("Successfully added Helm repo: %s", repoName)
	return nil
}

// HelmRepoUpdate updates all Helm repositories
func (d *Deployer) HelmRepoUpdate() error {
	d.logger.Info("Updating Helm repositories...")

	helmCmd := cmd.NewCmd("helm", "repo", "update")
	status := <-helmCmd.Start()

	if status.Exit != 0 {
		return fmt.Errorf("failed to update helm repos: %s", status.Stderr)
	}

	d.logger.Info("Successfully updated Helm repositories")
	return nil
}
