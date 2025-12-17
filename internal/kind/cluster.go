package kind

import (
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	"sigs.k8s.io/kind/pkg/cluster"
	"sigs.k8s.io/kind/pkg/log"
)

// Loggerus adapts logrus.Logger to kind's log.Logger interface
type Loggerus struct {
	logger *logrus.Logger
}

func NewLogger(logger *logrus.Logger) *Loggerus {
	return &Loggerus{logger: logger}
}

func (fl *Loggerus) V(level log.Level) log.InfoLogger {
	return fl
}

func (fl *Loggerus) Enabled() bool {
	return true
}

func (fl *Loggerus) Info(message string) {
	fl.logger.Info(message)
}

func (fl *Loggerus) Infof(format string, args ...interface{}) {
	fl.logger.Infof(format, args...)
}

func (fl *Loggerus) Warn(message string) {
	fl.logger.Warn(message)
}

func (fl *Loggerus) Warnf(format string, args ...interface{}) {
	fl.logger.Warnf(format, args...)
}

func (fl *Loggerus) Error(message string) {
	fl.logger.Error(message)
}

func (fl *Loggerus) Errorf(format string, args ...interface{}) {
	fl.logger.Errorf(format, args...)
}

// Cluster manages a KIND Kubernetes cluster
type Cluster struct {
	name       string
	configPath string
	kubeconfig string
	dockerHost string
	provider   *cluster.Provider
	logger     *logrus.Logger
}

// Config holds configuration for creating a KIND cluster
type Config struct {
	Name           string
	ConfigPath     string
	KubeconfigPath string
	DockerHost     string // Docker socket path (e.g., unix:///path/to/docker.sock)
}

// NewCluster creates a new KIND cluster manager
func NewCluster(logger *logrus.Logger, cfg Config) *Cluster {
	kindLogger := NewLogger(logger)
	provider := cluster.NewProvider(
		cluster.ProviderWithDocker(),
		cluster.ProviderWithLogger(kindLogger),
	)

	return &Cluster{
		name:       cfg.Name,
		configPath: cfg.ConfigPath,
		kubeconfig: cfg.KubeconfigPath,
		dockerHost: cfg.DockerHost,
		provider:   provider,
		logger:     logger,
	}
}

// Create creates the KIND cluster
func (c *Cluster) Create() error {
	c.logger.Infof("Creating KIND cluster '%s'...", c.name)

	// Set DOCKER_HOST if using custom Docker socket
	var oldDockerHost string
	if c.dockerHost != "" {
		oldDockerHost = os.Getenv("DOCKER_HOST")
		os.Setenv("DOCKER_HOST", c.dockerHost)
		defer func() {
			if oldDockerHost != "" {
				os.Setenv("DOCKER_HOST", oldDockerHost)
			} else {
				os.Unsetenv("DOCKER_HOST")
			}
		}()
		c.logger.Infof("Using Docker socket: %s", c.dockerHost)
	}

	var createOpts []cluster.CreateOption

	// Only use config file if provided and exists
	if c.configPath != "" {
		if _, err := os.Stat(c.configPath); err == nil {
			createOpts = append(createOpts, cluster.CreateWithConfigFile(c.configPath))
			c.logger.Infof("Using cluster config: %s", c.configPath)
		} else {
			c.logger.Warnf("Config file not found, creating cluster with defaults: %v", err)
		}
	}

	// Set kubeconfig path if provided
	if c.kubeconfig != "" {
		createOpts = append(createOpts, cluster.CreateWithKubeconfigPath(c.kubeconfig))
	}

	err := c.provider.Create(c.name, createOpts...)

	if err != nil {
		return fmt.Errorf("failed to create cluster: %w", err)
	}

	c.logger.Infof("KIND cluster '%s' created successfully", c.name)
	if c.kubeconfig != "" {
		c.logger.Infof("Kubeconfig written to: %s", c.kubeconfig)
	}
	return nil
}

// Delete deletes the KIND cluster
func (c *Cluster) Delete() error {
	c.logger.Infof("Deleting KIND cluster '%s'...", c.name)

	if err := c.provider.Delete(c.name, c.kubeconfig); err != nil {
		return fmt.Errorf("failed to delete cluster: %w", err)
	}

	c.logger.Infof("KIND cluster '%s' deleted successfully", c.name)
	return nil
}

// List returns a list of all KIND clusters
func (c *Cluster) List() ([]string, error) {
	return c.provider.List()
}

// KubeconfigPath returns the path to the kubeconfig file
func (c *Cluster) KubeconfigPath() string {
	return c.kubeconfig
}
