package docker

import (
	"context"
	"fmt"
	"time"

	cmd "github.com/go-cmd/cmd"
	"github.com/sirupsen/logrus"
)

// Daemon manages a Docker daemon instance
type Daemon struct {
	daemonCmd *cmd.Cmd
	logger    *logrus.Logger
}

// EnsureInstalled checks if Docker is installed and installs it if not
// Uses Docker's universal installation script - works on all platforms
func EnsureInstalled(logger *logrus.Logger) error {
	// Check if docker CLI is available
	checkCmd := cmd.NewCmd("docker", "--version")
	status := <-checkCmd.Start()

	if status.Exit == 0 {
		logger.Info("Docker is already installed")
		return nil
	}

	logger.Warn("Docker not found, installing using official Docker installation script...")

	// Use Docker's universal installation script (works on Linux, macOS, Windows with WSL)
	// For Windows without WSL, users should install Docker Desktop manually
	installScript := `
		curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
		sudo sh /tmp/get-docker.sh
		rm /tmp/get-docker.sh
	`

	installCmd := cmd.NewCmd("sh", "-c", installScript)
	installStatus := <-installCmd.Start()

	if installStatus.Exit != 0 {
		return fmt.Errorf("failed to install Docker: %s", installStatus.Stderr)
	}

	// Verify installation
	verifyCmd := cmd.NewCmd("docker", "--version")
	verifyStatus := <-verifyCmd.Start()

	if verifyStatus.Exit != 0 {
		return fmt.Errorf("Docker installation completed but docker command is still not available")
	}

	logger.Info("Docker installed successfully")
	return nil
}

// Start verifies Docker is available and returns a daemon handle
func Start(logger *logrus.Logger) (*Daemon, error) {
	logger.Info("Checking Docker availability...")

	// Ensure Docker is installed
	if err := EnsureInstalled(logger); err != nil {
		return nil, fmt.Errorf("Docker installation failed: %w", err)
	}

	// Check if Docker daemon is running
	if err := ensureDaemonRunning(logger); err != nil {
		return nil, err
	}

	logger.Info("Docker is ready")
	return &Daemon{
		daemonCmd: nil, // We don't manage the daemon lifecycle
		logger:    logger,
	}, nil
}

// ensureDaemonRunning checks if Docker daemon is running and attempts to start it if not
func ensureDaemonRunning(logger *logrus.Logger) error {
	// Check if daemon is already running
	infoCmd := cmd.NewCmd("docker", "info")
	status := <-infoCmd.Start()

	if status.Exit == 0 {
		logger.Info("Docker daemon is running")
		return nil
	}

	logger.Warn("Docker daemon not running, attempting to start...")

	// Try to start Docker daemon using system service manager
	// This works across different init systems (systemd, launchd, etc.)
	startCmd := cmd.NewCmd("sudo", "service", "docker", "start")
	startStatus := <-startCmd.Start()

	if startStatus.Exit != 0 {
		// Try systemctl (more modern systems)
		systemctlCmd := cmd.NewCmd("sudo", "systemctl", "start", "docker")
		systemctlStatus := <-systemctlCmd.Start()

		if systemctlStatus.Exit != 0 {
			return fmt.Errorf("failed to start Docker daemon - please start Docker manually (Docker Desktop on macOS/Windows, or 'sudo systemctl start docker' on Linux)")
		}
	}

	// Wait for daemon to become responsive
	return waitForDaemonReady(logger)
}

// waitForDaemonReady waits for the Docker daemon to become responsive
func waitForDaemonReady(logger *logrus.Logger) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	logger.Info("Waiting for Docker daemon to be ready...")

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for Docker daemon to start")
		case <-ticker.C:
			// Try to ping the daemon
			infoCmd := cmd.NewCmd("docker", "info")
			status := <-infoCmd.Start()
			if status.Exit == 0 {
				logger.Info("Docker daemon is ready")
				return nil
			}
		}
	}
}

// Stop is a no-op since we're using the system Docker daemon
func (d *Daemon) Stop() error {
	// We don't manage the daemon lifecycle anymore - it's managed by the system
	// Docker Desktop or system service will continue running
	d.logger.Info("Docker daemon management released (daemon continues running)")
	return nil
}
