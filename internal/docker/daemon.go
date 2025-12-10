package docker

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
)

// Daemon manages a Docker daemon instance
type Daemon struct {
	cmd    *exec.Cmd
	logger *logrus.Logger
}

// EnsureInstalled checks if Docker is installed and installs it if not
func EnsureInstalled(logger *logrus.Logger) error {
	// Check if dockerd is available
	if _, err := exec.LookPath("dockerd"); err == nil {
		logger.Info("Docker is already installed")
		return nil
	}

	logger.Warn("Docker not found, attempting to install...")

	// Detect OS and install accordingly
	switch runtime.GOOS {
	case "linux":
		return installLinux(logger)
	case "darwin":
		return fmt.Errorf("on macOS, please install Docker Desktop from https://www.docker.com/products/docker-desktop")
	case "windows":
		return fmt.Errorf("on Windows, please install Docker Desktop from https://www.docker.com/products/docker-desktop")
	default:
		return fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
}

// installLinux installs Docker on Linux systems
func installLinux(logger *logrus.Logger) error {
	// Check if running as root
	currentUser, err := user.Current()
	if err != nil {
		return fmt.Errorf("failed to get current user: %w", err)
	}

	if currentUser.Uid != "0" {
		return fmt.Errorf("Docker installation requires root privileges. Please run with sudo or install Docker manually")
	}

	// Detect package manager
	var installCmd *exec.Cmd

	if _, err := exec.LookPath("apt-get"); err == nil {
		// Debian/Ubuntu
		logger.Info("Detected apt-get, installing Docker...")
		installCmd = exec.Command("sh", "-c", "apt-get update && apt-get install -y docker.io")
	} else if _, err := exec.LookPath("dnf"); err == nil {
		// Fedora/RHEL 8+
		logger.Info("Detected dnf, installing Docker...")
		installCmd = exec.Command("dnf", "install", "-y", "docker")
	} else if _, err := exec.LookPath("yum"); err == nil {
		// CentOS/RHEL 7
		logger.Info("Detected yum, installing Docker...")
		installCmd = exec.Command("yum", "install", "-y", "docker")
	} else if _, err := exec.LookPath("pacman"); err == nil {
		// Arch Linux
		logger.Info("Detected pacman, installing Docker...")
		installCmd = exec.Command("pacman", "-S", "--noconfirm", "docker")
	} else {
		return fmt.Errorf("no supported package manager found (apt-get, dnf, yum, pacman)")
	}

	installCmd.Stdout = os.Stdout
	installCmd.Stderr = os.Stderr

	if err := installCmd.Run(); err != nil {
		return fmt.Errorf("failed to install Docker: %w", err)
	}

	// Verify installation
	if _, err := exec.LookPath("dockerd"); err != nil {
		return fmt.Errorf("Docker installation appeared to succeed but dockerd is still not found")
	}

	logger.Info("Docker installed successfully")
	return nil
}

// EnsureDirectories creates and sets permissions for Docker directories
func EnsureDirectories(logger *logrus.Logger) error {
	dirs := []string{
		"/var/lib/mobius-docker",
		"/var/run/mobius-docker",
	}

	for _, dir := range dirs {
		logger.Infof("Ensuring directory exists: %s", dir)

		// Create directory
		if err := os.MkdirAll(dir, 0755); err != nil {
			// If we don't have permission, try with sudo
			if os.IsPermission(err) {
				logger.Warnf("No permission to create %s, attempting with elevated privileges", dir)
				cmd := exec.Command("sudo", "mkdir", "-p", dir)
				if err := cmd.Run(); err != nil {
					return fmt.Errorf("failed to create directory %s: %w", dir, err)
				}
			} else {
				return fmt.Errorf("failed to create directory %s: %w", dir, err)
			}
		}

		// Get current user
		currentUser, err := user.Current()
		if err != nil {
			logger.Warnf("Could not determine current user, skipping permission setup")
			continue
		}

		// Set ownership if we're root or can sudo
		if currentUser.Uid == "0" {
			// Already root, just set permissions
			if err := os.Chmod(dir, 0755); err != nil {
				logger.Warnf("Failed to set permissions on %s: %v", dir, err)
			}
		} else {
			// Try to set ownership with sudo
			chownCmd := exec.Command("sudo", "chown", "-R",
				fmt.Sprintf("%s:%s", currentUser.Username, currentUser.Username), dir)
			if err := chownCmd.Run(); err != nil {
				logger.Warnf("Failed to set ownership on %s: %v (continuing anyway)", dir, err)
			}
		}
	}

	logger.Info("Directories are ready")
	return nil
}

// Start starts a Docker daemon for the application to use
func Start(logger *logrus.Logger) (*Daemon, error) {
	logger.Info("Starting Docker daemon...")

	// Ensure Docker is installed
	if err := EnsureInstalled(logger); err != nil {
		return nil, fmt.Errorf("Docker installation failed: %w", err)
	}

	// Ensure directories exist with proper permissions
	if err := EnsureDirectories(logger); err != nil {
		return nil, fmt.Errorf("directory setup failed: %w", err)
	}

	// Check if dockerd is available (should be after installation)
	dockerdPath, err := exec.LookPath("dockerd")
	if err != nil {
		return nil, fmt.Errorf("dockerd not found in PATH after installation: %w", err)
	}
	logger.Infof("Using dockerd at: %s", dockerdPath)

	// Create Docker daemon command with appropriate flags
	cmd := exec.Command("dockerd",
		"--host=unix:///var/run/mobius-docker.sock", // Custom socket to avoid conflicts
		"--data-root=/var/lib/mobius-docker",        // Custom data directory
		"--exec-root=/var/run/mobius-docker",        // Custom exec directory
		"--pidfile=/var/run/mobius-docker.pid",      // Custom PID file
		"--iptables=false",                          // Disable iptables to avoid conflicts
		"--ip-masq=false",                           // Disable IP masquerading
		"--bridge=none",                             // Don't create default bridge
		"--log-level=info",
	)

	// Set environment for the daemon
	cmd.Env = os.Environ()
	cmd.Stdout = logger.Writer()
	cmd.Stderr = logger.Writer()

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start dockerd: %w", err)
	}

	daemon := &Daemon{
		cmd:    cmd,
		logger: logger,
	}

	// Wait for Docker daemon to be ready
	logger.Info("Waiting for Docker daemon to be ready...")
	if err := daemon.waitForReady(); err != nil {
		daemon.Stop()
		return nil, err
	}

	logger.Info("Docker daemon is ready")
	return daemon, nil
}

// waitForReady waits for the Docker daemon to become responsive
func (d *Daemon) waitForReady() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for Docker daemon to start")
		case <-ticker.C:
			// Try to ping the daemon
			cmd := exec.Command("docker", "--host=unix:///var/run/mobius-docker.sock", "info")
			if err := cmd.Run(); err == nil {
				return nil
			}
		}
	}
}

// Stop stops the Docker daemon gracefully
func (d *Daemon) Stop() error {
	if d.cmd == nil || d.cmd.Process == nil {
		return nil
	}

	d.logger.Info("Stopping Docker daemon...")

	// Send SIGTERM for graceful shutdown
	if err := d.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		d.logger.Warnf("Failed to send SIGTERM to dockerd: %v", err)
		return d.cmd.Process.Kill()
	}

	// Wait for process to exit with timeout
	done := make(chan error, 1)
	go func() {
		done <- d.cmd.Wait()
	}()

	select {
	case <-time.After(10 * time.Second):
		d.logger.Warn("Docker daemon didn't stop gracefully, killing...")
		return d.cmd.Process.Kill()
	case err := <-done:
		if err != nil {
			d.logger.Warnf("Docker daemon exited with error: %v", err)
		} else {
			d.logger.Info("Docker daemon stopped gracefully")
		}
		return err
	}
}
