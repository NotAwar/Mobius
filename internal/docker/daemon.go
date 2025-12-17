package docker

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	cmd "github.com/go-cmd/cmd"
)

// Logger interface for dependency injection
type Logger interface {
	Info(args ...interface{})
	Infof(format string, args ...interface{})
	Warn(args ...interface{})
	Warnf(format string, args ...interface{})
	Warning(args ...interface{})
	Warningf(format string, args ...interface{})
	Error(args ...interface{})
	Errorf(format string, args ...interface{})
}

// Daemon manages a Docker daemon instance
type Daemon struct {
	logger     Logger
	socketPath string
	pidFile    string
}

// EnsureInstalled checks if Docker is installed and installs it if not
// Uses Docker's universal installation script - works on all platforms
func EnsureInstalled(logger Logger) error {
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

// Start verifies Docker is available and starts our own isolated daemon
func Start(logger Logger) (*Daemon, error) {
	logger.Info("Checking Docker availability...")

	// Ensure Docker is installed
	if err := EnsureInstalled(logger); err != nil {
		return nil, fmt.Errorf("Docker installation failed: %w", err)
	}
	
	// Check if bridge kernel module is available
	if _, err := os.Stat("/sys/module/bridge"); os.IsNotExist(err) {
		logger.Warn("Bridge kernel module not loaded, attempting to load...")
		loadCmd := exec.Command("sudo", "modprobe", "bridge")
		if err := loadCmd.Run(); err != nil {
			return nil, fmt.Errorf("Bridge kernel module is required but not available.\n" +
				"This is needed for Docker networking and KIND clusters.\n" +
				"Please ensure your kernel modules are installed:\n" +
				"  - Check: ls /lib/modules/$(uname -r)\n" +
				"  - Install: sudo pacman -S linux-cachyos linux-cachyos-headers\n" +
				"  - Reboot if needed\n" +
				"Error: %w", err)
		}
		logger.Info("Bridge module loaded successfully")
	}

	// Setup directories for our isolated daemon
	if err := setupDirectories(logger); err != nil {
		return nil, fmt.Errorf("Failed to setup directories: %w", err)
	}

	// Start our own dockerd process
	daemon, err := startIsolatedDaemon(logger)
	if err != nil {
		return nil, fmt.Errorf("Failed to start Docker daemon: %w", err)
	}

	// Wait for daemon to be ready
	if err := waitForDaemonReady(logger, daemon.socketPath); err != nil {
		daemon.Stop()
		return nil, fmt.Errorf("Docker daemon not responding: %w", err)
	}

	logger.Info("Docker daemon is ready")
	return daemon, nil
}

// setupDirectories creates the required directories for the isolated daemon
func setupDirectories(logger Logger) error {
	dataDir := "/var/lib/mobius-docker"
	runDir := "/var/run/mobius-docker"

	logger.Infof("Setting up Docker directories...")
	
	currentUser := os.Getenv("USER")
	
	for _, dir := range []string{dataDir, runDir} {
		// Check if directory exists and has proper permissions
		_, err := os.Stat(dir)
		if err == nil {
			// Directory exists - check if we can write to it
			testFile := filepath.Join(dir, ".test")
			if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
				// Can't write - try to fix permissions with sudo (non-interactive)
				logger.Warnf("Directory %s exists but is not writable, fixing permissions...", dir)
				
				chownCmd := exec.Command("sudo", "-n", "chown", "-R", currentUser+":"+currentUser, dir)
				chownCmd.Stdout = os.Stderr
				chownCmd.Stderr = os.Stderr
				if err := chownCmd.Run(); err != nil {
					return fmt.Errorf("failed to fix permissions on %s: %w (run with sudo or fix manually)", dir, err)
				}
				logger.Infof("Fixed permissions on %s", dir)
			} else {
				os.Remove(testFile) // Clean up test file
			}
			continue
		}
		
		// Directory doesn't exist - try to create it
		if err := os.MkdirAll(dir, 0755); err != nil {
			// Permission denied - try with sudo (non-interactive)
			logger.Warnf("Cannot create %s (permission denied), using sudo...", dir)
			
			mkdirCmd := exec.Command("sudo", "-n", "sh", "-c", 
				fmt.Sprintf("mkdir -p %s && chown %s:%s %s", dir, currentUser, currentUser, dir))
			mkdirCmd.Stdout = os.Stderr
			mkdirCmd.Stderr = os.Stderr
			if err := mkdirCmd.Run(); err != nil {
				return fmt.Errorf("failed to create directory %s: %w (run with sudo or create manually)", dir, err)
			}
		}
	}

	logger.Info("Docker directories ready")
	return nil
}

// startIsolatedDaemon starts our own dockerd process with root privileges
func startIsolatedDaemon(logger Logger) (*Daemon, error) {
	// Find dockerd executable
	dockerdPath, err := exec.LookPath("dockerd")
	if err != nil {
		return nil, fmt.Errorf("dockerd not found in PATH: %w", err)
	}

	socketPath := "/var/run/mobius-docker/docker.sock"
	dataRoot := "/var/lib/mobius-docker"
	execRoot := "/var/run/mobius-docker"

	logger.Info("Starting isolated Docker daemon...")
	logger.Infof("Socket: %s", socketPath)
	logger.Infof("Data root: %s", dataRoot)

	// Check if we can run sudo without password
	testCmd := exec.Command("sudo", "-n", "true")
	if err := testCmd.Run(); err != nil {
		logger.Warn("sudo requires password - you may need to configure passwordless sudo for dockerd")
		logger.Info("Attempting to authenticate with sudo...")
		
		// Print message to stderr (visible even with TUI)
		fmt.Fprintf(os.Stderr, "\n╔════════════════════════════════════════════╗\n")
		fmt.Fprintf(os.Stderr, "║   SUDO PASSWORD REQUIRED                  ║\n")
		fmt.Fprintf(os.Stderr, "║                                           ║\n")
		fmt.Fprintf(os.Stderr, "║   Starting Docker daemon requires root    ║\n")
		fmt.Fprintf(os.Stderr, "║   Please enter your password:             ║\n")
		fmt.Fprintf(os.Stderr, "╚════════════════════════════════════════════╝\n\n")
		
		// Pre-authenticate with sudo
		authCmd := exec.Command("sudo", "true")
		authCmd.Stdin = os.Stdin
		authCmd.Stdout = os.Stderr
		authCmd.Stderr = os.Stderr
		if err := authCmd.Run(); err != nil {
			return nil, fmt.Errorf("sudo authentication failed: %w", err)
		}
		
		fmt.Fprintf(os.Stderr, "\n✓ Authentication successful\n\n")
		logger.Info("Authentication successful")
	}

	pidFile := filepath.Join(execRoot, "docker.pid")
	
	// Declare variables before any goto
	maxWait := 15 * time.Second
	checkInterval := 200 * time.Millisecond
	elapsed := time.Duration(0)
	var startCmd *exec.Cmd
	var dockerdArgs string
	
	// Check if dockerd is already running
	if pidData, err := os.ReadFile(pidFile); err == nil {
		pid := strings.TrimSpace(string(pidData))
		if pid != "" {
			// Check if process is actually running
			checkCmd := exec.Command("ps", "-p", pid)
			if checkCmd.Run() == nil {
				logger.Info("Docker daemon already running, waiting for socket...")
				// Wait for socket to be ready
				goto waitForSocket
			}
		}
	}
	
	// dockerd requires root privileges - start with sudo
	// Use nohup to properly detach the process
	// Use vfs storage driver - slower but works without overlay support
	// Now that bridge module is loaded, remove --bridge=none to allow Docker networking
	dockerdArgs = fmt.Sprintf("nohup %s --host unix://%s --data-root %s --exec-root %s --pidfile %s --group docker --storage-driver vfs --iptables=false --ip-forward=false > /tmp/dockerd.log 2>&1 &",
		dockerdPath, socketPath, dataRoot, execRoot, pidFile)
	
	startCmd = exec.Command("sudo", "sh", "-c", dockerdArgs)
	startCmd.Stdout = os.Stderr
	startCmd.Stderr = os.Stderr
	if err := startCmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to start dockerd: %w", err)
	}
	
	// Give dockerd a moment to start
	time.Sleep(2 * time.Second)
	
	// Check if dockerd actually started successfully
	if logData, err := os.ReadFile("/tmp/dockerd.log"); err == nil {
		logStr := string(logData)
		if strings.Contains(logStr, "Error initializing network controller") || 
		   strings.Contains(logStr, "operation not supported") ||
		   strings.Contains(logStr, "failed to start daemon") {
			return nil, fmt.Errorf("dockerd failed to start - bridge networking not supported\n\n" +
				"Your kernel is missing the bridge module. This is required for KIND.\n" +
				"Solution: Reboot your system to use the updated kernel with bridge support.\n" +
				"After rebooting, run this server again.\n\n" +
				"Technical details:\n%s", logStr[max(0, len(logStr)-500):])
		}
	}

waitForSocket:
	// Now wait for socket to be created
	logger.Info("Waiting for Docker socket...")
	elapsed = 0
	
	for elapsed < maxWait {
		if _, err := os.Stat(socketPath); err == nil {
			// Socket exists - make it accessible
			logger.Info("Socket created, setting permissions...")
			chmodCmd := exec.Command("sudo", "chmod", "666", socketPath)
			chmodCmd.Stdout = os.Stderr
			chmodCmd.Stderr = os.Stderr
			if err := chmodCmd.Run(); err != nil {
				logger.Warnf("Failed to set socket permissions: %v", err)
			} else {
				logger.Info("Socket permissions updated")
			}
			break
		}
		time.Sleep(checkInterval)
		elapsed += checkInterval
	}
	
	if elapsed >= maxWait {
		return nil, fmt.Errorf("timeout waiting for Docker socket creation at %s", socketPath)
	}

	// Set DOCKER_HOST for all docker commands to use our socket
	os.Setenv("DOCKER_HOST", fmt.Sprintf("unix://%s", socketPath))

	// Clean up stale KIND resources if they exist
	// This prevents network ID mismatch errors when restarting dockerd
	logger.Info("Cleaning up stale KIND resources...")
	
	// Remove any leftover KIND containers
	removeContainersCmd := exec.Command("sh", "-c", 
		fmt.Sprintf("DOCKER_HOST=unix://%s docker ps -a --filter name=mobius-cluster --format '{{.ID}}' | xargs -r docker rm -f", socketPath))
	if err := removeContainersCmd.Run(); err == nil {
		logger.Info("Removed stale KIND containers")
	}
	
	// Remove KIND network
	removeNetworkCmd := exec.Command("docker", "network", "rm", "kind")
	removeNetworkCmd.Env = append(os.Environ(), fmt.Sprintf("DOCKER_HOST=unix://%s", socketPath))
	if err := removeNetworkCmd.Run(); err == nil {
		logger.Info("Removed stale KIND network")
	}

	return &Daemon{
		logger:     logger,
		socketPath: socketPath,
		pidFile:    pidFile,
	}, nil
}

// waitForDaemonReady waits for the Docker daemon to become responsive
func waitForDaemonReady(logger Logger, socketPath string) error {
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
			// Try to ping the daemon using the custom socket
			infoCmd := cmd.NewCmd("docker", "info")
			status := <-infoCmd.Start()
			if status.Exit == 0 {
				logger.Info("Docker daemon is responding")
				return nil
			}
		}
	}
}

// Stop gracefully shuts down the Docker daemon
func (d *Daemon) Stop() error {
	d.logger.Info("Stopping Docker daemon...")

	// Read PID from file
	pidData, err := os.ReadFile(d.pidFile)
	if err != nil {
		d.logger.Warnf("Could not read PID file: %v", err)
		return nil
	}

	pid := strings.TrimSpace(string(pidData))
	if pid == "" {
		d.logger.Info("No PID found, daemon may not be running")
		return nil
	}

	// Kill the dockerd process
	killCmd := exec.Command("sudo", "kill", "-TERM", pid)
	if err := killCmd.Run(); err != nil {
		d.logger.Warnf("Error stopping daemon: %v", err)
		// Try force kill
		forceKill := exec.Command("sudo", "kill", "-9", pid)
		if err := forceKill.Run(); err != nil {
			d.logger.Warnf("Force kill failed: %v", err)
		}
	}

	// Wait a moment for shutdown
	time.Sleep(1 * time.Second)

	// Clean up PID file
	os.Remove(d.pidFile)

	d.logger.Info("Docker daemon stopped")
	return nil
}
