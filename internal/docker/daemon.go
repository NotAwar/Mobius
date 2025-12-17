package docker

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/docker/docker/client"
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

// Daemon manages Docker connectivity
type Daemon struct {
	logger     Logger
	client     *client.Client
	dockerdCmd *exec.Cmd
	socketPath string
	dataRoot   string
}

// Start verifies Docker is available or starts an embedded dockerd
func Start(logger Logger) (*Daemon, error) {
	logger.Info("Checking Docker availability...")

	// First, try to connect to existing Docker daemon
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		if _, err := cli.Ping(ctx); err == nil {
			logger.Info("Connected to existing Docker daemon")
			info, _ := cli.Info(ctx)
			logger.Infof("Docker version: %s", info.ServerVersion)
			return &Daemon{
				logger: logger,
				client: cli,
			}, nil
		}
		cli.Close()
	}

	// No Docker daemon found - start our own embedded dockerd
	logger.Info("No Docker daemon found, starting embedded instance...")

	// Check if dockerd binary exists, if not download it
	dockerdPath, err := ensureDockerd(logger)
	if err != nil {
		return nil, fmt.Errorf("failed to ensure dockerd binary: %w", err)
	}

	// Setup isolated directories in user space
	homeDir, _ := os.UserHomeDir()
	dataRoot := filepath.Join(homeDir, ".mobius", "docker", "data")
	runRoot := filepath.Join(homeDir, ".mobius", "docker", "run")
	socketPath := filepath.Join(runRoot, "docker.sock")

	for _, dir := range []string{dataRoot, runRoot} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	logger.Infof("Data root: %s", dataRoot)
	logger.Infof("Socket: %s", socketPath)

	// Check if already running by looking for the process
	findCmd := exec.Command("pgrep", "-f", "dockerd.*"+socketPath)
	if output, err := findCmd.Output(); err == nil && len(output) > 0 {
		pid := strings.TrimSpace(string(output))
		// Process exists, check if socket exists too
		if _, err := os.Stat(socketPath); err == nil {
			logger.Info("Dockerd already running, connecting...")
			return connectToSocket(logger, socketPath)
		} else {
			// Process running but socket missing - kill it and restart
			logger.Warn("Dockerd process exists but socket missing, killing stale process...")
			exec.Command("sudo", "kill", "-9", pid).Run()
			time.Sleep(time.Second)
		}
	}

	// Start dockerd with sudo (needs root for networking)
	logger.Info("Starting dockerd with sudo (required for container networking)...")

	// Get the directory containing dockerd for PATH
	dockerdDir := filepath.Dir(dockerdPath)

	cmd := exec.Command("sudo", dockerdPath,
		"--host", "unix://"+socketPath,
		"--data-root", dataRoot,
		"--exec-root", runRoot,
		"--storage-driver", "vfs",
		"--iptables=false",
		"--ip-forward=false",
		"--userland-proxy=true",
		"--userland-proxy-path", filepath.Join(dockerdDir, "docker-proxy"),
		"--group", "root", // Use root group since dockerd runs as root (docker group may not exist)
	)

	// Add the binary directory to PATH so dockerd can find docker-proxy, containerd, etc.
	cmd.Env = append(os.Environ(), "PATH="+dockerdDir+":"+os.Getenv("PATH"))

	// Redirect dockerd logs
	logFile := filepath.Join(runRoot, "dockerd.log")
	logWriter, err := os.Create(logFile)
	if err != nil {
		return nil, fmt.Errorf("failed to create log file: %w", err)
	}

	cmd.Stdout = logWriter
	cmd.Stderr = logWriter

	if err := cmd.Start(); err != nil {
		logWriter.Close()
		return nil, fmt.Errorf("failed to start dockerd: %w\nYou may need to run with sudo or configure passwordless sudo", err)
	}

	logger.Info("Waiting for Docker socket...")

	// Wait for socket to be created (with timeout)
	socketReady := false
	for i := 0; i < 60; i++ { // 30 seconds
		if _, err := os.Stat(socketPath); err == nil {
			socketReady = true
			// Make socket accessible to all users (since we don't have docker group)
			logger.Info("Setting socket permissions...")
			chmodCmd := exec.Command("sudo", "chmod", "666", socketPath)
			if err := chmodCmd.Run(); err != nil {
				logger.Warnf("Failed to set socket permissions: %v", err)
				logger.Warn("You may need to run all docker commands with sudo")
			}
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	if !socketReady {
		cmd.Process.Kill()
		logWriter.Close()
		// Read log file to show error
		if logData, err := os.ReadFile(logFile); err == nil {
			return nil, fmt.Errorf("timeout waiting for socket.\n\nDockerd log:\n%s", string(logData))
		}
		return nil, fmt.Errorf("timeout waiting for Docker socket at %s", socketPath)
	}

	logger.Info("Socket created, connecting...")

	// Connect to our embedded daemon
	cli, err = client.NewClientWithOpts(
		client.WithHost("unix://"+socketPath),
		client.WithAPIVersionNegotiation(),
	)
	if err != nil {
		cmd.Process.Kill()
		logWriter.Close()
		return nil, fmt.Errorf("failed to create Docker client: %w", err)
	}

	// Wait for daemon to be ready
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	logger.Info("Waiting for daemon to be ready...")
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			cmd.Process.Kill()
			cli.Close()
			logWriter.Close()
			return nil, fmt.Errorf("timeout waiting for Docker daemon to respond")
		case <-ticker.C:
			if _, err := cli.Ping(ctx); err == nil {
				logger.Info("Embedded Docker daemon is ready!")
				return &Daemon{
					logger:     logger,
					client:     cli,
					dockerdCmd: cmd,
					socketPath: socketPath,
					dataRoot:   dataRoot,
				}, nil
			}
		}
	}
}

// connectToSocket connects to an existing docker socket
func connectToSocket(logger Logger, socketPath string) (*Daemon, error) {
	cli, err := client.NewClientWithOpts(
		client.WithHost("unix://"+socketPath),
		client.WithAPIVersionNegotiation(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to socket: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := cli.Ping(ctx); err != nil {
		cli.Close()
		return nil, fmt.Errorf("socket exists but daemon not responding: %w", err)
	}

	logger.Info("Connected to existing dockerd")
	return &Daemon{
		logger:     logger,
		client:     cli,
		socketPath: socketPath,
	}, nil
}

// ensureDockerd checks if dockerd exists, downloads if needed
func ensureDockerd(logger Logger) (string, error) {
	// Check if dockerd is in PATH
	if path, err := exec.LookPath("dockerd"); err == nil {
		logger.Info("Using system dockerd")
		return path, nil
	}

	// Check in ~/.mobius/bin
	homeDir, _ := os.UserHomeDir()
	binDir := filepath.Join(homeDir, ".mobius", "bin")
	dockerdPath := filepath.Join(binDir, "dockerd")

	if _, err := os.Stat(dockerdPath); err == nil {
		logger.Info("Using cached dockerd binary")
		return dockerdPath, nil
	}

	// Download Docker static binary
	logger.Info("Downloading Docker static binary...")

	if err := os.MkdirAll(binDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create bin directory: %w", err)
	}

	// Download Docker 28.0.0 static binary
	version := "28.0.0"
	arch := "x86_64" // TODO: detect architecture
	url := fmt.Sprintf("https://download.docker.com/linux/static/stable/%s/docker-%s.tgz", arch, version)

	logger.Infof("Downloading from %s", url)

	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("failed to download Docker: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("failed to download Docker: HTTP %d", resp.StatusCode)
	}

	// Save to temp file
	tmpFile := filepath.Join(binDir, "docker.tgz")
	out, err := os.Create(tmpFile)
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile)

	if _, err := io.Copy(out, resp.Body); err != nil {
		out.Close()
		return "", fmt.Errorf("failed to save Docker archive: %w", err)
	}
	out.Close()

	// Extract dockerd binary
	logger.Info("Extracting Docker binaries...")

	// Extract all Docker binaries (dockerd, docker-proxy, containerd, etc.)
	extractCmd := exec.Command("tar", "xzf", tmpFile, "-C", binDir, "--strip-components=1", "docker/")
	if err := extractCmd.Run(); err != nil {
		return "", fmt.Errorf("failed to extract Docker binaries: %w", err)
	}

	// Make all binaries executable
	binaries := []string{"dockerd", "docker-proxy", "containerd", "containerd-shim-runc-v2", "runc"}
	for _, binary := range binaries {
		binaryPath := filepath.Join(binDir, binary)
		if _, err := os.Stat(binaryPath); err == nil {
			if err := os.Chmod(binaryPath, 0755); err != nil {
				logger.Warnf("Failed to make %s executable: %v", binary, err)
			}
		}
	}

	logger.Info("Docker binary downloaded successfully")
	return dockerdPath, nil
}

// Stop closes the Docker client connection and stops embedded daemon if running
func (d *Daemon) Stop() error {
	d.logger.Info("Stopping Docker...")

	if d.client != nil {
		d.client.Close()
	}

	if d.dockerdCmd != nil && d.dockerdCmd.Process != nil {
		d.logger.Info("Stopping embedded Docker daemon...")

		// Since dockerd was started with sudo, we need to find and kill it properly
		// Get the actual dockerd PID (not the sudo PID)
		findCmd := exec.Command("pgrep", "-f", "dockerd.*"+d.socketPath)
		if output, err := findCmd.Output(); err == nil && len(output) > 0 {
			pid := strings.TrimSpace(string(output))
			d.logger.Infof("Found dockerd process: %s", pid)

			// Try graceful shutdown with SIGTERM
			exec.Command("sudo", "kill", "-TERM", pid).Run()

			// Wait up to 10 seconds
			for i := 0; i < 20; i++ {
				checkCmd := exec.Command("ps", "-p", pid)
				if checkCmd.Run() != nil {
					d.logger.Info("Docker daemon stopped gracefully")
					break
				}
				time.Sleep(500 * time.Millisecond)
			}

			// Force kill if still running
			if exec.Command("ps", "-p", pid).Run() == nil {
				d.logger.Warn("Force killing dockerd...")
				exec.Command("sudo", "kill", "-9", pid).Run()
			}
		}

		// Clean up socket
		if d.socketPath != "" {
			exec.Command("sudo", "rm", "-f", d.socketPath).Run()
		}
	}

	return nil
}

// GetClient returns the Docker client for direct use
func (d *Daemon) GetClient() *client.Client {
	return d.client
}

// GetSocketPath returns the Docker socket path (unix://...) or empty if using default
func (d *Daemon) GetSocketPath() string {
	if d.socketPath != "" {
		return "unix://" + d.socketPath
	}
	return ""
}

// EnsureKubectl checks if kubectl exists, downloads if needed
func EnsureKubectl(logger Logger) (string, error) {
	// Check if kubectl is in PATH
	if path, err := exec.LookPath("kubectl"); err == nil {
		logger.Info("Using system kubectl")
		return path, nil
	}

	// Check in ~/.mobius/bin
	homeDir, _ := os.UserHomeDir()
	binDir := filepath.Join(homeDir, ".mobius", "bin")
	kubectlPath := filepath.Join(binDir, "kubectl")

	if _, err := os.Stat(kubectlPath); err == nil {
		logger.Info("Using cached kubectl binary")
		return kubectlPath, nil
	}

	// Download kubectl
	logger.Info("Downloading kubectl...")

	if err := os.MkdirAll(binDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create bin directory: %w", err)
	}

	// Get latest stable version
	version := "v1.31.0" // Stable version compatible with KIND
	arch := "amd64"      // TODO: detect architecture
	goos := "linux"      // TODO: detect OS
	url := fmt.Sprintf("https://dl.k8s.io/release/%s/bin/%s/%s/kubectl", version, goos, arch)

	logger.Infof("Downloading from %s", url)

	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("failed to download kubectl: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("failed to download kubectl: HTTP %d", resp.StatusCode)
	}

	// Save to file
	out, err := os.Create(kubectlPath)
	if err != nil {
		return "", fmt.Errorf("failed to create kubectl file: %w", err)
	}
	defer out.Close()

	if _, err := io.Copy(out, resp.Body); err != nil {
		return "", fmt.Errorf("failed to save kubectl: %w", err)
	}

	// Make executable
	if err := os.Chmod(kubectlPath, 0755); err != nil {
		return "", fmt.Errorf("failed to make kubectl executable: %w", err)
	}

	logger.Info("kubectl downloaded successfully")
	return kubectlPath, nil
}
