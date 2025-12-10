package privileges

import (
	"os"
	"os/exec"
	"os/user"
	"strings"

	"github.com/sirupsen/logrus"
)

// CheckAndElevate checks if elevated privileges are needed and re-executes with sudo if necessary
func CheckAndElevate(logger *logrus.Logger) {
	currentUser, err := user.Current()
	if err == nil && currentUser.Uid != "0" {
		// Check if dockerd is available and we're not root
		if _, err := exec.LookPath("dockerd"); err != nil {
			logger.Warn("Docker not installed and not running as root. Re-executing with sudo...")
			// Re-execute with sudo
			cmd := exec.Command("sudo", append([]string{os.Args[0]}, os.Args[1:]...)...)
			cmd.Stdin = os.Stdin
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if err := cmd.Run(); err != nil {
				logger.Errorf("Failed to execute with sudo: %v", err)
				os.Exit(1)
			}
			os.Exit(0)
		}

		// Check if we can access Docker directories
		if _, err := os.Stat("/var/run/mobius-docker.sock"); err == nil {
			// Socket exists, check if we can use it
			testCmd := exec.Command("docker", "--host=unix:///var/run/mobius-docker.sock", "info")
			if err := testCmd.Run(); err != nil {
				logger.Warn("Cannot access existing Docker socket. You may need to run with sudo.")
			}
		}
	}
}

// FormatErrorMessage formats permission error messages with helpful guidance
func FormatErrorMessage(err error) string {
	if strings.Contains(err.Error(), "permission") {
		return err.Error() + "\n\nTry running with: sudo " + strings.Join(os.Args, " ")
	}
	return err.Error()
}
