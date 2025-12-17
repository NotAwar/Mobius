package client
package client

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"

	"mobius/internal/logger"
	"golang.org/x/crypto/ssh"
)

// SSHManager manages SSH server for remote management
type SSHManager struct {
	config   *Config
	log      logger.Logger
	server   *ssh.ServerConfig
	listener net.Listener
	running  bool
}

// NewSSHManager creates a new SSH manager
func NewSSHManager(cfg *Config, log logger.Logger) (*SSHManager, error) {
	// Create SSH server config
	serverConfig := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			// In production, validate against authorized keys
			// For now, accept all keys (should be secured)
			return &ssh.Permissions{}, nil
		},
	}

	// Load or generate host key
	hostKeyPath := "/etc/mobius/ssh_host_key"
	privateKey, err := loadOrGenerateHostKey(hostKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load host key: %w", err)
	}

	serverConfig.AddHostKey(privateKey)

	return &SSHManager{
		config: cfg,
		log:    log,
		server: serverConfig,
	}, nil
}

// Start starts the SSH server
func (s *SSHManager) Start(ctx context.Context) error {
	addr := fmt.Sprintf("0.0.0.0:%d", s.config.SSHPort)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	s.listener = listener
	s.running = true

	s.log.Info("SSH server listening", "port", s.config.SSHPort)

	go func() {
		for s.running {
			conn, err := listener.Accept()
			if err != nil {
				if s.running {
					s.log.Error("Failed to accept connection", "error", err)
				}
				continue
			}

			go s.handleConnection(conn)
		}
	}()

	// Handle context cancellation
	go func() {
		<-ctx.Done()
		s.Stop()
	}()

	return nil
}

// Stop stops the SSH server
func (s *SSHManager) Stop() {
	s.running = false
	if s.listener != nil {
		s.listener.Close()
	}
	s.log.Info("SSH server stopped")
}

// handleConnection handles an SSH connection
func (s *SSHManager) handleConnection(netConn net.Conn) {
	defer netConn.Close()

	// Perform SSH handshake
	sshConn, chans, reqs, err := ssh.NewServerConn(netConn, s.server)
	if err != nil {
		s.log.Error("SSH handshake failed", "error", err)
		return
	}
	defer sshConn.Close()

	s.log.Info("SSH connection established", "user", sshConn.User(), "remote", sshConn.RemoteAddr())

	// Discard global requests
	go ssh.DiscardRequests(reqs)

	// Handle channels
	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			s.log.Error("Failed to accept channel", "error", err)
			continue
		}

		go s.handleSession(channel, requests)
	}
}

// handleSession handles an SSH session
func (s *SSHManager) handleSession(channel ssh.Channel, requests <-chan *ssh.Request) {
	defer channel.Close()

	for req := range requests {
		switch req.Type {
		case "exec":
			// Execute command
			command := string(req.Payload[4:]) // Skip length prefix
			s.log.Info("Executing command", "command", command)

			if req.WantReply {
				req.Reply(true, nil)
			}

			// Execute command
			cmd := exec.Command("/bin/sh", "-c", command)
			cmd.Stdout = channel
			cmd.Stderr = channel

			if err := cmd.Run(); err != nil {
				s.log.Error("Command failed", "command", command, "error", err)
				channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{Status: 1}))
			} else {
				channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{Status: 0}))
			}
			return

		case "shell":
			// Start interactive shell
			if req.WantReply {
				req.Reply(true, nil)
			}

			s.log.Info("Starting shell session")

			// Start shell
			cmd := exec.Command("/bin/sh")
			cmd.Stdin = channel
			cmd.Stdout = channel
			cmd.Stderr = channel

			if err := cmd.Run(); err != nil {
				s.log.Error("Shell failed", "error", err)
			}
			return

		case "pty-req":
			// PTY request
			if req.WantReply {
				req.Reply(true, nil)
			}

		default:
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}
}

// loadOrGenerateHostKey loads or generates SSH host key
func loadOrGenerateHostKey(path string) (ssh.Signer, error) {
	// Try to load existing key
	if _, err := os.Stat(path); err == nil {
		keyData, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		return ssh.ParsePrivateKey(keyData)
	}

	// Generate new key
	cmd := exec.Command("ssh-keygen", "-t", "rsa", "-b", "2048", "-f", path, "-N", "")
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to generate host key: %w", err)
	}

	keyData, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return ssh.ParsePrivateKey(keyData)
}

// ExecuteCommand executes a command via SSH (helper for remote management)
func (s *SSHManager) ExecuteCommand(command string, output io.Writer) error {
	s.log.Info("Executing remote command", "command", command)

	cmd := exec.Command("/bin/sh", "-c", command)
	cmd.Stdout = output
	cmd.Stderr = output

	return cmd.Run()
}
