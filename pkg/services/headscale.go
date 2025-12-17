package services

import (
	"context"
	"fmt"
	"os/exec"

	"github.com/sirupsen/logrus"
)

// HeadscaleServiceImpl implements HeadscaleService
type HeadscaleServiceImpl struct {
	logger     *logrus.Logger
	kubeconfig string
	namespace  string
	podName    string
}

// NewHeadscaleService creates a new Headscale service
func NewHeadscaleService(logger *logrus.Logger, kubeconfig string) *HeadscaleServiceImpl {
	return &HeadscaleServiceImpl{
		logger:     logger,
		kubeconfig: kubeconfig,
		namespace:  "default",
		podName:    "", // Will be discovered
	}
}

// findHeadscalePod finds the Headscale pod name
func (s *HeadscaleServiceImpl) findHeadscalePod(ctx context.Context) (string, error) {
	if s.podName != "" {
		return s.podName, nil
	}

	cmd := exec.CommandContext(ctx, "kubectl", "get", "pods", "-n", s.namespace, "-l", "app.kubernetes.io/name=headscale", "-o", "jsonpath={.items[0].metadata.name}")
	if s.kubeconfig != "" {
		cmd.Args = append(cmd.Args, "--kubeconfig", s.kubeconfig)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to find Headscale pod: %w", err)
	}

	s.podName = string(output)
	return s.podName, nil
}

// GetStatus returns the status of Headscale
func (s *HeadscaleServiceImpl) GetStatus(ctx context.Context) (map[string]interface{}, error) {
	// Check if Headscale pod is running
	cmd := exec.CommandContext(ctx, "kubectl", "get", "pods", "-n", s.namespace, "-l", "app.kubernetes.io/name=headscale", "--no-headers")
	if s.kubeconfig != "" {
		cmd.Args = append(cmd.Args, "--kubeconfig", s.kubeconfig)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		s.logger.Warnf("Headscale not accessible: %v", err)
		return map[string]interface{}{
			"status": "unavailable",
			"users":  0,
			"nodes":  0,
			"ready":  false,
		}, nil
	}

	return map[string]interface{}{
		"status": "running",
		"users":  0,
		"nodes":  0,
		"ready":  len(output) > 0,
	}, nil
}

// GetUsers returns all Headscale users
func (s *HeadscaleServiceImpl) GetUsers(ctx context.Context) ([]map[string]interface{}, error) {
	podName, err := s.findHeadscalePod(ctx)
	if err != nil {
		s.logger.Errorf("Failed to find Headscale pod: %v", err)
		return []map[string]interface{}{}, nil
	}

	cmd := exec.CommandContext(ctx, "kubectl", "exec", "-n", s.namespace, podName, "--", "headscale", "users", "list", "--output", "json")
	if s.kubeconfig != "" {
		// Insert kubeconfig before exec
		args := []string{"--kubeconfig", s.kubeconfig}
		args = append(args, cmd.Args[1:]...)
		cmd.Args = append([]string{"kubectl"}, args...)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		s.logger.Errorf("Failed to get Headscale users: %v, output: %s", err, string(output))
		return []map[string]interface{}{}, nil
	}

	// TODO: Parse JSON output properly
	return []map[string]interface{}{}, nil
}

// CreateUser creates a new Headscale user
func (s *HeadscaleServiceImpl) CreateUser(ctx context.Context, name string) error {
	podName, err := s.findHeadscalePod(ctx)
	if err != nil {
		return fmt.Errorf("failed to find Headscale pod: %w", err)
	}

	cmd := exec.CommandContext(ctx, "kubectl", "exec", "-n", s.namespace, podName, "--", "headscale", "users", "create", name)
	if s.kubeconfig != "" {
		args := []string{"--kubeconfig", s.kubeconfig}
		args = append(args, cmd.Args[1:]...)
		cmd.Args = append([]string{"kubectl"}, args...)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		s.logger.Errorf("Failed to create Headscale user: %v, output: %s", err, string(output))
		return fmt.Errorf("failed to create user: %w", err)
	}

	return nil
}

// GetNodes returns all Headscale nodes
func (s *HeadscaleServiceImpl) GetNodes(ctx context.Context) ([]map[string]interface{}, error) {
	podName, err := s.findHeadscalePod(ctx)
	if err != nil {
		s.logger.Errorf("Failed to find Headscale pod: %v", err)
		return []map[string]interface{}{}, nil
	}

	cmd := exec.CommandContext(ctx, "kubectl", "exec", "-n", s.namespace, podName, "--", "headscale", "nodes", "list", "--output", "json")
	if s.kubeconfig != "" {
		args := []string{"--kubeconfig", s.kubeconfig}
		args = append(args, cmd.Args[1:]...)
		cmd.Args = append([]string{"kubectl"}, args...)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		s.logger.Errorf("Failed to get Headscale nodes: %v, output: %s", err, string(output))
		return []map[string]interface{}{}, nil
	}

	// TODO: Parse JSON output properly
	return []map[string]interface{}{}, nil
}
