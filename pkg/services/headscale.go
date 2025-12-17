package services

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"

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
		namespace:  "", // Will be discovered dynamically
		podName:    "",  // Will be discovered
	}
}

// discoverHeadscaleNamespace finds the namespace where Headscale is deployed
func (s *HeadscaleServiceImpl) discoverHeadscaleNamespace(ctx context.Context) (string, error) {
	if s.namespace != "" {
		return s.namespace, nil
	}

	// Try to find Headscale pod in all namespaces
	cmd := exec.CommandContext(ctx, "kubectl", "get", "pods", "--all-namespaces", "-l", "app.kubernetes.io/name=headscale", "-o", "jsonpath={.items[0].metadata.namespace}")
	if s.kubeconfig != "" {
		cmd.Args = append(cmd.Args, "--kubeconfig", s.kubeconfig)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		// Try common namespace names as fallback
		commonNamespaces := []string{"headscale", "networking", "vpn", "default"}
		for _, ns := range commonNamespaces {
			checkCmd := exec.CommandContext(ctx, "kubectl", "get", "pods", "-n", ns, "-l", "app.kubernetes.io/name=headscale", "--no-headers")
			if s.kubeconfig != "" {
				checkCmd.Args = append(checkCmd.Args, "--kubeconfig", s.kubeconfig)
			}
			
			if checkOutput, checkErr := checkCmd.CombinedOutput(); checkErr == nil && len(checkOutput) > 0 {
				s.namespace = ns
				s.logger.Infof("Discovered Headscale in namespace: %s", ns)
				return ns, nil
			}
		}
		
		return "", fmt.Errorf("failed to discover Headscale namespace: %w", err)
	}

	s.namespace = string(output)
	if s.namespace == "" {
		return "", fmt.Errorf("Headscale not found in any namespace")
	}
	
	s.logger.Infof("Discovered Headscale in namespace: %s", s.namespace)
	return s.namespace, nil
}

// findHeadscalePod finds the Headscale pod name
func (s *HeadscaleServiceImpl) findHeadscalePod(ctx context.Context) (string, error) {
	if s.podName != "" {
		return s.podName, nil
	}

	// First discover the namespace if not already done
	namespace, err := s.discoverHeadscaleNamespace(ctx)
	if err != nil {
		return "", err
	}

	cmd := exec.CommandContext(ctx, "kubectl", "get", "pods", "-n", namespace, "-l", "app.kubernetes.io/name=headscale", "-o", "jsonpath={.items[0].metadata.name}")
	if s.kubeconfig != "" {
		cmd.Args = append(cmd.Args, "--kubeconfig", s.kubeconfig)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to find Headscale pod: %w", err)
	}

	s.podName = string(output)
	s.logger.Infof("Discovered Headscale pod: %s in namespace: %s", s.podName, namespace)
	return s.podName, nil
}

// GetStatus returns the status of Headscale
func (s *HeadscaleServiceImpl) GetStatus(ctx context.Context) (map[string]interface{}, error) {
	// Discover namespace first
	namespace, err := s.discoverHeadscaleNamespace(ctx)
	if err != nil {
		s.logger.Warnf("Headscale not accessible: %v", err)
		return map[string]interface{}{
			"status":    "unavailable",
			"users":     0,
			"nodes":     0,
			"ready":     false,
			"namespace": "not-found",
		}, nil
	}

	// Check if Headscale pod is running
	cmd := exec.CommandContext(ctx, "kubectl", "get", "pods", "-n", namespace, "-l", "app.kubernetes.io/name=headscale", "--no-headers")
	if s.kubeconfig != "" {
		cmd.Args = append(cmd.Args, "--kubeconfig", s.kubeconfig)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		s.logger.Warnf("Headscale not accessible: %v", err)
		return map[string]interface{}{
			"status":    "unavailable",
			"users":     0,
			"nodes":     0,
			"ready":     false,
			"namespace": namespace,
		}, nil
	}

	return map[string]interface{}{
		"status":    "running",
		"users":     0,
		"nodes":     0,
		"ready":     len(output) > 0,
		"namespace": namespace,
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

	// Parse Headscale users JSON output
	var users []struct {
		Name      string    `json:"name"`
		CreatedAt time.Time `json:"createdAt"`
	}

	if err := json.Unmarshal(output, &users); err != nil {
		s.logger.Errorf("Failed to parse users JSON: %v", err)
		return []map[string]interface{}{}, nil
	}

	result := make([]map[string]interface{}, 0, len(users))
	for _, user := range users {
		result = append(result, map[string]interface{}{
			"name":      user.Name,
			"createdAt": user.CreatedAt.Format(time.RFC3339),
		})
	}

	return result, nil
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

	// Parse Headscale nodes JSON output
	var nodes []struct {
		Name     string    `json:"name"`
		User     string    `json:"user"`
		LastSeen time.Time `json:"lastSeen"`
		Online   bool      `json:"online"`
	}

	if err := json.Unmarshal(output, &nodes); err != nil {
		s.logger.Errorf("Failed to parse nodes JSON: %v", err)
		return []map[string]interface{}{}, nil
	}

	result := make([]map[string]interface{}, 0, len(nodes))
	for _, node := range nodes {
		result = append(result, map[string]interface{}{
			"name":     node.Name,
			"user":     node.User,
			"lastSeen": node.LastSeen.Format(time.RFC3339),
			"online":   node.Online,
		})
	}

	return result, nil
}
