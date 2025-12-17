package services

import (
	"context"
	"encoding/json"
	"os/exec"
	"strings"

	"github.com/sirupsen/logrus"
)

// ClusterServiceImpl implements ClusterService
type ClusterServiceImpl struct {
	logger     *logrus.Logger
	kubeconfig string
}

// NewClusterService creates a new cluster service
func NewClusterService(logger *logrus.Logger, kubeconfig string) *ClusterServiceImpl {
	return &ClusterServiceImpl{
		logger:     logger,
		kubeconfig: kubeconfig,
	}
}

// GetStatus returns the status of the Kubernetes cluster
func (s *ClusterServiceImpl) GetStatus(ctx context.Context) (map[string]interface{}, error) {
	// Check if kubectl is available
	cmd := exec.CommandContext(ctx, "kubectl", "version", "--client", "--short")
	if s.kubeconfig != "" {
		cmd.Args = append(cmd.Args, "--kubeconfig", s.kubeconfig)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		s.logger.Warnf("kubectl not available or cluster not accessible: %v", err)
		return map[string]interface{}{
			"status":  "unavailable",
			"ready":   false,
			"message": "Cluster not accessible",
		}, nil
	}

	// Get node count
	cmd = exec.CommandContext(ctx, "kubectl", "get", "nodes", "--no-headers")
	if s.kubeconfig != "" {
		cmd.Args = append(cmd.Args, "--kubeconfig", s.kubeconfig)
	}

	output, err = cmd.CombinedOutput()
	nodeCount := 0
	if err == nil {
		lines := strings.Split(strings.TrimSpace(string(output)), "\n")
		if len(lines) > 0 && lines[0] != "" {
			nodeCount = len(lines)
		}
	}

	return map[string]interface{}{
		"status":  "running",
		"nodes":   nodeCount,
		"version": strings.TrimSpace(string(output)),
		"ready":   true,
	}, nil
}

// GetNodes returns all Kubernetes nodes
func (s *ClusterServiceImpl) GetNodes(ctx context.Context) ([]map[string]interface{}, error) {
	cmd := exec.CommandContext(ctx, "kubectl", "get", "nodes", "-o", "json")
	if s.kubeconfig != "" {
		cmd.Args = append(cmd.Args, "--kubeconfig", s.kubeconfig)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		s.logger.Errorf("Failed to get nodes: %v, output: %s", err, string(output))
		return []map[string]interface{}{}, nil
	}

	// Parse kubectl JSON output
	var nodeList struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
			Status struct {
				Conditions []struct {
					Type   string `json:"type"`
					Status string `json:"status"`
				} `json:"conditions"`
			} `json:"status"`
		} `json:"items"`
	}

	if err := json.Unmarshal(output, &nodeList); err != nil {
		s.logger.Errorf("Failed to parse nodes JSON: %v", err)
		return []map[string]interface{}{}, nil
	}

	nodes := make([]map[string]interface{}, 0, len(nodeList.Items))
	for _, node := range nodeList.Items {
		status := "NotReady"
		for _, cond := range node.Status.Conditions {
			if cond.Type == "Ready" && cond.Status == "True" {
				status = "Ready"
				break
			}
		}

		role := "worker"
		if strings.Contains(node.Metadata.Name, "control-plane") || strings.Contains(node.Metadata.Name, "master") {
			role = "control-plane"
		}

		nodes = append(nodes, map[string]interface{}{
			"name":   node.Metadata.Name,
			"status": status,
			"role":   role,
		})
	}

	return nodes, nil
}

// GetPods returns all Kubernetes pods
func (s *ClusterServiceImpl) GetPods(ctx context.Context) ([]map[string]interface{}, error) {
	cmd := exec.CommandContext(ctx, "kubectl", "get", "pods", "--all-namespaces", "-o", "json")
	if s.kubeconfig != "" {
		cmd.Args = append(cmd.Args, "--kubeconfig", s.kubeconfig)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		s.logger.Errorf("Failed to get pods: %v, output: %s", err, string(output))
		return []map[string]interface{}{}, nil
	}

	// Parse kubectl JSON output
	var podList struct {
		Items []struct {
			Metadata struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"metadata"`
			Status struct {
				Phase             string `json:"phase"`
				ContainerStatuses []struct {
					RestartCount int `json:"restartCount"`
				} `json:"containerStatuses"`
			} `json:"status"`
		} `json:"items"`
	}

	if err := json.Unmarshal(output, &podList); err != nil {
		s.logger.Errorf("Failed to parse pods JSON: %v", err)
		return []map[string]interface{}{}, nil
	}

	pods := make([]map[string]interface{}, 0, len(podList.Items))
	for _, pod := range podList.Items {
		restarts := 0
		if len(pod.Status.ContainerStatuses) > 0 {
			for _, cs := range pod.Status.ContainerStatuses {
				restarts += cs.RestartCount
			}
		}

		pods = append(pods, map[string]interface{}{
			"name":      pod.Metadata.Name,
			"namespace": pod.Metadata.Namespace,
			"status":    pod.Status.Phase,
			"restarts":  restarts,
		})
	}

	return pods, nil
}
