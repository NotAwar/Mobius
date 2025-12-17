package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
)

// GetNamespaces returns all Kubernetes namespaces
func (s *ClusterServiceImpl) GetNamespaces(ctx context.Context) ([]map[string]interface{}, error) {
	cmd := exec.CommandContext(ctx, "kubectl", "get", "namespaces", "-o", "json")
	if s.kubeconfig != "" {
		cmd.Args = append(cmd.Args, "--kubeconfig", s.kubeconfig)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		s.logger.Errorf("Failed to get namespaces: %v", err)
		return []map[string]interface{}{}, err
	}

	var nsList struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
			Status struct {
				Phase string `json:"phase"`
			} `json:"status"`
		} `json:"items"`
	}

	if err := json.Unmarshal(output, &nsList); err != nil {
		s.logger.Errorf("Failed to parse namespaces JSON: %v", err)
		return []map[string]interface{}{}, err
	}

	namespaces := make([]map[string]interface{}, 0, len(nsList.Items))
	for _, ns := range nsList.Items {
		namespaces = append(namespaces, map[string]interface{}{
			"name":   ns.Metadata.Name,
			"status": ns.Status.Phase,
		})
	}

	return namespaces, nil
}

// GetDeployments returns all deployments
func (s *ClusterServiceImpl) GetDeployments(ctx context.Context, namespace string) ([]map[string]interface{}, error) {
	args := []string{"get", "deployments", "-o", "json"}
	if namespace != "" {
		args = append(args, "-n", namespace)
	} else {
		args = append(args, "--all-namespaces")
	}

	cmd := exec.CommandContext(ctx, "kubectl", args...)
	if s.kubeconfig != "" {
		cmd.Args = append(cmd.Args, "--kubeconfig", s.kubeconfig)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		s.logger.Errorf("Failed to get deployments: %v", err)
		return []map[string]interface{}{}, err
	}

	var depList struct {
		Items []struct {
			Metadata struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"metadata"`
			Spec struct {
				Replicas int32 `json:"replicas"`
			} `json:"spec"`
			Status struct {
				ReadyReplicas int32 `json:"readyReplicas"`
			} `json:"status"`
		} `json:"items"`
	}

	if err := json.Unmarshal(output, &depList); err != nil {
		s.logger.Errorf("Failed to parse deployments JSON: %v", err)
		return []map[string]interface{}{}, err
	}

	deployments := make([]map[string]interface{}, 0, len(depList.Items))
	for _, dep := range depList.Items {
		deployments = append(deployments, map[string]interface{}{
			"name":      dep.Metadata.Name,
			"namespace": dep.Metadata.Namespace,
			"replicas":  dep.Spec.Replicas,
			"ready":     dep.Status.ReadyReplicas,
		})
	}

	return deployments, nil
}

// GetServices returns all Kubernetes services
func (s *ClusterServiceImpl) GetServices(ctx context.Context, namespace string) ([]map[string]interface{}, error) {
	args := []string{"get", "services", "-o", "json"}
	if namespace != "" {
		args = append(args, "-n", namespace)
	} else {
		args = append(args, "--all-namespaces")
	}

	cmd := exec.CommandContext(ctx, "kubectl", args...)
	if s.kubeconfig != "" {
		cmd.Args = append(cmd.Args, "--kubeconfig", s.kubeconfig)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		s.logger.Errorf("Failed to get services: %v", err)
		return []map[string]interface{}{}, err
	}

	var svcList struct {
		Items []struct {
			Metadata struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"metadata"`
			Spec struct {
				Type      string `json:"type"`
				ClusterIP string `json:"clusterIP"`
			} `json:"spec"`
		} `json:"items"`
	}

	if err := json.Unmarshal(output, &svcList); err != nil {
		s.logger.Errorf("Failed to parse services JSON: %v", err)
		return []map[string]interface{}{}, err
	}

	services := make([]map[string]interface{}, 0, len(svcList.Items))
	for _, svc := range svcList.Items {
		services = append(services, map[string]interface{}{
			"name":       svc.Metadata.Name,
			"namespace":  svc.Metadata.Namespace,
			"type":       svc.Spec.Type,
			"cluster_ip": svc.Spec.ClusterIP,
		})
	}

	return services, nil
}

// GetPodLogs returns logs for a specific pod
func (s *ClusterServiceImpl) GetPodLogs(ctx context.Context, namespace, podName string, tailLines int64) (string, error) {
	cmd := exec.CommandContext(ctx, "kubectl", "logs", "-n", namespace, podName, fmt.Sprintf("--tail=%d", tailLines))
	if s.kubeconfig != "" {
		cmd.Args = append(cmd.Args, "--kubeconfig", s.kubeconfig)
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		s.logger.Errorf("Failed to get pod logs: %v, stderr: %s", err, stderr.String())
		return "", fmt.Errorf("failed to get logs: %w", err)
	}

	return stdout.String(), nil
}

// DeletePod deletes a specific pod
func (s *ClusterServiceImpl) DeletePod(ctx context.Context, namespace, podName string) error {
	cmd := exec.CommandContext(ctx, "kubectl", "delete", "pod", "-n", namespace, podName)
	if s.kubeconfig != "" {
		cmd.Args = append(cmd.Args, "--kubeconfig", s.kubeconfig)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		s.logger.Errorf("Failed to delete pod: %v, output: %s", err, string(output))
		return fmt.Errorf("failed to delete pod: %w", err)
	}

	return nil
}
