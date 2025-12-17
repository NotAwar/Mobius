package services

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"

	"github.com/sirupsen/logrus"
)

// PostgresServiceImpl implements PostgresService
type PostgresServiceImpl struct {
	logger     *logrus.Logger
	kubeconfig string
}

// NewPostgresService creates a new Postgres service
func NewPostgresService(logger *logrus.Logger, kubeconfig string) *PostgresServiceImpl {
	return &PostgresServiceImpl{
		logger:     logger,
		kubeconfig: kubeconfig,
	}
}

// GetStatus returns the status of PostgreSQL/CNPG
func (s *PostgresServiceImpl) GetStatus(ctx context.Context) (map[string]interface{}, error) {
	// Check if CNPG operator is running
	cmd := exec.CommandContext(ctx, "kubectl", "get", "pods", "-n", "cnpg-system", "--no-headers")
	if s.kubeconfig != "" {
		cmd.Args = append(cmd.Args, "--kubeconfig", s.kubeconfig)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		s.logger.Warnf("CNPG operator not accessible: %v", err)
		return map[string]interface{}{
			"status":    "unavailable",
			"operator":  "cloudnative-pg",
			"databases": 0,
			"ready":     false,
		}, nil
	}

	// Count databases (Cluster CRDs)
	cmd = exec.CommandContext(ctx, "kubectl", "get", "clusters.postgresql.cnpg.io", "--all-namespaces", "--no-headers")
	if s.kubeconfig != "" {
		cmd.Args = append(cmd.Args, "--kubeconfig", s.kubeconfig)
	}

	output, _ = cmd.CombinedOutput()
	dbCount := 0
	if len(output) > 0 {
		// Basic count of lines
		dbCount = len(string(output)) / 100 // Rough estimate
	}

	return map[string]interface{}{
		"status":    "running",
		"operator":  "cloudnative-pg",
		"databases": dbCount,
		"ready":     true,
	}, nil
}

// GetDatabases returns all PostgreSQL databases (CNPG Clusters)
func (s *PostgresServiceImpl) GetDatabases(ctx context.Context) ([]map[string]interface{}, error) {
	cmd := exec.CommandContext(ctx, "kubectl", "get", "clusters.postgresql.cnpg.io", "--all-namespaces", "-o", "json")
	if s.kubeconfig != "" {
		cmd.Args = append(cmd.Args, "--kubeconfig", s.kubeconfig)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		s.logger.Errorf("Failed to get databases: %v, output: %s", err, string(output))
		return []map[string]interface{}{}, nil
	}

	// Parse kubectl JSON output for CNPG Clusters
	var clusterList struct {
		Items []struct {
			Metadata struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"metadata"`
			Status struct {
				Phase            string `json:"phase"`
				Instances        int    `json:"instances"`
				ReadyInstances   int    `json:"readyInstances"`
			} `json:"status"`
			Spec struct {
				Instances int `json:"instances"`
			} `json:"spec"`
		} `json:"items"`
	}

	if err := json.Unmarshal(output, &clusterList); err != nil {
		s.logger.Errorf("Failed to parse databases JSON: %v", err)
		return []map[string]interface{}{}, nil
	}

	databases := make([]map[string]interface{}, 0, len(clusterList.Items))
	for _, cluster := range clusterList.Items {
		status := cluster.Status.Phase
		if status == "" {
			if cluster.Status.ReadyInstances == cluster.Spec.Instances && cluster.Spec.Instances > 0 {
				status = "Ready"
			} else {
				status = "Pending"
			}
		}

		databases = append(databases, map[string]interface{}{
			"name":      cluster.Metadata.Name,
			"namespace": cluster.Metadata.Namespace,
			"status":    status,
			"instances": cluster.Spec.Instances,
			"ready":     cluster.Status.ReadyInstances,
			"size":      "Unknown", // Size would require connecting to the database
		})
	}

	return databases, nil
}

// CreateDatabase creates a new PostgreSQL database
func (s *PostgresServiceImpl) CreateDatabase(ctx context.Context, name string) error {
	// TODO: Create CNPG Cluster CRD
	s.logger.Infof("Creating database: %s (not implemented)", name)
	return fmt.Errorf("database creation not yet implemented")
}

// DeleteDatabase deletes a PostgreSQL database
func (s *PostgresServiceImpl) DeleteDatabase(ctx context.Context, name string) error {
	// TODO: Delete CNPG Cluster CRD
	s.logger.Infof("Deleting database: %s (not implemented)", name)
	return fmt.Errorf("database deletion not yet implemented")
}
