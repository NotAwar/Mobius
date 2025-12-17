package services

import "context"

// ClusterService defines the interface for Kubernetes cluster operations
type ClusterService interface {
	GetStatus(ctx context.Context) (map[string]interface{}, error)
	GetNodes(ctx context.Context) ([]map[string]interface{}, error)
	GetPods(ctx context.Context) ([]map[string]interface{}, error)
	GetNamespaces(ctx context.Context) ([]map[string]interface{}, error)
	GetDeployments(ctx context.Context, namespace string) ([]map[string]interface{}, error)
	GetServices(ctx context.Context, namespace string) ([]map[string]interface{}, error)
	GetPodLogs(ctx context.Context, namespace, podName string, tailLines int64) (string, error)
	DeletePod(ctx context.Context, namespace, podName string) error
}

// PostgresService defines the interface for PostgreSQL operations
type PostgresService interface {
	GetStatus(ctx context.Context) (map[string]interface{}, error)
	GetDatabases(ctx context.Context) ([]map[string]interface{}, error)
	CreateDatabase(ctx context.Context, name string) error
	DeleteDatabase(ctx context.Context, name string) error
}

// HeadscaleService defines the interface for Headscale operations
type HeadscaleService interface {
	GetStatus(ctx context.Context) (map[string]interface{}, error)
	GetUsers(ctx context.Context) ([]map[string]interface{}, error)
	CreateUser(ctx context.Context, name string) error
	GetNodes(ctx context.Context) ([]map[string]interface{}, error)
}
