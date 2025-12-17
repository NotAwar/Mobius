package v1

import (
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

// AuditLog represents an audit log entry
type AuditLog struct {
	ID           string                 `json:"id"`
	Timestamp    time.Time              `json:"timestamp"`
	UserID       *string                `json:"user_id,omitempty"`
	Action       string                 `json:"action"`
	ResourceType string                 `json:"resource_type"`
	ResourceID   *string                `json:"resource_id,omitempty"`
	ResourceName *string                `json:"resource_name,omitempty"`
	Method       *string                `json:"method,omitempty"`
	Endpoint     *string                `json:"endpoint,omitempty"`
	IPAddress    *string                `json:"ip_address,omitempty"`
	UserAgent    *string                `json:"user_agent,omitempty"`
	RequestID    *string                `json:"request_id,omitempty"`
	StatusCode   *int                   `json:"status_code,omitempty"`
	ErrorMessage *string                `json:"error_message,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
	DurationMs   *int                   `json:"duration_ms,omitempty"`
	CreatedAt    time.Time              `json:"created_at"`
}

// GetAuditLogs retrieves paginated audit logs with filtering
// TODO: Connect to actual audit database once connection pool is configured
func (h *Handler) GetAuditLogs(c *fiber.Ctx) error {
	// Parse query parameters
	limit := c.QueryInt("limit", 100)
	// offset := c.QueryInt("offset", 0)
	// source := c.Query("source", "")
	// level := c.Query("level", "")
	// search := c.Query("search", "")

	if limit > 500 {
		limit = 500
	}

	// Return sample logs for now
	// TODO: Replace with actual database query
	logs := generateSampleLogs(limit)

	return c.JSON(fiber.Map{
		"logs":   logs,
		"total":  len(logs),
		"limit":  limit,
		"offset": 0,
	})
}

// GetAuditSources retrieves unique resource types (sources) from audit logs
// TODO: Connect to actual audit database once connection pool is configured
func (h *Handler) GetAuditSources(c *fiber.Ctx) error {
	sources := []string{"cluster", "postgres", "headscale", "api", "ui", "system"}

	return c.JSON(fiber.Map{
		"sources": sources,
	})
}

// generateSampleLogs creates sample log entries for testing
func generateSampleLogs(count int) []AuditLog {
	logs := make([]AuditLog, 0, count)
	now := time.Now()

	sampleData := []struct {
		action       string
		resourceType string
		method       string
		endpoint     string
		statusCode   int
	}{
		{"CLUSTER_STATUS_CHECK", "cluster", "GET", "/api/v1/cluster/status", 200},
		{"POSTGRES_DATABASE_LIST", "postgres", "GET", "/api/v1/postgres/databases", 200},
		{"HEADSCALE_NODES_LIST", "headscale", "GET", "/api/v1/headscale/nodes", 200},
		{"API_HEALTH_CHECK", "api", "GET", "/api/v1/health", 200},
		{"CLUSTER_NODES_LIST", "cluster", "GET", "/api/v1/cluster/nodes", 200},
		{"UI_PAGE_VIEW", "ui", "GET", "/", 200},
		{"SYSTEM_STARTUP", "system", "POST", "/api/v1/system/startup", 201},
		{"POSTGRES_DATABASE_CREATE", "postgres", "POST", "/api/v1/postgres/databases", 201},
		{"CLUSTER_POD_DELETE", "cluster", "DELETE", "/api/v1/cluster/pods/default/test-pod", 204},
		{"API_ERROR", "api", "GET", "/api/v1/nonexistent", 404},
	}

	for i := 0; i < count && i < len(sampleData)*10; i++ {
		data := sampleData[i%len(sampleData)]
		timestamp := now.Add(-time.Duration(i) * 5 * time.Second)
		
		method := data.method
		endpoint := data.endpoint
		statusCode := data.statusCode
		durationMs := 10 + (i * 5)
		requestID := uuid.New().String()
		ip := "127.0.0.1"
		
		logs = append(logs, AuditLog{
			ID:           uuid.New().String(),
			Timestamp:    timestamp,
			Action:       data.action,
			ResourceType: data.resourceType,
			Method:       &method,
			Endpoint:     &endpoint,
			StatusCode:   &statusCode,
			DurationMs:   &durationMs,
			RequestID:    &requestID,
			IPAddress:    &ip,
			CreatedAt:    timestamp,
		})
	}

	return logs
}
