package v1

import (
	"github.com/gofiber/fiber/v2"
)

// RegisterRoutes registers all v1 API routes
func (h *Handler) RegisterRoutes(router fiber.Router) {
	// Health check
	router.Get("/health", h.HealthCheck)

	// Status endpoints
	router.Get("/status/cluster", h.GetClusterStatus)
	router.Get("/status/postgres", h.GetPostgresStatus)
	router.Get("/status/headscale", h.GetHeadscaleStatus)

	// Cluster management
	router.Get("/cluster/nodes", h.GetClusterNodes)
	router.Get("/cluster/pods", h.GetClusterPods)

	// PostgreSQL management
	router.Get("/postgres/databases", h.GetPostgresDatabases)
	router.Post("/postgres/databases", h.CreatePostgresDatabase)
	router.Delete("/postgres/databases/:name", h.DeletePostgresDatabase)

	// Headscale management
	router.Get("/headscale/users", h.GetHeadscaleUsers)
	router.Post("/headscale/users", h.CreateHeadscaleUser)
	router.Get("/headscale/nodes", h.GetHeadscaleNodes)
}
