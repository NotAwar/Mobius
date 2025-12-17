package v1

import (
	"time"

	"github.com/gofiber/fiber/v2"
)

// HealthCheck returns the health status of the API
func (h *Handler) HealthCheck(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"status":  "ok",
		"service": "mobius-api",
		"version": "1.0.0",
		"timestamp": time.Now().Format(time.RFC3339),
	})
}

// HealthCheckDetailed returns detailed health status of all services
func (h *Handler) HealthCheckDetailed(c *fiber.Ctx) error {
	checks := make(map[string]interface{})
	overallStatus := "healthy"

	// Check cluster health
	clusterStatus, err := h.clusterService.GetStatus(c.Context())
	if err != nil {
		checks["cluster"] = fiber.Map{
			"status": "unhealthy",
			"error":  err.Error(),
		}
		overallStatus = "degraded"
	} else {
		checks["cluster"] = fiber.Map{
			"status": "healthy",
			"data":   clusterStatus,
		}
	}

	// Check PostgreSQL health
	databases, err := h.postgresService.GetDatabases(c.Context())
	if err != nil {
		checks["postgres"] = fiber.Map{
			"status": "unhealthy",
			"error":  err.Error(),
		}
		overallStatus = "degraded"
	} else {
		checks["postgres"] = fiber.Map{
			"status":   "healthy",
			"clusters": len(databases),
		}
	}

	// Check Headscale health
	users, err := h.headscaleService.GetUsers(c.Context())
	if err != nil {
		checks["headscale"] = fiber.Map{
			"status": "unhealthy",
			"error":  err.Error(),
		}
		overallStatus = "degraded"
	} else {
		nodes, _ := h.headscaleService.GetNodes(c.Context())
		checks["headscale"] = fiber.Map{
			"status": "healthy",
			"users":  len(users),
			"nodes":  len(nodes),
		}
	}

	return c.JSON(fiber.Map{
		"status":    overallStatus,
		"service":   "mobius-api",
		"version":   "1.0.0",
		"timestamp": time.Now().Format(time.RFC3339),
		"checks":    checks,
	})
}

// LivenessProbe returns a simple liveness check (is the API responding?)
func (h *Handler) LivenessProbe(c *fiber.Ctx) error {
	return c.SendString("OK")
}

// ReadinessProbe returns readiness status (is the API ready to serve traffic?)
func (h *Handler) ReadinessProbe(c *fiber.Ctx) error {
	// Check if we can query cluster status
	_, err := h.clusterService.GetStatus(c.Context())
	if err != nil {
		return c.Status(503).SendString("NOT READY")
	}
	
	return c.SendString("READY")
}
