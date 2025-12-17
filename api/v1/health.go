package v1

import "github.com/gofiber/fiber/v2"

// HealthCheck returns the health status of the API
func (h *Handler) HealthCheck(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"status":  "ok",
		"service": "mobius-api",
		"version": "1.0.0",
	})
}
