package v1

import (
	"github.com/gofiber/fiber/v2"
)

// GetPostgresStatus returns the status of PostgreSQL
func (h *Handler) GetPostgresStatus(c *fiber.Ctx) error {
	status, err := h.postgresService.GetStatus(c.Context())
	if err != nil {
		h.logger.Errorf("Failed to get Postgres status: %v", err)
		return c.Status(500).JSON(fiber.Map{
			"error": "Failed to get Postgres status",
		})
	}

	return c.JSON(status)
}

// GetPostgresDatabases returns all PostgreSQL databases
func (h *Handler) GetPostgresDatabases(c *fiber.Ctx) error {
	databases, err := h.postgresService.GetDatabases(c.Context())
	if err != nil {
		h.logger.Errorf("Failed to get databases: %v", err)
		return c.Status(500).JSON(fiber.Map{
			"error": "Failed to get databases",
		})
	}

	return c.JSON(fiber.Map{
		"databases": databases,
	})
}

// CreatePostgresDatabase creates a new PostgreSQL database
func (h *Handler) CreatePostgresDatabase(c *fiber.Ctx) error {
	type CreateDatabaseRequest struct {
		Name string `json:"name" validate:"required"`
	}

	var req CreateDatabaseRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	if req.Name == "" {
		return c.Status(400).JSON(fiber.Map{
			"error": "Database name is required",
		})
	}

	if err := h.postgresService.CreateDatabase(c.Context(), req.Name); err != nil {
		h.logger.Errorf("Failed to create database: %v", err)
		return c.Status(500).JSON(fiber.Map{
			"error": "Failed to create database",
		})
	}

	return c.Status(201).JSON(fiber.Map{
		"message": "Database created successfully",
		"name":    req.Name,
	})
}

// DeletePostgresDatabase deletes a PostgreSQL database
func (h *Handler) DeletePostgresDatabase(c *fiber.Ctx) error {
	name := c.Params("name")

	if name == "" {
		return c.Status(400).JSON(fiber.Map{
			"error": "Database name is required",
		})
	}

	if err := h.postgresService.DeleteDatabase(c.Context(), name); err != nil {
		h.logger.Errorf("Failed to delete database: %v", err)
		return c.Status(500).JSON(fiber.Map{
			"error": "Failed to delete database",
		})
	}

	return c.JSON(fiber.Map{
		"message": "Database deleted successfully",
		"name":    name,
	})
}
