package v1

import (
	"github.com/gofiber/fiber/v2"
)

// GetHeadscaleStatus returns the status of Headscale
func (h *Handler) GetHeadscaleStatus(c *fiber.Ctx) error {
	status, err := h.headscaleService.GetStatus(c.Context())
	if err != nil {
		h.logger.Errorf("Failed to get Headscale status: %v", err)
		return c.Status(500).JSON(fiber.Map{
			"error": "Failed to get Headscale status",
		})
	}

	return c.JSON(status)
}

// GetHeadscaleUsers returns all Headscale users
func (h *Handler) GetHeadscaleUsers(c *fiber.Ctx) error {
	users, err := h.headscaleService.GetUsers(c.Context())
	if err != nil {
		h.logger.Errorf("Failed to get Headscale users: %v", err)
		return c.Status(500).JSON(fiber.Map{
			"error": "Failed to get Headscale users",
		})
	}

	return c.JSON(fiber.Map{
		"users": users,
	})
}

// CreateHeadscaleUser creates a new Headscale user
func (h *Handler) CreateHeadscaleUser(c *fiber.Ctx) error {
	type CreateUserRequest struct {
		Name string `json:"name" validate:"required"`
	}

	var req CreateUserRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	if req.Name == "" {
		return c.Status(400).JSON(fiber.Map{
			"error": "User name is required",
		})
	}

	if err := h.headscaleService.CreateUser(c.Context(), req.Name); err != nil {
		h.logger.Errorf("Failed to create Headscale user: %v", err)
		return c.Status(500).JSON(fiber.Map{
			"error": "Failed to create Headscale user",
		})
	}

	return c.Status(201).JSON(fiber.Map{
		"message": "User created successfully",
		"name":    req.Name,
	})
}

// GetHeadscaleNodes returns all Headscale nodes
func (h *Handler) GetHeadscaleNodes(c *fiber.Ctx) error {
	nodes, err := h.headscaleService.GetNodes(c.Context())
	if err != nil {
		h.logger.Errorf("Failed to get Headscale nodes: %v", err)
		return c.Status(500).JSON(fiber.Map{
			"error": "Failed to get Headscale nodes",
		})
	}

	return c.JSON(fiber.Map{
		"nodes": nodes,
	})
}
