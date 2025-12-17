package v1

import (
	"github.com/gofiber/fiber/v2"
)

// GetClusterStatus returns the status of the Kubernetes cluster
func (h *Handler) GetClusterStatus(c *fiber.Ctx) error {
	status, err := h.clusterService.GetStatus(c.Context())
	if err != nil {
		h.logger.Errorf("Failed to get cluster status: %v", err)
		return c.Status(500).JSON(fiber.Map{
			"error": "Failed to get cluster status",
		})
	}

	return c.JSON(status)
}

// GetClusterNodes returns all Kubernetes nodes
func (h *Handler) GetClusterNodes(c *fiber.Ctx) error {
	nodes, err := h.clusterService.GetNodes(c.Context())
	if err != nil {
		h.logger.Errorf("Failed to get cluster nodes: %v", err)
		return c.Status(500).JSON(fiber.Map{
			"error": "Failed to get cluster nodes",
		})
	}

	return c.JSON(fiber.Map{
		"nodes": nodes,
	})
}

// GetClusterPods returns all Kubernetes pods
func (h *Handler) GetClusterPods(c *fiber.Ctx) error {
	pods, err := h.clusterService.GetPods(c.Context())
	if err != nil {
		h.logger.Errorf("Failed to get cluster pods: %v", err)
		return c.Status(500).JSON(fiber.Map{
			"error": "Failed to get cluster pods",
		})
	}

	return c.JSON(fiber.Map{
		"pods": pods,
	})
}
