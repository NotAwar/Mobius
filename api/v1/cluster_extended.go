package v1

import (
	"github.com/gofiber/fiber/v2"
)

// GetNamespaces returns all Kubernetes namespaces
func (h *Handler) GetNamespaces(c *fiber.Ctx) error {
	namespaces, err := h.clusterService.GetNamespaces(c.Context())
	if err != nil {
		h.logger.Errorf("Failed to get namespaces: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to get namespaces",
		})
	}

	return c.JSON(fiber.Map{
		"namespaces": namespaces,
		"count":      len(namespaces),
	})
}

// GetDeployments returns all deployments
func (h *Handler) GetDeployments(c *fiber.Ctx) error {
	namespace := c.Query("namespace", "")
	
	deployments, err := h.clusterService.GetDeployments(c.Context(), namespace)
	if err != nil {
		h.logger.Errorf("Failed to get deployments: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to get deployments",
		})
	}

	return c.JSON(fiber.Map{
		"deployments": deployments,
		"count":       len(deployments),
		"namespace":   namespace,
	})
}

// GetServices returns all Kubernetes services
func (h *Handler) GetServices(c *fiber.Ctx) error {
	namespace := c.Query("namespace", "")
	
	services, err := h.clusterService.GetServices(c.Context(), namespace)
	if err != nil {
		h.logger.Errorf("Failed to get services: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to get services",
		})
	}

	return c.JSON(fiber.Map{
		"services":  services,
		"count":     len(services),
		"namespace": namespace,
	})
}

// GetPodLogs returns logs for a specific pod
func (h *Handler) GetPodLogs(c *fiber.Ctx) error {
	namespace := c.Params("namespace")
	podName := c.Params("name")
	
	if namespace == "" || podName == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "namespace and pod name are required",
		})
	}

	tailLines := int64(100)
	if lines := c.QueryInt("lines", 100); lines > 0 {
		tailLines = int64(lines)
	}

	logs, err := h.clusterService.GetPodLogs(c.Context(), namespace, podName, tailLines)
	if err != nil {
		h.logger.Errorf("Failed to get pod logs: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to get pod logs",
		})
	}

	return c.JSON(fiber.Map{
		"namespace": namespace,
		"pod":       podName,
		"logs":      logs,
	})
}

// DeletePod deletes a specific pod
func (h *Handler) DeletePod(c *fiber.Ctx) error {
	namespace := c.Params("namespace")
	podName := c.Params("name")
	
	if namespace == "" || podName == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "namespace and pod name are required",
		})
	}

	err := h.clusterService.DeletePod(c.Context(), namespace, podName)
	if err != nil {
		h.logger.Errorf("Failed to delete pod: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to delete pod",
		})
	}

	h.logger.Infof("Deleted pod %s in namespace %s", podName, namespace)

	return c.JSON(fiber.Map{
		"message":   "Pod deleted successfully",
		"namespace": namespace,
		"pod":       podName,
	})
}

// RestartPod restarts a pod by deleting it (Kubernetes will recreate it)
func (h *Handler) RestartPod(c *fiber.Ctx) error {
	namespace := c.Params("namespace")
	podName := c.Params("name")
	
	if namespace == "" || podName == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "namespace and pod name are required",
		})
	}

	err := h.clusterService.DeletePod(c.Context(), namespace, podName)
	if err != nil {
		h.logger.Errorf("Failed to restart pod: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to restart pod",
		})
	}

	h.logger.Infof("Restarted pod %s in namespace %s", podName, namespace)

	return c.JSON(fiber.Map{
		"message":   "Pod restart initiated",
		"namespace": namespace,
		"pod":       podName,
	})
}
