package v1

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

// EnrollmentKey represents an enrollment key
type EnrollmentKey struct {
	ID                 string    `json:"id"`
	Name               string    `json:"name"`
	Key                string    `json:"key"`
	CreatedAt          time.Time `json:"created_at"`
	CreatedBy          string    `json:"created_by,omitempty"`
	ExpiresAt          *time.Time `json:"expires_at,omitempty"`
	MaxUses            int       `json:"max_uses"`
	UsedCount          int       `json:"used_count"`
	Revoked            bool      `json:"revoked"`
	Tags               []string  `json:"tags,omitempty"`
	AutoAssignGroupIDs []string  `json:"auto_assign_group_ids,omitempty"`
}

// EnrollmentRequest represents client enrollment request
type EnrollmentRequest struct {
	EnrollmentKey string                 `json:"enrollment_key"`
	Hostname      string                 `json:"hostname"`
	SystemInfo    map[string]interface{} `json:"system_info"`
}

// EnrollmentResponse represents enrollment response
type EnrollmentResponse struct {
	ClientID  string `json:"client_id"`
	ClientKey string `json:"client_key"`
	ServerURL string `json:"server_url"`
	Message   string `json:"message"`
}

// GetEnrollmentKeys lists all enrollment keys
func (h *Handler) GetEnrollmentKeys(c *fiber.Ctx) error {
	if h.dbPools == nil || h.dbPools.Clients == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"error": "Database unavailable",
		})
	}

	ctx := context.Background()
	
	query := `
		SELECT id, name, key, created_at, created_by, expires_at, 
		       max_uses, used_count, revoked, tags, auto_assign_group_ids
		FROM enrollment_keys
		WHERE revoked = FALSE
		ORDER BY created_at DESC
	`

	rows, err := h.dbPools.Clients.Query(ctx, query)
	if err != nil {
		h.logger.Errorf("Failed to query enrollment keys: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to retrieve enrollment keys",
		})
	}
	defer rows.Close()

	keys := make([]EnrollmentKey, 0)
	for rows.Next() {
		var key EnrollmentKey
		var expiresAt, createdBy interface{}
		var tags, groupIDs []string

		err := rows.Scan(&key.ID, &key.Name, &key.Key, &key.CreatedAt, &createdBy,
			&expiresAt, &key.MaxUses, &key.UsedCount, &key.Revoked, &tags, &groupIDs)
		if err != nil {
			h.logger.Errorf("Failed to scan enrollment key: %v", err)
			continue
		}

		if expiresAt != nil {
			t := expiresAt.(time.Time)
			key.ExpiresAt = &t
		}
		if createdBy != nil {
			key.CreatedBy = createdBy.(string)
		}
		key.Tags = tags
		key.AutoAssignGroupIDs = groupIDs

		keys = append(keys, key)
	}

	return c.JSON(fiber.Map{
		"keys":  keys,
		"total": len(keys),
	})
}

// CreateEnrollmentKey creates a new enrollment key
func (h *Handler) CreateEnrollmentKey(c *fiber.Ctx) error {
	if h.dbPools == nil || h.dbPools.Clients == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"error": "Database unavailable",
		})
	}

	var req struct {
		Name      string     `json:"name"`
		ExpiresAt *time.Time `json:"expires_at"`
		MaxUses   int        `json:"max_uses"`
		Tags      []string   `json:"tags"`
		GroupIDs  []string   `json:"group_ids"`
	}

	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	if req.Name == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Name is required",
		})
	}

	// Generate secure enrollment key
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to generate key",
		})
	}
	key := base64.URLEncoding.EncodeToString(keyBytes)

	ctx := context.Background()
	id := uuid.New().String()

	query := `
		INSERT INTO enrollment_keys (id, name, key, expires_at, max_uses, tags, auto_assign_group_ids)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING created_at
	`

	var createdAt time.Time
	err := h.dbPools.Clients.QueryRow(ctx, query, id, req.Name, key, req.ExpiresAt,
		req.MaxUses, req.Tags, req.GroupIDs).Scan(&createdAt)
	if err != nil {
		h.logger.Errorf("Failed to create enrollment key: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to create enrollment key",
		})
	}

	h.logger.Infof("Created enrollment key: %s (%s)", req.Name, id)

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"id":         id,
		"key":        key,
		"name":       req.Name,
		"created_at": createdAt,
		"expires_at": req.ExpiresAt,
		"max_uses":   req.MaxUses,
	})
}

// RevokeEnrollmentKey revokes an enrollment key
func (h *Handler) RevokeEnrollmentKey(c *fiber.Ctx) error {
	if h.dbPools == nil || h.dbPools.Clients == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"error": "Database unavailable",
		})
	}

	keyID := c.Params("id")
	ctx := context.Background()

	query := `UPDATE enrollment_keys SET revoked = TRUE WHERE id = $1`
	
	_, err := h.dbPools.Clients.Exec(ctx, query, keyID)
	if err != nil {
		h.logger.Errorf("Failed to revoke enrollment key: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to revoke key",
		})
	}

	h.logger.Infof("Revoked enrollment key: %s", keyID)

	return c.Status(fiber.StatusNoContent).Send(nil)
}

// EnrollClient handles client enrollment
func (h *Handler) EnrollClient(c *fiber.Ctx) error {
	if h.dbPools == nil || h.dbPools.Clients == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"error":   "Database unavailable",
			"message": "Server is not ready to accept enrollments",
		})
	}

	var req EnrollmentRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Invalid request body",
			"message": err.Error(),
		})
	}

	// Validate required fields
	if req.EnrollmentKey == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Validation error",
			"message": "Enrollment key is required",
		})
	}
	if req.Hostname == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Validation error",
			"message": "Hostname is required",
		})
	}

	ctx := context.Background()

	// Validate enrollment key
	var enrollKey EnrollmentKey
	query := `
		SELECT id, name, expires_at, max_uses, used_count, revoked, 
		       tags, auto_assign_group_ids
		FROM enrollment_keys
		WHERE key = $1
	`

	var expiresAt interface{}
	var tags, groupIDs []string
	err := h.dbPools.Clients.QueryRow(ctx, query, req.EnrollmentKey).Scan(
		&enrollKey.ID, &enrollKey.Name, &expiresAt, &enrollKey.MaxUses,
		&enrollKey.UsedCount, &enrollKey.Revoked, &tags, &groupIDs)
	if err != nil {
		h.logger.Warnf("Invalid enrollment key attempted: %s", req.EnrollmentKey[:10])
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error":   "Invalid enrollment key",
			"message": "The provided enrollment key is not valid",
		})
	}

	// Check if key is revoked
	if enrollKey.Revoked {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error":   "Enrollment key revoked",
			"message": "This enrollment key has been revoked",
		})
	}

	// Check if key is expired
	if expiresAt != nil {
		expiry := expiresAt.(time.Time)
		if time.Now().After(expiry) {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error":   "Enrollment key expired",
				"message": "This enrollment key has expired",
			})
		}
	}

	// Check max uses
	if enrollKey.MaxUses > 0 && enrollKey.UsedCount >= enrollKey.MaxUses {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error":   "Enrollment key exhausted",
			"message": "This enrollment key has reached its maximum usage limit",
		})
	}

	// Generate client ID and key
	clientID := uuid.New().String()
	clientKeyBytes := make([]byte, 32)
	if _, err := rand.Read(clientKeyBytes); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to generate client credentials",
		})
	}
	clientKey := base64.URLEncoding.EncodeToString(clientKeyBytes)

	// Extract system info
	osType := "unknown"
	if os, ok := req.SystemInfo["os"].(string); ok {
		osType = os
	}
	osVersion := ""
	if ver, ok := req.SystemInfo["os_version"].(string); ok {
		osVersion = ver
	}
	var ipAddresses []string
	if ips, ok := req.SystemInfo["ip_addresses"].([]interface{}); ok {
		for _, ip := range ips {
			if ipStr, ok := ip.(string); ok {
				ipAddresses = append(ipAddresses, ipStr)
			}
		}
	}
	ipAddress := ""
	if len(ipAddresses) > 0 {
		ipAddress = ipAddresses[0]
	}
	var macAddresses []string
	if macs, ok := req.SystemInfo["mac_addresses"].([]interface{}); ok {
		for _, mac := range macs {
			if macStr, ok := mac.(string); ok {
				macAddresses = append(macAddresses, macStr)
			}
		}
	}
	macAddress := ""
	if len(macAddresses) > 0 {
		macAddress = macAddresses[0]
	}

	// Insert client
	insertClientQuery := `
		INSERT INTO clients (
			id, hostname, ip_address, mac_address, os_type, os_version,
			status, enrollment_method, client_key, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW())
	`

	_, err = h.dbPools.Clients.Exec(ctx, insertClientQuery,
		clientID, req.Hostname, ipAddress, macAddress, osType, osVersion,
		"pending", "enrollment_key", clientKey)
	if err != nil {
		h.logger.Errorf("Failed to insert client: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to enroll client",
		})
	}

	// Apply auto-tags from enrollment key
	if len(tags) > 0 {
		for _, tag := range tags {
			insertTagQuery := `
				INSERT INTO client_tags (client_id, tag, created_at)
				VALUES ($1, $2, NOW())
				ON CONFLICT DO NOTHING
			`
			_, _ = h.dbPools.Clients.Exec(ctx, insertTagQuery, clientID, tag)
		}
	}

	// Apply auto-assign groups
	if len(groupIDs) > 0 {
		for _, groupID := range groupIDs {
			insertGroupQuery := `
				INSERT INTO client_group_members (group_id, client_id, added_at)
				VALUES ($1, $2, NOW())
				ON CONFLICT DO NOTHING
			`
			_, _ = h.dbPools.Clients.Exec(ctx, insertGroupQuery, groupID, clientID)
		}
	}

	// Increment enrollment key usage count
	updateKeyQuery := `UPDATE enrollment_keys SET used_count = used_count + 1 WHERE id = $1`
	_, _ = h.dbPools.Clients.Exec(ctx, updateKeyQuery, enrollKey.ID)

	// Create audit log
	auditQuery := `
		INSERT INTO audit_logs (id, action, resource_type, resource_id, 
		                        actor_type, actor_id, ip_address, timestamp, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), $8)
	`
	auditID := uuid.New().String()
	auditMetadata := map[string]interface{}{
		"hostname":        req.Hostname,
		"enrollment_key":  enrollKey.Name,
		"os_type":        osType,
		"ip_address":     ipAddress,
	}
	if h.dbPools.Audit != nil {
		_, _ = h.dbPools.Audit.Exec(ctx, auditQuery,
			auditID, "client_enrolled", "client", clientID,
			"client", clientID, c.IP(), auditMetadata)
	}

	h.logger.Infof("Client enrolled: %s (%s) using key: %s", req.Hostname, clientID, enrollKey.Name)

	response := EnrollmentResponse{
		ClientID:  clientID,
		ClientKey: clientKey,
		ServerURL: c.BaseURL(),
		Message:   "Enrollment successful",
	}

	return c.Status(fiber.StatusCreated).JSON(response)
}
