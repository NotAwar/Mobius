package v1

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

// Client represents a managed client
type Client struct {
	ID               string                 `json:"id"`
	Hostname         string                 `json:"hostname"`
	IPAddress        string                 `json:"ip_address,omitempty"`
	MACAddress       string                 `json:"mac_address,omitempty"`
	OSType           string                 `json:"os_type"`
	OSVersion        string                 `json:"os_version,omitempty"`
	AgentVersion     string                 `json:"agent_version,omitempty"`
	Status           string                 `json:"status"` // online, offline, pending
	LastCheckIn      *time.Time             `json:"last_check_in,omitempty"`
	Tags             []string               `json:"tags,omitempty"`
	Metadata         map[string]interface{} `json:"metadata,omitempty"`
	EnrollmentMethod string                 `json:"enrollment_method,omitempty"`
	CreatedAt        time.Time              `json:"created_at"`
	UpdatedAt        time.Time              `json:"updated_at"`
}

// ClientGroup represents a group of clients
type ClientGroup struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	Criteria    map[string]interface{} `json:"criteria,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

// ClientConfiguration represents client-specific configuration
type ClientConfiguration struct {
	ClientID      string                 `json:"client_id"`
	Configuration map[string]interface{} `json:"configuration"`
	UpdatedAt     time.Time              `json:"updated_at"`
}

// CheckIn represents a client check-in record
type CheckIn struct {
	ID        string                 `json:"id"`
	ClientID  string                 `json:"client_id"`
	Timestamp time.Time              `json:"timestamp"`
	IPAddress string                 `json:"ip_address,omitempty"`
	Status    string                 `json:"status"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// GetClients retrieves all clients with filters
func (h *Handler) GetClients(c *fiber.Ctx) error {
	limit := c.QueryInt("limit", 50)
	offset := c.QueryInt("offset", 0)
	status := c.Query("status", "")
	osType := c.Query("os_type", "")
	tag := c.Query("tag", "")

	if h.dbPools == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"error":   "Database unavailable",
			"message": "Database connection not configured",
		})
	}

	ctx := context.Background()

	// Build query with filters
	query := `
		SELECT DISTINCT c.id, c.hostname, c.ip_address, c.mac_address, 
		       c.os_type, c.os_version, c.agent_version, c.status,
		       c.last_seen, c.created_at, c.updated_at,
		       COALESCE(
		           (SELECT json_agg(tag) FROM client_tags WHERE client_id = c.id),
		           '[]'::json
		       ) as tags
		FROM clients c
	`
	
	joins := ""
	where := "WHERE 1=1"
	args := []interface{}{}
	argCount := 1

	if tag != "" {
		joins += " INNER JOIN client_tags ct ON c.id = ct.client_id"
		where += fmt.Sprintf(" AND ct.tag = $%d", argCount)
		args = append(args, tag)
		argCount++
	}

	if status != "" {
		where += fmt.Sprintf(" AND c.status = $%d", argCount)
		args = append(args, status)
		argCount++
	}

	if osType != "" {
		where += fmt.Sprintf(" AND c.os_type = $%d", argCount)
		args = append(args, osType)
		argCount++
	}

	query = query + joins + " " + where + " ORDER BY c.created_at DESC"
	query += fmt.Sprintf(" LIMIT $%d OFFSET $%d", argCount, argCount+1)
	args = append(args, limit, offset)

	rows, err := h.dbPools.Clients.Query(ctx, query, args...)
	if err != nil {
		h.logger.Errorf("Failed to query clients: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Database error",
			"message": "Failed to retrieve clients",
		})
	}
	defer rows.Close()

	clients := make([]Client, 0)
	for rows.Next() {
		var client Client
		var tagsJSON []byte
		var lastSeen sql.NullTime
		var ipAddr, macAddr, osVersion, agentVersion sql.NullString
		
		if err := rows.Scan(&client.ID, &client.Hostname, &ipAddr, &macAddr,
			&client.OSType, &osVersion, &agentVersion, &client.Status,
			&lastSeen, &client.CreatedAt, &client.UpdatedAt, &tagsJSON); err != nil {
			h.logger.Errorf("Failed to scan client: %v", err)
			continue
		}

		if ipAddr.Valid {
			client.IPAddress = ipAddr.String
		}
		if macAddr.Valid {
			client.MACAddress = macAddr.String
		}
		if osVersion.Valid {
			client.OSVersion = osVersion.String
		}
		if agentVersion.Valid {
			client.AgentVersion = agentVersion.String
		}
		if lastSeen.Valid {
			client.LastCheckIn = &lastSeen.Time
		}
		
		if len(tagsJSON) > 0 {
			json.Unmarshal(tagsJSON, &client.Tags)
		}

		clients = append(clients, client)
	}

	// Get total count
	countQuery := "SELECT COUNT(DISTINCT c.id) FROM clients c" + joins + " " + where
	var total int
	countArgs := args[:len(args)-2] // Remove LIMIT and OFFSET
	if err := h.dbPools.Clients.QueryRow(ctx, countQuery, countArgs...).Scan(&total); err != nil {
		h.logger.Errorf("Failed to count clients: %v", err)
		total = len(clients)
	}

	return c.JSON(fiber.Map{
		"clients": clients,
		"total":   total,
		"limit":   limit,
		"offset":  offset,
	})
}

// GetClient retrieves a specific client
func (h *Handler) GetClient(c *fiber.Ctx) error {
	clientID := c.Params("id")

	if h.dbPools == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"error":   "Database unavailable",
			"message": "Database connection not configured",
		})
	}

	ctx := context.Background()

	query := `
		SELECT c.id, c.hostname, c.ip_address, c.mac_address, 
		       c.os_type, c.os_version, c.agent_version, c.status,
		       c.last_seen, c.enrollment_method, c.created_at, c.updated_at,
		       COALESCE(
		           (SELECT json_agg(tag) FROM client_tags WHERE client_id = c.id),
		           '[]'::json
		       ) as tags
		FROM clients c
		WHERE c.id = $1
	`

	var client Client
	var tagsJSON []byte
	var lastSeen sql.NullTime
	var ipAddr, macAddr, osVersion, agentVersion, enrollMethod sql.NullString

	err := h.dbPools.Clients.QueryRow(ctx, query, clientID).Scan(
		&client.ID, &client.Hostname, &ipAddr, &macAddr,
		&client.OSType, &osVersion, &agentVersion, &client.Status,
		&lastSeen, &enrollMethod, &client.CreatedAt, &client.UpdatedAt, &tagsJSON)

	if err != nil {
		if err.Error() == "no rows in result set" {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error":   "Client not found",
				"message": fmt.Sprintf("Client with ID %s not found", clientID),
			})
		}
		h.logger.Errorf("Failed to query client: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Database error",
			"message": "Failed to retrieve client",
		})
	}

	if ipAddr.Valid {
		client.IPAddress = ipAddr.String
	}
	if macAddr.Valid {
		client.MACAddress = macAddr.String
	}
	if osVersion.Valid {
		client.OSVersion = osVersion.String
	}
	if agentVersion.Valid {
		client.AgentVersion = agentVersion.String
	}
	if enrollMethod.Valid {
		client.EnrollmentMethod = enrollMethod.String
	}
	if lastSeen.Valid {
		client.LastCheckIn = &lastSeen.Time
	}
	if len(tagsJSON) > 0 {
		json.Unmarshal(tagsJSON, &client.Tags)
	}

	return c.JSON(fiber.Map{
		"client": client,
	})
}

// CreateClient registers a new client
func (h *Handler) CreateClient(c *fiber.Ctx) error {
	var client Client
	if err := c.BodyParser(&client); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Invalid request body",
			"message": err.Error(),
		})
	}

	// Validate required fields
	if client.Hostname == "" || client.OSType == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Validation error",
			"message": "Hostname and os_type are required",
		})
	}

	if h.dbPools == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"error":   "Database unavailable",
			"message": "Database connection not configured",
		})
	}

	client.ID = uuid.New().String()
	if client.Status == "" {
		client.Status = "pending"
	}
	client.CreatedAt = time.Now()
	client.UpdatedAt = time.Now()

	ctx := context.Background()

	query := `
		INSERT INTO clients (id, hostname, ip_address, mac_address, os_type, os_version, 
		                     agent_version, status, enrollment_method, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`

	_, err := h.dbPools.Clients.Exec(ctx, query,
		client.ID, client.Hostname, client.IPAddress, client.MACAddress,
		client.OSType, client.OSVersion, client.AgentVersion, client.Status,
		client.EnrollmentMethod, client.CreatedAt, client.UpdatedAt)

	if err != nil {
		h.logger.Errorf("Failed to create client: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Database error",
			"message": "Failed to create client",
		})
	}

	// Add tags if provided
	if len(client.Tags) > 0 {
		for _, tag := range client.Tags {
			_, _ = h.dbPools.Clients.Exec(ctx,
				"INSERT INTO client_tags (client_id, tag) VALUES ($1, $2) ON CONFLICT DO NOTHING",
				client.ID, tag)
		}
	}

	h.logger.Infof("Registered new client: %s (%s)", client.Hostname, client.ID)

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"client": client,
	})
}

// UpdateClient updates client information
func (h *Handler) UpdateClient(c *fiber.Ctx) error {
	clientID := c.Params("id")

	var updates map[string]interface{}
	if err := c.BodyParser(&updates); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Invalid request body",
			"message": err.Error(),
		})
	}

	if h.dbPools == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"error":   "Database unavailable",
			"message": "Database connection not configured",
		})
	}

	ctx := context.Background()

	// Build dynamic update query
	setClauses := []string{}
	args := []interface{}{clientID}
	argCount := 2

	allowedFields := map[string]bool{
		"hostname": true, "ip_address": true, "mac_address": true,
		"os_type": true, "os_version": true, "agent_version": true,
		"status": true,
	}

	for field, value := range updates {
		if allowedFields[field] {
			setClauses = append(setClauses, fmt.Sprintf("%s = $%d", field, argCount))
			args = append(args, value)
			argCount++
		}
	}

	if len(setClauses) == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Validation error",
			"message": "No valid fields to update",
		})
	}

	setClauses = append(setClauses, "updated_at = NOW()")
	query := fmt.Sprintf("UPDATE clients SET %s WHERE id = $1",
		string(setClauses[0]))
	for i := 1; i < len(setClauses); i++ {
		query += ", " + setClauses[i]
	}

	result, err := h.dbPools.Clients.Exec(ctx, query, args...)
	if err != nil {
		h.logger.Errorf("Failed to update client: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Database error",
			"message": "Failed to update client",
		})
	}

	if result.RowsAffected() == 0 {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error":   "Client not found",
			"message": fmt.Sprintf("Client with ID %s not found", clientID),
		})
	}

	h.logger.Infof("Updated client: %s", clientID)

	return c.JSON(fiber.Map{
		"message":   "Client updated successfully",
		"client_id": clientID,
		"updates":   updates,
	})
}

// DeleteClient removes a client
func (h *Handler) DeleteClient(c *fiber.Ctx) error {
	clientID := c.Params("id")

	if h.dbPools == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"error":   "Database unavailable",
			"message": "Database connection not configured",
		})
	}

	ctx := context.Background()

	// Delete client (cascades will handle related records)
	query := "DELETE FROM clients WHERE id = $1"
	result, err := h.dbPools.Clients.Exec(ctx, query, clientID)
	if err != nil {
		h.logger.Errorf("Failed to delete client: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Database error",
			"message": "Failed to delete client",
		})
	}

	if result.RowsAffected() == 0 {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error":   "Client not found",
			"message": fmt.Sprintf("Client with ID %s not found", clientID),
		})
	}

	h.logger.Infof("Deleted client: %s", clientID)

	return c.Status(fiber.StatusNoContent).Send(nil)
}

// AddClientTag adds a tag to a client
func (h *Handler) AddClientTag(c *fiber.Ctx) error {
	clientID := c.Params("id")
	
	var req struct {
		Tag string `json:"tag"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Invalid request body",
			"message": err.Error(),
		})
	}

	if req.Tag == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Validation error",
			"message": "Tag cannot be empty",
		})
	}

	if h.dbPools == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"error":   "Database unavailable",
			"message": "Database connection not configured",
		})
	}

	ctx := context.Background()

	// Verify client exists
	var exists bool
	err := h.dbPools.Clients.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM clients WHERE id = $1)", clientID).Scan(&exists)
	if err != nil || !exists {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error":   "Client not found",
			"message": fmt.Sprintf("Client with ID %s not found", clientID),
		})
	}

	// Insert tag (ON CONFLICT DO NOTHING to avoid duplicates)
	query := "INSERT INTO client_tags (client_id, tag) VALUES ($1, $2) ON CONFLICT DO NOTHING"
	_, err = h.dbPools.Clients.Exec(ctx, query, clientID, req.Tag)
	if err != nil {
		h.logger.Errorf("Failed to add tag: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Database error",
			"message": "Failed to add tag",
		})
	}

	h.logger.Infof("Added tag '%s' to client: %s", req.Tag, clientID)

	return c.JSON(fiber.Map{
		"message":   "Tag added successfully",
		"client_id": clientID,
		"tag":       req.Tag,
	})
}

// RemoveClientTag removes a tag from a client
func (h *Handler) RemoveClientTag(c *fiber.Ctx) error {
	clientID := c.Params("id")
	tag := c.Params("tag")

	if h.dbPools == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"error":   "Database unavailable",
			"message": "Database connection not configured",
		})
	}

	ctx := context.Background()

	query := "DELETE FROM client_tags WHERE client_id = $1 AND tag = $2"
	result, err := h.dbPools.Clients.Exec(ctx, query, clientID, tag)
	if err != nil {
		h.logger.Errorf("Failed to remove tag: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Database error",
			"message": "Failed to remove tag",
		})
	}

	if result.RowsAffected() == 0 {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error":   "Tag not found",
			"message": fmt.Sprintf("Tag '%s' not found for client %s", tag, clientID),
		})
	}

	h.logger.Infof("Removed tag '%s' from client: %s", tag, clientID)

	return c.Status(fiber.StatusNoContent).Send(nil)
}

// GetClientGroups retrieves all client groups
func (h *Handler) GetClientGroups(c *fiber.Ctx) error {
	if h.dbPools == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"error":   "Database unavailable",
			"message": "Database connection not configured",
		})
	}

	ctx := context.Background()

	query := `
		SELECT g.id, g.name, g.description, g.created_at, g.updated_at,
		       (SELECT COUNT(*) FROM client_group_members WHERE group_id = g.id) as client_count,
		       COALESCE(
		           (SELECT json_agg(tag) FROM group_tags WHERE group_id = g.id),
		           '[]'::json
		       ) as tags
		FROM client_groups g
		ORDER BY g.created_at DESC
	`

	rows, err := h.dbPools.Clients.Query(ctx, query)
	if err != nil {
		h.logger.Errorf("Failed to query groups: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Database error",
			"message": "Failed to retrieve groups",
		})
	}
	defer rows.Close()

	type GroupWithCount struct {
		ClientGroup
		ClientCount int      `json:"client_count"`
		Tags        []string `json:"tags"`
	}

	groups := make([]GroupWithCount, 0)
	for rows.Next() {
		var group GroupWithCount
		var description sql.NullString
		var tagsJSON []byte

		if err := rows.Scan(&group.ID, &group.Name, &description,
			&group.CreatedAt, &group.UpdatedAt, &group.ClientCount, &tagsJSON); err != nil {
			h.logger.Errorf("Failed to scan group: %v", err)
			continue
		}

		if description.Valid {
			group.Description = description.String
		}
		if len(tagsJSON) > 0 {
			json.Unmarshal(tagsJSON, &group.Tags)
		}

		groups = append(groups, group)
	}

	return c.JSON(fiber.Map{
		"groups": groups,
		"total":  len(groups),
	})
}

// GetClientConfiguration retrieves client configuration
func (h *Handler) GetClientConfiguration(c *fiber.Ctx) error {
	clientID := c.Params("id")

	if h.dbPools == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"error":   "Database unavailable",
			"message": "Database connection not configured",
		})
	}

	ctx := context.Background()

	// Verify client exists
	var exists bool
	err := h.dbPools.Clients.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM clients WHERE id = $1)", clientID).Scan(&exists)
	if err != nil || !exists {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error":   "Client not found",
			"message": fmt.Sprintf("Client with ID %s not found", clientID),
		})
	}

	query := "SELECT configuration, updated_at FROM client_configurations WHERE client_id = $1"
	var configJSON []byte
	var updatedAt time.Time

	err = h.dbPools.Clients.QueryRow(ctx, query, clientID).Scan(&configJSON, &updatedAt)
	if err != nil {
		// Return default configuration if not found
		if err.Error() == "no rows in result set" {
			return c.JSON(fiber.Map{
				"client_id": clientID,
				"configuration": map[string]interface{}{
					"check_in_interval":  300,
					"osquery_interval":   60,
					"enable_osquery":     true,
					"enable_ssh":         true,
					"log_level":          "info",
					"max_query_results":  1000,
				},
				"updated_at": time.Now(),
			})
		}
		h.logger.Errorf("Failed to query configuration: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Database error",
			"message": "Failed to retrieve configuration",
		})
	}

	var configuration map[string]interface{}
	if err := json.Unmarshal(configJSON, &configuration); err != nil {
		h.logger.Errorf("Failed to parse configuration: %v", err)
		configuration = make(map[string]interface{})
	}

	return c.JSON(fiber.Map{
		"client_id":     clientID,
		"configuration": configuration,
		"updated_at":    updatedAt,
	})
}

// UpdateClientConfiguration updates client configuration
func (h *Handler) UpdateClientConfiguration(c *fiber.Ctx) error {
	clientID := c.Params("id")

	var config map[string]interface{}
	if err := c.BodyParser(&config); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Invalid request body",
			"message": err.Error(),
		})
	}

	if h.dbPools == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"error":   "Database unavailable",
			"message": "Database connection not configured",
		})
	}

	ctx := context.Background()

	// Verify client exists
	var exists bool
	err := h.dbPools.Clients.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM clients WHERE id = $1)", clientID).Scan(&exists)
	if err != nil || !exists {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error":   "Client not found",
			"message": fmt.Sprintf("Client with ID %s not found", clientID),
		})
	}

	configJSON, err := json.Marshal(config)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Invalid configuration",
			"message": "Failed to serialize configuration",
		})
	}

	query := `
		INSERT INTO client_configurations (client_id, configuration, updated_at)
		VALUES ($1, $2, NOW())
		ON CONFLICT (client_id) DO UPDATE
		SET configuration = $2, updated_at = NOW()
	`

	_, err = h.dbPools.Clients.Exec(ctx, query, clientID, configJSON)
	if err != nil {
		h.logger.Errorf("Failed to update configuration: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Database error",
			"message": "Failed to update configuration",
		})
	}

	h.logger.Infof("Updated configuration for client: %s", clientID)

	return c.JSON(fiber.Map{
		"client_id":     clientID,
		"configuration": config,
		"updated_at":    time.Now(),
	})
}

// GetClientCheckIns retrieves check-in history
func (h *Handler) GetClientCheckIns(c *fiber.Ctx) error {
	clientID := c.Params("id")
	limit := c.QueryInt("limit", 50)
	offset := c.QueryInt("offset", 0)

	if h.dbPools == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"error":   "Database unavailable",
			"message": "Database connection not configured",
		})
	}

	ctx := context.Background()

	// Verify client exists
	var exists bool
	err := h.dbPools.Clients.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM clients WHERE id = $1)", clientID).Scan(&exists)
	if err != nil || !exists {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error":   "Client not found",
			"message": fmt.Sprintf("Client with ID %s not found", clientID),
		})
	}

	query := `
		SELECT id, client_id, timestamp, ip_address, status, system_info
		FROM client_check_ins
		WHERE client_id = $1
		ORDER BY timestamp DESC
		LIMIT $2 OFFSET $3
	`

	rows, err := h.dbPools.Clients.Query(ctx, query, clientID, limit, offset)
	if err != nil {
		h.logger.Errorf("Failed to query check-ins: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Database error",
			"message": "Failed to retrieve check-ins",
		})
	}
	defer rows.Close()

	checkIns := make([]CheckIn, 0)
	for rows.Next() {
		var checkIn CheckIn
		var ipAddr sql.NullString
		var systemInfoJSON []byte

		if err := rows.Scan(&checkIn.ID, &checkIn.ClientID, &checkIn.Timestamp,
			&ipAddr, &checkIn.Status, &systemInfoJSON); err != nil {
			h.logger.Errorf("Failed to scan check-in: %v", err)
			continue
		}

		if ipAddr.Valid {
			checkIn.IPAddress = ipAddr.String
		}
		if len(systemInfoJSON) > 0 {
			json.Unmarshal(systemInfoJSON, &checkIn.Metadata)
		}

		checkIns = append(checkIns, checkIn)
	}

	// Get total count
	var total int
	countQuery := "SELECT COUNT(*) FROM client_check_ins WHERE client_id = $1"
	if err := h.dbPools.Clients.QueryRow(ctx, countQuery, clientID).Scan(&total); err != nil {
		h.logger.Errorf("Failed to count check-ins: %v", err)
		total = len(checkIns)
	}

	return c.JSON(fiber.Map{
		"check_ins": checkIns,
		"client_id": clientID,
		"total":     total,
		"limit":     limit,
		"offset":    offset,
	})
}

// ClientCheckIn records a check-in from a client
func (h *Handler) ClientCheckIn(c *fiber.Ctx) error {
	clientID := c.Params("id")

	if h.dbPools == nil || h.dbPools.Clients == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"error": "Database unavailable",
		})
	}

	// Validate client authentication
	clientKey := c.Get("X-Client-Key", "")
	if clientKey == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Missing client key",
		})
	}

	ctx := context.Background()

	// Verify client credentials
	var storedKey string
	var currentStatus string
	verifyQuery := `SELECT client_key, status FROM clients WHERE id = $1`
	err := h.dbPools.Clients.QueryRow(ctx, verifyQuery, clientID).Scan(&storedKey, &currentStatus)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Invalid client ID",
		})
	}

	if storedKey != clientKey {
		h.logger.Warnf("Invalid client key for client: %s", clientID)
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Invalid client key",
		})
	}

	// Parse check-in data
	var req struct {
		Timestamp      time.Time              `json:"timestamp"`
		SystemInfo     map[string]interface{} `json:"system_info"`
		OSQueryResults map[string]interface{} `json:"osquery_results"`
		HealthStatus   map[string]interface{} `json:"health_status"`
	}

	if err := c.BodyParser(&req); err != nil {
		h.logger.Warnf("Failed to parse check-in body: %v", err)
		req.SystemInfo = make(map[string]interface{})
	}

	// Update client status to online (trigger will update last_seen)
	updateQuery := `
		UPDATE clients 
		SET status = 'online', 
		    ip_address = $2,
		    updated_at = NOW()
		WHERE id = $1
	`
	_, err = h.dbPools.Clients.Exec(ctx, updateQuery, clientID, c.IP())
	if err != nil {
		h.logger.Errorf("Failed to update client status: %v", err)
	}

	// Record check-in
	checkInID := uuid.New().String()
	insertCheckInQuery := `
		INSERT INTO client_check_ins (id, client_id, timestamp, ip_address, status, system_info)
		VALUES ($1, $2, $3, $4, $5, $6)
	`
	
	_, err = h.dbPools.Clients.Exec(ctx, insertCheckInQuery,
		checkInID, clientID, time.Now(), c.IP(), "success", req.SystemInfo)
	if err != nil {
		h.logger.Errorf("Failed to record check-in: %v", err)
	}

	// Update hardware info if provided
	if cpuCores, ok := req.SystemInfo["cpu_cores"].(float64); ok {
		updateHWQuery := `
			INSERT INTO client_hardware (client_id, cpu_cores, total_memory_mb, updated_at)
			VALUES ($1, $2, $3, NOW())
			ON CONFLICT (client_id) DO UPDATE
			SET cpu_cores = $2, total_memory_mb = $3, updated_at = NOW()
		`
		memoryMB := int64(0)
		if mem, ok := req.SystemInfo["total_memory_mb"].(float64); ok {
			memoryMB = int64(mem)
		}
		_, _ = h.dbPools.Clients.Exec(ctx, updateHWQuery, clientID, int(cpuCores), memoryMB)
	}

	// Store OSQuery results if provided and OSQuery DB is available
	if len(req.OSQueryResults) > 0 && h.dbPools.OSQuery != nil {
		for queryName, results := range req.OSQueryResults {
			resultID := uuid.New().String()
			insertResultQuery := `
				INSERT INTO osquery_results (id, client_id, query_name, results, timestamp)
				VALUES ($1, $2, $3, $4, NOW())
			`
			_, _ = h.dbPools.OSQuery.Exec(ctx, insertResultQuery,
				resultID, clientID, queryName, results)
		}
	}

	h.logger.Debugf("Client check-in: %s from %s", clientID, c.IP())

	// Fetch pending commands if any (future feature)
	pendingCommands := []interface{}{}

	// Fetch current configuration
	configuration := map[string]interface{}{
		"check_in_interval":  300, // 5 minutes
		"osquery_interval":   60,  // 1 minute
		"enable_osquery":     true,
		"enable_ssh":         true,
	}

	return c.JSON(fiber.Map{
		"status":           "ok",
		"configuration":    configuration,
		"pending_commands": pendingCommands,
	})
}
