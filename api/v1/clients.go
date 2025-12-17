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
// TODO: Connect to clients database
func (h *Handler) GetClient(c *fiber.Ctx) error {
	clientID := c.Params("id")

	now := time.Now()
	lastCheckIn := now.Add(-5 * time.Minute)

	client := Client{
		ID:               clientID,
		Hostname:         "macbook-pro-01",
		IPAddress:        "192.168.1.100",
		MACAddress:       "00:1B:63:84:45:E6",
		OSType:           "darwin",
		OSVersion:        "14.1",
		AgentVersion:     "1.0.0",
		Status:           "online",
		LastCheckIn:      &lastCheckIn,
		Tags:             []string{"development", "macOS"},
		EnrollmentMethod: "manual",
		Metadata: map[string]interface{}{
			"cpu_cores": 8,
			"memory_gb": 16,
		},
		CreatedAt: now.Add(-30 * 24 * time.Hour),
		UpdatedAt: now,
	}

	return c.JSON(client)
}

// CreateClient registers a new client
// TODO: Connect to clients database
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

	client.ID = uuid.New().String()
	client.Status = "pending"
	client.CreatedAt = time.Now()
	client.UpdatedAt = time.Now()

	h.logger.Infof("Registered new client: %s (%s)", client.Hostname, client.ID)

	return c.Status(fiber.StatusCreated).JSON(client)
}

// UpdateClient updates client information
// TODO: Connect to clients database
func (h *Handler) UpdateClient(c *fiber.Ctx) error {
	clientID := c.Params("id")

	var updates map[string]interface{}
	if err := c.BodyParser(&updates); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Invalid request body",
			"message": err.Error(),
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
// TODO: Connect to clients database
func (h *Handler) DeleteClient(c *fiber.Ctx) error {
	clientID := c.Params("id")

	h.logger.Infof("Deleted client: %s", clientID)

	return c.Status(fiber.StatusNoContent).Send(nil)
}

// AddClientTag adds a tag to a client
// TODO: Connect to clients database
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

	h.logger.Infof("Added tag '%s' to client: %s", req.Tag, clientID)

	return c.JSON(fiber.Map{
		"message":   "Tag added successfully",
		"client_id": clientID,
		"tag":       req.Tag,
	})
}

// RemoveClientTag removes a tag from a client
// TODO: Connect to clients database
func (h *Handler) RemoveClientTag(c *fiber.Ctx) error {
	clientID := c.Params("id")
	tag := c.Params("tag")

	h.logger.Infof("Removed tag '%s' from client: %s", tag, clientID)

	return c.Status(fiber.StatusNoContent).Send(nil)
}

// GetClientGroups retrieves all client groups
// TODO: Connect to clients database
func (h *Handler) GetClientGroups(c *fiber.Ctx) error {
	groups := []ClientGroup{
		{
			ID:          uuid.New().String(),
			Name:        "Production Servers",
			Description: "All production Linux servers",
			Criteria: map[string]interface{}{
				"os_type": "linux",
				"tags":    []string{"production", "server"},
			},
			CreatedAt: time.Now().Add(-30 * 24 * time.Hour),
			UpdatedAt: time.Now(),
		},
		{
			ID:          uuid.New().String(),
			Name:        "Development Machines",
			Description: "Developer workstations",
			Criteria: map[string]interface{}{
				"tags": []string{"development"},
			},
			CreatedAt: time.Now().Add(-15 * 24 * time.Hour),
			UpdatedAt: time.Now(),
		},
	}

	return c.JSON(fiber.Map{
		"groups": groups,
		"total":  len(groups),
	})
}

// GetClientConfiguration retrieves client configuration
// TODO: Connect to clients database
func (h *Handler) GetClientConfiguration(c *fiber.Ctx) error {
	clientID := c.Params("id")

	config := ClientConfiguration{
		ClientID: clientID,
		Configuration: map[string]interface{}{
			"agent_update_interval": 3600,
			"log_level":            "info",
			"osquery_interval":      60,
			"max_query_results":     1000,
		},
		UpdatedAt: time.Now(),
	}

	return c.JSON(config)
}

// UpdateClientConfiguration updates client configuration
// TODO: Connect to clients database
func (h *Handler) UpdateClientConfiguration(c *fiber.Ctx) error {
	clientID := c.Params("id")

	var config map[string]interface{}
	if err := c.BodyParser(&config); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Invalid request body",
			"message": err.Error(),
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
// TODO: Connect to clients database
func (h *Handler) GetClientCheckIns(c *fiber.Ctx) error {
	clientID := c.Params("id")
	limit := c.QueryInt("limit", 50)

	// Sample check-ins
	checkIns := make([]CheckIn, 0, limit)
	now := time.Now()
	for i := 0; i < limit && i < 10; i++ {
		checkIns = append(checkIns, CheckIn{
			ID:        uuid.New().String(),
			ClientID:  clientID,
			Timestamp: now.Add(-time.Duration(i*5) * time.Minute),
			IPAddress: "192.168.1.100",
			Status:    "success",
			Metadata: map[string]interface{}{
				"agent_version": "1.0.0",
				"uptime_seconds": 86400 + (i * 300),
			},
		})
	}

	return c.JSON(fiber.Map{
		"check_ins": checkIns,
		"client_id": clientID,
		"total":     len(checkIns),
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
	if req.OSQueryResults != nil && len(req.OSQueryResults) > 0 && h.dbPools.OSQuery != nil {
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
