package service

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/MobiusDM/mobius/server/api/api"
)

// DeviceServiceDB implements DeviceService with database persistence
type DeviceServiceDB struct {
	db         *sqlx.DB
	wsNotifier WebSocketNotifier
}

// NewDeviceServiceDB creates a new database-backed device service
func NewDeviceServiceDB(db *sqlx.DB) *DeviceServiceDB {
	return &DeviceServiceDB{
		db:         db,
		wsNotifier: &NoOpWebSocketNotifier{},
	}
}

// SetWebSocketNotifier sets the WebSocket notifier
func (s *DeviceServiceDB) SetWebSocketNotifier(notifier WebSocketNotifier) {
	s.wsNotifier = notifier
}

// deviceRow represents a device row from the database
type deviceRow struct {
	ID               string         `db:"id"`
	UUID             string         `db:"uuid"`
	Hostname         string         `db:"hostname"`
	Platform         string         `db:"platform"`
	OSVersion        string         `db:"os_version"`
	SerialNumber     sql.NullString `db:"serial_number"`
	HardwareInfo     sql.NullString `db:"hardware_info"`
	Labels           sql.NullString `db:"labels"`
	EnrollmentSecret string         `db:"enrollment_secret"`
	Status           string         `db:"status"`
	EnrolledAt       time.Time      `db:"enrolled_at"`
	LastSeen         time.Time      `db:"last_seen"`
	DeletedAt        sql.NullTime   `db:"deleted_at"`
	CreatedAt        time.Time      `db:"created_at"`
	UpdatedAt        time.Time      `db:"updated_at"`
}

// toAPIDevice converts a database row to API device struct
func (dr *deviceRow) toAPIDevice() (*api.Device, error) {
	device := &api.Device{
		ID:         dr.ID,
		UUID:       dr.UUID,
		Hostname:   dr.Hostname,
		Platform:   dr.Platform,
		OSVersion:  dr.OSVersion,
		LastSeen:   dr.LastSeen,
		Status:     dr.Status,
		EnrolledAt: dr.EnrolledAt,
	}

	// Parse labels JSON if present
	if dr.Labels.Valid && dr.Labels.String != "" {
		if err := json.Unmarshal([]byte(dr.Labels.String), &device.Labels); err != nil {
			return nil, fmt.Errorf("failed to parse device labels: %w", err)
		}
	}

	return device, nil
}

// ListDevices returns a filtered list of devices with pagination
func (s *DeviceServiceDB) ListDevices(filters api.DeviceFilters) ([]*api.Device, int, error) {
	// Build query with filters
	query := `SELECT id, uuid, hostname, platform, os_version, serial_number, 
	                 hardware_info, labels, enrollment_secret, status, enrolled_at, 
	                 last_seen, deleted_at, created_at, updated_at 
	          FROM devices WHERE deleted_at IS NULL`

	args := []interface{}{}
	argPos := 1

	if filters.Platform != "" {
		query += fmt.Sprintf(" AND platform = $%d", argPos)
		args = append(args, filters.Platform)
		argPos++
	}

	if filters.Status != "" {
		query += fmt.Sprintf(" AND status = $%d", argPos)
		args = append(args, filters.Status)
		argPos++
	}

	if filters.Search != "" {
		query += fmt.Sprintf(" AND (hostname LIKE $%d OR uuid LIKE $%d)", argPos, argPos)
		searchPattern := "%" + filters.Search + "%"
		args = append(args, searchPattern)
		argPos++
	}

	// Get total count
	countQuery := strings.Replace(query,
		"SELECT id, uuid, hostname, platform, os_version, serial_number, hardware_info, labels, enrollment_secret, status, enrolled_at, last_seen, deleted_at, created_at, updated_at",
		"SELECT COUNT(*)", 1)

	var total int
	if err := s.db.Get(&total, countQuery, args...); err != nil {
		return nil, 0, fmt.Errorf("failed to count devices: %w", err)
	}

	// Add ordering and pagination
	query += " ORDER BY enrolled_at DESC"
	if filters.Limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d OFFSET $%d", argPos, argPos+1)
		args = append(args, filters.Limit, filters.Offset)
	}

	// Execute query
	var rows []deviceRow
	if err := s.db.Select(&rows, query, args...); err != nil {
		return nil, 0, fmt.Errorf("failed to query devices: %w", err)
	}

	// Convert to API devices
	devices := make([]*api.Device, 0, len(rows))
	for _, row := range rows {
		device, err := row.toAPIDevice()
		if err != nil {
			return nil, 0, err
		}
		devices = append(devices, device)
	}

	return devices, total, nil
}

// GetDevice returns a device by ID
func (s *DeviceServiceDB) GetDevice(id string) (*api.Device, error) {
	var row deviceRow
	err := s.db.Get(&row, `
		SELECT id, uuid, hostname, platform, os_version, serial_number, 
		       hardware_info, labels, enrollment_secret, status, enrolled_at, 
		       last_seen, deleted_at, created_at, updated_at 
		FROM devices 
		WHERE id = $1 AND deleted_at IS NULL
	`, id)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("device not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get device: %w", err)
	}

	return row.toAPIDevice()
}

// EnrollDevice enrolls a new device
func (s *DeviceServiceDB) EnrollDevice(enrollment api.DeviceEnrollment) (*api.Device, error) {
	// Validate enrollment secret (should be checked against server configuration)
	// For now, accept any non-empty secret
	if enrollment.EnrollmentSecret == "" {
		return nil, fmt.Errorf("enrollment secret is required")
	}

	// Generate device ID
	deviceID := uuid.New().String()
	now := time.Now()

	// Serialize labels as JSON
	var labelsJSON sql.NullString
	if enrollment.HardwareInfo != nil {
		labelsBytes, err := json.Marshal(enrollment.HardwareInfo)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize hardware info: %w", err)
		}
		labelsJSON = sql.NullString{String: string(labelsBytes), Valid: true}
	}

	// Insert device
	_, err := s.db.Exec(`
		INSERT INTO devices (
			id, uuid, hostname, platform, os_version, serial_number,
			hardware_info, enrollment_secret, status, enrolled_at, last_seen
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`, deviceID, enrollment.UUID, enrollment.Hostname, enrollment.Platform,
		enrollment.OSVersion, enrollment.SerialNumber, labelsJSON,
		enrollment.EnrollmentSecret, "online", now, now)

	if err != nil {
		return nil, fmt.Errorf("failed to enroll device: %w", err)
	}

	// Fetch the created device
	device, err := s.GetDevice(deviceID)
	if err != nil {
		return nil, err
	}

	// Notify via WebSocket
	s.wsNotifier.BroadcastDeviceStatusChange(deviceID, "", "online")

	return device, nil
}

// UpdateDevice updates a device
func (s *DeviceServiceDB) UpdateDevice(id string, updates api.DeviceUpdates) (*api.Device, error) {
	// Start transaction
	tx, err := s.db.Beginx()
	if err != nil {
		return nil, fmt.Errorf("failed to start transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Check if device exists
	var exists bool
	err = tx.Get(&exists, "SELECT EXISTS(SELECT 1 FROM devices WHERE id = $1 AND deleted_at IS NULL)", id)
	if err != nil {
		return nil, fmt.Errorf("failed to check device existence: %w", err)
	}
	if !exists {
		return nil, fmt.Errorf("device not found")
	}

	// Build update query dynamically
	updateParts := []string{}
	args := []interface{}{}
	argPos := 1

	if updates.Hostname != nil {
		updateParts = append(updateParts, fmt.Sprintf("hostname = $%d", argPos))
		args = append(args, *updates.Hostname)
		argPos++
	}

	if updates.OSVersion != nil {
		updateParts = append(updateParts, fmt.Sprintf("os_version = $%d", argPos))
		args = append(args, *updates.OSVersion)
		argPos++
	}

	if updates.Labels != nil {
		labelsJSON, err := json.Marshal(*updates.Labels)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize labels: %w", err)
		}
		updateParts = append(updateParts, fmt.Sprintf("labels = $%d", argPos))
		args = append(args, string(labelsJSON))
		argPos++
	}

	if len(updateParts) == 0 {
		return nil, fmt.Errorf("no fields to update")
	}

	// Add device ID to args
	args = append(args, id)

	// Execute update
	query := fmt.Sprintf("UPDATE devices SET %s WHERE id = $%d",
		strings.Join(updateParts, ", "), argPos)

	_, err = tx.Exec(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to update device: %w", err)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	// Fetch updated device
	return s.GetDevice(id)
}

// DeleteDevice soft-deletes a device
func (s *DeviceServiceDB) DeleteDevice(id string) error {
	result, err := s.db.Exec(`
		UPDATE devices 
		SET deleted_at = CURRENT_TIMESTAMP 
		WHERE id = $1 AND deleted_at IS NULL
	`, id)

	if err != nil {
		return fmt.Errorf("failed to delete device: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("device not found")
	}

	// Notify via WebSocket
	s.wsNotifier.BroadcastDeviceStatusChange(id, "online", "offline")

	return nil
}

// ExecuteCommand queues a command for a device
func (s *DeviceServiceDB) ExecuteCommand(deviceID, command string, parameters map[string]interface{}) (*api.DeviceCommandResult, error) {
	// Verify device exists and is online
	device, err := s.GetDevice(deviceID)
	if err != nil {
		return nil, err
	}

	if device.Status != "online" {
		return nil, fmt.Errorf("device is not online")
	}

	// Generate command ID
	commandID := uuid.New().String()
	now := time.Now()

	// Get default timeout from config (5 minutes)
	timeoutMinutes := 5
	expiresAt := now.Add(time.Duration(timeoutMinutes) * time.Minute)

	// Serialize parameters
	var paramsJSON sql.NullString
	if parameters != nil {
		paramsBytes, err := json.Marshal(parameters)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize parameters: %w", err)
		}
		paramsJSON = sql.NullString{String: string(paramsBytes), Valid: true}
	}

	// Insert command
	_, err = s.db.Exec(`
		INSERT INTO device_commands (
			id, device_id, command, parameters, status, timeout_minutes, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, commandID, deviceID, command, paramsJSON, "pending", timeoutMinutes, expiresAt)

	if err != nil {
		return nil, fmt.Errorf("failed to queue command: %w", err)
	}

	// Notify via WebSocket
	s.wsNotifier.BroadcastCommandExecution(commandID, deviceID, command, "pending", "")

	// Update device last seen
	_, err = s.db.Exec("UPDATE devices SET last_seen = CURRENT_TIMESTAMP WHERE id = $1", deviceID)
	if err != nil {
		// Log error but don't fail
		fmt.Printf("Warning: failed to update device last_seen: %v\n", err)
	}

	// Return command result
	return &api.DeviceCommandResult{
		ID:      commandID,
		Command: command,
		Status:  "pending",
	}, nil
}

// ExecuteOSQuery executes an OSQuery on a device
func (s *DeviceServiceDB) ExecuteOSQuery(deviceID, query string) (*api.OSQueryResult, error) {
	device, err := s.GetDevice(deviceID)
	if err != nil {
		return nil, err
	}

	if device.Status != "online" {
		return nil, fmt.Errorf("device is not online")
	}

	// Queue the OSQuery as a command
	// In a real implementation, the device client would execute this and report results
	// For now, we'll store the query and return a pending status

	startTime := time.Now()

	// Store query execution request
	_, err = s.db.Exec(`
		INSERT INTO osquery_results (device_id, query, columns, rows, duration_ms)
		VALUES ($1, $2, $3, $4, $5)
	`, deviceID, query, "[]", "[]", 0)

	if err != nil {
		return nil, fmt.Errorf("failed to store osquery request: %w", err)
	}

	duration := time.Since(startTime).Milliseconds()

	// Update device last seen
	_, err = s.db.Exec("UPDATE devices SET last_seen = CURRENT_TIMESTAMP WHERE id = $1", deviceID)
	if err != nil {
		fmt.Printf("Warning: failed to update device last_seen: %v\n", err)
	}

	return &api.OSQueryResult{
		Query:    query,
		Columns:  []string{},
		Rows:     []map[string]interface{}{},
		Duration: duration,
	}, nil
}
