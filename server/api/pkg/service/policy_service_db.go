package service

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/MobiusDM/mobius/server/api/api"
)

// PolicyServiceDB implements PolicyService with database persistence
type PolicyServiceDB struct {
	db         *sqlx.DB
	wsNotifier WebSocketNotifier
}

// NewPolicyServiceDB creates a new database-backed policy service
func NewPolicyServiceDB(db *sqlx.DB) *PolicyServiceDB {
	return &PolicyServiceDB{
		db:         db,
		wsNotifier: &NoOpWebSocketNotifier{}, // Default to no-op
	}
}

// SetWebSocketNotifier sets the WebSocket notifier
func (s *PolicyServiceDB) SetWebSocketNotifier(notifier WebSocketNotifier) {
	s.wsNotifier = notifier
}

// policyRow represents a policy row from the database
type policyRow struct {
	ID                string         `db:"id"`
	Name              string         `db:"name"`
	Description       sql.NullString `db:"description"`
	Platform          string         `db:"platform"`
	Enabled           bool           `db:"enabled"`
	ConfigurationJSON string         `db:"configuration"`
	CreatedAt         time.Time      `db:"created_at"`
	UpdatedAt         time.Time      `db:"updated_at"`
}

// deviceGroupRow represents a device group row from the database
type deviceGroupRow struct {
	ID          string         `db:"id"`
	Name        string         `db:"name"`
	Description sql.NullString `db:"description"`
	Filters     sql.NullString `db:"filters"`
	Labels      sql.NullString `db:"labels"`
	DeviceCount int            `db:"device_count"`
	CreatedAt   time.Time      `db:"created_at"`
	UpdatedAt   time.Time      `db:"updated_at"`
}

// toAPIDeviceGroup converts a database group row to an API DeviceGroup
func (r *deviceGroupRow) toAPIDeviceGroup() (*api.DeviceGroup, error) {
	group := &api.DeviceGroup{
		ID:          r.ID,
		Name:        r.Name,
		Description: r.Description.String,
		DeviceCount: r.DeviceCount,
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
	}

	// Parse filters JSON if present
	if r.Filters.Valid && r.Filters.String != "" {
		var filters map[string]string
		if err := json.Unmarshal([]byte(r.Filters.String), &filters); err != nil {
			return nil, fmt.Errorf("failed to unmarshal filters: %w", err)
		}
		group.Filters = filters
	}

	// Parse labels JSON if present
	if r.Labels.Valid && r.Labels.String != "" {
		var labels map[string]string
		if err := json.Unmarshal([]byte(r.Labels.String), &labels); err != nil {
			return nil, fmt.Errorf("failed to unmarshal labels: %w", err)
		}
		group.Labels = labels
	}

	return group, nil
}

// toAPIPolicy converts a database policy row to an API Policy
func (r *policyRow) toAPIPolicy() (*api.Policy, error) {
	var configuration map[string]interface{}
	if err := json.Unmarshal([]byte(r.ConfigurationJSON), &configuration); err != nil {
		return nil, fmt.Errorf("failed to unmarshal configuration: %w", err)
	}

	return &api.Policy{
		ID:            r.ID,
		Name:          r.Name,
		Description:   r.Description.String,
		Platform:      r.Platform,
		Enabled:       r.Enabled,
		Configuration: configuration,
		CreatedAt:     r.CreatedAt,
		UpdatedAt:     r.UpdatedAt,
	}, nil
}

// ListPolicies returns all policies
func (s *PolicyServiceDB) ListPolicies() ([]*api.Policy, error) {
	query := `
		SELECT id, name, description, platform, enabled, configuration, 
		       created_at, updated_at
		FROM policies
		WHERE deleted_at IS NULL
		ORDER BY created_at DESC
	`

	var rows []policyRow
	if err := s.db.Select(&rows, query); err != nil {
		return nil, fmt.Errorf("failed to list policies: %w", err)
	}

	policies := make([]*api.Policy, 0, len(rows))
	for _, row := range rows {
		policy, err := row.toAPIPolicy()
		if err != nil {
			return nil, err
		}
		policies = append(policies, policy)
	}

	return policies, nil
}

// GetPolicy returns a policy by ID
func (s *PolicyServiceDB) GetPolicy(id string) (*api.Policy, error) {
	query := `
		SELECT id, name, description, platform, enabled, configuration,
		       created_at, updated_at
		FROM policies
		WHERE id = ? AND deleted_at IS NULL
	`

	var row policyRow
	if err := s.db.Get(&row, query, id); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("policy not found")
		}
		return nil, fmt.Errorf("failed to get policy: %w", err)
	}

	return row.toAPIPolicy()
}

// CreatePolicy creates a new policy
func (s *PolicyServiceDB) CreatePolicy(policyCreate api.PolicyCreate) (*api.Policy, error) {
	// Marshal configuration to JSON
	configJSON, err := json.Marshal(policyCreate.Configuration)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal configuration: %w", err)
	}

	// Generate ID
	id := generateID()
	now := time.Now()

	query := `
		INSERT INTO policies (id, name, description, platform, enabled, configuration, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err = s.db.Exec(query, id, policyCreate.Name, policyCreate.Description,
		policyCreate.Platform, true, string(configJSON), now, now)
	if err != nil {
		return nil, fmt.Errorf("failed to create policy: %w", err)
	}

	// Return the created policy
	return s.GetPolicy(id)
}

// UpdatePolicy updates an existing policy
func (s *PolicyServiceDB) UpdatePolicy(id string, updates api.PolicyUpdate) (*api.Policy, error) {
	// Start transaction for atomic update
	tx, err := s.db.Beginx()
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Build dynamic update query
	query := "UPDATE policies SET updated_at = ?"
	args := []interface{}{time.Now()}

	if updates.Name != nil {
		query += ", name = ?"
		args = append(args, *updates.Name)
	}
	if updates.Description != nil {
		query += ", description = ?"
		args = append(args, *updates.Description)
	}
	if updates.Enabled != nil {
		query += ", enabled = ?"
		args = append(args, *updates.Enabled)
	}
	if updates.Configuration != nil {
		configJSON, err := json.Marshal(*updates.Configuration)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal configuration: %w", err)
		}
		query += ", configuration = ?"
		args = append(args, string(configJSON))
	}

	query += " WHERE id = ? AND deleted_at IS NULL"
	args = append(args, id)

	result, err := tx.Exec(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to update policy: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return nil, fmt.Errorf("policy not found")
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	// Return the updated policy
	return s.GetPolicy(id)
}

// DeletePolicy deletes a policy (soft delete)
func (s *PolicyServiceDB) DeletePolicy(id string) error {
	// Start transaction to handle cascading operations
	tx, err := s.db.Beginx()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Soft delete the policy
	query := `
		UPDATE policies 
		SET deleted_at = ?
		WHERE id = ? AND deleted_at IS NULL
	`

	result, err := tx.Exec(query, time.Now(), id)
	if err != nil {
		return fmt.Errorf("failed to delete policy: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("policy not found")
	}

	// Remove all policy assignments (cascade handled by database ON DELETE CASCADE)
	// The database will automatically handle cleanup of policy_assignments table

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// GetDevicePolicies returns policies assigned to a device
func (s *PolicyServiceDB) GetDevicePolicies(deviceID string) ([]*api.Policy, error) {
	query := `
		SELECT p.id, p.name, p.description, p.platform, p.enabled, p.configuration,
		       p.created_at, p.updated_at
		FROM policies p
		INNER JOIN policy_assignments pa ON p.id = pa.policy_id
		WHERE pa.device_id = ? 
		  AND p.deleted_at IS NULL
		  AND pa.unassigned_at IS NULL
		ORDER BY pa.assigned_at DESC
	`

	var rows []policyRow
	if err := s.db.Select(&rows, query, deviceID); err != nil {
		return nil, fmt.Errorf("failed to get device policies: %w", err)
	}

	policies := make([]*api.Policy, 0, len(rows))
	for _, row := range rows {
		policy, err := row.toAPIPolicy()
		if err != nil {
			return nil, err
		}
		policies = append(policies, policy)
	}

	return policies, nil
}

// AssignDevicePolicies assigns policies to a device (replaces existing assignments)
func (s *PolicyServiceDB) AssignDevicePolicies(deviceID string, policyIDs []string) error {
	tx, err := s.db.Beginx()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Validate that all policies exist
	for _, policyID := range policyIDs {
		var exists bool
		err := tx.Get(&exists, "SELECT EXISTS(SELECT 1 FROM policies WHERE id = ? AND deleted_at IS NULL)", policyID)
		if err != nil {
			return fmt.Errorf("failed to check policy existence: %w", err)
		}
		if !exists {
			return fmt.Errorf("policy %s not found", policyID)
		}
	}

	// Mark existing assignments as unassigned
	unassignQuery := `
		UPDATE policy_assignments
		SET unassigned_at = ?
		WHERE device_id = ? AND unassigned_at IS NULL
	`
	_, err = tx.Exec(unassignQuery, time.Now(), deviceID)
	if err != nil {
		return fmt.Errorf("failed to unassign existing policies: %w", err)
	}

	// Create new assignments
	now := time.Now()
	assignQuery := `
		INSERT INTO policy_assignments (policy_id, device_id, group_id, assigned_at)
		VALUES (?, ?, NULL, ?)
	`

	for _, policyID := range policyIDs {
		_, err = tx.Exec(assignQuery, policyID, deviceID, now)
		if err != nil {
			return fmt.Errorf("failed to assign policy %s: %w", policyID, err)
		}

		// Notify WebSocket clients
		s.wsNotifier.BroadcastPolicyAssignment(policyID, deviceID, "", "assigned")
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// GetPolicyDevices returns all devices assigned to a policy
func (s *PolicyServiceDB) GetPolicyDevices(policyID string) ([]*api.Device, error) {
	// First verify policy exists
	var exists bool
	err := s.db.Get(&exists, "SELECT EXISTS(SELECT 1 FROM policies WHERE id = ? AND deleted_at IS NULL)", policyID)
	if err != nil {
		return nil, fmt.Errorf("failed to check policy existence: %w", err)
	}
	if !exists {
		return nil, fmt.Errorf("policy not found")
	}

	query := `
		SELECT d.id, d.uuid, d.hostname, d.platform, d.os_version, d.status,
		       d.hardware_info, d.last_seen, d.enrolled_at, d.created_at, d.updated_at
		FROM devices d
		INNER JOIN policy_assignments pa ON d.id = pa.device_id
		WHERE pa.policy_id = ? 
		  AND d.deleted_at IS NULL
		  AND pa.unassigned_at IS NULL
		ORDER BY d.hostname
	`

	var rows []deviceRow
	if err := s.db.Select(&rows, query, policyID); err != nil {
		return nil, fmt.Errorf("failed to get policy devices: %w", err)
	}

	devices := make([]*api.Device, 0, len(rows))
	for _, row := range rows {
		device, err := row.toAPIDevice()
		if err != nil {
			return nil, err
		}
		devices = append(devices, device)
	}

	return devices, nil
}

// AssignPolicyToDevice assigns a single policy to a device
func (s *PolicyServiceDB) AssignPolicyToDevice(policyID, deviceID string) error {
	// Verify policy exists
	var policyExists bool
	err := s.db.Get(&policyExists, "SELECT EXISTS(SELECT 1 FROM policies WHERE id = ? AND deleted_at IS NULL)", policyID)
	if err != nil {
		return fmt.Errorf("failed to check policy existence: %w", err)
	}
	if !policyExists {
		return fmt.Errorf("policy not found")
	}

	// Check if already assigned
	var alreadyAssigned bool
	err = s.db.Get(&alreadyAssigned, `
		SELECT EXISTS(
			SELECT 1 FROM policy_assignments 
			WHERE policy_id = ? AND device_id = ? AND unassigned_at IS NULL
		)
	`, policyID, deviceID)
	if err != nil {
		return fmt.Errorf("failed to check existing assignment: %w", err)
	}
	if alreadyAssigned {
		return fmt.Errorf("policy already assigned to device")
	}

	// Create assignment
	query := `
		INSERT INTO policy_assignments (policy_id, device_id, group_id, assigned_at)
		VALUES (?, ?, NULL, ?)
	`

	_, err = s.db.Exec(query, policyID, deviceID, time.Now())
	if err != nil {
		return fmt.Errorf("failed to assign policy: %w", err)
	}

	// Notify WebSocket clients
	s.wsNotifier.BroadcastPolicyAssignment(policyID, deviceID, "", "assigned")

	return nil
}

// UnassignPolicyFromDevice removes a policy from a device
func (s *PolicyServiceDB) UnassignPolicyFromDevice(policyID, deviceID string) error {
	query := `
		UPDATE policy_assignments
		SET unassigned_at = ?
		WHERE policy_id = ? AND device_id = ? AND unassigned_at IS NULL
	`

	result, err := s.db.Exec(query, time.Now(), policyID, deviceID)
	if err != nil {
		return fmt.Errorf("failed to unassign policy: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("policy not assigned to device")
	}

	// Notify WebSocket clients
	s.wsNotifier.BroadcastPolicyAssignment(policyID, deviceID, "", "unassigned")

	return nil
}

// GetPolicyGroups returns all device groups assigned to a policy
func (s *PolicyServiceDB) GetPolicyGroups(policyID string) ([]*api.DeviceGroup, error) {
	// First verify policy exists
	var exists bool
	err := s.db.Get(&exists, "SELECT EXISTS(SELECT 1 FROM policies WHERE id = ? AND deleted_at IS NULL)", policyID)
	if err != nil {
		return nil, fmt.Errorf("failed to check policy existence: %w", err)
	}
	if !exists {
		return nil, fmt.Errorf("policy not found")
	}

	query := `
		SELECT dg.id, dg.name, dg.description, dg.filters, dg.labels,
		       dg.created_at, dg.updated_at,
		       COUNT(DISTINCT gm.device_id) as device_count
		FROM device_groups dg
		INNER JOIN policy_assignments pa ON dg.id = pa.group_id
		LEFT JOIN group_memberships gm ON dg.id = gm.group_id AND gm.removed_at IS NULL
		WHERE pa.policy_id = ? 
		  AND dg.deleted_at IS NULL
		  AND pa.unassigned_at IS NULL
		GROUP BY dg.id, dg.name, dg.description, dg.filters, dg.labels, dg.created_at, dg.updated_at
		ORDER BY dg.name
	`

	var rows []deviceGroupRow
	if err := s.db.Select(&rows, query, policyID); err != nil {
		return nil, fmt.Errorf("failed to get policy groups: %w", err)
	}

	groups := make([]*api.DeviceGroup, 0, len(rows))
	for _, row := range rows {
		group, err := row.toAPIDeviceGroup()
		if err != nil {
			return nil, err
		}
		groups = append(groups, group)
	}

	return groups, nil
}

// AssignPolicyToGroup assigns a policy to a device group
func (s *PolicyServiceDB) AssignPolicyToGroup(policyID, groupID string) error {
	// Verify policy exists
	var policyExists bool
	err := s.db.Get(&policyExists, "SELECT EXISTS(SELECT 1 FROM policies WHERE id = ? AND deleted_at IS NULL)", policyID)
	if err != nil {
		return fmt.Errorf("failed to check policy existence: %w", err)
	}
	if !policyExists {
		return fmt.Errorf("policy not found")
	}

	// Verify group exists
	var groupExists bool
	err = s.db.Get(&groupExists, "SELECT EXISTS(SELECT 1 FROM device_groups WHERE id = ? AND deleted_at IS NULL)", groupID)
	if err != nil {
		return fmt.Errorf("failed to check group existence: %w", err)
	}
	if !groupExists {
		return fmt.Errorf("device group not found")
	}

	// Check if already assigned
	var alreadyAssigned bool
	err = s.db.Get(&alreadyAssigned, `
		SELECT EXISTS(
			SELECT 1 FROM policy_assignments 
			WHERE policy_id = ? AND group_id = ? AND unassigned_at IS NULL
		)
	`, policyID, groupID)
	if err != nil {
		return fmt.Errorf("failed to check existing assignment: %w", err)
	}
	if alreadyAssigned {
		return fmt.Errorf("policy already assigned to group")
	}

	// Create assignment
	query := `
		INSERT INTO policy_assignments (policy_id, device_id, group_id, assigned_at)
		VALUES (?, NULL, ?, ?)
	`

	_, err = s.db.Exec(query, policyID, groupID, time.Now())
	if err != nil {
		return fmt.Errorf("failed to assign policy to group: %w", err)
	}

	// Notify WebSocket clients
	s.wsNotifier.BroadcastPolicyAssignment(policyID, "", groupID, "assigned")

	return nil
}

// UnassignPolicyFromGroup removes a policy from a device group
func (s *PolicyServiceDB) UnassignPolicyFromGroup(policyID, groupID string) error {
	query := `
		UPDATE policy_assignments
		SET unassigned_at = ?
		WHERE policy_id = ? AND group_id = ? AND unassigned_at IS NULL
	`

	result, err := s.db.Exec(query, time.Now(), policyID, groupID)
	if err != nil {
		return fmt.Errorf("failed to unassign policy from group: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("policy not assigned to group")
	}

	// Notify WebSocket clients
	s.wsNotifier.BroadcastPolicyAssignment(policyID, "", groupID, "unassigned")

	return nil
}
