package service

import (
	"crypto/sha256"
	"database/sql"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/MobiusDM/mobius/server/api/api"
)

// ApplicationServiceDB implements ApplicationService with database persistence
type ApplicationServiceDB struct {
	db *sqlx.DB
}

// NewApplicationServiceDB creates a new database-backed application service
func NewApplicationServiceDB(db *sqlx.DB) *ApplicationServiceDB {
	return &ApplicationServiceDB{
		db: db,
	}
}

// applicationRow represents an application row from the database
type applicationRow struct {
	ID          string    `db:"id"`
	Name        string    `db:"name"`
	Version     string    `db:"version"`
	Platform    string    `db:"platform"`
	Size        int64     `db:"size"`
	Checksum    string    `db:"checksum"`
	PackageData []byte    `db:"package_data"`
	CreatedAt   time.Time `db:"created_at"`
	UpdatedAt   time.Time `db:"updated_at"`
}

// toAPIApplication converts a database application row to an API Application
func (r *applicationRow) toAPIApplication() *api.Application {
	return &api.Application{
		ID:        r.ID,
		Name:      r.Name,
		Version:   r.Version,
		Platform:  r.Platform,
		Size:      r.Size,
		Checksum:  r.Checksum,
		CreatedAt: r.CreatedAt,
	}
}

// ListApplications returns all applications
func (s *ApplicationServiceDB) ListApplications() ([]*api.Application, error) {
	query := `
		SELECT id, name, version, platform, size, checksum, created_at, updated_at
		FROM applications
		WHERE deleted_at IS NULL
		ORDER BY name, version DESC
	`

	var rows []applicationRow
	if err := s.db.Select(&rows, query); err != nil {
		return nil, fmt.Errorf("failed to list applications: %w", err)
	}

	applications := make([]*api.Application, 0, len(rows))
	for _, row := range rows {
		applications = append(applications, row.toAPIApplication())
	}

	return applications, nil
}

// GetApplication returns an application by ID
func (s *ApplicationServiceDB) GetApplication(id string) (*api.Application, error) {
	query := `
		SELECT id, name, version, platform, size, checksum, created_at, updated_at
		FROM applications
		WHERE id = ? AND deleted_at IS NULL
	`

	var row applicationRow
	if err := s.db.Get(&row, query, id); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("application not found")
		}
		return nil, fmt.Errorf("failed to get application: %w", err)
	}

	return row.toAPIApplication(), nil
}

// GetApplicationPackage returns the binary package data for an application
func (s *ApplicationServiceDB) GetApplicationPackage(id string) ([]byte, error) {
	query := `
		SELECT package_data
		FROM applications
		WHERE id = ? AND deleted_at IS NULL
	`

	var packageData []byte
	if err := s.db.Get(&packageData, query, id); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("application not found")
		}
		return nil, fmt.Errorf("failed to get application package: %w", err)
	}

	return packageData, nil
}

// AddApplication adds a new application with binary package
func (s *ApplicationServiceDB) AddApplication(appCreate api.ApplicationCreate) (*api.Application, error) {
	// Calculate checksum
	checksum := fmt.Sprintf("%x", sha256.Sum256(appCreate.Package))

	// Generate ID
	id := generateID()
	now := time.Now()

	query := `
		INSERT INTO applications (id, name, version, platform, size, checksum, package_data, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := s.db.Exec(query, id, appCreate.Name, appCreate.Version, appCreate.Platform,
		int64(len(appCreate.Package)), checksum, appCreate.Package, now, now)
	if err != nil {
		return nil, fmt.Errorf("failed to add application: %w", err)
	}

	// Return the created application (without package data)
	return s.GetApplication(id)
}

// UpdateApplication updates an existing application
func (s *ApplicationServiceDB) UpdateApplication(id string, updates api.ApplicationUpdate) (*api.Application, error) {
	// Start transaction for atomic update
	tx, err := s.db.Beginx()
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Build dynamic update query
	query := "UPDATE applications SET updated_at = ?"
	args := []interface{}{time.Now()}

	if updates.Name != nil {
		query += ", name = ?"
		args = append(args, *updates.Name)
	}
	if updates.Version != nil {
		query += ", version = ?"
		args = append(args, *updates.Version)
	}

	query += " WHERE id = ? AND deleted_at IS NULL"
	args = append(args, id)

	result, err := tx.Exec(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to update application: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return nil, fmt.Errorf("application not found")
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	// Return the updated application
	return s.GetApplication(id)
}

// DeleteApplication deletes an application (soft delete)
func (s *ApplicationServiceDB) DeleteApplication(id string) error {
	query := `
		UPDATE applications 
		SET deleted_at = ?
		WHERE id = ? AND deleted_at IS NULL
	`

	result, err := s.db.Exec(query, time.Now(), id)
	if err != nil {
		return fmt.Errorf("failed to delete application: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("application not found")
	}

	return nil
}

// AssignApplicationToDevice assigns an application to a device for installation
func (s *ApplicationServiceDB) AssignApplicationToDevice(appID, deviceID string) error {
	// Verify application exists
	var appExists bool
	err := s.db.Get(&appExists, "SELECT EXISTS(SELECT 1 FROM applications WHERE id = ? AND deleted_at IS NULL)", appID)
	if err != nil {
		return fmt.Errorf("failed to check application existence: %w", err)
	}
	if !appExists {
		return fmt.Errorf("application not found")
	}

	// Verify device exists
	var deviceExists bool
	err = s.db.Get(&deviceExists, "SELECT EXISTS(SELECT 1 FROM devices WHERE id = ? AND deleted_at IS NULL)", deviceID)
	if err != nil {
		return fmt.Errorf("failed to check device existence: %w", err)
	}
	if !deviceExists {
		return fmt.Errorf("device not found")
	}

	// Check if already assigned
	var alreadyAssigned bool
	err = s.db.Get(&alreadyAssigned, `
		SELECT EXISTS(
			SELECT 1 FROM app_assignments 
			WHERE application_id = ? AND device_id = ? AND unassigned_at IS NULL
		)
	`, appID, deviceID)
	if err != nil {
		return fmt.Errorf("failed to check existing assignment: %w", err)
	}
	if alreadyAssigned {
		return fmt.Errorf("application already assigned to device")
	}

	// Create assignment
	query := `
		INSERT INTO app_assignments (application_id, device_id, group_id, status, assigned_at)
		VALUES (?, ?, NULL, 'pending', ?)
	`

	_, err = s.db.Exec(query, appID, deviceID, time.Now())
	if err != nil {
		return fmt.Errorf("failed to assign application: %w", err)
	}

	return nil
}

// UnassignApplicationFromDevice removes an application assignment from a device
func (s *ApplicationServiceDB) UnassignApplicationFromDevice(appID, deviceID string) error {
	query := `
		UPDATE app_assignments
		SET unassigned_at = ?
		WHERE application_id = ? AND device_id = ? AND unassigned_at IS NULL
	`

	result, err := s.db.Exec(query, time.Now(), appID, deviceID)
	if err != nil {
		return fmt.Errorf("failed to unassign application: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("application not assigned to device")
	}

	return nil
}

// AssignApplicationToGroup assigns an application to a device group
func (s *ApplicationServiceDB) AssignApplicationToGroup(appID, groupID string) error {
	// Verify application exists
	var appExists bool
	err := s.db.Get(&appExists, "SELECT EXISTS(SELECT 1 FROM applications WHERE id = ? AND deleted_at IS NULL)", appID)
	if err != nil {
		return fmt.Errorf("failed to check application existence: %w", err)
	}
	if !appExists {
		return fmt.Errorf("application not found")
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
			SELECT 1 FROM app_assignments 
			WHERE application_id = ? AND group_id = ? AND unassigned_at IS NULL
		)
	`, appID, groupID)
	if err != nil {
		return fmt.Errorf("failed to check existing assignment: %w", err)
	}
	if alreadyAssigned {
		return fmt.Errorf("application already assigned to group")
	}

	// Create assignment
	query := `
		INSERT INTO app_assignments (application_id, device_id, group_id, status, assigned_at)
		VALUES (?, NULL, ?, 'pending', ?)
	`

	_, err = s.db.Exec(query, appID, groupID, time.Now())
	if err != nil {
		return fmt.Errorf("failed to assign application to group: %w", err)
	}

	return nil
}

// UnassignApplicationFromGroup removes an application assignment from a group
func (s *ApplicationServiceDB) UnassignApplicationFromGroup(appID, groupID string) error {
	query := `
		UPDATE app_assignments
		SET unassigned_at = ?
		WHERE application_id = ? AND group_id = ? AND unassigned_at IS NULL
	`

	result, err := s.db.Exec(query, time.Now(), appID, groupID)
	if err != nil {
		return fmt.Errorf("failed to unassign application from group: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("application not assigned to group")
	}

	return nil
}

// GetDeviceApplications returns all applications assigned to a device
func (s *ApplicationServiceDB) GetDeviceApplications(deviceID string) ([]*api.Application, error) {
	query := `
		SELECT DISTINCT a.id, a.name, a.version, a.platform, a.size, a.checksum, a.created_at, a.updated_at
		FROM applications a
		INNER JOIN app_assignments aa ON a.id = aa.application_id
		WHERE (aa.device_id = ? OR aa.group_id IN (
			SELECT group_id FROM group_memberships 
			WHERE device_id = ? AND removed_at IS NULL
		))
		AND a.deleted_at IS NULL
		AND aa.unassigned_at IS NULL
		ORDER BY a.name, a.version DESC
	`

	var rows []applicationRow
	if err := s.db.Select(&rows, query, deviceID, deviceID); err != nil {
		return nil, fmt.Errorf("failed to get device applications: %w", err)
	}

	applications := make([]*api.Application, 0, len(rows))
	for _, row := range rows {
		applications = append(applications, row.toAPIApplication())
	}

	return applications, nil
}

// GetApplicationInstallationStatus returns the installation status for an application on a device
func (s *ApplicationServiceDB) GetApplicationInstallationStatus(appID, deviceID string) (string, error) {
	query := `
		SELECT status
		FROM app_assignments
		WHERE application_id = ? AND device_id = ? AND unassigned_at IS NULL
		ORDER BY assigned_at DESC
		LIMIT 1
	`

	var status string
	if err := s.db.Get(&status, query, appID, deviceID); err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("application not assigned to device")
		}
		return "", fmt.Errorf("failed to get installation status: %w", err)
	}

	return status, nil
}

// UpdateApplicationInstallationStatus updates the installation status for an application on a device
func (s *ApplicationServiceDB) UpdateApplicationInstallationStatus(appID, deviceID, status string) error {
	// Valid statuses: pending, downloading, installing, installed, failed
	validStatuses := map[string]bool{
		"pending":     true,
		"downloading": true,
		"installing":  true,
		"installed":   true,
		"failed":      true,
	}

	if !validStatuses[status] {
		return fmt.Errorf("invalid status: %s", status)
	}

	query := `
		UPDATE app_assignments
		SET status = ?, updated_at = ?
		WHERE application_id = ? AND device_id = ? AND unassigned_at IS NULL
	`

	result, err := s.db.Exec(query, status, time.Now(), appID, deviceID)
	if err != nil {
		return fmt.Errorf("failed to update installation status: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("application not assigned to device")
	}

	return nil
}
