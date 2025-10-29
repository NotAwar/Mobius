package service

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/notawar/mobius/server/api/api"
)

// LicenseServiceDB implements LicenseService with database persistence
type LicenseServiceDB struct {
	db *sqlx.DB
}

// NewLicenseServiceDB creates a new database-backed license service
func NewLicenseServiceDB(db *sqlx.DB) *LicenseServiceDB {
	return &LicenseServiceDB{
		db: db,
	}
}

// GetLicenseStatus returns the current license status
func (s *LicenseServiceDB) GetLicenseStatus() (*api.License, error) {
	var license struct {
		ID          string       `db:"id"`
		LicenseKey  string       `db:"license_key"`
		Tier        string       `db:"tier"`
		DeviceLimit int          `db:"device_limit"`
		Features    string       `db:"features"`
		IssuedAt    time.Time    `db:"issued_at"`
		ExpiresAt   sql.NullTime `db:"expires_at"`
		IsActive    bool         `db:"is_active"`
	}

	// Get the active license
	err := s.db.Get(&license, `
		SELECT id, license_key, tier, device_limit, features, issued_at, expires_at, is_active
		FROM licenses
		WHERE is_active = 1
		ORDER BY issued_at DESC
		LIMIT 1
	`)

	if err == sql.ErrNoRows {
		// No license found, return default community license
		return &api.License{
			Valid:           true,
			Tier:            "community",
			DeviceLimit:     10,
			DevicesEnrolled: 0,
			ExpiresAt:       nil,
			Features: []string{
				"device_management",
				"basic_policies",
			},
		}, nil
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get license: %w", err)
	}

	// Parse features JSON
	var features []string
	if err := json.Unmarshal([]byte(license.Features), &features); err != nil {
		return nil, fmt.Errorf("failed to parse license features: %w", err)
	}

	// Get enrolled device count
	var deviceCount int
	err = s.db.Get(&deviceCount, "SELECT COUNT(*) FROM devices WHERE deleted_at IS NULL")
	if err != nil {
		return nil, fmt.Errorf("failed to count devices: %w", err)
	}

	// Check if license is valid
	valid := license.IsActive
	if license.ExpiresAt.Valid && license.ExpiresAt.Time.Before(time.Now()) {
		valid = false
	}

	// Prepare expiry time
	var expiresAt *time.Time
	if license.ExpiresAt.Valid {
		expiresAt = &license.ExpiresAt.Time
	}

	return &api.License{
		Valid:           valid,
		Tier:            license.Tier,
		DeviceLimit:     license.DeviceLimit,
		DevicesEnrolled: deviceCount,
		ExpiresAt:       expiresAt,
		Features:        features,
	}, nil
}

// ActivateLicense activates a license key
func (s *LicenseServiceDB) ActivateLicense(key string) error {
	// Validate license key format and determine tier
	// In a real implementation, this would verify with a license server or validate signatures
	tier, deviceLimit, features, expiresAt, err := s.validateLicenseKey(key)
	if err != nil {
		return fmt.Errorf("invalid license key: %w", err)
	}

	// Start transaction
	tx, err := s.db.Beginx()
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Deactivate existing licenses
	_, err = tx.Exec("UPDATE licenses SET is_active = 0 WHERE is_active = 1")
	if err != nil {
		return fmt.Errorf("failed to deactivate existing licenses: %w", err)
	}

	// Serialize features
	featuresJSON, err := json.Marshal(features)
	if err != nil {
		return fmt.Errorf("failed to serialize features: %w", err)
	}

	// Insert new license
	licenseID := uuid.New().String()
	_, err = tx.Exec(`
		INSERT INTO licenses (id, license_key, tier, device_limit, features, expires_at, is_active)
		VALUES ($1, $2, $3, $4, $5, $6, 1)
	`, licenseID, key, tier, deviceLimit, string(featuresJSON), expiresAt)

	if err != nil {
		return fmt.Errorf("failed to insert license: %w", err)
	}

	// Log license activation
	_, err = tx.Exec(`
		INSERT INTO license_audit (license_id, action, details)
		VALUES ($1, 'activated', $2)
	`, licenseID, fmt.Sprintf(`{"tier":"%s","device_limit":%d}`, tier, deviceLimit))

	if err != nil {
		return fmt.Errorf("failed to log license activation: %w", err)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// validateLicenseKey validates a license key and extracts its properties
func (s *LicenseServiceDB) validateLicenseKey(key string) (tier string, deviceLimit int, features []string, expiresAt interface{}, err error) {
	// This is a simplified validation. In production, you would:
	// 1. Verify cryptographic signature
	// 2. Check with license server
	// 3. Validate format and checksum

	switch key {
	case "community-license":
		return "community", 10, []string{"device_management", "basic_policies"}, nil, nil

	case "professional-license":
		expiry := time.Now().AddDate(1, 0, 0) // 1 year from now
		return "professional", 100, []string{
			"device_management",
			"basic_policies",
			"advanced_policies",
			"application_management",
			"osquery",
		}, expiry, nil

	case "enterprise-license":
		expiry := time.Now().AddDate(1, 0, 0) // 1 year from now
		return "enterprise", 10000, []string{
			"device_management",
			"basic_policies",
			"advanced_policies",
			"application_management",
			"osquery",
			"custom_scripts",
			"api_access",
			"webhooks",
			"audit_logs",
		}, expiry, nil

	default:
		return "", 0, nil, nil, fmt.Errorf("unknown license key")
	}
}

// CheckDeviceLimit checks if the device limit has been reached
func (s *LicenseServiceDB) CheckDeviceLimit() (bool, error) {
	license, err := s.GetLicenseStatus()
	if err != nil {
		return false, err
	}

	if !license.Valid {
		return false, fmt.Errorf("license is not valid")
	}

	if license.DevicesEnrolled >= license.DeviceLimit {
		return false, nil
	}

	return true, nil
}

// HasFeature checks if the current license includes a specific feature
func (s *LicenseServiceDB) HasFeature(feature string) (bool, error) {
	license, err := s.GetLicenseStatus()
	if err != nil {
		return false, err
	}

	if !license.Valid {
		return false, nil
	}

	for _, f := range license.Features {
		if f == feature {
			return true, nil
		}
	}

	return false, nil
}
