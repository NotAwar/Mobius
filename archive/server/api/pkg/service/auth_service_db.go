package service

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/MobiusDM/mobius/server/api/api"
	"github.com/MobiusDM/mobius/server/api/pkg/auth"
)

// AuthServiceDB implements AuthService with database persistence
type AuthServiceDB struct {
	db         *sqlx.DB
	jwtManager *auth.JWTManager
}

// NewAuthServiceDB creates a new database-backed auth service
func NewAuthServiceDB(db *sqlx.DB, jwtManager *auth.JWTManager) *AuthServiceDB {
	return &AuthServiceDB{
		db:         db,
		jwtManager: jwtManager,
	}
}

// Login authenticates a user and returns a token
func (s *AuthServiceDB) Login(email, password string) (*api.AuthResponse, error) {
	// Query user by email
	var user struct {
		ID           string    `db:"id"`
		Email        string    `db:"email"`
		Name         string    `db:"name"`
		PasswordHash string    `db:"password_hash"`
		Role         string    `db:"role"`
		IsActive     bool      `db:"is_active"`
		CreatedAt    time.Time `db:"created_at"`
		UpdatedAt    time.Time `db:"updated_at"`
	}

	err := s.db.Get(&user, `
		SELECT id, email, name, password_hash, role, is_active, created_at, updated_at
		FROM users
		WHERE email = $1
	`, email)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("invalid credentials")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query user: %w", err)
	}

	// Check if user is active
	if !user.IsActive {
		return nil, fmt.Errorf("user account is disabled")
	}

	// Verify password
	if err := auth.VerifyPassword(password, user.PasswordHash); err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	// Generate JWT tokens
	accessToken, accessExpiry, err := s.jwtManager.GenerateAccessToken(user.ID, user.Email, user.Role)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Store token in database for revocation tracking
	tokenID := uuid.New().String()
	tokenHash := auth.HashToken(accessToken)

	_, err = s.db.Exec(`
		INSERT INTO auth_tokens (id, user_id, token_hash, expires_at)
		VALUES ($1, $2, $3, $4)
	`, tokenID, user.ID, tokenHash, accessExpiry)

	if err != nil {
		return nil, fmt.Errorf("failed to store token: %w", err)
	}

	// Update last login time
	_, err = s.db.Exec(`
		UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1
	`, user.ID)

	if err != nil {
		// Log but don't fail
		fmt.Printf("Warning: failed to update last_login: %v\n", err)
	}

	// Return auth response
	return &api.AuthResponse{
		Token:     accessToken,
		ExpiresAt: accessExpiry,
		User: &api.User{
			ID:        user.ID,
			Email:     user.Email,
			Name:      user.Name,
			Role:      user.Role,
			CreatedAt: user.CreatedAt,
			UpdatedAt: user.UpdatedAt,
		},
	}, nil
}

// ValidateToken validates a user token
func (s *AuthServiceDB) ValidateToken(token string) (*api.User, error) {
	// Validate JWT token
	claims, err := s.jwtManager.ValidateToken(token)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	// Check if token is revoked
	tokenHash := auth.HashToken(token)
	var isRevoked bool
	err = s.db.Get(&isRevoked, `
		SELECT is_revoked 
		FROM auth_tokens 
		WHERE token_hash = $1
	`, tokenHash)

	if err == sql.ErrNoRows {
		// Token not found in database (might be old format or deleted)
		// Validate based on JWT claims only
	} else if err != nil {
		return nil, fmt.Errorf("failed to check token revocation: %w", err)
	} else if isRevoked {
		return nil, fmt.Errorf("token has been revoked")
	}

	// Get user details
	var user struct {
		ID        string    `db:"id"`
		Email     string    `db:"email"`
		Name      string    `db:"name"`
		Role      string    `db:"role"`
		IsActive  bool      `db:"is_active"`
		CreatedAt time.Time `db:"created_at"`
		UpdatedAt time.Time `db:"updated_at"`
	}

	err = s.db.Get(&user, `
		SELECT id, email, name, role, is_active, created_at, updated_at
		FROM users
		WHERE id = $1
	`, claims.UserID)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("user not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	if !user.IsActive {
		return nil, fmt.Errorf("user account is disabled")
	}

	return &api.User{
		ID:        user.ID,
		Email:     user.Email,
		Name:      user.Name,
		Role:      user.Role,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}, nil
}

// ValidateDeviceToken validates a device token
func (s *AuthServiceDB) ValidateDeviceToken(token string) (*api.Device, error) {
	tokenHash := auth.HashToken(token)

	// Query device token
	var deviceID string
	err := s.db.Get(&deviceID, `
		SELECT device_id
		FROM device_tokens
		WHERE token_hash = $1 AND is_revoked = 0
		  AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
	`, tokenHash)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("invalid device token")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to validate device token: %w", err)
	}

	// Get device details
	var device struct {
		ID         string    `db:"id"`
		UUID       string    `db:"uuid"`
		Hostname   string    `db:"hostname"`
		Platform   string    `db:"platform"`
		OSVersion  string    `db:"os_version"`
		Status     string    `db:"status"`
		EnrolledAt time.Time `db:"enrolled_at"`
		LastSeen   time.Time `db:"last_seen"`
	}

	err = s.db.Get(&device, `
		SELECT id, uuid, hostname, platform, os_version, status, enrolled_at, last_seen
		FROM devices
		WHERE id = $1 AND deleted_at IS NULL
	`, deviceID)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("device not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get device: %w", err)
	}

	// Update last seen
	_, err = s.db.Exec("UPDATE devices SET last_seen = CURRENT_TIMESTAMP WHERE id = $1", deviceID)
	if err != nil {
		fmt.Printf("Warning: failed to update device last_seen: %v\n", err)
	}

	return &api.Device{
		ID:         device.ID,
		UUID:       device.UUID,
		Hostname:   device.Hostname,
		Platform:   device.Platform,
		OSVersion:  device.OSVersion,
		Status:     device.Status,
		EnrolledAt: device.EnrolledAt,
		LastSeen:   device.LastSeen,
	}, nil
}

// RevokeToken revokes a user token
func (s *AuthServiceDB) RevokeToken(token string) error {
	tokenHash := auth.HashToken(token)

	result, err := s.db.Exec(`
		UPDATE auth_tokens
		SET is_revoked = 1, revoked_at = CURRENT_TIMESTAMP
		WHERE token_hash = $1 AND is_revoked = 0
	`, tokenHash)

	if err != nil {
		return fmt.Errorf("failed to revoke token: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("token not found or already revoked")
	}

	return nil
}

// CreateUser creates a new user
func (s *AuthServiceDB) CreateUser(email, password, name, role string) (*api.User, error) {
	// Hash password
	passwordHash, err := auth.HashPassword(password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Generate user ID
	userID := uuid.New().String()
	now := time.Now()

	// Insert user
	_, err = s.db.Exec(`
		INSERT INTO users (id, email, name, password_hash, role, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, userID, email, name, passwordHash, role, now, now)

	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return &api.User{
		ID:        userID,
		Email:     email,
		Name:      name,
		Role:      role,
		CreatedAt: now,
		UpdatedAt: now,
	}, nil
}

// CleanupExpiredTokens removes expired tokens from the database
func (s *AuthServiceDB) CleanupExpiredTokens() error {
	// Delete tokens that expired more than 24 hours ago
	cutoff := time.Now().Add(-24 * time.Hour)

	result, err := s.db.Exec(`
		DELETE FROM auth_tokens
		WHERE expires_at < $1
	`, cutoff)

	if err != nil {
		return fmt.Errorf("failed to cleanup expired tokens: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err == nil && rowsAffected > 0 {
		fmt.Printf("Cleaned up %d expired tokens\n", rowsAffected)
	}

	return nil
}
