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

// User represents a user from the app database
type User struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Username  string    `json:"username"`
	FullName  string    `json:"full_name,omitempty"`
	Role      string    `json:"role"`
	Active    bool      `json:"active"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// UserPreferences represents user preferences
type UserPreferences struct {
	UserID         string                 `json:"user_id"`
	Theme          string                 `json:"theme,omitempty"`
	Language       string                 `json:"language,omitempty"`
	Timezone       string                 `json:"timezone,omitempty"`
	Notifications  bool                   `json:"notifications"`
	Settings       map[string]interface{} `json:"settings,omitempty"`
	UpdatedAt      time.Time              `json:"updated_at"`
}

// CreateUserRequest represents the request body for creating a user
type CreateUserRequest struct {
	Email    string `json:"email"`
	Username string `json:"username"`
	FullName string `json:"full_name,omitempty"`
	Role     string `json:"role"`
	Active   bool   `json:"active"`
}

// UpdateUserRequest represents the request body for updating a user
type UpdateUserRequest struct {
	Email    *string `json:"email,omitempty"`
	Username *string `json:"username,omitempty"`
	FullName *string `json:"full_name,omitempty"`
	Role     *string `json:"role,omitempty"`
	Active   *bool   `json:"active,omitempty"`
}

// GetUsers retrieves all users with optional filters
func (h *Handler) GetUsers(c *fiber.Ctx) error {
	// Query parameters
	limit := c.QueryInt("limit", 50)
	offset := c.QueryInt("offset", 0)
	role := c.Query("role", "")
	active := c.Query("active", "")

	// Check if database is available
	if h.dbPools == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"error":   "Database unavailable",
			"message": "Database connection not configured",
		})
	}

	ctx := context.Background()

	// Build query with filters
	query := `
		SELECT id, email, username, 
		       COALESCE(first_name || ' ' || last_name, '') as full_name,
		       role, active, created_at, updated_at
		FROM users
		WHERE 1=1
	`
	args := []interface{}{}
	argCount := 1

	if role != "" {
		query += fmt.Sprintf(" AND role = $%d", argCount)
		args = append(args, role)
		argCount++
	}

	if active != "" {
		activeBool := active == "true"
		query += fmt.Sprintf(" AND active = $%d", argCount)
		args = append(args, activeBool)
		argCount++
	}

	query += " ORDER BY created_at DESC"
	query += fmt.Sprintf(" LIMIT $%d OFFSET $%d", argCount, argCount+1)
	args = append(args, limit, offset)

	// Execute query
	rows, err := h.dbPools.App.Query(ctx, query, args...)
	if err != nil {
		h.logger.Errorf("Failed to query users: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Database error",
			"message": "Failed to retrieve users",
		})
	}
	defer rows.Close()

	users := make([]User, 0)
	for rows.Next() {
		var user User
		if err := rows.Scan(&user.ID, &user.Email, &user.Username, &user.FullName,
			&user.Role, &user.Active, &user.CreatedAt, &user.UpdatedAt); err != nil {
			h.logger.Errorf("Failed to scan user: %v", err)
			continue
		}
		users = append(users, user)
	}

	// Get total count
	countQuery := "SELECT COUNT(*) FROM users WHERE 1=1"
	countArgs := []interface{}{}
	countArgNum := 1
	if role != "" {
		countQuery += fmt.Sprintf(" AND role = $%d", countArgNum)
		countArgs = append(countArgs, role)
		countArgNum++
	}
	if active != "" {
		activeBool := active == "true"
		countQuery += fmt.Sprintf(" AND active = $%d", countArgNum)
		countArgs = append(countArgs, activeBool)
	}

	var total int
	if err := h.dbPools.App.QueryRow(ctx, countQuery, countArgs...).Scan(&total); err != nil {
		h.logger.Errorf("Failed to count users: %v", err)
		total = len(users)
	}

	return c.JSON(fiber.Map{
		"users":  users,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

// GetUser retrieves a specific user by ID
func (h *Handler) GetUser(c *fiber.Ctx) error {
	userID := c.Params("id")

	if h.dbPools == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"error":   "Database unavailable",
			"message": "Database connection not configured",
		})
	}

	ctx := context.Background()

	query := `
		SELECT id, email, username,
		       COALESCE(first_name || ' ' || last_name, '') as full_name,
		       role, active, created_at, updated_at
		FROM users
		WHERE id = $1
	`

	var user User
	err := h.dbPools.App.QueryRow(ctx, query, userID).Scan(
		&user.ID, &user.Email, &user.Username, &user.FullName,
		&user.Role, &user.Active, &user.CreatedAt, &user.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error":   "Not found",
			"message": "User not found",
		})
	}

	if err != nil {
		h.logger.Errorf("Failed to query user: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Database error",
			"message": "Failed to retrieve user",
		})
	}

	return c.JSON(user)
}

// CreateUser creates a new user
func (h *Handler) CreateUser(c *fiber.Ctx) error {
	var req CreateUserRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Invalid request body",
			"message": err.Error(),
		})
	}

	// Validate required fields
	if req.Email == "" || req.Username == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Validation error",
			"message": "Email and username are required",
		})
	}

	if h.dbPools == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"error":   "Database unavailable",
			"message": "Database connection not configured",
		})
	}

	ctx := context.Background()

	// Parse full name into first and last
	firstName := ""
	lastName := ""
	if req.FullName != "" {
		parts := splitFullName(req.FullName)
		if len(parts) > 0 {
			firstName = parts[0]
		}
		if len(parts) > 1 {
			lastName = parts[len(parts)-1]
		}
	}

	// Set default role if not specified
	if req.Role == "" {
		req.Role = "user"
	}

	query := `
		INSERT INTO users (id, email, username, first_name, last_name, role, active)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, email, username,
		          COALESCE(first_name || ' ' || last_name, '') as full_name,
		          role, active, created_at, updated_at
	`

	userID := uuid.New().String()
	var user User
	err := h.dbPools.App.QueryRow(ctx, query,
		userID, req.Email, req.Username, firstName, lastName, req.Role, req.Active,
	).Scan(&user.ID, &user.Email, &user.Username, &user.FullName,
		&user.Role, &user.Active, &user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		h.logger.Errorf("Failed to create user: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Database error",
			"message": "Failed to create user",
		})
	}

	h.logger.Infof("Created user: %s (%s)", user.Username, user.Email)

	return c.Status(fiber.StatusCreated).JSON(user)
}

// UpdateUser updates an existing user
func (h *Handler) UpdateUser(c *fiber.Ctx) error {
	userID := c.Params("id")

	var req UpdateUserRequest
	if err := c.BodyParser(&req); err != nil {
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
	updates := []string{}
	args := []interface{}{}
	argCount := 1

	if req.Email != nil {
		updates = append(updates, fmt.Sprintf("email = $%d", argCount))
		args = append(args, *req.Email)
		argCount++
	}
	if req.Username != nil {
		updates = append(updates, fmt.Sprintf("username = $%d", argCount))
		args = append(args, *req.Username)
		argCount++
	}
	if req.FullName != nil {
		parts := splitFullName(*req.FullName)
		firstName := ""
		lastName := ""
		if len(parts) > 0 {
			firstName = parts[0]
		}
		if len(parts) > 1 {
			lastName = parts[len(parts)-1]
		}
		updates = append(updates, fmt.Sprintf("first_name = $%d, last_name = $%d", argCount, argCount+1))
		args = append(args, firstName, lastName)
		argCount += 2
	}
	if req.Role != nil {
		updates = append(updates, fmt.Sprintf("role = $%d", argCount))
		args = append(args, *req.Role)
		argCount++
	}
	if req.Active != nil {
		updates = append(updates, fmt.Sprintf("active = $%d", argCount))
		args = append(args, *req.Active)
		argCount++
	}

	if len(updates) == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Validation error",
			"message": "No fields to update",
		})
	}

	// Add updated_at
	updates = append(updates, "updated_at = CURRENT_TIMESTAMP")
	args = append(args, userID)

	query := fmt.Sprintf(`
		UPDATE users
		SET %s
		WHERE id = $%d
		RETURNING id, email, username,
		          COALESCE(first_name || ' ' || last_name, '') as full_name,
		          role, active, created_at, updated_at
	`, joinStrings(updates, ", "), argCount)

	var user User
	err := h.dbPools.App.QueryRow(ctx, query, args...).Scan(
		&user.ID, &user.Email, &user.Username, &user.FullName,
		&user.Role, &user.Active, &user.CreatedAt, &user.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error":   "Not found",
			"message": "User not found",
		})
	}

	if err != nil {
		h.logger.Errorf("Failed to update user: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Database error",
			"message": "Failed to update user",
		})
	}

	h.logger.Infof("Updated user: %s", userID)

	return c.JSON(user)
}

// DeleteUser deletes a user
func (h *Handler) DeleteUser(c *fiber.Ctx) error {
	userID := c.Params("id")

	if h.dbPools == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"error":   "Database unavailable",
			"message": "Database connection not configured",
		})
	}

	ctx := context.Background()

	query := "DELETE FROM users WHERE id = $1"
	result, err := h.dbPools.App.Exec(ctx, query, userID)

	if err != nil {
		h.logger.Errorf("Failed to delete user: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Database error",
			"message": "Failed to delete user",
		})
	}

	if result.RowsAffected() == 0 {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error":   "Not found",
			"message": "User not found",
		})
	}

	h.logger.Infof("Deleted user: %s", userID)

	return c.Status(fiber.StatusNoContent).Send(nil)
}

// GetUserPreferences retrieves user preferences
func (h *Handler) GetUserPreferences(c *fiber.Ctx) error {
	userID := c.Params("id")

	if h.dbPools == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"error":   "Database unavailable",
			"message": "Database connection not configured",
		})
	}

	ctx := context.Background()

	query := `
		SELECT user_id, theme, language, timezone, notifications, updated_at
		FROM user_preferences
		WHERE user_id = $1
	`

	var prefs UserPreferences
	err := h.dbPools.App.QueryRow(ctx, query, userID).Scan(
		&prefs.UserID, &prefs.Theme, &prefs.Language, &prefs.Timezone,
		&prefs.Notifications, &prefs.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		// Return default preferences
		prefs = UserPreferences{
			UserID:        userID,
			Theme:         "light",
			Language:      "en",
			Timezone:      "UTC",
			Notifications: true,
			Settings:      make(map[string]interface{}),
			UpdatedAt:     time.Now(),
		}
		return c.JSON(prefs)
	}

	if err != nil {
		h.logger.Errorf("Failed to query user preferences: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Database error",
			"message": "Failed to retrieve user preferences",
		})
	}

	prefs.Settings = make(map[string]interface{})

	return c.JSON(prefs)
}

// UpdateUserPreferences updates user preferences
func (h *Handler) UpdateUserPreferences(c *fiber.Ctx) error {
	userID := c.Params("id")

	var prefs UserPreferences
	if err := c.BodyParser(&prefs); err != nil {
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

	// Convert settings to JSONB
	notificationsJSON, _ := json.Marshal(prefs.Settings)

	query := `
		INSERT INTO user_preferences (user_id, theme, language, timezone, notifications)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (user_id) DO UPDATE SET
			theme = EXCLUDED.theme,
			language = EXCLUDED.language,
			timezone = EXCLUDED.timezone,
			notifications = EXCLUDED.notifications,
			updated_at = CURRENT_TIMESTAMP
		RETURNING user_id, theme, language, timezone, notifications, updated_at
	`

	err := h.dbPools.App.QueryRow(ctx, query,
		userID, prefs.Theme, prefs.Language, prefs.Timezone, notificationsJSON,
	).Scan(&prefs.UserID, &prefs.Theme, &prefs.Language, &prefs.Timezone,
		&prefs.Notifications, &prefs.UpdatedAt)

	if err != nil {
		h.logger.Errorf("Failed to update user preferences: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Database error",
			"message": "Failed to update user preferences",
		})
	}

	h.logger.Infof("Updated preferences for user: %s", userID)

	return c.JSON(prefs)
}

// ResetUserPassword initiates password reset
// TODO: Integrate with Keycloak
func (h *Handler) ResetUserPassword(c *fiber.Ctx) error {
	userID := c.Params("id")

	h.logger.Infof("Password reset requested for user: %s", userID)

	return c.JSON(fiber.Map{
		"message": "Password reset email sent",
		"user_id": userID,
	})
}

// Helper function to split full name into parts
func splitFullName(fullName string) []string {
	parts := []string{}
	for _, part := range []rune(fullName) {
		if part == ' ' {
			continue
		}
	}
	// Simple split by space
	current := ""
	for _, char := range fullName {
		if char == ' ' {
			if current != "" {
				parts = append(parts, current)
				current = ""
			}
		} else {
			current += string(char)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}

// Helper function to join strings
func joinStrings(strs []string, sep string) string {
	if len(strs) == 0 {
		return ""
	}
	result := strs[0]
	for i := 1; i < len(strs); i++ {
		result += sep + strs[i]
	}
	return result
}
