package v1

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// RequireRole is a placeholder middleware for role-based access control
func RequireRole(roles ...string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// TODO: Implement proper RBAC
		// For now, just pass through
		return c.Next()
	}
}

// SetupGroupRoutes registers all client group management routes
func SetupGroupRoutes(app *fiber.App, dbPool *pgxpool.Pool) {
	groups := app.Group("/api/v1/client-groups")

	// List all groups
	groups.Get("/", RequireRole("admin", "operator", "viewer"), func(c *fiber.Ctx) error {
		return ListClientGroups(c, dbPool)
	})

	// Create group
	groups.Post("/", RequireRole("admin", "operator"), func(c *fiber.Ctx) error {
		return CreateClientGroup(c, dbPool)
	})

	// Get group details
	groups.Get("/:id", RequireRole("admin", "operator", "viewer"), func(c *fiber.Ctx) error {
		return GetClientGroup(c, dbPool)
	})

	// Update group
	groups.Put("/:id", RequireRole("admin", "operator"), func(c *fiber.Ctx) error {
		return UpdateClientGroup(c, dbPool)
	})

	// Delete group
	groups.Delete("/:id", RequireRole("admin"), func(c *fiber.Ctx) error {
		return DeleteClientGroup(c, dbPool)
	})

	// Get group members
	groups.Get("/:id/members", RequireRole("admin", "operator", "viewer"), func(c *fiber.Ctx) error {
		return GetGroupMembers(c, dbPool)
	})

	// Add members to group (bulk)
	groups.Post("/:id/members", RequireRole("admin", "operator"), func(c *fiber.Ctx) error {
		return AddGroupMembers(c, dbPool)
	})

	// Remove member from group
	groups.Delete("/:id/members/:clientId", RequireRole("admin", "operator"), func(c *fiber.Ctx) error {
		return RemoveGroupMember(c, dbPool)
	})
}

// ListClientGroups returns all client groups
func ListClientGroups(c *fiber.Ctx, dbPool *pgxpool.Pool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	query := `
		SELECT 
			g.id, 
			g.name, 
			g.description, 
			g.criteria,
			g.created_at, 
			g.updated_at,
			COUNT(DISTINCT gm.client_id) as member_count
		FROM client_groups g
		LEFT JOIN client_group_members gm ON g.id = gm.group_id
		GROUP BY g.id, g.name, g.description, g.criteria, g.created_at, g.updated_at
		ORDER BY g.name ASC
	`

	rows, err := dbPool.Query(ctx, query)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{
			"error": "Failed to fetch groups",
		})
	}
	defer rows.Close()

	type GroupWithCount struct {
		ID          string                 `json:"id"`
		Name        string                 `json:"name"`
		Description string                 `json:"description,omitempty"`
		Criteria    map[string]interface{} `json:"criteria,omitempty"`
		CreatedAt   time.Time              `json:"created_at"`
		UpdatedAt   time.Time              `json:"updated_at"`
		MemberCount int                    `json:"member_count"`
	}

	groups := []GroupWithCount{}

	for rows.Next() {
		var group GroupWithCount
		var criteriaBytes []byte

		err := rows.Scan(
			&group.ID,
			&group.Name,
			&group.Description,
			&criteriaBytes,
			&group.CreatedAt,
			&group.UpdatedAt,
			&group.MemberCount,
		)
		if err != nil {
			continue
		}

		// Parse criteria JSON
		if len(criteriaBytes) > 0 {
			json.Unmarshal(criteriaBytes, &group.Criteria)
		}

		groups = append(groups, group)
	}

	return c.JSON(fiber.Map{
		"groups": groups,
		"total":  len(groups),
	})
}

// CreateClientGroup creates a new client group
func CreateClientGroup(c *fiber.Ctx, dbPool *pgxpool.Pool) error {
	type CreateRequest struct {
		Name        string                 `json:"name"`
		Description string                 `json:"description"`
		Criteria    map[string]interface{} `json:"criteria"`
	}

	var req CreateRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	// Validate
	if req.Name == "" {
		return c.Status(400).JSON(fiber.Map{
			"error": "Name is required",
		})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Convert criteria to JSON
	criteriaJSON, _ := json.Marshal(req.Criteria)

	groupID := uuid.New().String()

	query := `
		INSERT INTO client_groups (id, name, description, criteria, created_at, updated_at)
		VALUES ($1, $2, $3, $4, NOW(), NOW())
		RETURNING id, name, description, criteria, created_at, updated_at
	`

	var group ClientGroup
	var criteriaBytes []byte

	err := dbPool.QueryRow(ctx, query, groupID, req.Name, req.Description, criteriaJSON).Scan(
		&group.ID,
		&group.Name,
		&group.Description,
		&criteriaBytes,
		&group.CreatedAt,
		&group.UpdatedAt,
	)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{
			"error": "Failed to create group",
		})
	}

	// Parse criteria JSON
	if len(criteriaBytes) > 0 {
		json.Unmarshal(criteriaBytes, &group.Criteria)
	}

	return c.Status(201).JSON(group)
}

// GetClientGroup returns a specific client group
func GetClientGroup(c *fiber.Ctx, dbPool *pgxpool.Pool) error {
	groupID := c.Params("id")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	query := `
		SELECT id, name, description, criteria, created_at, updated_at
		FROM client_groups
		WHERE id = $1
	`

	var group ClientGroup
	var criteriaBytes []byte

	err := dbPool.QueryRow(ctx, query, groupID).Scan(
		&group.ID,
		&group.Name,
		&group.Description,
		&criteriaBytes,
		&group.CreatedAt,
		&group.UpdatedAt,
	)

	if err != nil {
		return c.Status(404).JSON(fiber.Map{
			"error": "Group not found",
		})
	}

	// Parse criteria JSON
	if len(criteriaBytes) > 0 {
		json.Unmarshal(criteriaBytes, &group.Criteria)
	}

	return c.JSON(group)
}

// UpdateClientGroup updates an existing client group
func UpdateClientGroup(c *fiber.Ctx, dbPool *pgxpool.Pool) error {
	groupID := c.Params("id")

	type UpdateRequest struct {
		Name        *string                 `json:"name"`
		Description *string                 `json:"description"`
		Criteria    *map[string]interface{} `json:"criteria"`
	}

	var req UpdateRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Build dynamic update query
	updates := []string{}
	args := []interface{}{groupID}
	argIdx := 2

	if req.Name != nil {
		updates = append(updates, fmt.Sprintf("name = $%d", argIdx))
		args = append(args, *req.Name)
		argIdx++
	}

	if req.Description != nil {
		updates = append(updates, fmt.Sprintf("description = $%d", argIdx))
		args = append(args, *req.Description)
		argIdx++
	}

	if req.Criteria != nil {
		criteriaJSON, _ := json.Marshal(*req.Criteria)
		updates = append(updates, fmt.Sprintf("criteria = $%d", argIdx))
		args = append(args, criteriaJSON)
		argIdx++
	}

	if len(updates) == 0 {
		return c.Status(400).JSON(fiber.Map{
			"error": "No fields to update",
		})
	}

	// Add updated_at
	updates = append(updates, "updated_at = NOW()")

	query := fmt.Sprintf(`
		UPDATE client_groups
		SET %s
		WHERE id = $1
		RETURNING id, name, description, criteria, created_at, updated_at
	`, join(updates, ", "))

	var group ClientGroup
	var criteriaBytes []byte

	err := dbPool.QueryRow(ctx, query, args...).Scan(
		&group.ID,
		&group.Name,
		&group.Description,
		&criteriaBytes,
		&group.CreatedAt,
		&group.UpdatedAt,
	)

	if err != nil {
		return c.Status(404).JSON(fiber.Map{
			"error": "Group not found",
		})
	}

	// Parse criteria JSON
	if len(criteriaBytes) > 0 {
		json.Unmarshal(criteriaBytes, &group.Criteria)
	}

	return c.JSON(group)
}

// DeleteClientGroup deletes a client group
func DeleteClientGroup(c *fiber.Ctx, dbPool *pgxpool.Pool) error {
	groupID := c.Params("id")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Delete group (members will be cascade deleted by foreign key)
	query := `DELETE FROM client_groups WHERE id = $1`

	result, err := dbPool.Exec(ctx, query, groupID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{
			"error": "Failed to delete group",
		})
	}

	if result.RowsAffected() == 0 {
		return c.Status(404).JSON(fiber.Map{
			"error": "Group not found",
		})
	}

	return c.JSON(fiber.Map{
		"message": "Group deleted successfully",
	})
}

// GetGroupMembers returns all members of a group
func GetGroupMembers(c *fiber.Ctx, dbPool *pgxpool.Pool) error {
	groupID := c.Params("id")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	query := `
		SELECT 
			c.id, 
			c.hostname, 
			c.ip_address, 
			c.mac_address, 
			c.os_type, 
			c.os_version, 
			c.status, 
			c.last_check_in,
			c.created_at
		FROM clients c
		INNER JOIN client_group_members gm ON c.id = gm.client_id
		WHERE gm.group_id = $1
		ORDER BY c.hostname ASC
	`

	rows, err := dbPool.Query(ctx, query, groupID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{
			"error": "Failed to fetch group members",
		})
	}
	defer rows.Close()

	members := []Client{}

	for rows.Next() {
		var client Client

		err := rows.Scan(
			&client.ID,
			&client.Hostname,
			&client.IPAddress,
			&client.MACAddress,
			&client.OSType,
			&client.OSVersion,
			&client.Status,
			&client.LastCheckIn,
			&client.CreatedAt,
		)
		if err != nil {
			continue
		}

		members = append(members, client)
	}

	return c.JSON(fiber.Map{
		"members": members,
		"total":   len(members),
	})
}

// AddGroupMembers adds clients to a group (bulk operation)
func AddGroupMembers(c *fiber.Ctx, dbPool *pgxpool.Pool) error {
	groupID := c.Params("id")

	type AddMembersRequest struct {
		ClientIDs []string `json:"client_ids"`
	}

	var req AddMembersRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	if len(req.ClientIDs) == 0 {
		return c.Status(400).JSON(fiber.Map{
			"error": "At least one client ID is required",
		})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Insert members (ON CONFLICT DO NOTHING to handle duplicates)
	added := 0
	for _, clientID := range req.ClientIDs {
		query := `
			INSERT INTO client_group_members (group_id, client_id, joined_at)
			VALUES ($1, $2, NOW())
			ON CONFLICT (group_id, client_id) DO NOTHING
		`

		result, err := dbPool.Exec(ctx, query, groupID, clientID)
		if err != nil {
			continue
		}

		if result.RowsAffected() > 0 {
			added++
		}
	}

	return c.JSON(fiber.Map{
		"message": "Members added successfully",
		"added":   added,
		"total":   len(req.ClientIDs),
	})
}

// RemoveGroupMember removes a client from a group
func RemoveGroupMember(c *fiber.Ctx, dbPool *pgxpool.Pool) error {
	groupID := c.Params("id")
	clientID := c.Params("clientId")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	query := `
		DELETE FROM client_group_members
		WHERE group_id = $1 AND client_id = $2
	`

	result, err := dbPool.Exec(ctx, query, groupID, clientID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{
			"error": "Failed to remove member",
		})
	}

	if result.RowsAffected() == 0 {
		return c.Status(404).JSON(fiber.Map{
			"error": "Member not found in group",
		})
	}

	return c.JSON(fiber.Map{
		"message": "Member removed successfully",
	})
}

// Helper function to join strings
func join(strs []string, sep string) string {
	if len(strs) == 0 {
		return ""
	}
	result := strs[0]
	for i := 1; i < len(strs); i++ {
		result += sep + strs[i]
	}
	return result
}
