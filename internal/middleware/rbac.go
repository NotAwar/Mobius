package middleware

import (
	"github.com/gofiber/fiber/v2"
)

// Role definitions
const (
	RoleAdmin    = "admin"
	RoleOperator = "operator"
	RoleViewer   = "viewer"
	RoleUser     = "user"
)

// Permission definitions
const (
	PermissionClusterRead   = "cluster:read"
	PermissionClusterWrite  = "cluster:write"
	PermissionClusterDelete = "cluster:delete"

	PermissionPostgresRead   = "postgres:read"
	PermissionPostgresWrite  = "postgres:write"
	PermissionPostgresDelete = "postgres:delete"

	PermissionHeadscaleRead   = "headscale:read"
	PermissionHeadscaleWrite  = "headscale:write"
	PermissionHeadscaleDelete = "headscale:delete"

	PermissionUserRead   = "user:read"
	PermissionUserWrite  = "user:write"
	PermissionUserDelete = "user:delete"

	PermissionClientRead   = "client:read"
	PermissionClientWrite  = "client:write"
	PermissionClientDelete = "client:delete"

	PermissionOSQueryRead   = "osquery:read"
	PermissionOSQueryWrite  = "osquery:write"
	PermissionOSQueryDelete = "osquery:delete"

	PermissionAuditRead = "audit:read"

	PermissionConfigRead  = "config:read"
	PermissionConfigWrite = "config:write"
)

// RolePermissions maps roles to their permissions
var RolePermissions = map[string][]string{
	RoleAdmin: {
		// Full access to everything
		PermissionClusterRead, PermissionClusterWrite, PermissionClusterDelete,
		PermissionPostgresRead, PermissionPostgresWrite, PermissionPostgresDelete,
		PermissionHeadscaleRead, PermissionHeadscaleWrite, PermissionHeadscaleDelete,
		PermissionUserRead, PermissionUserWrite, PermissionUserDelete,
		PermissionClientRead, PermissionClientWrite, PermissionClientDelete,
		PermissionOSQueryRead, PermissionOSQueryWrite, PermissionOSQueryDelete,
		PermissionAuditRead,
		PermissionConfigRead, PermissionConfigWrite,
	},
	RoleOperator: {
		// Read/Write access, no delete for critical resources
		PermissionClusterRead, PermissionClusterWrite,
		PermissionPostgresRead, PermissionPostgresWrite,
		PermissionHeadscaleRead, PermissionHeadscaleWrite,
		PermissionUserRead,
		PermissionClientRead, PermissionClientWrite, PermissionClientDelete,
		PermissionOSQueryRead, PermissionOSQueryWrite,
		PermissionAuditRead,
		PermissionConfigRead,
	},
	RoleViewer: {
		// Read-only access
		PermissionClusterRead,
		PermissionPostgresRead,
		PermissionHeadscaleRead,
		PermissionUserRead,
		PermissionClientRead,
		PermissionOSQueryRead,
		PermissionAuditRead,
		PermissionConfigRead,
	},
	RoleUser: {
		// Limited access for regular users
		PermissionClientRead,
		PermissionOSQueryRead,
	},
}

// RequirePermission returns middleware that checks for specific permission
func RequirePermission(permission string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		roles := GetRoles(c)
		
		// Check if user has permission through any of their roles
		hasPermission := false
		for _, role := range roles {
			if permissions, ok := RolePermissions[role]; ok {
				for _, perm := range permissions {
					if perm == permission {
						hasPermission = true
						break
					}
				}
			}
			if hasPermission {
				break
			}
		}

		if !hasPermission {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error":      "Forbidden",
				"message":    "Insufficient permissions",
				"permission": permission,
				"roles":      roles,
			})
		}

		return c.Next()
	}
}

// RequireAnyPermission returns middleware that checks for any of the specified permissions
func RequireAnyPermission(permissions ...string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		roles := GetRoles(c)
		
		hasPermission := false
		for _, role := range roles {
			if rolePerms, ok := RolePermissions[role]; ok {
				for _, rolePerm := range rolePerms {
					for _, requiredPerm := range permissions {
						if rolePerm == requiredPerm {
							hasPermission = true
							break
						}
					}
					if hasPermission {
						break
					}
				}
			}
			if hasPermission {
				break
			}
		}

		if !hasPermission {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error":       "Forbidden",
				"message":     "Insufficient permissions",
				"permissions": permissions,
				"roles":       roles,
			})
		}

		return c.Next()
	}
}

// RequireAllPermissions returns middleware that checks for all specified permissions
func RequireAllPermissions(permissions ...string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		roles := GetRoles(c)
		
		// Get all user permissions
		userPermissions := make(map[string]bool)
		for _, role := range roles {
			if rolePerms, ok := RolePermissions[role]; ok {
				for _, perm := range rolePerms {
					userPermissions[perm] = true
				}
			}
		}

		// Check if user has all required permissions
		for _, requiredPerm := range permissions {
			if !userPermissions[requiredPerm] {
				return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
					"error":       "Forbidden",
					"message":     "Insufficient permissions - requires all specified permissions",
					"permissions": permissions,
					"roles":       roles,
				})
			}
		}

		return c.Next()
	}
}

// IsAdmin checks if user has admin role
func IsAdmin(c *fiber.Ctx) bool {
	return HasRole(c, RoleAdmin)
}

// IsOperator checks if user has operator role
func IsOperator(c *fiber.Ctx) bool {
	return HasRole(c, RoleOperator)
}

// IsViewer checks if user has viewer role
func IsViewer(c *fiber.Ctx) bool {
	return HasRole(c, RoleViewer)
}

// GetUserPermissions returns all permissions for the user
func GetUserPermissions(c *fiber.Ctx) []string {
	roles := GetRoles(c)
	permissionSet := make(map[string]bool)
	
	for _, role := range roles {
		if perms, ok := RolePermissions[role]; ok {
			for _, perm := range perms {
				permissionSet[perm] = true
			}
		}
	}

	permissions := make([]string, 0, len(permissionSet))
	for perm := range permissionSet {
		permissions = append(permissions, perm)
	}

	return permissions
}
