package v1

import (
	"mobius/internal/middleware"

	"github.com/gofiber/fiber/v2"
)

// RegisterRoutes registers all v1 API routes with authentication and RBAC
func (h *Handler) RegisterRoutes(router fiber.Router) {
	// Public endpoints (no authentication required)
	public := router.Group("")
	public.Get("/health", h.HealthCheck)
	public.Get("/health/live", h.LivenessProbe)
	public.Get("/health/ready", h.ReadinessProbe)
	
	// Client enrollment endpoint (public - requires enrollment key)
	public.Post("/clients/enroll", h.EnrollClient)

	// Protected endpoints (authentication required)
	// Initialize Keycloak middleware
	keycloak := middleware.NewKeycloakAuth(h.logger, middleware.KeycloakConfig{
		RealmURL:     getEnv("KEYCLOAK_REALM_URL", "https://keycloak.example.com/auth/realms/mobius"),
		ClientID:     getEnv("KEYCLOAK_CLIENT_ID", "mobius-api"),
		ClientSecret: getEnv("KEYCLOAK_CLIENT_SECRET", ""),
		Enabled:      getEnvBool("KEYCLOAK_ENABLED", false), // Set to true in production
	})

	protected := router.Group("", keycloak.Middleware())

	// Health check (detailed) - requires authentication
	protected.Get("/health/detailed", 
		middleware.RequirePermission(middleware.PermissionClusterRead),
		h.HealthCheckDetailed)

	// Status endpoints - viewer can read
	statusGroup := protected.Group("/status")
	statusGroup.Get("/cluster", 
		middleware.RequirePermission(middleware.PermissionClusterRead),
		h.GetClusterStatus)
	statusGroup.Get("/postgres", 
		middleware.RequirePermission(middleware.PermissionPostgresRead),
		h.GetPostgresStatus)
	statusGroup.Get("/headscale", 
		middleware.RequirePermission(middleware.PermissionHeadscaleRead),
		h.GetHeadscaleStatus)

	// Cluster management - read/write/delete permissions
	clusterGroup := protected.Group("/cluster")
	clusterGroup.Get("/status", 
		middleware.RequirePermission(middleware.PermissionClusterRead),
		h.GetClusterStatus)
	clusterGroup.Get("/nodes", 
		middleware.RequirePermission(middleware.PermissionClusterRead),
		h.GetClusterNodes)
	clusterGroup.Get("/pods", 
		middleware.RequirePermission(middleware.PermissionClusterRead),
		h.GetClusterPods)
	clusterGroup.Get("/namespaces", 
		middleware.RequirePermission(middleware.PermissionClusterRead),
		h.GetNamespaces)
	clusterGroup.Get("/deployments", 
		middleware.RequirePermission(middleware.PermissionClusterRead),
		h.GetDeployments)
	clusterGroup.Get("/services", 
		middleware.RequirePermission(middleware.PermissionClusterRead),
		h.GetServices)
	clusterGroup.Get("/pods/:namespace/:name/logs", 
		middleware.RequirePermission(middleware.PermissionClusterRead),
		h.GetPodLogs)
	clusterGroup.Delete("/pods/:namespace/:name", 
		middleware.RequirePermission(middleware.PermissionClusterDelete),
		h.DeletePod)
	clusterGroup.Post("/pods/:namespace/:name/restart", 
		middleware.RequirePermission(middleware.PermissionClusterWrite),
		h.RestartPod)

	// PostgreSQL management - read/write/delete permissions
	postgresGroup := protected.Group("/postgres")
	postgresGroup.Get("/databases", 
		middleware.RequirePermission(middleware.PermissionPostgresRead),
		h.GetPostgresDatabases)
	postgresGroup.Post("/databases", 
		middleware.RequirePermission(middleware.PermissionPostgresWrite),
		h.CreatePostgresDatabase)
	postgresGroup.Delete("/databases/:name", 
		middleware.RequirePermission(middleware.PermissionPostgresDelete),
		h.DeletePostgresDatabase)

	// Headscale management - read/write/delete permissions
	headscaleGroup := protected.Group("/headscale")
	headscaleGroup.Get("/users", 
		middleware.RequirePermission(middleware.PermissionHeadscaleRead),
		h.GetHeadscaleUsers)
	headscaleGroup.Post("/users", 
		middleware.RequirePermission(middleware.PermissionHeadscaleWrite),
		h.CreateHeadscaleUser)
	headscaleGroup.Get("/nodes", 
		middleware.RequirePermission(middleware.PermissionHeadscaleRead),
		h.GetHeadscaleNodes)

	// User Management - admin/operator only
	usersGroup := protected.Group("/users")
	usersGroup.Get("", 
		middleware.RequirePermission(middleware.PermissionUserRead),
		h.GetUsers)
	usersGroup.Get("/:id", 
		middleware.RequirePermission(middleware.PermissionUserRead),
		h.GetUser)
	usersGroup.Post("", 
		middleware.RequirePermission(middleware.PermissionUserWrite),
		h.CreateUser)
	usersGroup.Put("/:id", 
		middleware.RequirePermission(middleware.PermissionUserWrite),
		h.UpdateUser)
	usersGroup.Delete("/:id", 
		middleware.RequirePermission(middleware.PermissionUserDelete),
		h.DeleteUser)
	usersGroup.Get("/:id/preferences", 
		middleware.RequireAnyPermission(middleware.PermissionUserRead, middleware.PermissionUserWrite),
		h.GetUserPreferences)
	usersGroup.Put("/:id/preferences", 
		middleware.RequirePermission(middleware.PermissionUserWrite),
		h.UpdateUserPreferences)
	usersGroup.Post("/:id/reset-password", 
		middleware.RequirePermission(middleware.PermissionUserWrite),
		h.ResetUserPassword)

	// Client Management - operator can manage
	clientsGroup := protected.Group("/clients")
	
	// Enrollment keys management (admin only)
	clientsGroup.Get("/enrollment-keys", 
		middleware.RequirePermission(middleware.PermissionClientWrite),
		h.GetEnrollmentKeys)
	clientsGroup.Post("/enrollment-keys", 
		middleware.RequirePermission(middleware.PermissionClientWrite),
		h.CreateEnrollmentKey)
	clientsGroup.Delete("/enrollment-keys/:id", 
		middleware.RequirePermission(middleware.PermissionClientWrite),
		h.RevokeEnrollmentKey)
	
	// Client management
	clientsGroup.Get("", 
		middleware.RequirePermission(middleware.PermissionClientRead),
		h.GetClients)
	clientsGroup.Get("/:id", 
		middleware.RequirePermission(middleware.PermissionClientRead),
		h.GetClient)
	clientsGroup.Post("", 
		middleware.RequirePermission(middleware.PermissionClientWrite),
		h.CreateClient)
	clientsGroup.Put("/:id", 
		middleware.RequirePermission(middleware.PermissionClientWrite),
		h.UpdateClient)
	clientsGroup.Delete("/:id", 
		middleware.RequirePermission(middleware.PermissionClientDelete),
		h.DeleteClient)
	clientsGroup.Post("/:id/tags", 
		middleware.RequirePermission(middleware.PermissionClientWrite),
		h.AddClientTag)
	clientsGroup.Delete("/:id/tags/:tag", 
		middleware.RequirePermission(middleware.PermissionClientWrite),
		h.RemoveClientTag)
	clientsGroup.Get("/groups", 
		middleware.RequirePermission(middleware.PermissionClientRead),
		h.GetClientGroups)
	clientsGroup.Get("/:id/configuration", 
		middleware.RequirePermission(middleware.PermissionClientRead),
		h.GetClientConfiguration)
	clientsGroup.Put("/:id/configuration", 
		middleware.RequirePermission(middleware.PermissionClientWrite),
		h.UpdateClientConfiguration)
	clientsGroup.Get("/:id/check-ins", 
		middleware.RequirePermission(middleware.PermissionClientRead),
		h.GetClientCheckIns)
	
	// Client check-in endpoint (requires client authentication, not user authentication)
	// This is a special endpoint that clients use to check in
	router.Post("/clients/:id/check-in", h.ClientCheckIn)

	// OSQuery Management - operator can manage
	osqueryGroup := protected.Group("/osquery")
	
	// Queries
	osqueryGroup.Get("/queries", 
		middleware.RequirePermission(middleware.PermissionOSQueryRead),
		h.GetOSQueryQueries)
	osqueryGroup.Get("/queries/:id", 
		middleware.RequirePermission(middleware.PermissionOSQueryRead),
		h.GetOSQueryQuery)
	osqueryGroup.Post("/queries", 
		middleware.RequirePermission(middleware.PermissionOSQueryWrite),
		h.CreateOSQueryQuery)
	osqueryGroup.Put("/queries/:id", 
		middleware.RequirePermission(middleware.PermissionOSQueryWrite),
		h.UpdateOSQueryQuery)
	osqueryGroup.Delete("/queries/:id", 
		middleware.RequirePermission(middleware.PermissionOSQueryDelete),
		h.DeleteOSQueryQuery)
	osqueryGroup.Post("/queries/:id/execute", 
		middleware.RequirePermission(middleware.PermissionOSQueryWrite),
		h.ExecuteOSQueryQuery)
	
	// Packs
	osqueryGroup.Get("/packs", 
		middleware.RequirePermission(middleware.PermissionOSQueryRead),
		h.GetOSQueryPacks)
	osqueryGroup.Post("/packs", 
		middleware.RequirePermission(middleware.PermissionOSQueryWrite),
		h.CreateOSQueryPack)
	
	// Results
	osqueryGroup.Get("/results", 
		middleware.RequirePermission(middleware.PermissionOSQueryRead),
		h.GetOSQueryResults)
	osqueryGroup.Get("/results/export", 
		middleware.RequirePermission(middleware.PermissionOSQueryRead),
		h.ExportOSQueryResults)

	// Audit logs - admin/operator can read, admin can manage sources
	auditGroup := protected.Group("/audit")
	auditGroup.Get("/logs", 
		middleware.RequirePermission(middleware.PermissionAuditRead),
		h.GetAuditLogs)
	auditGroup.Get("/sources", 
		middleware.RequirePermission(middleware.PermissionAuditRead),
		h.GetAuditSources)
}

// Helper functions for environment variables
func getEnv(key, defaultValue string) string {
	// TODO: Implement proper environment variable loading
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	// TODO: Implement proper environment variable loading
	return defaultValue
}
