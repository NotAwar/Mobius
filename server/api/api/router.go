package api

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog/log"
)

// Router creates and configures the main API router
func NewRouter(deps *Dependencies) *mux.Router {
	r := mux.NewRouter()

	// Middleware
	r.Use(LoggingMiddleware)
	r.Use(CORSMiddleware)
	r.Use(SecurityHeadersMiddleware)

	// API versioning
	api := r.PathPrefix("/api/v1").Subrouter()

	// Public routes (no auth required)
	api.HandleFunc("/health", HealthHandler).Methods("GET")
	api.HandleFunc("/metrics", MetricsHandler).Methods("GET")
	api.HandleFunc("/auth/login", deps.handleLogin).Methods("POST")

	// Protected routes
	protected := api.PathPrefix("").Subrouter()
	protected.Use(deps.authMiddleware)

	// License management
	protected.HandleFunc("/license/status", deps.handleGetLicense).Methods("GET")
	protected.HandleFunc("/license", deps.handleUpdateLicense).Methods("PUT")

	// Device routes
	devices := protected.PathPrefix("/devices").Subrouter()
	devices.HandleFunc("", deps.handleListDevices).Methods("GET")
	devices.HandleFunc("", deps.handleEnrollDevice).Methods("POST")
	devices.HandleFunc("/{deviceId}", deps.handleGetDevice).Methods("GET")
	devices.HandleFunc("/{deviceId}", deps.handleUpdateDevice).Methods("PUT")
	devices.HandleFunc("/{deviceId}", deps.handleUnenrollDevice).Methods("DELETE")
	devices.HandleFunc("/{deviceId}/commands", deps.handleDeviceCommand).Methods("POST")
	devices.HandleFunc("/{deviceId}/osquery", deps.handleDeviceOSQuery).Methods("POST")

	// Device Groups management
	groups := protected.PathPrefix("/device-groups").Subrouter()
	groups.HandleFunc("", deps.handleListDeviceGroups).Methods("GET")
	groups.HandleFunc("", deps.handleCreateDeviceGroup).Methods("POST")
	groups.HandleFunc("/{groupId}", deps.handleGetDeviceGroup).Methods("GET")
	groups.HandleFunc("/{groupId}", deps.handleUpdateDeviceGroup).Methods("PUT")
	groups.HandleFunc("/{groupId}", deps.handleDeleteDeviceGroup).Methods("DELETE")
	groups.HandleFunc("/{groupId}/devices", deps.handleGetGroupDevices).Methods("GET")
	groups.HandleFunc("/{groupId}/devices/{deviceId}", deps.handleAddDeviceToGroup).Methods("POST")
	groups.HandleFunc("/{groupId}/devices/{deviceId}", deps.handleRemoveDeviceFromGroup).Methods("DELETE")

	// Policy management
	policies := protected.PathPrefix("/policies").Subrouter()
	policies.HandleFunc("", deps.handleListPolicies).Methods("GET")
	policies.HandleFunc("", deps.handleCreatePolicy).Methods("POST")
	policies.HandleFunc("/{policyId}", deps.handleGetPolicy).Methods("GET")
	policies.HandleFunc("/{policyId}", deps.handleUpdatePolicy).Methods("PUT")
	policies.HandleFunc("/{policyId}", deps.handleDeletePolicy).Methods("DELETE")
	
	// Policy assignment endpoints
	policies.HandleFunc("/{policyId}/devices", deps.handleGetPolicyDevices).Methods("GET")
	policies.HandleFunc("/{policyId}/devices/{deviceId}", deps.handleAssignPolicyToDevice).Methods("POST")
	policies.HandleFunc("/{policyId}/devices/{deviceId}", deps.handleUnassignPolicyFromDevice).Methods("DELETE")
	policies.HandleFunc("/{policyId}/groups", deps.handleGetPolicyGroups).Methods("GET")
	policies.HandleFunc("/{policyId}/groups/{groupId}", deps.handleAssignPolicyToGroup).Methods("POST")
	policies.HandleFunc("/{policyId}/groups/{groupId}", deps.handleUnassignPolicyFromGroup).Methods("DELETE")

	// Application management
	apps := protected.PathPrefix("/applications").Subrouter()
	apps.HandleFunc("", deps.handleListApplications).Methods("GET")
	apps.HandleFunc("", deps.handleAddApplication).Methods("POST")
	apps.HandleFunc("/{appId}", deps.handleGetApplication).Methods("GET")
	apps.HandleFunc("/{appId}", deps.handleUpdateApplication).Methods("PUT")
	apps.HandleFunc("/{appId}", deps.handleDeleteApplication).Methods("DELETE")

	// WebSocket endpoint for real-time updates
	protected.HandleFunc("/ws", deps.handleWebSocket).Methods("GET")

	// Device API (for client connections)
	deviceAPI := api.PathPrefix("/device").Subrouter()
	deviceAPI.Use(deps.deviceAuthMiddleware)
	deviceAPI.HandleFunc("/checkin", deps.handleDeviceCheckin).Methods("POST")
	deviceAPI.HandleFunc("/policies", deps.handleDeviceGetPolicies).Methods("GET")
	deviceAPI.HandleFunc("/applications", deps.handleDeviceGetApplications).Methods("GET")

	// Legacy CLI compatibility routes (/api/latest/mobius/*)
	legacyAPI := r.PathPrefix("/api/latest/mobius").Subrouter()

	// Legacy authentication
	legacyAPI.HandleFunc("/login", deps.handleLegacyLogin).Methods("POST")
	legacyAPI.HandleFunc("/logout", deps.handleLegacyLogout).Methods("POST")

	// Legacy version endpoint
	legacyAPI.HandleFunc("/version", deps.handleLegacyVersion).Methods("GET")

	// Legacy protected routes
	legacyProtected := legacyAPI.PathPrefix("").Subrouter()
	legacyProtected.Use(deps.authMiddleware)

	// Legacy config endpoint
	legacyProtected.HandleFunc("/config", deps.handleLegacyConfig).Methods("GET")

	// Legacy license endpoints
	legacyProtected.HandleFunc("/license", deps.handleGetLicense).Methods("GET")
	legacyProtected.HandleFunc("/license/status", deps.handleGetLicense).Methods("GET")
	legacyProtected.HandleFunc("/license", deps.handleUpdateLicense).Methods("PUT")

	// Legacy setup endpoint (for initial setup check)
	legacyAPI.HandleFunc("/setup", deps.handleLegacySetup).Methods("GET", "POST")

	// Serve static files (Svelte frontend)
	// Only serve frontend if static files exist
	staticDir := "./static"
	if deps.StaticDir != "" {
		staticDir = deps.StaticDir
	}
	
	// Serve static assets (JS, CSS, images)
	r.PathPrefix("/assets/").Handler(http.StripPrefix("/assets/", http.FileServer(http.Dir(filepath.Join(staticDir, "assets")))))
	r.PathPrefix("/_app/").Handler(http.StripPrefix("/_app/", http.FileServer(http.Dir(filepath.Join(staticDir, "_app")))))
	
	// Handle SPA routes - serve index.html for all non-API routes
	r.PathPrefix("/").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Don't serve index.html for API routes
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}
		
		// Serve index.html for all other routes (SPA routing)
		indexPath := filepath.Join(staticDir, "index.html")
		http.ServeFile(w, r, indexPath)
	})

	return r
}

// Dependencies holds all handler dependencies
type Dependencies struct {
	// Services
	LicenseService     LicenseService
	DeviceService      DeviceService
	DeviceGroupService DeviceGroupService
	PolicyService      PolicyService
	ApplicationService ApplicationService
	AuthService        AuthService
	GroupService       GroupService
	
	// WebSocket support
	WSHub WSHub
	
	// Static file serving
	StaticDir string
}

// Service interfaces
type LicenseService interface {
	GetLicense() (*License, error)
	UpdateLicense(key string) error
	ValidateLicense() error
}

type DeviceService interface {
	ListDevices(filters DeviceFilters) ([]*Device, int, error)
	GetDevice(id string) (*Device, error)
	EnrollDevice(enrollment DeviceEnrollment) (*Device, error)
	UnenrollDevice(id string) error
	UpdateDevice(id string, updates DeviceUpdates) (*Device, error)
	ExecuteCommand(deviceID, command string, parameters map[string]interface{}) (*DeviceCommandResult, error)
	ExecuteOSQuery(deviceID, query string) (*OSQueryResult, error)
}

type DeviceGroupService interface {
	ListDeviceGroups() ([]*DeviceGroup, error)
	GetDeviceGroup(id string) (*DeviceGroup, error)
	CreateDeviceGroup(group DeviceGroupCreate) (*DeviceGroup, error)
	UpdateDeviceGroup(id string, updates DeviceGroupUpdate) (*DeviceGroup, error)
	DeleteDeviceGroup(id string) error
	GetGroupDevices(groupID string) ([]*Device, error)
	AddDeviceToGroup(groupID, deviceID string) error
	RemoveDeviceFromGroup(groupID, deviceID string) error
	GetDeviceGroups(deviceID string) ([]*DeviceGroup, error)
}

type PolicyService interface {
	ListPolicies() ([]*Policy, error)
	GetPolicy(id string) (*Policy, error)
	CreatePolicy(policy PolicyCreate) (*Policy, error)
	UpdatePolicy(id string, updates PolicyUpdate) (*Policy, error)
	DeletePolicy(id string) error
	GetDevicePolicies(deviceID string) ([]*Policy, error)
	AssignDevicePolicies(deviceID string, policyIDs []string) error
	
	// Policy assignment methods
	GetPolicyDevices(policyID string) ([]*Device, error)
	AssignPolicyToDevice(policyID, deviceID string) error
	UnassignPolicyFromDevice(policyID, deviceID string) error
	GetPolicyGroups(policyID string) ([]*DeviceGroup, error)
	AssignPolicyToGroup(policyID, groupID string) error
	UnassignPolicyFromGroup(policyID, groupID string) error
}

type ApplicationService interface {
	ListApplications() ([]*Application, error)
	GetApplication(id string) (*Application, error)
	AddApplication(app ApplicationCreate) (*Application, error)
	UpdateApplication(id string, updates ApplicationUpdate) (*Application, error)
	DeleteApplication(id string) error
}

type AuthService interface {
	Login(email, password string) (*AuthResponse, error)
	ValidateToken(token string) (*User, error)
	ValidateDeviceToken(token string) (*Device, error)
}

type GroupService interface {
	CreateGroup(group Group) error
	GetGroups() ([]Group, error)
	GetGroup(id string) (*Group, error)
	UpdateGroup(id string, group Group) error
	DeleteGroup(id string) error
	AddDeviceToGroup(groupID, deviceID string) error
	RemoveDeviceFromGroup(groupID, deviceID string) error
}

type WSHub interface {
	Run(ctx context.Context)
	BroadcastEvent(eventType string, data interface{})
	GetClientCount() int
	HandleWebSocket(w http.ResponseWriter, r *http.Request, userID, userRole string)
}

// Data models
type License struct {
	Valid           bool       `json:"valid"`
	Tier            string     `json:"tier"`
	DeviceLimit     int        `json:"device_limit"`
	DevicesEnrolled int        `json:"devices_enrolled"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
	Features        []string   `json:"features"`
}

type Device struct {
	ID         string            `json:"id"`
	UUID       string            `json:"uuid"`
	Hostname   string            `json:"hostname"`
	Platform   string            `json:"platform"`
	OSVersion  string            `json:"os_version"`
	LastSeen   time.Time         `json:"last_seen"`
	Status     string            `json:"status"`
	EnrolledAt time.Time         `json:"enrolled_at"`
	Labels     map[string]string `json:"labels,omitempty"`
}

type Group struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	DeviceIDs   []string `json:"device_ids"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type DeviceFilters struct {
	Limit    int    `json:"limit"`
	Offset   int    `json:"offset"`
	Platform string `json:"platform,omitempty"`
	Status   string `json:"status,omitempty"`
	Search   string `json:"search,omitempty"`
}

type DeviceEnrollment struct {
	UUID             string                 `json:"uuid"`
	Hostname         string                 `json:"hostname"`
	Platform         string                 `json:"platform"`
	OSVersion        string                 `json:"os_version"`
	EnrollmentSecret string                 `json:"enrollment_secret"`
	HardwareInfo     map[string]interface{} `json:"hardware_info,omitempty"`
	SerialNumber     string                 `json:"serial_number,omitempty"`
}

type DeviceUpdates struct {
	Hostname  *string            `json:"hostname,omitempty"`
	OSVersion *string            `json:"os_version,omitempty"`
	Labels    *map[string]string `json:"labels,omitempty"`
}

// Enhanced MDM types for device management
type DeviceCommandResult struct {
	ID         string                 `json:"id"`
	Command    string                 `json:"command"`
	Status     string                 `json:"status"` // "pending", "running", "completed", "failed"
	Result     map[string]interface{} `json:"result,omitempty"`
	Error      string                 `json:"error,omitempty"`
	ExecutedAt *time.Time             `json:"executed_at,omitempty"`
}

type OSQueryResult struct {
	Query    string                   `json:"query"`
	Columns  []string                 `json:"columns"`
	Rows     []map[string]interface{} `json:"rows"`
	Duration int64                    `json:"duration_ms"`
	Error    string                   `json:"error,omitempty"`
}

type Policy struct {
	ID            string                 `json:"id"`
	Name          string                 `json:"name"`
	Description   string                 `json:"description"`
	Platform      string                 `json:"platform"`
	Enabled       bool                   `json:"enabled"`
	Configuration map[string]interface{} `json:"configuration"`
	CreatedAt     time.Time              `json:"created_at"`
	UpdatedAt     time.Time              `json:"updated_at"`
}

type PolicyCreate struct {
	Name          string                 `json:"name"`
	Description   string                 `json:"description"`
	Platform      string                 `json:"platform"`
	Configuration map[string]interface{} `json:"configuration"`
}

type PolicyUpdate struct {
	Name          *string                 `json:"name,omitempty"`
	Description   *string                 `json:"description,omitempty"`
	Enabled       *bool                   `json:"enabled,omitempty"`
	Configuration *map[string]interface{} `json:"configuration,omitempty"`
}

type Application struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Version   string    `json:"version"`
	Platform  string    `json:"platform"`
	Size      int64     `json:"size"`
	Checksum  string    `json:"checksum"`
	CreatedAt time.Time `json:"created_at"`
}

type ApplicationCreate struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Platform string `json:"platform"`
	Package  []byte `json:"-"` // Binary data
}

type ApplicationUpdate struct {
	Name    *string `json:"name,omitempty"`
	Version *string `json:"version,omitempty"`
}

type User struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type AuthResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	User      *User     `json:"user"`
}

type APIError struct {
	Error   string      `json:"error"`
	Message string      `json:"message"`
	Code    int         `json:"code"`
	Details interface{} `json:"details,omitempty"`
}

// Device Group types for enhanced device management
type DeviceGroup struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	DeviceCount int               `json:"device_count"`
	Filters     map[string]string `json:"filters,omitempty"`     // Auto-assignment filters
	Labels      map[string]string `json:"labels,omitempty"`      // Group metadata
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

type DeviceGroupCreate struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Filters     map[string]string `json:"filters,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
}

type DeviceGroupUpdate struct {
	Name        *string            `json:"name,omitempty"`
	Description *string            `json:"description,omitempty"`
	Filters     *map[string]string `json:"filters,omitempty"`
	Labels      *map[string]string `json:"labels,omitempty"`
}

// Utility functions
func WriteJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Error().Err(err).Msg("Failed to encode JSON response")
	}
}

func WriteError(w http.ResponseWriter, status int, message string) {
	WriteJSON(w, status, APIError{
		Error:   http.StatusText(status),
		Message: message,
		Code:    status,
	})
}

// handleWebSocket handles WebSocket connection requests
func (d *Dependencies) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// Extract user info from the auth middleware context
	userID := r.Header.Get("X-User-ID")
	userRole := r.Header.Get("X-User-Role")
	
	if userID == "" {
		WriteError(w, http.StatusUnauthorized, "User not authenticated")
		return
	}
	
	if d.WSHub != nil {
		d.WSHub.HandleWebSocket(w, r, userID, userRole)
	} else {
		WriteError(w, http.StatusServiceUnavailable, "WebSocket service not available")
	}
}
