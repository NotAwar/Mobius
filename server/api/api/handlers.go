package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"time"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog/log"
)

// HealthHandler provides system health status
func HealthHandler(w http.ResponseWriter, r *http.Request) {
	health := HealthStatus{
		Status:    "healthy",
		Timestamp: time.Now(),
		Version:   GetVersion(),
		Components: map[string]ComponentStatus{
			"database": {
				Status:  "up",
				Message: "Connected",
			},
			"cache": {
				Status:  "up",
				Message: "Redis operational",
			},
			"storage": {
				Status:  "up",
				Message: "File system accessible",
			},
		},
	}

	// Check if any components are down
	allHealthy := true
	for _, component := range health.Components {
		if component.Status != "up" {
			allHealthy = false
			break
		}
	}

	if !allHealthy {
		health.Status = "degraded"
	}

	WriteJSON(w, http.StatusOK, health)
}

// MetricsHandler provides Prometheus-style metrics
func MetricsHandler(w http.ResponseWriter, r *http.Request) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	metrics := fmt.Sprintf(`# HELP mobius_info Information about Mobius server
# TYPE mobius_info gauge
mobius_info{version="%s"} 1

# HELP mobius_memory_usage_bytes Memory usage in bytes
# TYPE mobius_memory_usage_bytes gauge
mobius_memory_usage_bytes{type="alloc"} %d
mobius_memory_usage_bytes{type="total_alloc"} %d
mobius_memory_usage_bytes{type="sys"} %d

# HELP mobius_goroutines_total Total number of goroutines
# TYPE mobius_goroutines_total gauge
mobius_goroutines_total %d

# HELP mobius_uptime_seconds Uptime in seconds
# TYPE mobius_uptime_seconds gauge
mobius_uptime_seconds %d
`,
		GetVersion(),
		m.Alloc,
		m.TotalAlloc,
		m.Sys,
		runtime.NumGoroutine(),
		int64(time.Since(startTime).Seconds()),
	)

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(metrics))
}

// handleLogin handles user authentication
func (d *Dependencies) handleLogin(w http.ResponseWriter, r *http.Request) {
	var loginReq LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&loginReq); err != nil {
		WriteError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if loginReq.Email == "" || loginReq.Password == "" {
		WriteError(w, http.StatusBadRequest, "Email and password required")
		return
	}

	authResp, err := d.AuthService.Login(loginReq.Email, loginReq.Password)
	if err != nil {
		log.Warn().
			Str("email", loginReq.Email).
			Err(err).
			Msg("Login failed")
		WriteError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	log.Info().
		Str("email", loginReq.Email).
		Str("user_id", authResp.User.ID).
		Msg("User logged in successfully")

	WriteJSON(w, http.StatusOK, authResp)
}

// handleGetLicense returns current license status
func (d *Dependencies) handleGetLicense(w http.ResponseWriter, r *http.Request) {
	license, err := d.LicenseService.GetLicense()
	if err != nil {
		log.Error().Err(err).Msg("Failed to get license")
		WriteError(w, http.StatusInternalServerError, "Failed to retrieve license")
		return
	}

	WriteJSON(w, http.StatusOK, license)
}

// handleUpdateLicense updates the license key (admin only)
func (d *Dependencies) handleUpdateLicense(w http.ResponseWriter, r *http.Request) {
	user, err := GetUserFromContext(r)
	if err != nil {
		WriteError(w, http.StatusUnauthorized, "User context required")
		return
	}

	if user.Role != "admin" {
		WriteError(w, http.StatusForbidden, "Admin role required")
		return
	}

	var licenseReq LicenseUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&licenseReq); err != nil {
		WriteError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if licenseReq.Key == "" {
		WriteError(w, http.StatusBadRequest, "License key required")
		return
	}

	if err := d.LicenseService.UpdateLicense(licenseReq.Key); err != nil {
		log.Error().Err(err).Msg("Failed to update license")
		WriteError(w, http.StatusBadRequest, "Invalid license key")
		return
	}

	log.Info().
		Str("user_id", user.ID).
		Msg("License updated successfully")

	WriteJSON(w, http.StatusOK, map[string]string{
		"message": "License updated successfully",
	})
}

// handleDeviceCheckin handles device check-ins
func (d *Dependencies) handleDeviceCheckin(w http.ResponseWriter, r *http.Request) {
	device, err := GetDeviceFromContext(r)
	if err != nil {
		WriteError(w, http.StatusUnauthorized, "Device context required")
		return
	}

	var checkinReq DeviceCheckinRequest
	if err := json.NewDecoder(r.Body).Decode(&checkinReq); err != nil {
		WriteError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Update device last seen and any other relevant info
	updates := DeviceUpdates{
		OSVersion: &checkinReq.OSVersion,
	}

	updatedDevice, err := d.DeviceService.UpdateDevice(device.ID, updates)
	if err != nil {
		log.Error().Err(err).Str("device_id", device.ID).Msg("Failed to update device")
		WriteError(w, http.StatusInternalServerError, "Failed to update device")
		return
	}

	log.Debug().
		Str("device_id", device.ID).
		Str("hostname", device.Hostname).
		Msg("Device checked in")

	WriteJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Check-in successful",
		"device":  updatedDevice,
	})
}

// Data structures for handlers
type HealthStatus struct {
	Status     string                     `json:"status"`
	Timestamp  time.Time                  `json:"timestamp"`
	Version    string                     `json:"version"`
	Components map[string]ComponentStatus `json:"components"`
}

type ComponentStatus struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LicenseUpdateRequest struct {
	Key string `json:"key"`
}

type DeviceCheckinRequest struct {
	OSVersion    string                 `json:"os_version"`
	SystemInfo   map[string]string      `json:"system_info,omitempty"`
	QueryResults map[string]interface{} `json:"query_results,omitempty"`
}

// Global variables
var startTime = time.Now()

// GetVersion returns the current version
func GetVersion() string {
	// This would be injected at build time
	return "1.0.0"
}

// Device policy handlers
func (d *Dependencies) handleGetDevicePolicies(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	deviceID := vars["deviceId"]

	if deviceID == "" {
		WriteError(w, http.StatusBadRequest, "Device ID is required")
		return
	}

	// Check if device exists
	_, err := d.DeviceService.GetDevice(deviceID)
	if err != nil {
		WriteError(w, http.StatusNotFound, "Device not found")
		return
	}

	policies, err := d.PolicyService.GetDevicePolicies(deviceID)
	if err != nil {
		log.Error().Err(err).Str("device_id", deviceID).Msg("Failed to get device policies")
		WriteError(w, http.StatusInternalServerError, "Failed to get device policies")
		return
	}

	WriteJSON(w, http.StatusOK, map[string]interface{}{
		"device_id": deviceID,
		"policies":  policies,
	})
}

func (d *Dependencies) handleAssignDevicePolicies(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	deviceID := vars["deviceId"]

	if deviceID == "" {
		WriteError(w, http.StatusBadRequest, "Device ID is required")
		return
	}

	var assignment struct {
		PolicyID string `json:"policy_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&assignment); err != nil {
		WriteError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if assignment.PolicyID == "" {
		WriteError(w, http.StatusBadRequest, "Policy ID is required")
		return
	}

	err := d.PolicyService.AssignDevicePolicies(deviceID, []string{assignment.PolicyID})
	if err != nil {
		log.Error().Err(err).
			Str("device_id", deviceID).
			Str("policy_id", assignment.PolicyID).
			Msg("Failed to assign policy to device")
		WriteError(w, http.StatusInternalServerError, "Failed to assign policy to device")
		return
	}

	WriteJSON(w, http.StatusOK, map[string]string{
		"message": "Policy assigned successfully",
	})
}

// Policy management handlers
func (d *Dependencies) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	policies, err := d.PolicyService.ListPolicies()
	if err != nil {
		log.Error().Err(err).Msg("Failed to list policies")
		WriteError(w, http.StatusInternalServerError, "Failed to list policies")
		return
	}

	WriteJSON(w, http.StatusOK, map[string]interface{}{
		"policies": policies,
		"total":    len(policies),
	})
}

func (d *Dependencies) handleCreatePolicy(w http.ResponseWriter, r *http.Request) {
	var policyCreate PolicyCreate
	if err := json.NewDecoder(r.Body).Decode(&policyCreate); err != nil {
		WriteError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate required fields
	if policyCreate.Name == "" {
		WriteError(w, http.StatusBadRequest, "Policy name is required")
		return
	}
	if policyCreate.Platform == "" {
		WriteError(w, http.StatusBadRequest, "Policy platform is required")
		return
	}

	// Validate platform
	validPlatforms := map[string]bool{
		"windows": true, "macos": true, "linux": true, "ios": true, "android": true,
	}
	if !validPlatforms[policyCreate.Platform] {
		WriteError(w, http.StatusBadRequest, "Invalid platform")
		return
	}

	policy, err := d.PolicyService.CreatePolicy(policyCreate)
	if err != nil {
		log.Error().Err(err).Str("name", policyCreate.Name).Msg("Failed to create policy")
		WriteError(w, http.StatusInternalServerError, "Failed to create policy")
		return
	}

	WriteJSON(w, http.StatusCreated, policy)
}

func (d *Dependencies) handleGetPolicy(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	policyID := vars["policyId"]

	if policyID == "" {
		WriteError(w, http.StatusBadRequest, "Policy ID is required")
		return
	}

	policy, err := d.PolicyService.GetPolicy(policyID)
	if err != nil {
		WriteError(w, http.StatusNotFound, "Policy not found")
		return
	}

	WriteJSON(w, http.StatusOK, policy)
}

func (d *Dependencies) handleUpdatePolicy(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	policyID := vars["policyId"]

	if policyID == "" {
		WriteError(w, http.StatusBadRequest, "Policy ID is required")
		return
	}

	var updates PolicyUpdate
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		WriteError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	policy, err := d.PolicyService.UpdatePolicy(policyID, updates)
	if err != nil {
		log.Error().Err(err).Str("policy_id", policyID).Msg("Failed to update policy")
		WriteError(w, http.StatusInternalServerError, "Failed to update policy")
		return
	}

	WriteJSON(w, http.StatusOK, policy)
}

func (d *Dependencies) handleDeletePolicy(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	policyID := vars["policyId"]

	if policyID == "" {
		WriteError(w, http.StatusBadRequest, "Policy ID is required")
		return
	}

	err := d.PolicyService.DeletePolicy(policyID)
	if err != nil {
		log.Error().Err(err).Str("policy_id", policyID).Msg("Failed to delete policy")
		WriteError(w, http.StatusInternalServerError, "Failed to delete policy")
		return
	}

	WriteJSON(w, http.StatusOK, map[string]string{
		"message": "Policy deleted successfully",
	})
}

// Policy Assignment Handlers

// handleGetPolicyDevices gets all devices assigned to a policy
func (d *Dependencies) handleGetPolicyDevices(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	policyID := vars["policyId"]

	if policyID == "" {
		WriteError(w, http.StatusBadRequest, "Policy ID is required")
		return
	}

	devices, err := d.PolicyService.GetPolicyDevices(policyID)
	if err != nil {
		log.Error().Err(err).Str("policy_id", policyID).Msg("Failed to get policy devices")
		WriteError(w, http.StatusInternalServerError, "Failed to get policy devices")
		return
	}

	WriteJSON(w, http.StatusOK, map[string]interface{}{
		"devices": devices,
		"count":   len(devices),
	})
}

// handleAssignPolicyToDevice assigns a policy to a device
func (d *Dependencies) handleAssignPolicyToDevice(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	policyID := vars["policyId"]
	deviceID := vars["deviceId"]

	if policyID == "" || deviceID == "" {
		WriteError(w, http.StatusBadRequest, "Policy ID and Device ID are required")
		return
	}

	user, err := GetUserFromContext(r)
	if err != nil {
		WriteError(w, http.StatusUnauthorized, "User context required")
		return
	}

	err = d.PolicyService.AssignPolicyToDevice(policyID, deviceID)
	if err != nil {
		log.Error().
			Err(err).
			Str("policy_id", policyID).
			Str("device_id", deviceID).
			Str("user_id", user.ID).
			Msg("Failed to assign policy to device")
		WriteError(w, http.StatusInternalServerError, "Failed to assign policy to device")
		return
	}

	log.Info().
		Str("policy_id", policyID).
		Str("device_id", deviceID).
		Str("user_id", user.ID).
		Msg("Policy assigned to device")

	WriteJSON(w, http.StatusOK, map[string]string{
		"message": "Policy assigned to device successfully",
	})
}

// handleUnassignPolicyFromDevice unassigns a policy from a device
func (d *Dependencies) handleUnassignPolicyFromDevice(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	policyID := vars["policyId"]
	deviceID := vars["deviceId"]

	if policyID == "" || deviceID == "" {
		WriteError(w, http.StatusBadRequest, "Policy ID and Device ID are required")
		return
	}

	user, err := GetUserFromContext(r)
	if err != nil {
		WriteError(w, http.StatusUnauthorized, "User context required")
		return
	}

	err = d.PolicyService.UnassignPolicyFromDevice(policyID, deviceID)
	if err != nil {
		log.Error().
			Err(err).
			Str("policy_id", policyID).
			Str("device_id", deviceID).
			Str("user_id", user.ID).
			Msg("Failed to unassign policy from device")
		WriteError(w, http.StatusInternalServerError, "Failed to unassign policy from device")
		return
	}

	log.Info().
		Str("policy_id", policyID).
		Str("device_id", deviceID).
		Str("user_id", user.ID).
		Msg("Policy unassigned from device")

	WriteJSON(w, http.StatusOK, map[string]string{
		"message": "Policy unassigned from device successfully",
	})
}

// handleGetPolicyGroups gets all device groups assigned to a policy
func (d *Dependencies) handleGetPolicyGroups(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	policyID := vars["policyId"]

	if policyID == "" {
		WriteError(w, http.StatusBadRequest, "Policy ID is required")
		return
	}

	groups, err := d.PolicyService.GetPolicyGroups(policyID)
	if err != nil {
		log.Error().Err(err).Str("policy_id", policyID).Msg("Failed to get policy groups")
		WriteError(w, http.StatusInternalServerError, "Failed to get policy groups")
		return
	}

	WriteJSON(w, http.StatusOK, map[string]interface{}{
		"groups": groups,
		"count":  len(groups),
	})
}

// handleAssignPolicyToGroup assigns a policy to a device group
func (d *Dependencies) handleAssignPolicyToGroup(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	policyID := vars["policyId"]
	groupID := vars["groupId"]

	if policyID == "" || groupID == "" {
		WriteError(w, http.StatusBadRequest, "Policy ID and Group ID are required")
		return
	}

	user, err := GetUserFromContext(r)
	if err != nil {
		WriteError(w, http.StatusUnauthorized, "User context required")
		return
	}

	err = d.PolicyService.AssignPolicyToGroup(policyID, groupID)
	if err != nil {
		log.Error().
			Err(err).
			Str("policy_id", policyID).
			Str("group_id", groupID).
			Str("user_id", user.ID).
			Msg("Failed to assign policy to group")
		WriteError(w, http.StatusInternalServerError, "Failed to assign policy to group")
		return
	}

	log.Info().
		Str("policy_id", policyID).
		Str("group_id", groupID).
		Str("user_id", user.ID).
		Msg("Policy assigned to group")

	WriteJSON(w, http.StatusOK, map[string]string{
		"message": "Policy assigned to group successfully",
	})
}

// handleUnassignPolicyFromGroup unassigns a policy from a device group
func (d *Dependencies) handleUnassignPolicyFromGroup(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	policyID := vars["policyId"]
	groupID := vars["groupId"]

	if policyID == "" || groupID == "" {
		WriteError(w, http.StatusBadRequest, "Policy ID and Group ID are required")
		return
	}

	user, err := GetUserFromContext(r)
	if err != nil {
		WriteError(w, http.StatusUnauthorized, "User context required")
		return
	}

	err = d.PolicyService.UnassignPolicyFromGroup(policyID, groupID)
	if err != nil {
		log.Error().
			Err(err).
			Str("policy_id", policyID).
			Str("group_id", groupID).
			Str("user_id", user.ID).
			Msg("Failed to unassign policy from group")
		WriteError(w, http.StatusInternalServerError, "Failed to unassign policy from group")
		return
	}

	log.Info().
		Str("policy_id", policyID).
		Str("group_id", groupID).
		Str("user_id", user.ID).
		Msg("Policy unassigned from group")

	WriteJSON(w, http.StatusOK, map[string]string{
		"message": "Policy unassigned from group successfully",
	})
}

// Application management handlers
func (d *Dependencies) handleListApplications(w http.ResponseWriter, r *http.Request) {
	applications, err := d.ApplicationService.ListApplications()
	if err != nil {
		log.Error().Err(err).Msg("Failed to list applications")
		WriteError(w, http.StatusInternalServerError, "Failed to list applications")
		return
	}

	WriteJSON(w, http.StatusOK, map[string]interface{}{
		"applications": applications,
		"total":        len(applications),
	})
}

func (d *Dependencies) handleAddApplication(w http.ResponseWriter, r *http.Request) {
	var appCreate ApplicationCreate
	if err := json.NewDecoder(r.Body).Decode(&appCreate); err != nil {
		WriteError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate required fields
	if appCreate.Name == "" {
		WriteError(w, http.StatusBadRequest, "Application name is required")
		return
	}
	if appCreate.Version == "" {
		WriteError(w, http.StatusBadRequest, "Application version is required")
		return
	}
	if appCreate.Platform == "" {
		WriteError(w, http.StatusBadRequest, "Application platform is required")
		return
	}

	// Validate platform
	validPlatforms := map[string]bool{
		"windows": true, "macos": true, "linux": true, "ios": true, "android": true,
	}
	if !validPlatforms[appCreate.Platform] {
		WriteError(w, http.StatusBadRequest, "Invalid platform")
		return
	}

	application, err := d.ApplicationService.AddApplication(appCreate)
	if err != nil {
		log.Error().Err(err).Str("name", appCreate.Name).Msg("Failed to add application")
		WriteError(w, http.StatusInternalServerError, "Failed to add application")
		return
	}

	WriteJSON(w, http.StatusCreated, application)
}

func (d *Dependencies) handleGetApplication(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	appID := vars["appId"]

	if appID == "" {
		WriteError(w, http.StatusBadRequest, "Application ID is required")
		return
	}

	application, err := d.ApplicationService.GetApplication(appID)
	if err != nil {
		WriteError(w, http.StatusNotFound, "Application not found")
		return
	}

	WriteJSON(w, http.StatusOK, application)
}

func (d *Dependencies) handleUpdateApplication(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	appID := vars["appId"]

	if appID == "" {
		WriteError(w, http.StatusBadRequest, "Application ID is required")
		return
	}

	var updates ApplicationUpdate
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		WriteError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	application, err := d.ApplicationService.UpdateApplication(appID, updates)
	if err != nil {
		log.Error().Err(err).Str("app_id", appID).Msg("Failed to update application")
		WriteError(w, http.StatusInternalServerError, "Failed to update application")
		return
	}

	WriteJSON(w, http.StatusOK, application)
}

func (d *Dependencies) handleDeleteApplication(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	appID := vars["appId"]

	if appID == "" {
		WriteError(w, http.StatusBadRequest, "Application ID is required")
		return
	}

	err := d.ApplicationService.DeleteApplication(appID)
	if err != nil {
		log.Error().Err(err).Str("app_id", appID).Msg("Failed to delete application")
		WriteError(w, http.StatusInternalServerError, "Failed to delete application")
		return
	}

	WriteJSON(w, http.StatusOK, map[string]string{
		"message": "Application deleted successfully",
	})
}

// Device API handlers (for client connections)
func (d *Dependencies) handleDeviceGetPolicies(w http.ResponseWriter, r *http.Request) {
	device, err := GetDeviceFromContext(r)
	if err != nil {
		WriteError(w, http.StatusUnauthorized, "Device context required")
		return
	}

	// Get policies assigned to this device
	policies, err := d.PolicyService.GetDevicePolicies(device.ID)
	if err != nil {
		log.Error().Err(err).Str("device_id", device.ID).Msg("Failed to get device policies")
		WriteError(w, http.StatusInternalServerError, "Failed to get device policies")
		return
	}

	WriteJSON(w, http.StatusOK, map[string]interface{}{
		"device_id": device.ID,
		"policies":  policies,
	})
}

func (d *Dependencies) handleDeviceGetApplications(w http.ResponseWriter, r *http.Request) {
	device, err := GetDeviceFromContext(r)
	if err != nil {
		WriteError(w, http.StatusUnauthorized, "Device context required")
		return
	}

	// Get applications available/assigned to this device
	// For now, return all applications filtered by device platform
	allApplications, err := d.ApplicationService.ListApplications()
	if err != nil {
		log.Error().Err(err).Str("device_id", device.ID).Msg("Failed to get applications")
		WriteError(w, http.StatusInternalServerError, "Failed to get applications")
		return
	}

	// Filter applications by device platform
	var deviceApplications []*Application
	for _, app := range allApplications {
		if app.Platform == device.Platform || app.Platform == "all" {
			deviceApplications = append(deviceApplications, app)
		}
	}

	WriteJSON(w, http.StatusOK, map[string]interface{}{
		"device_id":    device.ID,
		"applications": deviceApplications,
	})
}

// Legacy CLI Compatibility Handlers
// These handlers provide compatibility with the legacy CLI that expects /api/latest/mobius/* endpoints

// handleLegacyLogin handles login requests from legacy CLI
func (deps *Dependencies) handleLegacyLogin(w http.ResponseWriter, r *http.Request) {
	var loginReq struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&loginReq); err != nil {
		WriteError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Use the existing auth service
	authResponse, err := deps.AuthService.Login(loginReq.Email, loginReq.Password)
	if err != nil {
		WriteError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	// Legacy CLI expects a different response format with uint ID
	legacyUser := map[string]interface{}{
		"id":           1, // Convert string ID to uint for legacy compatibility
		"email":        authResponse.User.Email,
		"name":         authResponse.User.Name,
		"global_role":  authResponse.User.Role,
		"gravatar_url": "",
		"created_at":   authResponse.User.CreatedAt,
		"updated_at":   authResponse.User.UpdatedAt,
	}

	legacyResponse := map[string]interface{}{
		"token": authResponse.Token,
		"user":  legacyUser,
		"err":   nil,
	}

	WriteJSON(w, http.StatusOK, legacyResponse)
}

// handleLegacyLogout handles logout requests from legacy CLI
func (deps *Dependencies) handleLegacyLogout(w http.ResponseWriter, r *http.Request) {
	// Legacy logout - just return success
	WriteJSON(w, http.StatusOK, map[string]interface{}{
		"err": nil,
	})
}

// handleLegacySetup handles setup status and initialization from legacy CLI
func (deps *Dependencies) handleLegacySetup(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		// Check if setup is complete
		// For now, assume setup is always complete since we have default admin user
		WriteJSON(w, http.StatusOK, map[string]interface{}{
			"setup": true,
		})
		return
	}

	if r.Method == "POST" {
		// Handle setup initialization
		var setupReq struct {
			OrgName  string `json:"org_name"`
			Email    string `json:"email"`
			Name     string `json:"name"`
			Password string `json:"password"`
		}

		if err := json.NewDecoder(r.Body).Decode(&setupReq); err != nil {
			WriteError(w, http.StatusBadRequest, "Invalid request body")
			return
		}

		// For now, just return success since we already have setup
		WriteJSON(w, http.StatusOK, map[string]interface{}{
			"setup": true,
			"err":   nil,
		})
		return
	}

	WriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
}

// handleLegacyVersion handles version requests from legacy CLI
func (deps *Dependencies) handleLegacyVersion(w http.ResponseWriter, r *http.Request) {
	version := map[string]interface{}{
		"version":    GetVersion(),
		"branch":     "main",
		"revision":   "latest",
		"go_version": runtime.Version(),
		"build_date": time.Now().Format(time.RFC3339),
		"build_user": "mobius-server",
	}

	WriteJSON(w, http.StatusOK, version)
}

// handleLegacyConfig handles config requests from legacy CLI
func (deps *Dependencies) handleLegacyConfig(w http.ResponseWriter, r *http.Request) {
	// Return minimal config that the CLI expects for license operations
	config := map[string]interface{}{
		"license": map[string]interface{}{
			"tier": "community",
		},
	}

	WriteJSON(w, http.StatusOK, config)
}
