package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog/log"
)

// Enhanced device management handlers with comprehensive MDM functionality

// handleListDevices lists devices with advanced filtering and pagination
func (d *Dependencies) handleListDevices(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters
	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")
	platform := r.URL.Query().Get("platform")
	status := r.URL.Query().Get("status")
	search := r.URL.Query().Get("search") // Search by hostname or UUID

	// Set defaults
	limit := 50
	offset := 0

	if limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 && parsed <= 500 {
			limit = parsed
		}
	}

	if offsetStr != "" {
		if parsed, err := strconv.Atoi(offsetStr); err == nil && parsed >= 0 {
			offset = parsed
		}
	}

	// Validate platform
	validPlatforms := map[string]bool{
		"windows": true, "macos": true, "linux": true, "ios": true, "android": true,
	}
	if platform != "" && !validPlatforms[platform] {
		WriteError(w, http.StatusBadRequest, "Invalid platform. Must be one of: windows, macos, linux, ios, android")
		return
	}

	// Validate status
	validStatuses := map[string]bool{
		"online": true, "offline": true, "enrolled": true, "pending": true, "unenrolled": true,
	}
	if status != "" && !validStatuses[status] {
		WriteError(w, http.StatusBadRequest, "Invalid status. Must be one of: online, offline, enrolled, pending, unenrolled")
		return
	}

	filters := DeviceFilters{
		Limit:    limit,
		Offset:   offset,
		Platform: platform,
		Status:   status,
		Search:   search,
	}

	devices, total, err := d.DeviceService.ListDevices(filters)
	if err != nil {
		log.Error().Err(err).Msg("Failed to list devices")
		WriteError(w, http.StatusInternalServerError, "Failed to list devices")
		return
	}

	log.Debug().
		Int("total", total).
		Int("returned", len(devices)).
		Int("limit", limit).
		Int("offset", offset).
		Msg("Listed devices")

	WriteJSON(w, http.StatusOK, map[string]interface{}{
		"devices": devices,
		"total":   total,
		"limit":   limit,
		"offset":  offset,
	})
}

// handleEnrollDevice handles device enrollment with enhanced validation
func (d *Dependencies) handleEnrollDevice(w http.ResponseWriter, r *http.Request) {
	var enrollment DeviceEnrollmentRequest
	if err := json.NewDecoder(r.Body).Decode(&enrollment); err != nil {
		WriteError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate required fields
	if enrollment.UUID == "" {
		WriteError(w, http.StatusBadRequest, "Device UUID is required")
		return
	}
	if enrollment.Hostname == "" {
		WriteError(w, http.StatusBadRequest, "Device hostname is required")
		return
	}
	if enrollment.Platform == "" {
		WriteError(w, http.StatusBadRequest, "Device platform is required")
		return
	}

	// Validate platform
	validPlatforms := map[string]bool{
		"windows": true, "macos": true, "linux": true, "ios": true, "android": true,
	}
	if !validPlatforms[enrollment.Platform] {
		WriteError(w, http.StatusBadRequest, "Invalid platform")
		return
	}

	// Check license limits
	license, err := d.LicenseService.GetLicense()
	if err != nil {
		log.Error().Err(err).Msg("Failed to check license")
		WriteError(w, http.StatusInternalServerError, "Failed to check license")
		return
	}

	if license.DeviceLimit > 0 && license.DevicesEnrolled >= license.DeviceLimit {
		WriteError(w, http.StatusForbidden, "Device enrollment limit reached for current license")
		return
	}

	// Convert to service model
	serviceEnrollment := DeviceEnrollment{
		UUID:             enrollment.UUID,
		Hostname:         enrollment.Hostname,
		Platform:         enrollment.Platform,
		OSVersion:        enrollment.OSVersion,
		EnrollmentSecret: enrollment.EnrollmentSecret,
		HardwareInfo:     enrollment.HardwareInfo,
		SerialNumber:     enrollment.SerialNumber,
	}

	device, err := d.DeviceService.EnrollDevice(serviceEnrollment)
	if err != nil {
		log.Error().
			Err(err).
			Str("uuid", enrollment.UUID).
			Str("hostname", enrollment.Hostname).
			Msg("Failed to enroll device")
		WriteError(w, http.StatusInternalServerError, "Failed to enroll device")
		return
	}

	log.Info().
		Str("device_id", device.ID).
		Str("uuid", device.UUID).
		Str("hostname", device.Hostname).
		Str("platform", device.Platform).
		Msg("Device enrolled successfully")

	WriteJSON(w, http.StatusCreated, device)
}

// handleGetDevice retrieves detailed device information
func (d *Dependencies) handleGetDevice(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	deviceID := vars["deviceId"]

	if deviceID == "" {
		WriteError(w, http.StatusBadRequest, "Device ID is required")
		return
	}

	device, err := d.DeviceService.GetDevice(deviceID)
	if err != nil {
		log.Debug().Err(err).Str("device_id", deviceID).Msg("Device not found")
		WriteError(w, http.StatusNotFound, "Device not found")
		return
	}

	WriteJSON(w, http.StatusOK, device)
}

// handleUpdateDevice updates device information
func (d *Dependencies) handleUpdateDevice(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	deviceID := vars["deviceId"]

	if deviceID == "" {
		WriteError(w, http.StatusBadRequest, "Device ID is required")
		return
	}

	var updates DeviceUpdates
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		WriteError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	updatedDevice, err := d.DeviceService.UpdateDevice(deviceID, updates)
	if err != nil {
		log.Debug().Err(err).Str("device_id", deviceID).Msg("Device not found for update")
		WriteError(w, http.StatusNotFound, "Device not found")
		return
	}

	log.Info().Str("device_id", deviceID).Msg("Device updated successfully")
	WriteJSON(w, http.StatusOK, updatedDevice)
}

// handleUnenrollDevice removes a device from management
func (d *Dependencies) handleUnenrollDevice(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	deviceID := vars["deviceId"]

	if deviceID == "" {
		WriteError(w, http.StatusBadRequest, "Device ID is required")
		return
	}

	err := d.DeviceService.UnenrollDevice(deviceID)
	if err != nil {
		log.Debug().Err(err).Str("device_id", deviceID).Msg("Device not found for unenrollment")
		WriteError(w, http.StatusNotFound, "Device not found")
		return
	}

	log.Info().Str("device_id", deviceID).Msg("Device unenrolled successfully")
	WriteJSON(w, http.StatusOK, map[string]string{"message": "Device unenrolled successfully"})
}

// handleDeviceCommand sends a command to a device
func (d *Dependencies) handleDeviceCommand(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	deviceID := vars["deviceId"]

	if deviceID == "" {
		WriteError(w, http.StatusBadRequest, "Device ID is required")
		return
	}

	var commandReq DeviceCommandRequest
	if err := json.NewDecoder(r.Body).Decode(&commandReq); err != nil {
		WriteError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate command
	validCommands := map[string]bool{
		"restart":       true,
		"shutdown":      true,
		"lock":          true,
		"wipe":          true,
		"collect_logs":  true,
		"run_osquery":   true,
		"install_app":   true,
		"uninstall_app": true,
	}

	if !validCommands[commandReq.Command] {
		WriteError(w, http.StatusBadRequest, "Invalid command")
		return
	}

	// Check if device exists
	device, err := d.DeviceService.GetDevice(deviceID)
	if err != nil {
		WriteError(w, http.StatusNotFound, "Device not found")
		return
	}

	// Check if device is online
	if device.Status != "online" {
		WriteError(w, http.StatusConflict, "Device is not online")
		return
	}

	user, err := GetUserFromContext(r)
	if err != nil {
		WriteError(w, http.StatusUnauthorized, "User context required")
		return
	}

	// Execute command (this would integrate with device communication layer)
	commandResult, err := d.DeviceService.ExecuteCommand(deviceID, commandReq.Command, commandReq.Parameters)
	if err != nil {
		log.Error().
			Err(err).
			Str("device_id", deviceID).
			Str("command", commandReq.Command).
			Str("user_id", user.ID).
			Msg("Failed to execute device command")
		WriteError(w, http.StatusInternalServerError, "Failed to execute command")
		return
	}

	log.Info().
		Str("device_id", deviceID).
		Str("command", commandReq.Command).
		Str("user_id", user.ID).
		Msg("Device command executed")

	WriteJSON(w, http.StatusOK, commandResult)
}

// handleDeviceOSQuery executes an OSQuery on a device
func (d *Dependencies) handleDeviceOSQuery(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	deviceID := vars["deviceId"]

	if deviceID == "" {
		WriteError(w, http.StatusBadRequest, "Device ID is required")
		return
	}

	var queryReq OSQueryRequest
	if err := json.NewDecoder(r.Body).Decode(&queryReq); err != nil {
		WriteError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if queryReq.Query == "" {
		WriteError(w, http.StatusBadRequest, "OSQuery SQL is required")
		return
	}

	// Validate SQL query (basic security check)
	if !isValidOSQuery(queryReq.Query) {
		WriteError(w, http.StatusBadRequest, "Invalid or dangerous OSQuery")
		return
	}

	user, err := GetUserFromContext(r)
	if err != nil {
		WriteError(w, http.StatusUnauthorized, "User context required")
		return
	}

	// Execute OSQuery
	result, err := d.DeviceService.ExecuteOSQuery(deviceID, queryReq.Query)
	if err != nil {
		log.Error().
			Err(err).
			Str("device_id", deviceID).
			Str("query", queryReq.Query).
			Str("user_id", user.ID).
			Msg("Failed to execute OSQuery")
		WriteError(w, http.StatusInternalServerError, "Failed to execute OSQuery")
		return
	}

	log.Info().
		Str("device_id", deviceID).
		Str("user_id", user.ID).
		Int("rows", len(result.Rows)).
		Msg("OSQuery executed successfully")

	WriteJSON(w, http.StatusOK, result)
}

// Enhanced data models (new types not in router.go)

type DeviceEnrollmentRequest struct {
	UUID             string                 `json:"uuid"`
	Hostname         string                 `json:"hostname"`
	Platform         string                 `json:"platform"`
	OSVersion        string                 `json:"os_version,omitempty"`
	EnrollmentSecret string                 `json:"enrollment_secret,omitempty"`
	HardwareInfo     map[string]interface{} `json:"hardware_info,omitempty"`
	SerialNumber     string                 `json:"serial_number,omitempty"`
}

type DeviceCommandRequest struct {
	Command    string                 `json:"command"`
	Parameters map[string]interface{} `json:"parameters,omitempty"`
}

type OSQueryRequest struct {
	Query string `json:"query"`
}

// Utility functions

// isValidOSQuery performs basic validation on OSQuery SQL
func isValidOSQuery(query string) bool {
	// Basic security checks - prevent dangerous operations
	dangerousKeywords := []string{
		"INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER",
		"EXEC", "EXECUTE", "xp_", "sp_", "--", "/*", "*/",
	}

	queryUpper := strings.ToUpper(query)
	for _, keyword := range dangerousKeywords {
		if strings.Contains(queryUpper, keyword) {
			return false
		}
	}

	// Must start with SELECT
	trimmed := strings.TrimSpace(queryUpper)
	if !strings.HasPrefix(trimmed, "SELECT") {
		return false
	}

	return true
}
