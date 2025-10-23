package api

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog/log"
)

// Device Group Management Handlers

// handleListDeviceGroups lists all device groups with optional filtering
func (d *Dependencies) handleListDeviceGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := d.DeviceGroupService.ListDeviceGroups()
	if err != nil {
		log.Error().Err(err).Msg("Failed to list device groups")
		WriteError(w, http.StatusInternalServerError, "Failed to list device groups")
		return
	}

	WriteJSON(w, http.StatusOK, map[string]interface{}{
		"device_groups": groups,
		"count":         len(groups),
	})
}

// handleCreateDeviceGroup creates a new device group
func (d *Dependencies) handleCreateDeviceGroup(w http.ResponseWriter, r *http.Request) {
	var req DeviceGroupCreate
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate required fields
	if req.Name == "" {
		WriteError(w, http.StatusBadRequest, "Group name is required")
		return
	}

	user, err := GetUserFromContext(r)
	if err != nil {
		WriteError(w, http.StatusUnauthorized, "User context required")
		return
	}

	group, err := d.DeviceGroupService.CreateDeviceGroup(req)
	if err != nil {
		log.Error().
			Err(err).
			Str("user_id", user.ID).
			Str("group_name", req.Name).
			Msg("Failed to create device group")
		WriteError(w, http.StatusInternalServerError, "Failed to create device group")
		return
	}

	log.Info().
		Str("group_id", group.ID).
		Str("group_name", group.Name).
		Str("user_id", user.ID).
		Msg("Device group created")

	WriteJSON(w, http.StatusCreated, group)
}

// handleGetDeviceGroup retrieves a specific device group
func (d *Dependencies) handleGetDeviceGroup(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	groupID := vars["groupId"]

	if groupID == "" {
		WriteError(w, http.StatusBadRequest, "Group ID is required")
		return
	}

	group, err := d.DeviceGroupService.GetDeviceGroup(groupID)
	if err != nil {
		WriteError(w, http.StatusNotFound, "Device group not found")
		return
	}

	WriteJSON(w, http.StatusOK, group)
}

// handleUpdateDeviceGroup updates a device group
func (d *Dependencies) handleUpdateDeviceGroup(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	groupID := vars["groupId"]

	if groupID == "" {
		WriteError(w, http.StatusBadRequest, "Group ID is required")
		return
	}

	var updates DeviceGroupUpdate
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		WriteError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	user, err := GetUserFromContext(r)
	if err != nil {
		WriteError(w, http.StatusUnauthorized, "User context required")
		return
	}

	updatedGroup, err := d.DeviceGroupService.UpdateDeviceGroup(groupID, updates)
	if err != nil {
		log.Error().
			Err(err).
			Str("group_id", groupID).
			Str("user_id", user.ID).
			Msg("Failed to update device group")
		WriteError(w, http.StatusInternalServerError, "Failed to update device group")
		return
	}

	log.Info().
		Str("group_id", groupID).
		Str("user_id", user.ID).
		Msg("Device group updated")

	WriteJSON(w, http.StatusOK, updatedGroup)
}

// handleDeleteDeviceGroup deletes a device group
func (d *Dependencies) handleDeleteDeviceGroup(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	groupID := vars["groupId"]

	if groupID == "" {
		WriteError(w, http.StatusBadRequest, "Group ID is required")
		return
	}

	user, err := GetUserFromContext(r)
	if err != nil {
		WriteError(w, http.StatusUnauthorized, "User context required")
		return
	}

	err = d.DeviceGroupService.DeleteDeviceGroup(groupID)
	if err != nil {
		log.Error().
			Err(err).
			Str("group_id", groupID).
			Str("user_id", user.ID).
			Msg("Failed to delete device group")
		WriteError(w, http.StatusInternalServerError, "Failed to delete device group")
		return
	}

	log.Info().
		Str("group_id", groupID).
		Str("user_id", user.ID).
		Msg("Device group deleted")

	WriteJSON(w, http.StatusOK, map[string]string{
		"message": "Device group deleted successfully",
	})
}

// handleGetGroupDevices lists all devices in a specific group
func (d *Dependencies) handleGetGroupDevices(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	groupID := vars["groupId"]

	if groupID == "" {
		WriteError(w, http.StatusBadRequest, "Group ID is required")
		return
	}

	devices, err := d.DeviceGroupService.GetGroupDevices(groupID)
	if err != nil {
		log.Error().Err(err).Str("group_id", groupID).Msg("Failed to get group devices")
		WriteError(w, http.StatusInternalServerError, "Failed to get group devices")
		return
	}

	WriteJSON(w, http.StatusOK, map[string]interface{}{
		"devices": devices,
		"count":   len(devices),
	})
}

// handleAddDeviceToGroup adds a device to a group
func (d *Dependencies) handleAddDeviceToGroup(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	groupID := vars["groupId"]
	deviceID := vars["deviceId"]

	if groupID == "" || deviceID == "" {
		WriteError(w, http.StatusBadRequest, "Group ID and Device ID are required")
		return
	}

	user, err := GetUserFromContext(r)
	if err != nil {
		WriteError(w, http.StatusUnauthorized, "User context required")
		return
	}

	err = d.DeviceGroupService.AddDeviceToGroup(groupID, deviceID)
	if err != nil {
		log.Error().
			Err(err).
			Str("group_id", groupID).
			Str("device_id", deviceID).
			Str("user_id", user.ID).
			Msg("Failed to add device to group")
		WriteError(w, http.StatusInternalServerError, "Failed to add device to group")
		return
	}

	log.Info().
		Str("group_id", groupID).
		Str("device_id", deviceID).
		Str("user_id", user.ID).
		Msg("Device added to group")

	WriteJSON(w, http.StatusOK, map[string]string{
		"message": "Device added to group successfully",
	})
}

// handleRemoveDeviceFromGroup removes a device from a group
func (d *Dependencies) handleRemoveDeviceFromGroup(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	groupID := vars["groupId"]
	deviceID := vars["deviceId"]

	if groupID == "" || deviceID == "" {
		WriteError(w, http.StatusBadRequest, "Group ID and Device ID are required")
		return
	}

	user, err := GetUserFromContext(r)
	if err != nil {
		WriteError(w, http.StatusUnauthorized, "User context required")
		return
	}

	err = d.DeviceGroupService.RemoveDeviceFromGroup(groupID, deviceID)
	if err != nil {
		log.Error().
			Err(err).
			Str("group_id", groupID).
			Str("device_id", deviceID).
			Str("user_id", user.ID).
			Msg("Failed to remove device from group")
		WriteError(w, http.StatusInternalServerError, "Failed to remove device from group")
		return
	}

	log.Info().
		Str("group_id", groupID).
		Str("device_id", deviceID).
		Str("user_id", user.ID).
		Msg("Device removed from group")

	WriteJSON(w, http.StatusOK, map[string]string{
		"message": "Device removed from group successfully",
	})
}
