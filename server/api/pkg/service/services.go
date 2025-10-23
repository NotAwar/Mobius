package service

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/notawar/mobius/mobius-server/api"
)

// WebSocketNotifier interface for WebSocket notifications
type WebSocketNotifier interface {
	BroadcastDeviceStatusChange(deviceID, oldStatus, newStatus string)
	BroadcastPolicyAssignment(policyID, deviceID, groupID, action string)
	BroadcastCommandExecution(commandID, deviceID, command, status, result string)
	BroadcastGroupMembership(groupID, deviceID, action string)
}

// NoOpWebSocketNotifier is a no-op implementation for when WebSocket is disabled
type NoOpWebSocketNotifier struct{}

func (n *NoOpWebSocketNotifier) BroadcastDeviceStatusChange(deviceID, oldStatus, newStatus string) {}
func (n *NoOpWebSocketNotifier) BroadcastPolicyAssignment(policyID, deviceID, groupID, action string) {}
func (n *NoOpWebSocketNotifier) BroadcastCommandExecution(commandID, deviceID, command, status, result string) {}
func (n *NoOpWebSocketNotifier) BroadcastGroupMembership(groupID, deviceID, action string) {}

// LicenseServiceImpl implements the LicenseService interface
type LicenseServiceImpl struct {
	// In a real implementation, this would use a database
	currentLicense *api.License
}

// NewLicenseService creates a new license service instance
func NewLicenseService() *LicenseServiceImpl {
	return &LicenseServiceImpl{
		currentLicense: &api.License{
			Valid:           true,
			Tier:            "community",
			DeviceLimit:     10,
			DevicesEnrolled: 0,
			ExpiresAt:       nil, // Community license never expires
			Features: []string{
				"device_management",
				"basic_policies",
			},
		},
	}
}

// GetLicense returns the current license information
func (s *LicenseServiceImpl) GetLicense() (*api.License, error) {
	return s.currentLicense, nil
}

// UpdateLicense updates the license key
func (s *LicenseServiceImpl) UpdateLicense(key string) error {
	// In a real implementation, this would validate the license key
	// against a licensing server or cryptographic signature

	if key == "" {
		return fmt.Errorf("license key cannot be empty")
	}

	// Mock license validation
	switch key {
	case "community-license":
		s.currentLicense = &api.License{
			Valid:           true,
			Tier:            "community",
			DeviceLimit:     10,
			DevicesEnrolled: s.currentLicense.DevicesEnrolled,
			ExpiresAt:       nil,
			Features: []string{
				"device_management",
				"basic_policies",
			},
		}
	case "professional-license":
		expiry := time.Now().AddDate(1, 0, 0) // 1 year from now
		s.currentLicense = &api.License{
			Valid:           true,
			Tier:            "professional",
			DeviceLimit:     100,
			DevicesEnrolled: s.currentLicense.DevicesEnrolled,
			ExpiresAt:       &expiry,
			Features: []string{
				"device_management",
				"advanced_policies",
				"application_management",
				"reporting",
			},
		}
	case "enterprise-license":
		expiry := time.Now().AddDate(1, 0, 0) // 1 year from now
		s.currentLicense = &api.License{
			Valid:           true,
			Tier:            "enterprise",
			DeviceLimit:     -1, // Unlimited
			DevicesEnrolled: s.currentLicense.DevicesEnrolled,
			ExpiresAt:       &expiry,
			Features: []string{
				"device_management",
				"advanced_policies",
				"application_management",
				"reporting",
				"integrations",
				"custom_scripts",
				"priority_support",
			},
		}
	default:
		return fmt.Errorf("invalid license key")
	}

	return nil
}

// ValidateLicense checks if the current license is valid
func (s *LicenseServiceImpl) ValidateLicense() error {
	if !s.currentLicense.Valid {
		return fmt.Errorf("license is invalid")
	}

	if s.currentLicense.ExpiresAt != nil && time.Now().After(*s.currentLicense.ExpiresAt) {
		s.currentLicense.Valid = false
		return fmt.Errorf("license has expired")
	}

	if s.currentLicense.DeviceLimit > 0 && s.currentLicense.DevicesEnrolled >= s.currentLicense.DeviceLimit {
		return fmt.Errorf("device limit exceeded")
	}

	return nil
}

// DeviceServiceImpl implements the DeviceService interface
type DeviceServiceImpl struct {
	// In a real implementation, this would use a database
	devices     map[string]*api.Device
	wsNotifier  WebSocketNotifier
}

// NewDeviceService creates a new device service instance
func NewDeviceService() *DeviceServiceImpl {
	return &DeviceServiceImpl{
		devices:    make(map[string]*api.Device),
		wsNotifier: &NoOpWebSocketNotifier{}, // Default to no-op
	}
}

// SetWebSocketNotifier sets the WebSocket notifier
func (s *DeviceServiceImpl) SetWebSocketNotifier(notifier WebSocketNotifier) {
	s.wsNotifier = notifier
}

// ListDevices returns a filtered list of devices with pagination
func (s *DeviceServiceImpl) ListDevices(filters api.DeviceFilters) ([]*api.Device, int, error) {
	var result []*api.Device

	// Filter devices
	for _, device := range s.devices {
		if filters.Platform != "" && device.Platform != filters.Platform {
			continue
		}
		if filters.Status != "" && device.Status != filters.Status {
			continue
		}
		if filters.Search != "" {
			// Search in hostname or UUID
			searchLower := strings.ToLower(filters.Search)
			hostnameLower := strings.ToLower(device.Hostname)
			uuidLower := strings.ToLower(device.UUID)
			if !strings.Contains(hostnameLower, searchLower) && !strings.Contains(uuidLower, searchLower) {
				continue
			}
		}

		result = append(result, device)
	}

	total := len(result)

	// Apply pagination
	start := filters.Offset
	if start > len(result) {
		start = len(result)
	}

	end := start + filters.Limit
	if end > len(result) {
		end = len(result)
	}

	if start < end {
		result = result[start:end]
	} else {
		result = []*api.Device{}
	}

	return result, total, nil
} // GetDevice returns a device by ID
func (s *DeviceServiceImpl) GetDevice(id string) (*api.Device, error) {
	device, exists := s.devices[id]
	if !exists {
		return nil, fmt.Errorf("device not found")
	}
	return device, nil
}

// EnrollDevice enrolls a new device
func (s *DeviceServiceImpl) EnrollDevice(enrollment api.DeviceEnrollment) (*api.Device, error) {
	// Generate a new device ID using the UUID
	deviceID := enrollment.UUID

	device := &api.Device{
		ID:         deviceID,
		UUID:       enrollment.UUID,
		Hostname:   enrollment.Hostname,
		Platform:   enrollment.Platform,
		OSVersion:  enrollment.OSVersion,
		Status:     "online", // Set to online so commands can be executed
		LastSeen:   time.Now(),
		EnrolledAt: time.Now(),
		Labels:     make(map[string]string),
	}

	s.devices[deviceID] = device
	
	// Notify WebSocket clients of device enrollment
	s.wsNotifier.BroadcastDeviceStatusChange(deviceID, "", "online")
	
	return device, nil
}

// UnenrollDevice removes a device from management
func (s *DeviceServiceImpl) UnenrollDevice(id string) error {
	_, exists := s.devices[id]
	if !exists {
		return fmt.Errorf("device not found")
	}

	delete(s.devices, id)
	return nil
}

// UpdateDevice updates device information
func (s *DeviceServiceImpl) UpdateDevice(id string, updates api.DeviceUpdates) (*api.Device, error) {
	device, exists := s.devices[id]
	if !exists {
		return nil, fmt.Errorf("device not found")
	}

	// Apply updates
	if updates.Hostname != nil {
		device.Hostname = *updates.Hostname
	}
	if updates.OSVersion != nil {
		device.OSVersion = *updates.OSVersion
	}
	if updates.Labels != nil {
		device.Labels = *updates.Labels
	}

	device.LastSeen = time.Now()
	s.devices[id] = device
	return device, nil
}

// ExecuteCommand executes a command on a device
func (s *DeviceServiceImpl) ExecuteCommand(deviceID, command string, parameters map[string]interface{}) (*api.DeviceCommandResult, error) {
	device, exists := s.devices[deviceID]
	if !exists {
		return nil, fmt.Errorf("device not found")
	}

	if device.Status != "online" {
		return nil, fmt.Errorf("device is not online")
	}

	// Generate command ID
	commandID := generateID()
	now := time.Now()

	// In a real implementation, this would queue the command for the device
	// and return a command result that gets updated asynchronously
	result := &api.DeviceCommandResult{
		ID:      commandID,
		Command: command,
		Status:  "completed", // Mock immediate completion
		Result: map[string]interface{}{
			"success": true,
			"message": fmt.Sprintf("Command '%s' executed successfully on device %s", command, device.Hostname),
		},
		ExecutedAt: &now,
	}

	// Notify WebSocket clients of command execution
	s.wsNotifier.BroadcastCommandExecution(commandID, deviceID, command, "completed", 
		fmt.Sprintf("Command '%s' executed successfully", command))

	// Update device last seen
	device.LastSeen = time.Now()
	s.devices[deviceID] = device

	return result, nil
}

// ExecuteOSQuery executes an OSQuery on a device
func (s *DeviceServiceImpl) ExecuteOSQuery(deviceID, query string) (*api.OSQueryResult, error) {
	device, exists := s.devices[deviceID]
	if !exists {
		return nil, fmt.Errorf("device not found")
	}

	if device.Status != "online" {
		return nil, fmt.Errorf("device is not online")
	}

	// Mock OSQuery result - in real implementation this would execute actual OSQuery
	result := &api.OSQueryResult{
		Query:    query,
		Columns:  []string{"name", "version", "platform"},
		Duration: 150, // milliseconds
	}

	// Generate mock data based on query
	if query == "SELECT name, version, platform FROM osquery_info;" {
		result.Rows = []map[string]interface{}{
			{
				"name":     "osqueryd",
				"version":  "5.10.2",
				"platform": device.Platform,
			},
		}
	} else {
		// Default mock result
		result.Rows = []map[string]interface{}{
			{
				"name":     "mock_data",
				"version":  "1.0.0",
				"platform": device.Platform,
			},
		}
	}

	// Update device last seen
	device.LastSeen = time.Now()
	s.devices[deviceID] = device

	return result, nil
}

// DeviceGroupServiceImpl implements the DeviceGroupService interface
type DeviceGroupServiceImpl struct {
	groups       map[string]*api.DeviceGroup
	groupDevices map[string][]string // group ID -> device IDs
	wsNotifier   WebSocketNotifier
}

// NewDeviceGroupService creates a new device group service instance
func NewDeviceGroupService() *DeviceGroupServiceImpl {
	return &DeviceGroupServiceImpl{
		groups:       make(map[string]*api.DeviceGroup),
		groupDevices: make(map[string][]string),
		wsNotifier:   &NoOpWebSocketNotifier{}, // Default to no-op
	}
}

// SetWebSocketNotifier sets the WebSocket notifier
func (s *DeviceGroupServiceImpl) SetWebSocketNotifier(notifier WebSocketNotifier) {
	s.wsNotifier = notifier
}

// ListDeviceGroups returns all device groups
func (s *DeviceGroupServiceImpl) ListDeviceGroups() ([]*api.DeviceGroup, error) {
	groups := make([]*api.DeviceGroup, 0, len(s.groups))
	for _, group := range s.groups {
		// Update device count
		group.DeviceCount = len(s.groupDevices[group.ID])
		groups = append(groups, group)
	}
	return groups, nil
}

// GetDeviceGroup returns a specific device group
func (s *DeviceGroupServiceImpl) GetDeviceGroup(id string) (*api.DeviceGroup, error) {
	group, exists := s.groups[id]
	if !exists {
		return nil, fmt.Errorf("device group not found")
	}
	// Update device count
	group.DeviceCount = len(s.groupDevices[id])
	return group, nil
}

// CreateDeviceGroup creates a new device group
func (s *DeviceGroupServiceImpl) CreateDeviceGroup(create api.DeviceGroupCreate) (*api.DeviceGroup, error) {
	groupID := generateID()
	now := time.Now()

	group := &api.DeviceGroup{
		ID:          groupID,
		Name:        create.Name,
		Description: create.Description,
		DeviceCount: 0,
		Filters:     create.Filters,
		Labels:      create.Labels,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if group.Filters == nil {
		group.Filters = make(map[string]string)
	}
	if group.Labels == nil {
		group.Labels = make(map[string]string)
	}

	s.groups[groupID] = group
	s.groupDevices[groupID] = []string{}

	return group, nil
}

// UpdateDeviceGroup updates a device group
func (s *DeviceGroupServiceImpl) UpdateDeviceGroup(id string, updates api.DeviceGroupUpdate) (*api.DeviceGroup, error) {
	group, exists := s.groups[id]
	if !exists {
		return nil, fmt.Errorf("device group not found")
	}

	// Apply updates
	if updates.Name != nil {
		group.Name = *updates.Name
	}
	if updates.Description != nil {
		group.Description = *updates.Description
	}
	if updates.Filters != nil {
		group.Filters = *updates.Filters
	}
	if updates.Labels != nil {
		group.Labels = *updates.Labels
	}

	group.UpdatedAt = time.Now()
	s.groups[id] = group

	return group, nil
}

// DeleteDeviceGroup deletes a device group
func (s *DeviceGroupServiceImpl) DeleteDeviceGroup(id string) error {
	_, exists := s.groups[id]
	if !exists {
		return fmt.Errorf("device group not found")
	}

	delete(s.groups, id)
	delete(s.groupDevices, id)
	return nil
}

// GetGroupDevices returns all devices in a group
func (s *DeviceGroupServiceImpl) GetGroupDevices(groupID string) ([]*api.Device, error) {
	_, exists := s.groups[groupID]
	if !exists {
		return nil, fmt.Errorf("device group not found")
	}

	deviceIDs := s.groupDevices[groupID]
	// In a real implementation, this would fetch devices from DeviceService
	// For now, return mock data
	devices := make([]*api.Device, 0, len(deviceIDs))
	
	// This is a simplified implementation - in reality we'd need to 
	// coordinate with DeviceService to get actual device objects
	for _, deviceID := range deviceIDs {
		// Mock device data
		device := &api.Device{
			ID:       deviceID,
			UUID:     deviceID,
			Hostname: fmt.Sprintf("device-%s", deviceID[:8]),
			Platform: "macos",
			Status:   "online",
			LastSeen: time.Now(),
		}
		devices = append(devices, device)
	}

	return devices, nil
}

// AddDeviceToGroup adds a device to a group
func (s *DeviceGroupServiceImpl) AddDeviceToGroup(groupID, deviceID string) error {
	_, exists := s.groups[groupID]
	if !exists {
		return fmt.Errorf("device group not found")
	}

	// Check if device is already in the group
	deviceIDs := s.groupDevices[groupID]
	for _, id := range deviceIDs {
		if id == deviceID {
			return fmt.Errorf("device already in group")
		}
	}

	// Add device to group
	s.groupDevices[groupID] = append(s.groupDevices[groupID], deviceID)
	
	// Notify WebSocket clients of group membership change
	s.wsNotifier.BroadcastGroupMembership(groupID, deviceID, "added")
	
	return nil
}

// RemoveDeviceFromGroup removes a device from a group
func (s *DeviceGroupServiceImpl) RemoveDeviceFromGroup(groupID, deviceID string) error {
	_, exists := s.groups[groupID]
	if !exists {
		return fmt.Errorf("device group not found")
	}

	// Find and remove device from group
	deviceIDs := s.groupDevices[groupID]
	for i, id := range deviceIDs {
		if id == deviceID {
			// Remove device from slice
			s.groupDevices[groupID] = append(deviceIDs[:i], deviceIDs[i+1:]...)
			
			// Notify WebSocket clients of group membership change
			s.wsNotifier.BroadcastGroupMembership(groupID, deviceID, "removed")
			
			return nil
		}
	}

	return fmt.Errorf("device not found in group")
}

// GetDeviceGroups returns all groups that contain a specific device
func (s *DeviceGroupServiceImpl) GetDeviceGroups(deviceID string) ([]*api.DeviceGroup, error) {
	groups := make([]*api.DeviceGroup, 0)
	
	for groupID, deviceIDs := range s.groupDevices {
		for _, id := range deviceIDs {
			if id == deviceID {
				if group, exists := s.groups[groupID]; exists {
					group.DeviceCount = len(s.groupDevices[groupID])
					groups = append(groups, group)
				}
				break
			}
		}
	}
	
	return groups, nil
}

// PolicyServiceImpl implements the PolicyService interface
type PolicyServiceImpl struct {
	policies       map[string]*api.Policy
	devicePolicies map[string][]string // device ID -> policy IDs
	groupPolicies  map[string][]string // group ID -> policy IDs
	wsNotifier     WebSocketNotifier
}

// NewPolicyService creates a new policy service instance
func NewPolicyService() *PolicyServiceImpl {
	return &PolicyServiceImpl{
		policies:       make(map[string]*api.Policy),
		devicePolicies: make(map[string][]string),
		groupPolicies:  make(map[string][]string),
		wsNotifier:     &NoOpWebSocketNotifier{}, // Default to no-op
	}
}

// SetWebSocketNotifier sets the WebSocket notifier
func (s *PolicyServiceImpl) SetWebSocketNotifier(notifier WebSocketNotifier) {
	s.wsNotifier = notifier
}

// ListPolicies returns all policies
func (s *PolicyServiceImpl) ListPolicies() ([]*api.Policy, error) {
	var result []*api.Policy
	for _, policy := range s.policies {
		result = append(result, policy)
	}
	return result, nil
}

// GetPolicy returns a policy by ID
func (s *PolicyServiceImpl) GetPolicy(id string) (*api.Policy, error) {
	policy, exists := s.policies[id]
	if !exists {
		return nil, fmt.Errorf("policy not found")
	}
	return policy, nil
}

// CreatePolicy creates a new policy
func (s *PolicyServiceImpl) CreatePolicy(policyCreate api.PolicyCreate) (*api.Policy, error) {
	policy := &api.Policy{
		ID:            generateID(),
		Name:          policyCreate.Name,
		Description:   policyCreate.Description,
		Platform:      policyCreate.Platform,
		Enabled:       true,
		Configuration: policyCreate.Configuration,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	s.policies[policy.ID] = policy
	return policy, nil
}

// UpdatePolicy updates an existing policy
func (s *PolicyServiceImpl) UpdatePolicy(id string, updates api.PolicyUpdate) (*api.Policy, error) {
	policy, exists := s.policies[id]
	if !exists {
		return nil, fmt.Errorf("policy not found")
	}

	// Apply updates
	if updates.Name != nil {
		policy.Name = *updates.Name
	}
	if updates.Description != nil {
		policy.Description = *updates.Description
	}
	if updates.Enabled != nil {
		policy.Enabled = *updates.Enabled
	}
	if updates.Configuration != nil {
		policy.Configuration = *updates.Configuration
	}

	policy.UpdatedAt = time.Now()
	return policy, nil
}

// DeletePolicy deletes a policy
func (s *PolicyServiceImpl) DeletePolicy(id string) error {
	_, exists := s.policies[id]
	if !exists {
		return fmt.Errorf("policy not found")
	}

	delete(s.policies, id)

	// Remove from device assignments
	for deviceID, policyIDs := range s.devicePolicies {
		var newPolicyIDs []string
		for _, policyID := range policyIDs {
			if policyID != id {
				newPolicyIDs = append(newPolicyIDs, policyID)
			}
		}
		s.devicePolicies[deviceID] = newPolicyIDs
	}

	return nil
}

// GetDevicePolicies returns policies assigned to a device
func (s *PolicyServiceImpl) GetDevicePolicies(deviceID string) ([]*api.Policy, error) {
	policyIDs, exists := s.devicePolicies[deviceID]
	if !exists {
		return []*api.Policy{}, nil
	}

	var result []*api.Policy
	for _, policyID := range policyIDs {
		if policy, exists := s.policies[policyID]; exists {
			result = append(result, policy)
		}
	}

	return result, nil
}

// AssignDevicePolicies assigns policies to a device
func (s *PolicyServiceImpl) AssignDevicePolicies(deviceID string, policyIDs []string) error {
	// Validate that all policies exist
	for _, policyID := range policyIDs {
		if _, exists := s.policies[policyID]; !exists {
			return fmt.Errorf("policy %s not found", policyID)
		}
	}

	s.devicePolicies[deviceID] = policyIDs
	return nil
}

// GetPolicyDevices returns all devices assigned to a policy
func (s *PolicyServiceImpl) GetPolicyDevices(policyID string) ([]*api.Device, error) {
	_, exists := s.policies[policyID]
	if !exists {
		return nil, fmt.Errorf("policy not found")
	}

	devices := make([]*api.Device, 0)
	
	// Find all devices with this policy assigned
	for deviceID, policyIDs := range s.devicePolicies {
		for _, assignedPolicyID := range policyIDs {
			if assignedPolicyID == policyID {
				// Mock device data - in real implementation, get from DeviceService
				device := &api.Device{
					ID:       deviceID,
					UUID:     deviceID,
					Hostname: fmt.Sprintf("device-%s", deviceID[:8]),
					Platform: "macos",
					Status:   "online",
					LastSeen: time.Now(),
				}
				devices = append(devices, device)
				break
			}
		}
	}
	
	return devices, nil
}

// AssignPolicyToDevice assigns a single policy to a device
func (s *PolicyServiceImpl) AssignPolicyToDevice(policyID, deviceID string) error {
	_, exists := s.policies[policyID]
	if !exists {
		return fmt.Errorf("policy not found")
	}

	// Get current policies for device
	currentPolicies := s.devicePolicies[deviceID]
	
	// Check if policy is already assigned
	for _, existingPolicyID := range currentPolicies {
		if existingPolicyID == policyID {
			return fmt.Errorf("policy already assigned to device")
		}
	}
	
	// Add policy to device
	s.devicePolicies[deviceID] = append(currentPolicies, policyID)
	
	// Notify WebSocket clients of policy assignment
	s.wsNotifier.BroadcastPolicyAssignment(policyID, deviceID, "", "assigned")
	
	return nil
}

// UnassignPolicyFromDevice removes a policy from a device
func (s *PolicyServiceImpl) UnassignPolicyFromDevice(policyID, deviceID string) error {
	currentPolicies := s.devicePolicies[deviceID]
	
	// Find and remove the policy
	for i, existingPolicyID := range currentPolicies {
		if existingPolicyID == policyID {
			// Remove policy from slice
			s.devicePolicies[deviceID] = append(currentPolicies[:i], currentPolicies[i+1:]...)
			return nil
		}
	}
	
	return fmt.Errorf("policy not assigned to device")
}

// GetPolicyGroups returns all device groups assigned to a policy
func (s *PolicyServiceImpl) GetPolicyGroups(policyID string) ([]*api.DeviceGroup, error) {
	_, exists := s.policies[policyID]
	if !exists {
		return nil, fmt.Errorf("policy not found")
	}

	groups := make([]*api.DeviceGroup, 0)
	
	// Find all groups with this policy assigned
	for groupID, policyIDs := range s.groupPolicies {
		for _, assignedPolicyID := range policyIDs {
			if assignedPolicyID == policyID {
				// Mock group data - in real implementation, get from DeviceGroupService
				group := &api.DeviceGroup{
					ID:          groupID,
					Name:        fmt.Sprintf("group-%s", groupID[:8]),
					Description: "Mock device group",
					DeviceCount: 0,
					CreatedAt:   time.Now(),
					UpdatedAt:   time.Now(),
				}
				groups = append(groups, group)
				break
			}
		}
	}
	
	return groups, nil
}

// AssignPolicyToGroup assigns a policy to a device group
func (s *PolicyServiceImpl) AssignPolicyToGroup(policyID, groupID string) error {
	_, exists := s.policies[policyID]
	if !exists {
		return fmt.Errorf("policy not found")
	}

	// Get current policies for group
	currentPolicies := s.groupPolicies[groupID]
	
	// Check if policy is already assigned
	for _, existingPolicyID := range currentPolicies {
		if existingPolicyID == policyID {
			return fmt.Errorf("policy already assigned to group")
		}
	}
	
	// Add policy to group
	s.groupPolicies[groupID] = append(currentPolicies, policyID)
	
	// Notify WebSocket clients of policy assignment
	s.wsNotifier.BroadcastPolicyAssignment(policyID, "", groupID, "assigned")
	
	return nil
}

// UnassignPolicyFromGroup removes a policy from a device group
func (s *PolicyServiceImpl) UnassignPolicyFromGroup(policyID, groupID string) error {
	currentPolicies := s.groupPolicies[groupID]
	
	// Find and remove the policy
	for i, existingPolicyID := range currentPolicies {
		if existingPolicyID == policyID {
			// Remove policy from slice
			s.groupPolicies[groupID] = append(currentPolicies[:i], currentPolicies[i+1:]...)
			return nil
		}
	}
	
	return fmt.Errorf("policy not assigned to group")
}

// Utility function to generate IDs (in a real implementation, use UUIDs)
func generateID() string {
	return fmt.Sprintf("id_%d", time.Now().UnixNano())
}

// ApplicationServiceImpl implements the ApplicationService interface
type ApplicationServiceImpl struct {
	applications map[string]*api.Application
}

// NewApplicationService creates a new application service instance
func NewApplicationService() *ApplicationServiceImpl {
	return &ApplicationServiceImpl{
		applications: make(map[string]*api.Application),
	}
}

// ListApplications returns all applications
func (s *ApplicationServiceImpl) ListApplications() ([]*api.Application, error) {
	var result []*api.Application
	for _, app := range s.applications {
		result = append(result, app)
	}
	return result, nil
}

// GetApplication returns an application by ID
func (s *ApplicationServiceImpl) GetApplication(id string) (*api.Application, error) {
	app, exists := s.applications[id]
	if !exists {
		return nil, fmt.Errorf("application not found")
	}
	return app, nil
}

// AddApplication adds a new application
func (s *ApplicationServiceImpl) AddApplication(appCreate api.ApplicationCreate) (*api.Application, error) {
	app := &api.Application{
		ID:        generateID(),
		Name:      appCreate.Name,
		Version:   appCreate.Version,
		Platform:  appCreate.Platform,
		Size:      int64(len(appCreate.Package)),
		Checksum:  fmt.Sprintf("%x", sha256.Sum256(appCreate.Package)),
		CreatedAt: time.Now(),
	}

	s.applications[app.ID] = app
	return app, nil
}

// UpdateApplication updates an existing application
func (s *ApplicationServiceImpl) UpdateApplication(id string, updates api.ApplicationUpdate) (*api.Application, error) {
	app, exists := s.applications[id]
	if !exists {
		return nil, fmt.Errorf("application not found")
	}

	if updates.Name != nil {
		app.Name = *updates.Name
	}
	if updates.Version != nil {
		app.Version = *updates.Version
	}

	return app, nil
}

// DeleteApplication deletes an application
func (s *ApplicationServiceImpl) DeleteApplication(id string) error {
	_, exists := s.applications[id]
	if !exists {
		return fmt.Errorf("application not found")
	}

	delete(s.applications, id)
	return nil
}

// AuthServiceImpl implements the AuthService interface
type AuthServiceImpl struct {
	users        map[string]*api.User
	tokens       map[string]*api.User
	deviceTokens map[string]*api.Device
}

// NewAuthService creates a new auth service instance
func NewAuthService() *AuthServiceImpl {
	service := &AuthServiceImpl{
		users:        make(map[string]*api.User),
		tokens:       make(map[string]*api.User),
		deviceTokens: make(map[string]*api.Device),
	}

	// Create default admin user
	adminUser := &api.User{
		ID:        "admin-1",
		Email:     "admin@mobius.local",
		Name:      "Administrator",
		Role:      "admin",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	service.users["admin@mobius.local"] = adminUser

	return service
}

// Login authenticates a user and returns a token
func (s *AuthServiceImpl) Login(email, password string) (*api.AuthResponse, error) {
	user, exists := s.users[email]
	if !exists {
		return nil, fmt.Errorf("invalid credentials")
	}

	// In a real implementation, check password hash
	if password != "admin123" { // Mock password validation
		return nil, fmt.Errorf("invalid credentials")
	}

	// Generate token (in a real implementation, use JWT)
	token := fmt.Sprintf("token_%s_%d", user.ID, time.Now().Unix())
	s.tokens[token] = user

	return &api.AuthResponse{
		Token:     token,
		ExpiresAt: time.Now().Add(24 * time.Hour),
		User:      user,
	}, nil
}

// ValidateToken validates a user token
func (s *AuthServiceImpl) ValidateToken(token string) (*api.User, error) {
	user, exists := s.tokens[token]
	if !exists {
		return nil, fmt.Errorf("invalid token")
	}
	return user, nil
}

// ValidateDeviceToken validates a device token
func (s *AuthServiceImpl) ValidateDeviceToken(token string) (*api.Device, error) {
	device, exists := s.deviceTokens[token]
	if !exists {
		return nil, fmt.Errorf("invalid device token")
	}
	return device, nil
}

// GroupServiceImpl implements the GroupService interface
type GroupServiceImpl struct {
	groups map[string]*api.Group
	mu     sync.RWMutex
}

// NewGroupService creates a new group service instance
func NewGroupService() *GroupServiceImpl {
	service := &GroupServiceImpl{
		groups: make(map[string]*api.Group),
	}

	// Create sample groups
	sampleGroups := []*api.Group{
		{
			ID:          "group-1",
			Name:        "Development Team",
			Description: "Devices for development team members",
			DeviceIDs:   []string{"device-1", "device-2"},
			CreatedAt:   time.Now().Add(-24 * time.Hour),
			UpdatedAt:   time.Now().Add(-1 * time.Hour),
		},
		{
			ID:          "group-2",
			Name:        "QA Team",
			Description: "Quality assurance testing devices",
			DeviceIDs:   []string{"device-3"},
			CreatedAt:   time.Now().Add(-12 * time.Hour),
			UpdatedAt:   time.Now(),
		},
	}

	for _, group := range sampleGroups {
		service.groups[group.ID] = group
	}

	return service
}

// CreateGroup creates a new device group
func (s *GroupServiceImpl) CreateGroup(group api.Group) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if group.ID == "" {
		group.ID = fmt.Sprintf("group-%d", time.Now().Unix())
	}
	group.CreatedAt = time.Now()
	group.UpdatedAt = time.Now()

	s.groups[group.ID] = &group
	return nil
}

// GetGroups returns all device groups
func (s *GroupServiceImpl) GetGroups() ([]api.Group, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	groups := make([]api.Group, 0, len(s.groups))
	for _, group := range s.groups {
		groups = append(groups, *group)
	}
	return groups, nil
}

// GetGroup returns a specific device group by ID
func (s *GroupServiceImpl) GetGroup(id string) (*api.Group, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	group, exists := s.groups[id]
	if !exists {
		return nil, fmt.Errorf("group not found")
	}
	return group, nil
}

// UpdateGroup updates an existing device group
func (s *GroupServiceImpl) UpdateGroup(id string, group api.Group) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, exists := s.groups[id]
	if !exists {
		return fmt.Errorf("group not found")
	}

	// Update fields
	existing.Name = group.Name
	existing.Description = group.Description
	existing.UpdatedAt = time.Now()

	return nil
}

// DeleteGroup removes a device group
func (s *GroupServiceImpl) DeleteGroup(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.groups[id]; !exists {
		return fmt.Errorf("group not found")
	}

	delete(s.groups, id)
	return nil
}

// AddDeviceToGroup adds a device to a group
func (s *GroupServiceImpl) AddDeviceToGroup(groupID, deviceID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	group, exists := s.groups[groupID]
	if !exists {
		return fmt.Errorf("group not found")
	}

	// Check if device is already in group
	for _, id := range group.DeviceIDs {
		if id == deviceID {
			return nil // Already in group
		}
	}

	group.DeviceIDs = append(group.DeviceIDs, deviceID)
	group.UpdatedAt = time.Now()
	return nil
}

// RemoveDeviceFromGroup removes a device from a group
func (s *GroupServiceImpl) RemoveDeviceFromGroup(groupID, deviceID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	group, exists := s.groups[groupID]
	if !exists {
		return fmt.Errorf("group not found")
	}

	// Find and remove device from group
	for i, id := range group.DeviceIDs {
		if id == deviceID {
			group.DeviceIDs = append(group.DeviceIDs[:i], group.DeviceIDs[i+1:]...)
			group.UpdatedAt = time.Now()
			return nil
		}
	}

	return fmt.Errorf("device not in group")
}
