package service

import (
	"testing"

	"github.com/notawar/mobius/mobius-server/api"
)

func TestLicenseService(t *testing.T) {
	service := NewLicenseService()

	t.Run("GetLicense returns default community license", func(t *testing.T) {
		license, err := service.GetLicense()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !license.Valid {
			t.Errorf("expected license to be valid")
		}
		if license.Tier != "community" {
			t.Errorf("expected tier 'community', got '%s'", license.Tier)
		}
		if license.DeviceLimit != 10 {
			t.Errorf("expected device limit 10, got %d", license.DeviceLimit)
		}
		if license.ExpiresAt != nil {
			t.Errorf("expected community license to never expire, got %v", license.ExpiresAt)
		}
	})

	t.Run("UpdateLicense to professional", func(t *testing.T) {
		err := service.UpdateLicense("professional-license")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		license, err := service.GetLicense()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if license.Tier != "professional" {
			t.Errorf("expected tier 'professional', got '%s'", license.Tier)
		}
		if license.DeviceLimit != 100 {
			t.Errorf("expected device limit 100, got %d", license.DeviceLimit)
		}
		if license.ExpiresAt == nil {
			t.Errorf("expected professional license to have expiry date")
		}
	})

	t.Run("UpdateLicense to enterprise", func(t *testing.T) {
		err := service.UpdateLicense("enterprise-license")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		license, err := service.GetLicense()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if license.Tier != "enterprise" {
			t.Errorf("expected tier 'enterprise', got '%s'", license.Tier)
		}
		if license.DeviceLimit != -1 {
			t.Errorf("expected unlimited devices (-1), got %d", license.DeviceLimit)
		}
	})

	t.Run("UpdateLicense with invalid key", func(t *testing.T) {
		err := service.UpdateLicense("invalid-key")
		if err == nil {
			t.Fatalf("expected error for invalid license key")
		}
	})

	t.Run("ValidateLicense", func(t *testing.T) {
		// Set to community license
		service.UpdateLicense("community-license")

		err := service.ValidateLicense()
		if err != nil {
			t.Errorf("unexpected error validating community license: %v", err)
		}
	})
}

func TestDeviceService(t *testing.T) {
	t.Run("ListDevices empty initially", func(t *testing.T) {
		service := NewDeviceService()
		devices, total, err := service.ListDevices(api.DeviceFilters{
			Limit:  50,
			Offset: 0,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(devices) != 0 {
			t.Errorf("expected 0 devices, got %d", len(devices))
		}
		if total != 0 {
			t.Errorf("expected total 0, got %d", total)
		}
	})

	t.Run("EnrollDevice", func(t *testing.T) {
		service := NewDeviceService()
		enrollment := api.DeviceEnrollment{
			UUID:             "test-device-uuid",
			Hostname:         "test-workstation",
			Platform:         "windows",
			OSVersion:        "Windows 11 Pro",
			EnrollmentSecret: "secret123",
		}

		device, err := service.EnrollDevice(enrollment)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if device.UUID != enrollment.UUID {
			t.Errorf("expected UUID '%s', got '%s'", enrollment.UUID, device.UUID)
		}
		if device.Hostname != enrollment.Hostname {
			t.Errorf("expected hostname '%s', got '%s'", enrollment.Hostname, device.Hostname)
		}
		if device.Platform != enrollment.Platform {
			t.Errorf("expected platform '%s', got '%s'", enrollment.Platform, device.Platform)
		}
		if device.Status != "online" {
			t.Errorf("expected status 'online', got '%s'", device.Status)
		}
	})

	t.Run("GetDevice", func(t *testing.T) {
		service := NewDeviceService()
		enrollment := api.DeviceEnrollment{
			UUID:             "test-device-uuid",
			Hostname:         "test-workstation",
			Platform:         "windows",
			OSVersion:        "Windows 11 Pro",
			EnrollmentSecret: "secret123",
		}
		device, _ := service.EnrollDevice(enrollment)

		retrieved, err := service.GetDevice(device.ID)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if retrieved.ID != device.ID {
			t.Errorf("expected device ID '%s', got '%s'", device.ID, retrieved.ID)
		}
	})

	t.Run("GetDevice non-existent", func(t *testing.T) {
		service := NewDeviceService()
		_, err := service.GetDevice("non-existent-id")
		if err == nil {
			t.Fatalf("expected error for non-existent device")
		}
	})

	t.Run("ListDevices with enrolled device", func(t *testing.T) {
		service := NewDeviceService()
		enrollment := api.DeviceEnrollment{
			UUID:             "test-device-uuid",
			Hostname:         "test-workstation",
			Platform:         "windows",
			OSVersion:        "Windows 11 Pro",
			EnrollmentSecret: "secret123",
		}
		service.EnrollDevice(enrollment)

		devices, total, err := service.ListDevices(api.DeviceFilters{
			Limit:  50,
			Offset: 0,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(devices) != 1 {
			t.Errorf("expected 1 device, got %d", len(devices))
		}
		if total != 1 {
			t.Errorf("expected total 1, got %d", total)
		}
	})

	t.Run("ListDevices with platform filter", func(t *testing.T) {
		service := NewDeviceService()
		enrollment := api.DeviceEnrollment{
			UUID:             "test-device-uuid",
			Hostname:         "test-workstation",
			Platform:         "windows",
			OSVersion:        "Windows 11 Pro",
			EnrollmentSecret: "secret123",
		}
		service.EnrollDevice(enrollment)

		devices, total, err := service.ListDevices(api.DeviceFilters{
			Limit:    50,
			Offset:   0,
			Platform: "windows",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(devices) != 1 {
			t.Errorf("expected 1 windows device, got %d", len(devices))
		}
		if total != 1 {
			t.Errorf("expected total 1, got %d", total)
		}
	})

	t.Run("ListDevices with non-matching platform filter", func(t *testing.T) {
		service := NewDeviceService()
		enrollment := api.DeviceEnrollment{
			UUID:             "test-device-uuid",
			Hostname:         "test-workstation",
			Platform:         "windows",
			OSVersion:        "Windows 11 Pro",
			EnrollmentSecret: "secret123",
		}
		service.EnrollDevice(enrollment)

		devices, total, err := service.ListDevices(api.DeviceFilters{
			Limit:    50,
			Offset:   0,
			Platform: "macos",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(devices) != 0 {
			t.Errorf("expected 0 macos devices, got %d", len(devices))
		}
		if total != 0 {
			t.Errorf("expected total 0, got %d", total)
		}
	})

	t.Run("UpdateDevice", func(t *testing.T) {
		service := NewDeviceService()
		enrollment := api.DeviceEnrollment{
			UUID:             "test-device-uuid",
			Hostname:         "test-workstation",
			Platform:         "windows",
			OSVersion:        "Windows 11 Pro",
			EnrollmentSecret: "secret123",
		}
		device, _ := service.EnrollDevice(enrollment)

		newHostname := "updated-workstation"
		newOSVersion := "Windows 11 Pro 22H2"

		updates := api.DeviceUpdates{
			Hostname:  &newHostname,
			OSVersion: &newOSVersion,
		}

		updated, err := service.UpdateDevice(device.ID, updates)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if updated.Hostname != newHostname {
			t.Errorf("expected hostname '%s', got '%s'", newHostname, updated.Hostname)
		}
		if updated.OSVersion != newOSVersion {
			t.Errorf("expected OS version '%s', got '%s'", newOSVersion, updated.OSVersion)
		}
		if updated.Status != "online" {
			t.Errorf("expected status 'online' after update, got '%s'", updated.Status)
		}
	})

	t.Run("UnenrollDevice", func(t *testing.T) {
		service := NewDeviceService()
		enrollment := api.DeviceEnrollment{
			UUID:             "test-device-uuid",
			Hostname:         "test-workstation",
			Platform:         "windows",
			OSVersion:        "Windows 11",
			EnrollmentSecret: "secret123",
		}

		// Enroll device first
		device, err := service.EnrollDevice(enrollment)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Unenroll device
		err = service.UnenrollDevice(device.ID)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Verify device is removed
		_, err = service.GetDevice(device.ID)
		if err == nil {
			t.Errorf("expected error when getting unenrolled device")
		}
	})

	t.Run("ExecuteCommand", func(t *testing.T) {
		service := NewDeviceService()
		enrollment := api.DeviceEnrollment{
			UUID:             "test-device-uuid",
			Hostname:         "test-workstation",
			Platform:         "windows",
			OSVersion:        "Windows 11",
			EnrollmentSecret: "secret123",
		}

		// Enroll device
		device, err := service.EnrollDevice(enrollment)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Set device to online status (simulate device check-in)
		device.Status = "online"
		service.devices[device.ID] = device

		// Execute command
		result, err := service.ExecuteCommand(device.ID, "restart", nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.Command != "restart" {
			t.Errorf("expected command 'restart', got '%s'", result.Command)
		}
		if result.Status != "completed" {
			t.Errorf("expected status 'completed', got '%s'", result.Status)
		}

		// Test with offline device
		device.Status = "offline"
		service.devices[device.ID] = device

		_, err = service.ExecuteCommand(device.ID, "restart", nil)
		if err == nil {
			t.Errorf("expected error when executing command on offline device")
		}
	})

	t.Run("ExecuteOSQuery", func(t *testing.T) {
		service := NewDeviceService()
		enrollment := api.DeviceEnrollment{
			UUID:             "test-device-uuid",
			Hostname:         "test-workstation",
			Platform:         "linux",
			OSVersion:        "Ubuntu 22.04",
			EnrollmentSecret: "secret123",
		}

		// Enroll device
		device, err := service.EnrollDevice(enrollment)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Set device to online status
		device.Status = "online"
		service.devices[device.ID] = device

		// Execute OSQuery
		query := "SELECT name, version, platform FROM osquery_info;"
		result, err := service.ExecuteOSQuery(device.ID, query)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.Query != query {
			t.Errorf("expected query '%s', got '%s'", query, result.Query)
		}
		if len(result.Columns) == 0 {
			t.Errorf("expected columns in result")
		}
		if len(result.Rows) == 0 {
			t.Errorf("expected rows in result")
		}

		// Test with offline device
		device.Status = "offline"
		service.devices[device.ID] = device

		_, err = service.ExecuteOSQuery(device.ID, query)
		if err == nil {
			t.Errorf("expected error when executing OSQuery on offline device")
		}
	})

	t.Run("ListDevicesWithSearch", func(t *testing.T) {
		// Create a completely fresh service for this test
		service := NewDeviceService()

		// Enroll multiple devices with unique identifiers to avoid any collision
		enrollments := []api.DeviceEnrollment{
			{UUID: "search-test-device-1", Hostname: "search-laptop-001", Platform: "windows", OSVersion: "Windows 11", EnrollmentSecret: "secret1"},
			{UUID: "search-test-device-2", Hostname: "search-server-002", Platform: "linux", OSVersion: "Ubuntu 22.04", EnrollmentSecret: "secret2"},
			{UUID: "search-test-device-3", Hostname: "search-workstation-003", Platform: "macos", OSVersion: "macOS 14", EnrollmentSecret: "secret3"},
		}

		for _, enrollment := range enrollments {
			_, err := service.EnrollDevice(enrollment)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		}

		// Test search by hostname
		filters := api.DeviceFilters{
			Limit:  10,
			Offset: 0,
			Search: "laptop",
		}
		devices, total, err := service.ListDevices(filters)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if total != 1 {
			t.Errorf("expected 1 device with search 'laptop', got %d", total)
		}
		if len(devices) != 1 || devices[0].Hostname != "search-laptop-001" {
			t.Errorf("expected search-laptop-001 in search results")
		}

		// Test search by UUID
		filters.Search = "search-test-device-2"
		devices, total, err = service.ListDevices(filters)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if total != 1 {
			t.Errorf("expected 1 device with search 'search-test-device-2', got %d", total)
		}
		if len(devices) != 1 || devices[0].UUID != "search-test-device-2" {
			t.Errorf("expected search-test-device-2 in search results")
		}
	})
}

func TestPolicyService(t *testing.T) {
	service := NewPolicyService()

	t.Run("ListPolicies empty initially", func(t *testing.T) {
		policies, err := service.ListPolicies()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(policies) != 0 {
			t.Errorf("expected 0 policies, got %d", len(policies))
		}
	})

	var policyID string
	t.Run("CreatePolicy", func(t *testing.T) {
		policyCreate := api.PolicyCreate{
			Name:        "Test Security Policy",
			Description: "Test policy for unit tests",
			Platform:    "windows",
			Configuration: map[string]interface{}{
				"require_encryption": true,
				"password_length":    8,
			},
		}

		policy, err := service.CreatePolicy(policyCreate)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		policyID = policy.ID
		if policy.Name != policyCreate.Name {
			t.Errorf("expected name '%s', got '%s'", policyCreate.Name, policy.Name)
		}
		if !policy.Enabled {
			t.Errorf("expected policy to be enabled by default")
		}
	})

	t.Run("GetPolicy", func(t *testing.T) {
		policy, err := service.GetPolicy(policyID)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if policy.ID != policyID {
			t.Errorf("expected policy ID '%s', got '%s'", policyID, policy.ID)
		}
	})

	t.Run("ListPolicies with created policy", func(t *testing.T) {
		policies, err := service.ListPolicies()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(policies) != 1 {
			t.Errorf("expected 1 policy, got %d", len(policies))
		}
	})

	t.Run("UpdatePolicy", func(t *testing.T) {
		newName := "Updated Security Policy"
		enabled := false

		updates := api.PolicyUpdate{
			Name:    &newName,
			Enabled: &enabled,
		}

		policy, err := service.UpdatePolicy(policyID, updates)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if policy.Name != newName {
			t.Errorf("expected name '%s', got '%s'", newName, policy.Name)
		}
		if policy.Enabled != false {
			t.Errorf("expected policy to be disabled")
		}
	})

	t.Run("AssignDevicePolicies", func(t *testing.T) {
		deviceID := "test-device-1"
		policyIDs := []string{policyID}

		err := service.AssignDevicePolicies(deviceID, policyIDs)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Verify assignment
		policies, err := service.GetDevicePolicies(deviceID)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(policies) != 1 {
			t.Errorf("expected 1 policy assigned, got %d", len(policies))
		}
		if policies[0].ID != policyID {
			t.Errorf("expected policy ID '%s', got '%s'", policyID, policies[0].ID)
		}
	})

	t.Run("GetDevicePolicies for non-existent device", func(t *testing.T) {
		policies, err := service.GetDevicePolicies("non-existent-device")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(policies) != 0 {
			t.Errorf("expected 0 policies for non-existent device, got %d", len(policies))
		}
	})

	t.Run("DeletePolicy", func(t *testing.T) {
		err := service.DeletePolicy(policyID)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Verify policy is gone
		_, err = service.GetPolicy(policyID)
		if err == nil {
			t.Fatalf("expected error for deleted policy")
		}

		// Verify device assignment is removed
		policies, err := service.GetDevicePolicies("test-device-1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(policies) != 0 {
			t.Errorf("expected 0 policies after deletion, got %d", len(policies))
		}
	})
}

func TestApplicationService(t *testing.T) {
	service := NewApplicationService()

	t.Run("ListApplications empty initially", func(t *testing.T) {
		apps, err := service.ListApplications()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(apps) != 0 {
			t.Errorf("expected 0 applications, got %d", len(apps))
		}
	})

	var appID string
	t.Run("AddApplication", func(t *testing.T) {
		appCreate := api.ApplicationCreate{
			Name:     "Test Application",
			Version:  "1.0.0",
			Platform: "windows",
			Package:  []byte("mock-binary-data"),
		}

		app, err := service.AddApplication(appCreate)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		appID = app.ID
		if app.Name != appCreate.Name {
			t.Errorf("expected name '%s', got '%s'", appCreate.Name, app.Name)
		}
		if app.Size != int64(len(appCreate.Package)) {
			t.Errorf("expected size %d, got %d", len(appCreate.Package), app.Size)
		}
		if app.Checksum == "" {
			t.Errorf("expected checksum to be calculated")
		}
	})

	t.Run("GetApplication", func(t *testing.T) {
		app, err := service.GetApplication(appID)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if app.ID != appID {
			t.Errorf("expected app ID '%s', got '%s'", appID, app.ID)
		}
	})

	t.Run("UpdateApplication", func(t *testing.T) {
		newName := "Updated Test Application"
		newVersion := "1.1.0"

		updates := api.ApplicationUpdate{
			Name:    &newName,
			Version: &newVersion,
		}

		app, err := service.UpdateApplication(appID, updates)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if app.Name != newName {
			t.Errorf("expected name '%s', got '%s'", newName, app.Name)
		}
		if app.Version != newVersion {
			t.Errorf("expected version '%s', got '%s'", newVersion, app.Version)
		}
	})

	t.Run("DeleteApplication", func(t *testing.T) {
		err := service.DeleteApplication(appID)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Verify application is gone
		_, err = service.GetApplication(appID)
		if err == nil {
			t.Fatalf("expected error for deleted application")
		}
	})
}

func TestAuthService(t *testing.T) {
	service := NewAuthService()

	t.Run("Login with valid credentials", func(t *testing.T) {
		authResp, err := service.Login("admin@mobius.local", "admin123")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if authResp.Token == "" {
			t.Errorf("expected token to be generated")
		}
		if authResp.User == nil {
			t.Fatalf("expected user to be returned")
		}
		if authResp.User.Email != "admin@mobius.local" {
			t.Errorf("expected email 'admin@mobius.local', got '%s'", authResp.User.Email)
		}
		if authResp.User.Role != "admin" {
			t.Errorf("expected role 'admin', got '%s'", authResp.User.Role)
		}
	})

	t.Run("Login with invalid credentials", func(t *testing.T) {
		_, err := service.Login("admin@mobius.local", "wrong-password")
		if err == nil {
			t.Fatalf("expected error for invalid credentials")
		}
	})

	t.Run("Login with non-existent user", func(t *testing.T) {
		_, err := service.Login("nonexistent@mobius.local", "admin123")
		if err == nil {
			t.Fatalf("expected error for non-existent user")
		}
	})

	t.Run("ValidateToken", func(t *testing.T) {
		// First login to get a token
		authResp, _ := service.Login("admin@mobius.local", "admin123")

		user, err := service.ValidateToken(authResp.Token)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if user.Email != "admin@mobius.local" {
			t.Errorf("expected email 'admin@mobius.local', got '%s'", user.Email)
		}
	})

	t.Run("ValidateToken with invalid token", func(t *testing.T) {
		_, err := service.ValidateToken("invalid-token")
		if err == nil {
			t.Fatalf("expected error for invalid token")
		}
	})

	t.Run("ValidateDeviceToken with non-existent token", func(t *testing.T) {
		_, err := service.ValidateDeviceToken("device-token-123")
		if err == nil {
			t.Fatalf("expected error for non-existent device token")
		}
	})
}
