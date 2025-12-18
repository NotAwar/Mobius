package client

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"
)

// EnrollmentRequest represents the request sent to enroll a client
type EnrollmentRequest struct {
	EnrollmentKey string     `json:"enrollment_key"`
	Hostname      string     `json:"hostname"`
	SystemInfo    SystemInfo `json:"system_info"`
}

// EnrollmentResponse represents the server's response
type EnrollmentResponse struct {
	ClientID  string `json:"client_id"`
	ClientKey string `json:"client_key"`
	ServerURL string `json:"server_url"`
	Message   string `json:"message"`
}

// Enroll enrolls the client with the server
func Enroll(serverURL, enrollmentKey, configPath string) error {
	// Collect system information
	collector := &SystemInfoCollector{
		config: DefaultConfig(),
	}
	sysInfo := collector.Collect()

	// Get hostname
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown-" + uuid.New().String()[:8]
	}

	// Prepare enrollment request
	req := EnrollmentRequest{
		EnrollmentKey: enrollmentKey,
		Hostname:      hostname,
		SystemInfo:    sysInfo,
	}

	// Marshal request
	data, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false, // Should verify in production
			},
		},
	}

	// Send enrollment request
	enrollURL := serverURL + "/api/v1/clients/enroll"
	resp, err := client.Post(enrollURL, "application/json", bytes.NewBuffer(data))
	if err != nil {
		return fmt.Errorf("failed to send enrollment request: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("enrollment failed with status: %d", resp.StatusCode)
	}

	// Parse response
	var enrollResp EnrollmentResponse
	if err := json.NewDecoder(resp.Body).Decode(&enrollResp); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	// Create configuration with enrollment info
	cfg := DefaultConfig()
	cfg.ServerURL = serverURL
	cfg.ClientID = enrollResp.ClientID
	cfg.ClientKey = enrollResp.ClientKey

	// Ensure config directory exists
	configDir := "/etc/mobius"
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Save configuration
	if err := cfg.Save(configPath); err != nil {
		return fmt.Errorf("failed to save configuration: %w", err)
	}

	fmt.Printf("✓ Enrollment successful\n")
	fmt.Printf("  Client ID: %s\n", enrollResp.ClientID)
	fmt.Printf("  Configuration saved to: %s\n", configPath)
	if enrollResp.Message != "" {
		fmt.Printf("  Message: %s\n", enrollResp.Message)
	}

	return nil
}
