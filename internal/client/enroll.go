package client
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
























































}	return nil	}		fmt.Printf("  Message: %s\n", enrollResp.Message)	if enrollResp.Message != "" {	fmt.Printf("  Configuration saved to: %s\n", configPath)	fmt.Printf("  Client ID: %s\n", enrollResp.ClientID)	fmt.Printf("✓ Enrollment successful\n")	}		return fmt.Errorf("failed to save configuration: %w", err)	if err := cfg.Save(configPath); err != nil {	// Save configuration	}		return fmt.Errorf("failed to create config directory: %w", err)	if err := os.MkdirAll(configDir, 0755); err != nil {	configDir := "/etc/mobius"	// Ensure config directory exists	cfg.ClientKey = enrollResp.ClientKey	cfg.ClientID = enrollResp.ClientID	cfg.ServerURL = serverURL	cfg := DefaultConfig()	// Create configuration with enrollment info	}		return fmt.Errorf("failed to decode response: %w", err)	if err := json.NewDecoder(resp.Body).Decode(&enrollResp); err != nil {	var enrollResp EnrollmentResponse	// Parse response	}		return fmt.Errorf("enrollment failed with status: %d", resp.StatusCode)	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {	// Check response status	defer resp.Body.Close()	}		return fmt.Errorf("failed to send enrollment request: %w", err)	if err != nil {	resp, err := client.Post(enrollURL, "application/json", bytes.NewBuffer(data))	enrollURL := serverURL + "/api/v1/clients/enroll"	// Send enrollment request	}		},			},				InsecureSkipVerify: false, // Should verify in production			TLSClientConfig: &tls.Config{		Transport: &http.Transport{		Timeout: 30 * time.Second,	client := &http.Client{	// Create HTTP client with timeout