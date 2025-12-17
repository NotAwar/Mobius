package client
package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"mobius/internal/logger"
)

// Reporter handles communication with the server
type Reporter struct {
	config     *Config
	log        logger.Logger
	httpClient *http.Client
}

// NewReporter creates a new reporter
func NewReporter(cfg *Config, log logger.Logger) (*Reporter, error) {
	// Create HTTP client with TLS configuration
	tlsConfig := &tls.Config{
		InsecureSkipVerify: !cfg.TLSVerify,
	}
	if cfg.TLSServerName != "" {
		tlsConfig.ServerName = cfg.TLSServerName
	}

	client := &http.Client{
		Timeout: cfg.HeartbeatTimeout,
		Transport: &http.Transport{
			TLSClientConfig:     tlsConfig,
			MaxIdleConns:        10,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
		},
	}

	return &Reporter{
		config:     cfg,
		log:        log,
		httpClient: client,
	}, nil
}

// CheckIn sends a check-in to the server
func (r *Reporter) CheckIn(ctx context.Context, data CheckInData) error {
	url := fmt.Sprintf("%s/api/v1/clients/%s/check-in", r.config.ServerURL, r.config.ClientID)

	payload := map[string]interface{}{
		"timestamp":       data.Timestamp,
		"system_info":     data.SystemInfo,
		"osquery_results": data.OSQueryResults,
		"health_status":   data.HealthStatus,
	}

	return r.sendRequest(ctx, "POST", url, payload)
}

// ReportHardwareInfo sends detailed hardware information
func (r *Reporter) ReportHardwareInfo(ctx context.Context, hwInfo interface{}) error {
	url := fmt.Sprintf("%s/api/v1/clients/%s/hardware", r.config.ServerURL, r.config.ClientID)

	payload := map[string]interface{}{
		"timestamp":      time.Now(),
		"hardware_info":  hwInfo,
	}

	return r.sendRequest(ctx, "PUT", url, payload)
}

// ReportOSQueryResults sends OSQuery results
func (r *Reporter) ReportOSQueryResults(ctx context.Context, queryID string, results interface{}) error {
	url := fmt.Sprintf("%s/api/v1/osquery/results", r.config.ServerURL)

	payload := map[string]interface{}{
		"client_id":  r.config.ClientID,
		"query_id":   queryID,
		"timestamp":  time.Now(),
		"results":    results,
	}

	return r.sendRequest(ctx, "POST", url, payload)
}

// ReportEvent sends an event to the server
func (r *Reporter) ReportEvent(ctx context.Context, eventType string, data interface{}) error {
	url := fmt.Sprintf("%s/api/v1/clients/%s/events", r.config.ServerURL, r.config.ClientID)

	payload := map[string]interface{}{
		"client_id":  r.config.ClientID,
		"event_type": eventType,
		"timestamp":  time.Now(),
		"data":       data,
	}

	return r.sendRequest(ctx, "POST", url, payload)
}

// sendRequest sends an authenticated request to the server
func (r *Reporter) sendRequest(ctx context.Context, method, url string, payload interface{}) error {
	// Marshal payload
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewBuffer(data))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Client-ID", r.config.ClientID)
	req.Header.Set("X-Client-Key", r.config.ClientKey)
	req.Header.Set("User-Agent", "Mobius-Client/1.0")

	// Send request
	resp, err := r.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("server returned status: %d", resp.StatusCode)
	}

	return nil
}

// FetchConfiguration retrieves configuration from server
func (r *Reporter) FetchConfiguration(ctx context.Context) (map[string]interface{}, error) {
	url := fmt.Sprintf("%s/api/v1/clients/%s/configuration", r.config.ServerURL, r.config.ClientID)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-Client-ID", r.config.ClientID)
	req.Header.Set("X-Client-Key", r.config.ClientKey)

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned status: %d", resp.StatusCode)
	}

	var config map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return config, nil
}
