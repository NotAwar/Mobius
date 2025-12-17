package client

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"sync"
	"time"

	"mobius/internal/logger"
)

// OSQueryManager manages OSQuery integration
type OSQueryManager struct {
	config  *Config
	log     logger.Logger
	results map[string]interface{}
	mu      sync.RWMutex
	running bool
}

// NewOSQueryManager creates a new OSQuery manager
func NewOSQueryManager(cfg *Config, log logger.Logger) (*OSQueryManager, error) {
	return &OSQueryManager{
		config:  cfg,
		log:     log,
		results: make(map[string]interface{}),
	}, nil
}

// Start starts the OSQuery manager
func (o *OSQueryManager) Start(ctx context.Context) error {
	o.mu.Lock()
	if o.running {
		o.mu.Unlock()
		return fmt.Errorf("OSQuery manager already running")
	}
	o.running = true
	o.mu.Unlock()

	o.log.Info("Starting OSQuery manager")

	// Start collection loop
	go o.collectionLoop(ctx)

	return nil
}

// Stop stops the OSQuery manager
func (o *OSQueryManager) Stop() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.running = false
	o.log.Info("Stopped OSQuery manager")
}

// collectionLoop periodically collects OSQuery results
func (o *OSQueryManager) collectionLoop(ctx context.Context) {
	ticker := time.NewTicker(o.config.OSQueryInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			o.collectResults()
		}
	}
}

// collectResults collects results from OSQuery
func (o *OSQueryManager) collectResults() {
	// Run basic system queries
	queries := map[string]string{
		"os_version":      "SELECT * FROM os_version;",
		"system_info":     "SELECT * FROM system_info;",
		"processes":       "SELECT pid, name, state, cmdline FROM processes WHERE state != 'S' LIMIT 10;",
		"logged_in_users": "SELECT * FROM logged_in_users;",
		"listening_ports": "SELECT * FROM listening_ports LIMIT 20;",
	}

	results := make(map[string]interface{})
	for name, query := range queries {
		if result, err := o.executeQuery(query); err == nil {
			results[name] = result
		} else {
			o.log.Warn("Query failed", "query", name, "error", err)
		}
	}

	o.mu.Lock()
	o.results = results
	o.mu.Unlock()
}

// executeQuery executes an OSQuery query
func (o *OSQueryManager) executeQuery(query string) ([]map[string]interface{}, error) {
	// Use osqueryi to execute the query
	cmd := exec.Command("osqueryi", "--json", query)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to execute query: %w", err)
	}

	var results []map[string]interface{}
	if err := json.Unmarshal(output, &results); err != nil {
		return nil, fmt.Errorf("failed to parse results: %w", err)
	}

	return results, nil
}

// GetRecentResults returns the most recent query results
func (o *OSQueryManager) GetRecentResults() map[string]interface{} {
	o.mu.RLock()
	defer o.mu.RUnlock()

	// Return a copy
	results := make(map[string]interface{})
	for k, v := range o.results {
		results[k] = v
	}
	return results
}

// ExecuteQuery executes a custom query (called remotely via API)
func (o *OSQueryManager) ExecuteQuery(query string) ([]map[string]interface{}, error) {
	o.log.Info("Executing custom query", "query", query)
	return o.executeQuery(query)
}
