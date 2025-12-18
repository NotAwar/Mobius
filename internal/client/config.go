package client

import (
	"errors"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the client configuration
type Config struct {
	// Server connection
	ServerURL string `yaml:"server_url"`
	ClientID  string `yaml:"client_id"`
	ClientKey string `yaml:"client_key"`
	
	// Check-in settings
	CheckInInterval  time.Duration `yaml:"check_in_interval"`
	HeartbeatTimeout time.Duration `yaml:"heartbeat_timeout"`
	
	// OSQuery settings
	OSQuerySocket      string        `yaml:"osquery_socket"`
	OSQueryInterval    time.Duration `yaml:"osquery_interval"`
	OSQueryLogPath     string        `yaml:"osquery_log_path"`
	EnableOSQuery      bool          `yaml:"enable_osquery"`
	OSQueryPacksPath   string        `yaml:"osquery_packs_path"`
	OSQueryFlagsPath   string        `yaml:"osquery_flags_path"`
	OSQueryExtensions  []string      `yaml:"osquery_extensions"`
	OSQueryTablePlugin string        `yaml:"osquery_table_plugin"`
	
	// SSH settings (for remote management)
	SSHPort          int      `yaml:"ssh_port"`
	SSHAuthorizedKeys []string `yaml:"ssh_authorized_keys"`
	EnableSSH        bool     `yaml:"enable_ssh"`
	
	// Security
	TLSCert       string `yaml:"tls_cert"`
	TLSKey        string `yaml:"tls_key"`
	TLSVerify     bool   `yaml:"tls_verify"`
	TLSServerName string `yaml:"tls_server_name"`
	
	// Logging
	LogLevel  string `yaml:"log_level"`
	LogFile   string `yaml:"log_file"`
	LogFormat string `yaml:"log_format"` // json, text
	
	// System info collection
	CollectHardwareInfo  bool `yaml:"collect_hardware_info"`
	CollectSoftwareInfo  bool `yaml:"collect_software_info"`
	CollectNetworkInfo   bool `yaml:"collect_network_info"`
	HardwareInfoInterval time.Duration `yaml:"hardware_info_interval"`
	
	// Auto-update
	EnableAutoUpdate bool   `yaml:"enable_auto_update"`
	UpdateChannel    string `yaml:"update_channel"` // stable, beta, dev
	
	// Resource limits (to keep service lightweight)
	MaxMemoryMB int `yaml:"max_memory_mb"`
	MaxCPUPct   int `yaml:"max_cpu_pct"`
}

// DefaultConfig returns a configuration with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		CheckInInterval:     5 * time.Minute,
		HeartbeatTimeout:    30 * time.Second,
		OSQuerySocket:       "/var/osquery/osquery.sock",
		OSQueryInterval:     60 * time.Second,
		OSQueryLogPath:      "/var/log/osquery/osqueryd.results.log",
		EnableOSQuery:       true,
		OSQueryPacksPath:    "/etc/mobius/osquery/packs",
		OSQueryFlagsPath:    "/etc/mobius/osquery/osquery.flags",
		SSHPort:             2222,
		EnableSSH:           true,
		TLSVerify:           true,
		LogLevel:            "info",
		LogFile:             "/var/log/mobius/client.log",
		LogFormat:           "json",
		CollectHardwareInfo: true,
		CollectSoftwareInfo: true,
		CollectNetworkInfo:  true,
		HardwareInfoInterval: 1 * time.Hour,
		EnableAutoUpdate:    false,
		UpdateChannel:       "stable",
		MaxMemoryMB:         50,  // Keep under 50MB
		MaxCPUPct:           5,   // Keep under 5% CPU
	}
}

// LoadConfig loads configuration from file
func LoadConfig(path string) (*Config, error) {
	// Start with defaults
	cfg := DefaultConfig()
	
	// Check if file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, fmt.Errorf("config file not found: %s", path)
	}
	
	// Read file
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}
	
	// Parse YAML
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}
	
	return cfg, nil
}

// Validate checks if configuration is valid
func (c *Config) Validate() error {
	if c.ServerURL == "" {
		return errors.New("server_url is required")
	}
	if c.ClientID == "" {
		return errors.New("client_id is required (client not enrolled)")
	}
	if c.ClientKey == "" {
		return errors.New("client_key is required (client not enrolled)")
	}
	if c.CheckInInterval < 10*time.Second {
		return errors.New("check_in_interval must be at least 10 seconds")
	}
	if c.MaxMemoryMB < 10 {
		return errors.New("max_memory_mb must be at least 10MB")
	}
	if c.MaxCPUPct < 1 || c.MaxCPUPct > 100 {
		return errors.New("max_cpu_pct must be between 1 and 100")
	}
	return nil
}

// Save writes configuration to file
func (c *Config) Save(path string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}
	
	return nil
}