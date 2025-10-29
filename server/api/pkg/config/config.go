package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/notawar/mobius/server/api/pkg/database"
)

// AppConfig holds all application configuration
type AppConfig struct {
	// Server configuration
	Server ServerConfig

	// Database configuration
	Database database.Config

	// JWT configuration
	JWT JWTConfig

	// Command configuration
	Commands CommandConfig

	// Backup configuration
	Backup BackupConfig

	// Cleanup configuration
	Cleanup CleanupConfig

	// Static file serving directory (for frontend)
	StaticDir string

	// MySQL configuration (Score-compatible)
	MySQL MySQLConfig

	// Redis configuration (Score-compatible)
	Redis RedisConfig

	// JSON logging (Score-compatible)
	LoggingJSON bool
}

// MySQLConfig holds MySQL database settings (Score-compatible)
type MySQLConfig struct {
	Address  string // Format: "host:port"
	Database string
	Username string
	Password string
}

// RedisConfig holds Redis cache settings (Score-compatible)
type RedisConfig struct {
	Address  string // Format: "host:port"
	Password string
}

// ServerConfig holds server-specific settings
type ServerConfig struct {
	Port         int
	Host         string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

// JWTConfig holds JWT token settings
type JWTConfig struct {
	Secret           string
	AccessExpiry     time.Duration // Configurable by admin
	RefreshExpiry    time.Duration
	SigningAlgorithm string // "HS256" or "RS256"
}

// CommandConfig holds device command settings
type CommandConfig struct {
	DefaultTimeout time.Duration
	MaxTimeout     time.Duration
}

// BackupConfig holds database backup settings
type BackupConfig struct {
	Enabled   bool
	Schedule  string // Cron format
	Directory string
}

// CleanupConfig holds data retention settings
type CleanupConfig struct {
	Enabled              bool
	CommandRetentionDays int
	OSQueryRetentionDays int
	TokenRetentionHours  int
	DeletedDevicesDays   int
}

// LoadConfig loads configuration from environment variables and defaults
// Supports both legacy MOBIUS_* variables and Score specification variables
func LoadConfig() (*AppConfig, error) {
	// Determine server address - Score uses MOBIUS_SERVER_ADDRESS
	serverAddress := getEnv("MOBIUS_SERVER_ADDRESS", "")
	var host string
	var port int

	if serverAddress != "" {
		// Parse MOBIUS_SERVER_ADDRESS (format: "host:port")
		parts := strings.Split(serverAddress, ":")
		if len(parts) == 2 {
			host = parts[0]
			if parsedPort, err := strconv.Atoi(parts[1]); err == nil {
				port = parsedPort
			} else {
				port = 8081 // fallback on parse error
			}
		} else {
			// Invalid format, use defaults
			host = "0.0.0.0"
			port = 8081
		}
	} else {
		// Fallback to legacy MOBIUS_HOST:MOBIUS_PORT format
		host = getEnv("MOBIUS_HOST", "0.0.0.0")
		port = getEnvAsInt("MOBIUS_PORT", 8081)
	}

	config := &AppConfig{
		Server: ServerConfig{
			Port:         port,
			Host:         host,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
		},
		Database: database.Config{
			Path:              getEnv("MOBIUS_DB_PATH", "./mobius.db"),
			Driver:            getEnv("MOBIUS_DB_DRIVER", "sqlite3"),
			MaxOpenConns:      getEnvAsInt("MOBIUS_DB_MAX_OPEN_CONNS", 25),
			MaxIdleConns:      getEnvAsInt("MOBIUS_DB_MAX_IDLE_CONNS", 5),
			ConnMaxLifetime:   5 * time.Minute,
			EnableForeignKeys: true,
			EnableWAL:         true,
		},
		JWT: JWTConfig{
			Secret:           getEnv("MOBIUS_JWT_SECRET", generateDefaultSecret()),
			AccessExpiry:     time.Duration(getEnvAsInt("MOBIUS_JWT_ACCESS_EXPIRY_MINUTES", 15)) * time.Minute,
			RefreshExpiry:    time.Duration(getEnvAsInt("MOBIUS_JWT_REFRESH_EXPIRY_DAYS", 7)) * 24 * time.Hour,
			SigningAlgorithm: "HS256", // Industry standard for self-hosted
		},
		Commands: CommandConfig{
			DefaultTimeout: time.Duration(getEnvAsInt("MOBIUS_COMMAND_TIMEOUT_MINUTES", 5)) * time.Minute,
			MaxTimeout:     time.Duration(getEnvAsInt("MOBIUS_COMMAND_MAX_TIMEOUT_MINUTES", 60)) * time.Minute,
		},
		Backup: BackupConfig{
			Enabled:   getEnvAsBool("MOBIUS_BACKUP_ENABLED", true),
			Schedule:  getEnv("MOBIUS_BACKUP_SCHEDULE", "0 2 * * *"), // 2 AM daily
			Directory: getEnv("MOBIUS_BACKUP_DIR", "./backups"),
		},
		Cleanup: CleanupConfig{
			Enabled:              getEnvAsBool("MOBIUS_CLEANUP_ENABLED", true),
			CommandRetentionDays: getEnvAsInt("MOBIUS_CLEANUP_COMMANDS_DAYS", 30),
			OSQueryRetentionDays: getEnvAsInt("MOBIUS_CLEANUP_OSQUERY_DAYS", 90),
			TokenRetentionHours:  getEnvAsInt("MOBIUS_CLEANUP_TOKENS_HOURS", 24),
			DeletedDevicesDays:   getEnvAsInt("MOBIUS_CLEANUP_DELETED_DEVICES_DAYS", 7),
		},
		// Score-compatible static file directory
		StaticDir: getEnv("MOBIUS_STATIC_DIR", "./static"),

		// Score-compatible MySQL configuration
		MySQL: MySQLConfig{
			Address:  getEnv("MOBIUS_MYSQL_ADDRESS", ""),
			Database: getEnv("MOBIUS_MYSQL_DATABASE", "mobius"),
			Username: getEnv("MOBIUS_MYSQL_USERNAME", ""),
			Password: getEnv("MOBIUS_MYSQL_PASSWORD", ""),
		},

		// Score-compatible Redis configuration
		Redis: RedisConfig{
			Address:  getEnv("MOBIUS_REDIS_ADDRESS", ""),
			Password: getEnv("MOBIUS_REDIS_PASSWORD", ""),
		},

		// Score-compatible JSON logging
		LoggingJSON: getEnvAsBool("MOBIUS_LOGGING_JSON", false),
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return config, nil
}

// Validate checks if the configuration is valid
func (c *AppConfig) Validate() error {
	// Validate JWT access expiry
	if c.JWT.AccessExpiry < 1*time.Minute {
		return fmt.Errorf("JWT access expiry must be at least 1 minute")
	}
	if c.JWT.AccessExpiry > 24*time.Hour {
		return fmt.Errorf("JWT access expiry cannot exceed 24 hours")
	}

	// Validate command timeouts
	if c.Commands.DefaultTimeout < 1*time.Minute {
		return fmt.Errorf("command default timeout must be at least 1 minute")
	}
	if c.Commands.DefaultTimeout > c.Commands.MaxTimeout {
		return fmt.Errorf("command default timeout cannot exceed max timeout")
	}

	// Validate database path (not :memory: in production)
	if c.Database.Path == "" {
		return fmt.Errorf("database path cannot be empty")
	}

	return nil
}

// Helper functions for environment variables

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvAsInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getEnvAsBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}

func generateDefaultSecret() string {
	// In production, this should be read from a file or environment variable
	// This is just a placeholder - will be replaced with proper key generation
	return "CHANGE_ME_IN_PRODUCTION_" + strconv.FormatInt(time.Now().Unix(), 10)
}
