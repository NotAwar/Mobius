package database

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3" // SQLite driver
	"github.com/rs/zerolog/log"
)

// Migration SQL will be loaded from external files
// This avoids the embed issue and allows for runtime flexibility
const initialSchemaMigration = "../migrations/001_initial_schema.up.sql"

// Config represents database configuration
type Config struct {
	// Database path (e.g., "./mobius.db" or ":memory:")
	Path string

	// Driver name (currently only "sqlite3" supported)
	Driver string

	// Connection pool settings
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration

	// Enable foreign keys (SQLite specific)
	EnableForeignKeys bool

	// Enable WAL mode for better concurrency (SQLite specific)
	EnableWAL bool
}

// DefaultConfig returns a configuration with sensible defaults
func DefaultConfig() Config {
	return Config{
		Path:              "./mobius.db",
		Driver:            "sqlite3",
		MaxOpenConns:      25,
		MaxIdleConns:      5,
		ConnMaxLifetime:   5 * time.Minute,
		EnableForeignKeys: true,
		EnableWAL:         true,
	}
}

// TestConfig returns an in-memory configuration for testing
func TestConfig() Config {
	return Config{
		Path:              ":memory:",
		Driver:            "sqlite3",
		MaxOpenConns:      1,
		MaxIdleConns:      1,
		ConnMaxLifetime:   0,
		EnableForeignKeys: true,
		EnableWAL:         false, // WAL not supported for :memory:
	}
}

// DB wraps the database connection with additional functionality
type DB struct {
	*sqlx.DB
	config Config
}

// NewDB creates a new database connection
func NewDB(config Config) (*DB, error) {
	// Build DSN with SQLite options
	dsn := config.Path
	if config.Driver == "sqlite3" {
		params := "?_journal_mode=WAL&_timeout=5000&_busy_timeout=5000"
		if config.EnableForeignKeys {
			params += "&_foreign_keys=ON"
		}
		if !config.EnableWAL && config.Path != ":memory:" {
			params = "?_journal_mode=DELETE&_timeout=5000&_busy_timeout=5000"
			if config.EnableForeignKeys {
				params += "&_foreign_keys=ON"
			}
		}
		if config.Path != ":memory:" {
			dsn += params
		} else if config.EnableForeignKeys {
			dsn += "?_foreign_keys=ON"
		}
	}

	// Open database connection
	sqlDB, err := sql.Open(config.Driver, dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool
	sqlDB.SetMaxOpenConns(config.MaxOpenConns)
	sqlDB.SetMaxIdleConns(config.MaxIdleConns)
	sqlDB.SetConnMaxLifetime(config.ConnMaxLifetime)

	// Wrap with sqlx for enhanced functionality
	db := sqlx.NewDb(sqlDB, config.Driver)

	// Verify connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	log.Info().
		Str("path", config.Path).
		Str("driver", config.Driver).
		Int("max_open_conns", config.MaxOpenConns).
		Msg("Database connection established")

	return &DB{
		DB:     db,
		config: config,
	}, nil
}

// Initialize runs migrations and sets up the database
func (db *DB) Initialize() error {
	log.Info().Msg("Initializing database schema...")

	// Create migrations directory if using file-based database
	if db.config.Path != ":memory:" {
		dbDir := filepath.Dir(db.config.Path)
		if err := os.MkdirAll(dbDir, 0755); err != nil {
			return fmt.Errorf("failed to create database directory: %w", err)
		}
	}

	// Run migrations
	if err := db.runMigrations(); err != nil {
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	log.Info().Msg("Database initialized successfully")
	return nil
}

// runMigrations executes database migrations
func (db *DB) runMigrations() error {
	// Determine migration file path relative to the binary
	migrationPath := filepath.Join("migrations", "001_initial_schema.up.sql")

	// Try to read from current directory first
	migrationSQL, err := os.ReadFile(migrationPath)
	if err != nil {
		// Try from server/api directory (when running tests or from different location)
		migrationPath = filepath.Join("server", "api", "migrations", "001_initial_schema.up.sql")
		migrationSQL, err = os.ReadFile(migrationPath)
		if err != nil {
			return fmt.Errorf("failed to read migration file: %w", err)
		}
	}

	// Execute migration in a transaction
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Execute migration SQL
	if _, err := tx.Exec(string(migrationSQL)); err != nil {
		return fmt.Errorf("failed to execute migration: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit migration: %w", err)
	}

	log.Info().Msg("Applied migration: 001_initial_schema")
	return nil
}

// GetSchemaVersion returns the current schema version
func (db *DB) GetSchemaVersion() (int, error) {
	var version int
	err := db.Get(&version, "SELECT MAX(version) FROM schema_migrations")
	if err != nil {
		return 0, err
	}
	return version, nil
}

// Health checks database connection health
func (db *DB) Health() error {
	if err := db.Ping(); err != nil {
		return fmt.Errorf("database ping failed: %w", err)
	}
	return nil
}

// Stats returns database statistics
func (db *DB) Stats() sql.DBStats {
	return db.DB.Stats()
}

// Close closes the database connection
func (db *DB) Close() error {
	log.Info().Msg("Closing database connection")
	return db.DB.Close()
}

// Backup creates a backup of the database
func (db *DB) Backup(destPath string) error {
	if db.config.Path == ":memory:" {
		return fmt.Errorf("cannot backup in-memory database")
	}

	// Create backup directory
	backupDir := filepath.Dir(destPath)
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return fmt.Errorf("failed to create backup directory: %w", err)
	}

	// For SQLite, we can use the VACUUM INTO command or file copy
	// Using VACUUM INTO for consistency
	_, err := db.Exec(fmt.Sprintf("VACUUM INTO '%s'", destPath))
	if err != nil {
		return fmt.Errorf("failed to backup database: %w", err)
	}

	log.Info().Str("path", destPath).Msg("Database backup created")
	return nil
}

// Restore restores the database from a backup
func (db *DB) Restore(backupPath string) error {
	if db.config.Path == ":memory:" {
		return fmt.Errorf("cannot restore to in-memory database")
	}

	// Close current connection
	if err := db.Close(); err != nil {
		return fmt.Errorf("failed to close database: %w", err)
	}

	// Copy backup file to database path
	input, err := os.ReadFile(backupPath)
	if err != nil {
		return fmt.Errorf("failed to read backup file: %w", err)
	}

	if err := os.WriteFile(db.config.Path, input, 0600); err != nil {
		return fmt.Errorf("failed to write database file: %w", err)
	}

	log.Info().Str("from", backupPath).Msg("Database restored from backup")
	return nil
}
