package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

// PoolConfig holds configuration for a database connection pool
type PoolConfig struct {
	Host            string
	Port            int
	Database        string
	User            string
	Password        string
	MaxConns        int32
	MinConns        int32
	MaxConnLifetime time.Duration
	MaxConnIdleTime time.Duration
	HealthCheckPeriod time.Duration
}

// DatabasePools holds connection pools for all databases
type DatabasePools struct {
	App     *pgxpool.Pool
	Clients *pgxpool.Pool
	OSQuery *pgxpool.Pool
	Audit   *pgxpool.Pool
	logger  *zap.SugaredLogger
}

// NewDatabasePools creates connection pools for all databases
func NewDatabasePools(logger *zap.SugaredLogger, baseConfig PoolConfig) (*DatabasePools, error) {
	pools := &DatabasePools{
		logger: logger,
	}

	// Create app database pool
	appConfig := baseConfig
	appConfig.Database = "app"
	var err error
	pools.App, err = createPool(logger, appConfig, "app")
	if err != nil {
		return nil, fmt.Errorf("failed to create app pool: %w", err)
	}

	// Create clients database pool
	clientsConfig := baseConfig
	clientsConfig.Database = "clients"
	pools.Clients, err = createPool(logger, clientsConfig, "clients")
	if err != nil {
		pools.App.Close()
		return nil, fmt.Errorf("failed to create clients pool: %w", err)
	}

	// Create osquery database pool
	osqueryConfig := baseConfig
	osqueryConfig.Database = "osquery"
	pools.OSQuery, err = createPool(logger, osqueryConfig, "osquery")
	if err != nil {
		pools.App.Close()
		pools.Clients.Close()
		return nil, fmt.Errorf("failed to create osquery pool: %w", err)
	}

	// Create audit database pool
	auditConfig := baseConfig
	auditConfig.Database = "audit"
	pools.Audit, err = createPool(logger, auditConfig, "audit")
	if err != nil {
		pools.App.Close()
		pools.Clients.Close()
		pools.OSQuery.Close()
		return nil, fmt.Errorf("failed to create audit pool: %w", err)
	}

	logger.Info("All database pools created successfully")
	return pools, nil
}

// createPool creates a single connection pool
func createPool(logger *zap.SugaredLogger, config PoolConfig, name string) (*pgxpool.Pool, error) {
	// Set defaults
	if config.MaxConns == 0 {
		config.MaxConns = 25
	}
	if config.MinConns == 0 {
		config.MinConns = 5
	}
	if config.MaxConnLifetime == 0 {
		config.MaxConnLifetime = 1 * time.Hour
	}
	if config.MaxConnIdleTime == 0 {
		config.MaxConnIdleTime = 30 * time.Minute
	}
	if config.HealthCheckPeriod == 0 {
		config.HealthCheckPeriod = 1 * time.Minute
	}

	// Build connection string
	connString := fmt.Sprintf(
		"postgres://%s:%s@%s:%d/%s?sslmode=disable",
		config.User,
		config.Password,
		config.Host,
		config.Port,
		config.Database,
	)

	// Configure pool
	poolConfig, err := pgxpool.ParseConfig(connString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse connection string: %w", err)
	}

	poolConfig.MaxConns = config.MaxConns
	poolConfig.MinConns = config.MinConns
	poolConfig.MaxConnLifetime = config.MaxConnLifetime
	poolConfig.MaxConnIdleTime = config.MaxConnIdleTime
	poolConfig.HealthCheckPeriod = config.HealthCheckPeriod

	// Create pool
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create pool: %w", err)
	}

	// Verify connection
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	logger.Infof("Database pool '%s' created successfully (max_conns=%d, min_conns=%d)", 
		name, config.MaxConns, config.MinConns)
	return pool, nil
}

// Close closes all database pools
func (dp *DatabasePools) Close() {
	if dp.App != nil {
		dp.App.Close()
		dp.logger.Info("Closed app database pool")
	}
	if dp.Clients != nil {
		dp.Clients.Close()
		dp.logger.Info("Closed clients database pool")
	}
	if dp.OSQuery != nil {
		dp.OSQuery.Close()
		dp.logger.Info("Closed osquery database pool")
	}
	if dp.Audit != nil {
		dp.Audit.Close()
		dp.logger.Info("Closed audit database pool")
	}
}

// HealthCheck performs health checks on all pools
func (dp *DatabasePools) HealthCheck(ctx context.Context) map[string]error {
	results := make(map[string]error)

	if dp.App != nil {
		results["app"] = dp.App.Ping(ctx)
	}
	if dp.Clients != nil {
		results["clients"] = dp.Clients.Ping(ctx)
	}
	if dp.OSQuery != nil {
		results["osquery"] = dp.OSQuery.Ping(ctx)
	}
	if dp.Audit != nil {
		results["audit"] = dp.Audit.Ping(ctx)
	}

	return results
}

// Stats returns statistics for all pools
func (dp *DatabasePools) Stats() map[string]PoolStats {
	stats := make(map[string]PoolStats)

	if dp.App != nil {
		stats["app"] = getPoolStats(dp.App)
	}
	if dp.Clients != nil {
		stats["clients"] = getPoolStats(dp.Clients)
	}
	if dp.OSQuery != nil {
		stats["osquery"] = getPoolStats(dp.OSQuery)
	}
	if dp.Audit != nil {
		stats["audit"] = getPoolStats(dp.Audit)
	}

	return stats
}

// PoolStats represents pool statistics
type PoolStats struct {
	AcquireCount         int64
	AcquireDuration      time.Duration
	AcquiredConns        int32
	CanceledAcquireCount int64
	ConstructingConns    int32
	EmptyAcquireCount    int64
	IdleConns            int32
	MaxConns             int32
	TotalConns           int32
}

// getPoolStats extracts statistics from a pool
func getPoolStats(pool *pgxpool.Pool) PoolStats {
	stat := pool.Stat()
	return PoolStats{
		AcquireCount:         stat.AcquireCount(),
		AcquireDuration:      stat.AcquireDuration(),
		AcquiredConns:        stat.AcquiredConns(),
		CanceledAcquireCount: stat.CanceledAcquireCount(),
		ConstructingConns:    stat.ConstructingConns(),
		EmptyAcquireCount:    stat.EmptyAcquireCount(),
		IdleConns:            stat.IdleConns(),
		MaxConns:             stat.MaxConns(),
		TotalConns:           stat.TotalConns(),
	}
}
