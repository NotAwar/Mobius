package api

import (
	"context"
	"fmt"
	v1 "mobius/api/v1"
	"mobius/internal/middleware"
	"mobius/pkg/config"
	"mobius/pkg/db"
	"mobius/pkg/services"
	"os"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	fiberlogger "github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/fiber/v2/middleware/requestid"
	"github.com/sirupsen/logrus"
	"go.uber.org/zap"
)

// Server represents the Fiber API server
type Server struct {
	app        *fiber.App
	logger     *logrus.Logger
	port       string
	kubeconfig string
	dbPools    *db.DatabasePools
}

// Config holds API server configuration
type Config struct {
	Port              string
	Kubeconfig        string
	EnableRateLimiter bool
	RateLimitMax      int           // Maximum requests
	RateLimitWindow   time.Duration // Time window
}

// DefaultConfig returns default API server configuration
func DefaultConfig() Config {
	return Config{
		Port:              "3000",
		Kubeconfig:        "configs/cluster/kubeconfig",
		EnableRateLimiter: true,
		RateLimitMax:      100,                // 100 requests
		RateLimitWindow:   1 * time.Minute,    // per minute
	}
}

// NewServer creates a new Fiber API server
func NewServer(logger *logrus.Logger, config Config) *Server {
	app := fiber.New(fiber.Config{
		AppName:      "Mobius API",
		ServerHeader: "Mobius",
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			code := fiber.StatusInternalServerError
			message := "Internal Server Error"

			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
				message = e.Message
			}

			logger.Errorf("Request error [%s] %s: %v", c.Method(), c.Path(), err)

			return c.Status(code).JSON(fiber.Map{
				"error":      message,
				"request_id": c.Locals("requestid"),
				"timestamp":  time.Now().Format(time.RFC3339),
			})
		},
	})

	// Middleware
	app.Use(requestid.New())
	app.Use(middleware.NewAuditLogger(logger).Handler())
	
	// Rate limiting middleware (if enabled)
	if config.EnableRateLimiter {
		app.Use(limiter.New(limiter.Config{
			Max:        config.RateLimitMax,
			Expiration: config.RateLimitWindow,
			KeyGenerator: func(c *fiber.Ctx) string {
				// Rate limit by IP address
				return c.IP()
			},
			LimitReached: func(c *fiber.Ctx) error {
				logger.Warnf("Rate limit exceeded for IP: %s", c.IP())
				return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
					"error":      "Too many requests",
					"message":    fmt.Sprintf("Rate limit exceeded. Maximum %d requests per %v allowed.", config.RateLimitMax, config.RateLimitWindow),
					"request_id": c.Locals("requestid"),
					"timestamp":  time.Now().Format(time.RFC3339),
					"retry_after": config.RateLimitWindow.Seconds(),
				})
			},
			Storage: nil, // Uses in-memory storage by default
		}))
		logger.Infof("Rate limiting enabled: %d requests per %v", config.RateLimitMax, config.RateLimitWindow)
	}
	
	app.Use(recover.New(recover.Config{
		EnableStackTrace: true,
	}))
	app.Use(fiberlogger.New(fiberlogger.Config{
		Format:     "[${time}] ${status} - ${method} ${path} (${latency}) - ${ip}\n",
		TimeFormat: "2006-01-02 15:04:05",
	}))
	app.Use(cors.New(cors.Config{
		AllowOrigins: "http://localhost:3000, http://localhost:3001, http://localhost:5173, http://localhost:4173",
		AllowHeaders: "Origin, Content-Type, Accept, Authorization",
		AllowMethods: "GET, POST, PUT, DELETE, PATCH, OPTIONS",
	}))

	server := &Server{
		app:        app,
		logger:     logger,
		port:       config.Port,
		kubeconfig: config.Kubeconfig,
		dbPools:    nil, // Will be initialized with InitializeDatabases()
	}

	// Setup routes
	server.setupRoutes()

	return server
}

// InitializeDatabases initializes database connection pools
func (s *Server) InitializeDatabases() error {
	// Load configuration from environment
	cfg := config.LoadConfig()

	// Check if database host is set (skip if not configured)
	if cfg.Database.Host == "" || cfg.Database.Host == "localhost" {
		// Check if postgres is actually available
		if os.Getenv("DB_HOST") == "" {
			s.logger.Warn("Database not configured - API will use sample data. Set DB_HOST to enable database.")
			return nil
		}
	}

	s.logger.Info("Initializing database connection pools...")

	// Convert logrus logger to zap for database pooling
	zapLogger, err := zap.NewProduction()
	if err != nil {
		return fmt.Errorf("failed to create zap logger: %w", err)
	}

	// Create pool configuration
	poolConfig := db.PoolConfig{
		Host:            cfg.Database.Host,
		Port:            cfg.Database.Port,
		User:            cfg.Database.User,
		Password:        cfg.Database.Password,
		MaxConns:        cfg.Database.MaxConns,
		MinConns:        cfg.Database.MinConns,
		MaxConnLifetime: cfg.Database.MaxConnLifetime,
		MaxConnIdleTime: cfg.Database.MaxConnIdleTime,
	}

	// Initialize database pools
	dbPools, err := db.NewDatabasePools(zapLogger.Sugar(), poolConfig)
	if err != nil {
		return fmt.Errorf("failed to initialize database pools: %w", err)
	}

	s.dbPools = dbPools
	s.logger.Info("Database connection pools initialized successfully")

	// Perform health check
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	healthResults := s.dbPools.HealthCheck(ctx)
	for dbName, err := range healthResults {
		if err != nil {
			s.logger.Warnf("Database %s health check failed: %v", dbName, err)
		} else {
			s.logger.Infof("Database %s: connected", dbName)
		}
	}

	return nil
}

// setupRoutes configures all API routes
func (s *Server) setupRoutes() {
	// Root route - helpful message for users who access API directly
	s.app.Get("/", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"message": "Mobius API Server",
			"version": "v1",
			"ui":      "http://localhost:3000",
			"api":     "http://localhost:3001/api/v1",
			"health":  "http://localhost:3001/api/v1/health",
		})
	})

	// Create services
	clusterService := services.NewClusterService(s.logger, s.kubeconfig)
	postgresService := services.NewPostgresService(s.logger, s.kubeconfig)
	headscaleService := services.NewHeadscaleService(s.logger, s.kubeconfig)

	// Initialize database pools
	if s.dbPools == nil {
		s.logger.Warn("Database pools not initialized - API endpoints will use sample data")
	}

	// Create v1 handler
	v1Handler := v1.NewHandler(s.logger, clusterService, postgresService, headscaleService, s.dbPools)

	// Register v1 routes
	apiV1 := s.app.Group("/api/v1")
	v1Handler.RegisterRoutes(apiV1)

	// Legacy /api routes (redirect to /api/v1 for backward compatibility)
	api := s.app.Group("/api")
	v1Handler.RegisterRoutes(api)
}

// Start starts the API server in a goroutine
func (s *Server) Start() error {
	s.logger.Infof("Starting API server on port %s", s.port)

	go func() {
		if err := s.app.Listen(":" + s.port); err != nil {
			s.logger.Errorf("API server error: %v", err)
		}
	}()

	// Give the server a moment to start
	time.Sleep(200 * time.Millisecond)
	s.logger.Infof("API server running at http://localhost:%s", s.port)

	return nil
}

// Stop gracefully stops the API server
func (s *Server) Stop() error {
	s.logger.Info("Stopping API server...")

	// Close database pools first
	if s.dbPools != nil {
		s.logger.Info("Closing database connections...")
		s.dbPools.Close()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := s.app.ShutdownWithContext(ctx); err != nil {
		return fmt.Errorf("failed to stop API server: %w", err)
	}

	s.logger.Info("API server stopped")
	return nil
}
