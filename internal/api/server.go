package api

import (
	"context"
	"fmt"
	v1 "mobius/api/v1"
	"mobius/pkg/services"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	fiberlogger "github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/sirupsen/logrus"
)

// Server represents the Fiber API server
type Server struct {
	app        *fiber.App
	logger     *logrus.Logger
	port       string
	kubeconfig string
}

// Config holds API server configuration
type Config struct {
	Port       string
	Kubeconfig string
}

// DefaultConfig returns default API server configuration
func DefaultConfig() Config {
	return Config{
		Port:       "3000",
		Kubeconfig: "configs/cluster/kubeconfig",
	}
}

// NewServer creates a new Fiber API server
func NewServer(logger *logrus.Logger, config Config) *Server {
	app := fiber.New(fiber.Config{
		AppName:      "Mobius API",
		ServerHeader: "Mobius",
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	})

	// Middleware
	app.Use(recover.New())
	app.Use(fiberlogger.New())
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
	}

	// Setup routes
	server.setupRoutes()

	return server
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

	// Create v1 handler
	v1Handler := v1.NewHandler(s.logger, clusterService, postgresService, headscaleService)

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

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := s.app.ShutdownWithContext(ctx); err != nil {
		return fmt.Errorf("failed to stop API server: %w", err)
	}

	s.logger.Info("API server stopped")
	return nil
}
