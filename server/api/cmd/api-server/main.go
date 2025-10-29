package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/notawar/mobius/server/api/api"
	"github.com/notawar/mobius/server/api/pkg/config"
	"github.com/notawar/mobius/server/api/pkg/service"
	"github.com/notawar/mobius/server/api/pkg/websocket"
)

func main() {
	// Load configuration from environment
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load configuration")
	}

	// Configure logging (use JSON format if MOBIUS_LOGGING_JSON=true)
	zerolog.SetGlobalLevel(zerolog.DebugLevel)
	if cfg.LoggingJSON {
		log.Logger = log.Output(os.Stderr)
	} else {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	}

	// Build server address from config (Port and Host)
	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	if cfg.Server.Host == "" {
		addr = fmt.Sprintf(":%d", cfg.Server.Port)
	}

	log.Info().
		Str("addr", addr).
		Str("static_dir", cfg.StaticDir).
		Bool("json_logging", cfg.LoggingJSON).
		Msg("Starting Mobius MDM API server")

	// Initialize services
	licenseService := service.NewLicenseService()
	deviceService := service.NewDeviceService()
	deviceGroupService := service.NewDeviceGroupService()
	policyService := service.NewPolicyService()
	groupService := service.NewGroupService()
	authService := service.NewAuthService()
	applicationService := service.NewApplicationService()

	// Initialize WebSocket hub
	wsHub := websocket.NewHub()
	ctx := context.Background()
	go wsHub.Run(ctx)

	// Create dependencies
	deps := &api.Dependencies{
		LicenseService:     licenseService,
		DeviceService:      deviceService,
		DeviceGroupService: deviceGroupService,
		PolicyService:      policyService,
		GroupService:       groupService,
		ApplicationService: applicationService,
		AuthService:        authService,
		WSHub:              wsHub,
		StaticDir:          cfg.StaticDir, // Use Score-compatible static directory
	}

	// Create router
	router := api.NewRouter(deps)

	// Create server
	server := &http.Server{
		Addr:         addr,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in a goroutine
	go func() {
		log.Info().Msg("Starting HTTP server")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("Server failed to start")
		}
	}()

	log.Info().Str("addr", addr).Msg("Mobius MDM API server started successfully")
	log.Info().Msg("Available endpoints:")
	log.Info().Msg("  GET  /api/v1/health - Health check")
	log.Info().Msg("  POST /api/v1/auth/login - User login (admin@mobius.local / admin123)")
	log.Info().Msg("  GET  /api/v1/license/status - License status")
	log.Info().Msg("  GET  /api/v1/devices - List devices")
	log.Info().Msg("  GET  /api/v1/policies - List policies")
	log.Info().Msg("  GET  /api/v1/applications - List applications")

	// Wait for interrupt signal to gracefully shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info().Msg("Shutting down server...")

	// Create a deadline for shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Shutdown server
	if err := server.Shutdown(ctx); err != nil {
		log.Error().Err(err).Msg("Server forced to shutdown")
		os.Exit(1)
	}

	log.Info().Msg("Server shutdown complete")
}
