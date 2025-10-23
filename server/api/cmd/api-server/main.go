package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/notawar/mobius/mobius-server/api"
	"github.com/notawar/mobius/mobius-server/pkg/service"
	"github.com/notawar/mobius/mobius-server/pkg/websocket"
)

func main() {
	// Configure logging for development
	zerolog.SetGlobalLevel(zerolog.DebugLevel)
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	addr := ":8081"

	log.Info().
		Str("addr", addr).
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
		StaticDir:          "./static", // Serve Svelte frontend from static directory
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
