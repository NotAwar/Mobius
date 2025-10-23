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
	"github.com/spf13/cobra"

	"github.com/notawar/mobius/mobius-server/api"
	"github.com/notawar/mobius/mobius-server/pkg/service"
)

// simpleServeCmd represents a simplified serve command for the new API
var simpleServeCmd = &cobra.Command{
	Use:   "api-serve",
	Short: "Start the new Mobius MDM API server",
	Long: `Start the simplified Mobius MDM API server with the new architecture
for device management, policy enforcement, and application distribution.`,
	RunE: runSimpleServe,
}

func init() {
	// TODO: Integrate with proper root command structure
	// rootCmd.AddCommand(simpleServeCmd)

	// Server configuration flags
	simpleServeCmd.Flags().String("addr", ":8081", "Address to bind the API server to")
	simpleServeCmd.Flags().Bool("dev-mode", false, "Enable development mode")
}

func runSimpleServe(cmd *cobra.Command, args []string) error {
	// Configure logging
	if devMode, _ := cmd.Flags().GetBool("dev-mode"); devMode {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	} else {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}

	addr, _ := cmd.Flags().GetString("addr")

	log.Info().
		Str("addr", addr).
		Msg("Starting new Mobius MDM API server")

	// Initialize services
	licenseService := service.NewLicenseService()
	deviceService := service.NewDeviceService()
	policyService := service.NewPolicyService()
	authService := service.NewAuthService()
	applicationService := service.NewApplicationService()

	// Create dependencies
	deps := &api.Dependencies{
		LicenseService:     licenseService,
		DeviceService:      deviceService,
		PolicyService:      policyService,
		ApplicationService: applicationService,
		AuthService:        authService,
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
	log.Info().Msg("API documentation available at /api/v1/health")

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
		return err
	}

	log.Info().Msg("Server shutdown complete")
	return nil
}
