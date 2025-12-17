package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"mobius/internal/client"
	"mobius/internal/logger"
)

const (
	version = "1.0.0"
)

func main() {
	// Parse command-line flags
	configPath := flag.String("config", "/etc/mobius/client.yaml", "Path to configuration file")
	enrollKey := flag.String("enroll-key", "", "Enrollment key for onboarding")
	serverURL := flag.String("server", "", "Server URL for enrollment")
	debug := flag.Bool("debug", false, "Enable debug logging")
	showVersion := flag.Bool("version", false, "Show version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("Mobius Client v%s\n", version)
		os.Exit(0)
	}

	// Initialize logger
	log := logger.New(*debug)

	log.Info("Starting Mobius Client", "version", version)

	// Handle enrollment if key provided
	if *enrollKey != "" && *serverURL != "" {
		log.Info("Enrollment mode detected")
		if err := client.Enroll(*serverURL, *enrollKey, *configPath); err != nil {
			log.Error("Enrollment failed", "error", err)
			os.Exit(1)
		}
		log.Info("Enrollment successful, starting service...")
	}

	// Load configuration
	cfg, err := client.LoadConfig(*configPath)
	if err != nil {
		log.Error("Failed to load configuration", "error", err)
		os.Exit(1)
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		log.Error("Invalid configuration", "error", err)
		os.Exit(1)
	}

	// Create context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize client service
	svc, err := client.NewService(cfg, log)
	if err != nil {
		log.Error("Failed to initialize service", "error", err)
		os.Exit(1)
	}

	// Handle graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Start service
	errCh := make(chan error, 1)
	go func() {
		errCh <- svc.Start(ctx)
	}()

	// Wait for shutdown signal or error
	select {
	case sig := <-sigCh:
		log.Info("Received shutdown signal", "signal", sig)
		cancel()
		// Give service time to cleanup
		time.Sleep(2 * time.Second)
	case err := <-errCh:
		if err != nil {
			log.Error("Service error", "error", err)
			os.Exit(1)
		}
	}

	log.Info("Mobius Client stopped")
}
