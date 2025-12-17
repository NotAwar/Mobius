package main

import (
	"mobius/internal/api"
	"os"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"
)

func main() {
	// Initialize logger
	log := logrus.New()
	log.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})
	log.SetLevel(logrus.InfoLevel)

	// Create API server with default config
	config := api.DefaultConfig()
	config.Port = "3001"
	server := api.NewServer(log, config)

	// Start API server
	if err := server.Start(); err != nil {
		log.Fatalf("Failed to start API server: %v", err)
	}

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	// Graceful shutdown
	log.Info("Shutting down API server...")
	if err := server.Stop(); err != nil {
		log.Errorf("Error stopping API server: %v", err)
	}
}
