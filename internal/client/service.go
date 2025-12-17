package client

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"time"

	"mobius/internal/logger"
)

// Service represents the main client service
type Service struct {
	config *Config
	log    logger.Logger

	// Components
	reporter  *Reporter
	osquery   *OSQueryManager
	sysinfo   *SystemInfoCollector
	ssh       *SSHManager
	health    *HealthMonitor

	// State
	lastCheckIn time.Time
	mu          sync.RWMutex
	running     bool
}

// NewService creates a new client service
func NewService(cfg *Config, log logger.Logger) (*Service, error) {
	svc := &Service{
		config: cfg,
		log:    log,
	}

	// Initialize reporter
	reporter, err := NewReporter(cfg, log)
	if err != nil {
		return nil, fmt.Errorf("failed to create reporter: %w", err)
	}
	svc.reporter = reporter

	// Initialize OSQuery manager if enabled
	if cfg.EnableOSQuery {
		osquery, err := NewOSQueryManager(cfg, log)
		if err != nil {
			log.Warn("Failed to initialize OSQuery, continuing without it", "error", err)
		} else {
			svc.osquery = osquery
		}
	}

	// Initialize system info collector
	sysinfo := NewSystemInfoCollector(cfg, log)
	svc.sysinfo = sysinfo

	// Initialize SSH manager if enabled
	if cfg.EnableSSH {
		ssh, err := NewSSHManager(cfg, log)
		if err != nil {
			log.Warn("Failed to initialize SSH, continuing without it", "error", err)
		} else {
			svc.ssh = ssh
		}
	}

	// Initialize health monitor
	health := NewHealthMonitor(cfg, log)
	svc.health = health

	return svc, nil
}

// Start starts the service
func (s *Service) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return fmt.Errorf("service already running")
	}
	s.running = true
	s.mu.Unlock()

	s.log.Info("Starting Mobius Client Service")

	// Start health monitoring
	go s.health.Start(ctx)

	// Start SSH server if enabled
	if s.ssh != nil {
		if err := s.ssh.Start(ctx); err != nil {
			s.log.Error("Failed to start SSH server", "error", err)
		}
	}

	// Start OSQuery manager if available
	if s.osquery != nil {
		if err := s.osquery.Start(ctx); err != nil {
			s.log.Error("Failed to start OSQuery", "error", err)
		}
	}

	// Perform initial check-in
	if err := s.checkIn(ctx); err != nil {
		s.log.Error("Initial check-in failed", "error", err)
	}

	// Start main event loop
	checkInTicker := time.NewTicker(s.config.CheckInInterval)
	defer checkInTicker.Stop()

	hwInfoTicker := time.NewTicker(s.config.HardwareInfoInterval)
	defer hwInfoTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			s.log.Info("Shutting down service")
			s.shutdown()
			return nil

		case <-checkInTicker.C:
			if err := s.checkIn(ctx); err != nil {
				s.log.Error("Check-in failed", "error", err)
			}

		case <-hwInfoTicker.C:
			if err := s.collectAndReportHardwareInfo(ctx); err != nil {
				s.log.Error("Hardware info collection failed", "error", err)
			}

		default:
			// Monitor resource usage
			s.monitorResources()
			time.Sleep(1 * time.Second)
		}
	}
}

// checkIn performs a check-in with the server
func (s *Service) checkIn(ctx context.Context) error {
	s.log.Debug("Performing check-in")

	// Collect current system info
	info := s.sysinfo.Collect()

	// Get OSQuery results if available
	var osqueryResults map[string]interface{}
	if s.osquery != nil {
		osqueryResults = s.osquery.GetRecentResults()
	}

	// Send check-in to server
	if err := s.reporter.CheckIn(ctx, CheckInData{
		Timestamp:      time.Now(),
		SystemInfo:     info,
		OSQueryResults: osqueryResults,
		HealthStatus:   s.health.GetStatus(),
	}); err != nil {
		return fmt.Errorf("failed to send check-in: %w", err)
	}

	s.mu.Lock()
	s.lastCheckIn = time.Now()
	s.mu.Unlock()

	s.log.Debug("Check-in successful")
	return nil
}

// collectAndReportHardwareInfo collects detailed hardware info and reports it
func (s *Service) collectAndReportHardwareInfo(ctx context.Context) error {
	s.log.Debug("Collecting hardware information")

	hwInfo := s.sysinfo.CollectDetailed()

	if err := s.reporter.ReportHardwareInfo(ctx, hwInfo); err != nil {
		return fmt.Errorf("failed to report hardware info: %w", err)
	}

	s.log.Debug("Hardware info reported")
	return nil
}

// monitorResources monitors resource usage and throttles if needed
func (s *Service) monitorResources() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	memoryMB := m.Alloc / 1024 / 1024

	if memoryMB > uint64(s.config.MaxMemoryMB) {
		s.log.Warn("Memory usage exceeds limit, forcing GC",
			"current_mb", memoryMB,
			"limit_mb", s.config.MaxMemoryMB)
		runtime.GC()
	}
}

// shutdown gracefully shuts down the service
func (s *Service) shutdown() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return
	}

	s.log.Info("Shutting down components")

	// Stop SSH server
	if s.ssh != nil {
		s.ssh.Stop()
	}

	// Stop OSQuery
	if s.osquery != nil {
		s.osquery.Stop()
	}

	s.running = false
}

// CheckInData represents data sent during check-in
type CheckInData struct {
	Timestamp      time.Time
	SystemInfo     SystemInfo
	OSQueryResults map[string]interface{}
	HealthStatus   HealthStatus
}
