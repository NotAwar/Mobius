package client

import (
	"context"
	"runtime"
	"time"

	"mobius/internal/logger"

	"github.com/shirou/gopsutil/v3/cpu"
)

// HealthStatus represents the health status of the client
type HealthStatus struct {
	Status           string    `json:"status"` // healthy, degraded, unhealthy
	CPUUsagePercent  float64   `json:"cpu_usage_percent"`
	MemoryUsageMB    uint64    `json:"memory_usage_mb"`
	MemoryLimitMB    int       `json:"memory_limit_mb"`
	DiskUsagePercent float64   `json:"disk_usage_percent"`
	Uptime           uint64    `json:"uptime_seconds"`
	LastCheckIn      time.Time `json:"last_check_in"`
	OSQueryStatus    string    `json:"osquery_status"`
	SSHStatus        string    `json:"ssh_status"`
}

// HealthMonitor monitors client health
type HealthMonitor struct {
	config      *Config
	log         logger.Logger
	status      HealthStatus
	startTime   time.Time
}

// NewHealthMonitor creates a new health monitor
func NewHealthMonitor(cfg *Config, log logger.Logger) *HealthMonitor {
	return &HealthMonitor{
		config:    cfg,
		log:       log,
		startTime: time.Now(),
		status: HealthStatus{
			Status:        "healthy",
			MemoryLimitMB: cfg.MaxMemoryMB,
		},
	}
}

// Start starts the health monitor
func (h *HealthMonitor) Start(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h.updateStatus()
		}
	}
}

// updateStatus updates the health status
func (h *HealthMonitor) updateStatus() {
	// Get CPU usage
	if cpuPercent, err := cpu.Percent(time.Second, false); err == nil && len(cpuPercent) > 0 {
		h.status.CPUUsagePercent = cpuPercent[0]
	}

	// Get memory usage
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	h.status.MemoryUsageMB = m.Alloc / 1024 / 1024

	// Calculate uptime
	h.status.Uptime = uint64(time.Since(h.startTime).Seconds())

	// Determine overall status
	if h.status.MemoryUsageMB > uint64(h.config.MaxMemoryMB) {
		h.status.Status = "unhealthy"
		h.log.Warn("Memory usage exceeds limit",
			"usage", h.status.MemoryUsageMB,
			"limit", h.config.MaxMemoryMB)
	} else if h.status.CPUUsagePercent > float64(h.config.MaxCPUPct) {
		h.status.Status = "degraded"
		h.log.Warn("CPU usage exceeds limit",
			"usage", h.status.CPUUsagePercent,
			"limit", h.config.MaxCPUPct)
	} else {
		h.status.Status = "healthy"
	}
}

// GetStatus returns the current health status
func (h *HealthMonitor) GetStatus() HealthStatus {
	return h.status
}

// UpdateLastCheckIn updates the last check-in time
func (h *HealthMonitor) UpdateLastCheckIn() {
	h.status.LastCheckIn = time.Now()
}
