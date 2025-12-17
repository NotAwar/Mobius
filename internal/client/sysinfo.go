package client
package client

import (
	"os"
	"runtime"
	"time"

	"mobius/internal/logger"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
)

// SystemInfo represents basic system information
type SystemInfo struct {
	Hostname       string    `json:"hostname"`
	OS             string    `json:"os"`
	OSVersion      string    `json:"os_version"`
	Arch           string    `json:"arch"`
	CPUCores       int       `json:"cpu_cores"`
	TotalMemoryMB  uint64    `json:"total_memory_mb"`
	UsedMemoryMB   uint64    `json:"used_memory_mb"`
	DiskTotalGB    uint64    `json:"disk_total_gb"`
	DiskUsedGB     uint64    `json:"disk_used_gb"`
	IPAddresses    []string  `json:"ip_addresses"`
	MACAddresses   []string  `json:"mac_addresses"`
	Uptime         uint64    `json:"uptime_seconds"`
	LastBootTime   time.Time `json:"last_boot_time"`
	KernelVersion  string    `json:"kernel_version"`
	CollectedAt    time.Time `json:"collected_at"`
}

// SystemInfoCollector collects system information
type SystemInfoCollector struct {
	config *Config
	log    logger.Logger
}

// NewSystemInfoCollector creates a new system info collector
func NewSystemInfoCollector(cfg *Config, log logger.Logger) *SystemInfoCollector {
	return &SystemInfoCollector{
		config: cfg,
		log:    log,
	}
}

// Collect collects basic system information
func (s *SystemInfoCollector) Collect() SystemInfo {
	info := SystemInfo{
		OS:           runtime.GOOS,
		Arch:         runtime.GOARCH,
		CPUCores:     runtime.NumCPU(),
		CollectedAt:  time.Now(),
	}

	// Get hostname
	if hostname, err := os.Hostname(); err == nil {
		info.Hostname = hostname
	}

	// Get host info
	if hostInfo, err := host.Info(); err == nil {
		info.OSVersion = hostInfo.Platform + " " + hostInfo.PlatformVersion
		info.Uptime = hostInfo.Uptime
		info.LastBootTime = time.Unix(int64(hostInfo.BootTime), 0)
		info.KernelVersion = hostInfo.KernelVersion
	}

	// Get memory info
	if vmStat, err := mem.VirtualMemory(); err == nil {
		info.TotalMemoryMB = vmStat.Total / 1024 / 1024
		info.UsedMemoryMB = vmStat.Used / 1024 / 1024
	}

	// Get disk info (root partition)
	if diskStat, err := disk.Usage("/"); err == nil {
		info.DiskTotalGB = diskStat.Total / 1024 / 1024 / 1024
		info.DiskUsedGB = diskStat.Used / 1024 / 1024 / 1024
	}

	// Get network interfaces
	if interfaces, err := net.Interfaces(); err == nil {
		for _, iface := range interfaces {
			for _, addr := range iface.Addrs {
				if addr.Addr != "" && addr.Addr != "127.0.0.1" && addr.Addr != "::1" {
					info.IPAddresses = append(info.IPAddresses, addr.Addr)
				}
			}
			if iface.HardwareAddr != "" {
				info.MACAddresses = append(info.MACAddresses, iface.HardwareAddr)
			}
		}
	}

	return info
}

// CollectDetailed collects detailed hardware information
func (s *SystemInfoCollector) CollectDetailed() map[string]interface{} {
	detailed := make(map[string]interface{})

	// Basic info
	detailed["basic"] = s.Collect()

	// CPU info
	if cpuInfo, err := cpu.Info(); err == nil && len(cpuInfo) > 0 {
		detailed["cpu"] = map[string]interface{}{
			"model":      cpuInfo[0].ModelName,
			"family":     cpuInfo[0].Family,
			"cores":      cpuInfo[0].Cores,
			"mhz":        cpuInfo[0].Mhz,
			"cache_size": cpuInfo[0].CacheSize,
			"vendor_id":  cpuInfo[0].VendorID,
		}
	}

	// CPU usage
	if cpuPercent, err := cpu.Percent(time.Second, false); err == nil && len(cpuPercent) > 0 {
		detailed["cpu_usage"] = cpuPercent[0]
	}

	// Disk partitions
	if partitions, err := disk.Partitions(false); err == nil {
		var diskInfo []map[string]interface{}
		for _, part := range partitions {
			if usage, err := disk.Usage(part.Mountpoint); err == nil {
				diskInfo = append(diskInfo, map[string]interface{}{
					"device":      part.Device,
					"mountpoint":  part.Mountpoint,
					"fstype":      part.Fstype,
					"total_gb":    usage.Total / 1024 / 1024 / 1024,
					"used_gb":     usage.Used / 1024 / 1024 / 1024,
					"free_gb":     usage.Free / 1024 / 1024 / 1024,
					"used_pct":    usage.UsedPercent,
				})
			}
		}
		detailed["disks"] = diskInfo
	}

	// Network interfaces detailed
	if interfaces, err := net.Interfaces(); err == nil {
		var netInfo []map[string]interface{}
		for _, iface := range interfaces {
			ifaceInfo := map[string]interface{}{
				"name":  iface.Name,
				"mtu":   iface.MTU,
				"flags": iface.Flags,
			}
			if len(iface.Addrs) > 0 {
				ifaceInfo["addresses"] = iface.Addrs
			}
			if iface.HardwareAddr != "" {
				ifaceInfo["mac"] = iface.HardwareAddr
			}
			netInfo = append(netInfo, ifaceInfo)
		}
		detailed["network_interfaces"] = netInfo
	}

	// Network IO counters
	if ioCounters, err := net.IOCounters(false); err == nil && len(ioCounters) > 0 {
		detailed["network_io"] = map[string]interface{}{
			"bytes_sent":   ioCounters[0].BytesSent,
			"bytes_recv":   ioCounters[0].BytesRecv,
			"packets_sent": ioCounters[0].PacketsSent,
			"packets_recv": ioCounters[0].PacketsRecv,
			"errors_in":    ioCounters[0].Errin,
			"errors_out":   ioCounters[0].Errout,
			"drop_in":      ioCounters[0].Dropin,
			"drop_out":     ioCounters[0].Dropout,
		}
	}

	return detailed
}
