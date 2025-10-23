<script lang="ts">
  import Layout from '$lib/Layout.svelte';
  import { onMount } from 'svelte';
  import { apiClient, type Device, type LicenseStatus, type HealthStatus } from '$lib/api';
  import { Monitor, Shield, Package, Users, AlertCircle, CheckCircle, XCircle } from 'lucide-svelte';

  let loading = true;
  let error: string | null = null;
  let devices: Device[] = [];
  let deviceStats = {
    total: 0,
    online: 0,
    offline: 0,
    pending: 0
  };
  let licenseStatus: LicenseStatus | null = null;
  let healthStatus: HealthStatus | null = null;
  let recentActivity: any[] = [];

  onMount(async () => {
    await loadDashboardData();
  });

  async function loadDashboardData() {
    loading = true;
    error = null;

    try {
      // Load all dashboard data in parallel
      const [devicesResponse, licenseResponse, healthResponse] = await Promise.all([
        apiClient.getDevices({ limit: 10 }),
        apiClient.getLicenseStatus(),
        apiClient.getHealth()
      ]);

      devices = devicesResponse.devices;
      licenseStatus = licenseResponse;
      healthStatus = healthResponse;

      // Calculate device statistics
      deviceStats = {
        total: devicesResponse.total,
        online: devices.filter(d => d.status === 'online').length,
        offline: devices.filter(d => d.status === 'offline').length,
        pending: devices.filter(d => d.status === 'pending').length
      };

      // Mock recent activity (in a real app, this would come from an API)
      recentActivity = [
        { type: 'device_enrolled', message: 'New device "MacBook-Pro-15" enrolled', time: '2 minutes ago' },
        { type: 'policy_applied', message: 'Security policy applied to 5 devices', time: '15 minutes ago' },
        { type: 'application_installed', message: 'Chrome browser installed on 3 devices', time: '1 hour ago' },
        { type: 'device_offline', message: 'Device "Windows-Laptop-01" went offline', time: '2 hours ago' }
      ];

    } catch (err) {
      console.error('Failed to load dashboard data:', err);
      error = 'Failed to load dashboard data. Please try again.';
    } finally {
      loading = false;
    }
  }

  function getStatusColor(status: string) {
    switch (status) {
      case 'online': return 'text-green-600';
      case 'offline': return 'text-red-600';
      case 'pending': return 'text-yellow-600';
      default: return 'text-gray-600';
    }
  }

  function getStatusIcon(status: string) {
    switch (status) {
      case 'online': return CheckCircle;
      case 'offline': return XCircle;
      case 'pending': return AlertCircle;
      default: return AlertCircle;
    }
  }
</script>

<Layout>
  <div class="dashboard">
    <!-- Header -->
    <div class="dashboard-header">
      <div>
        <h1>Dashboard</h1>
        <p>Overview of your Mobius MDM environment</p>
      </div>
      
      {#if healthStatus}
        <div class="health-indicator {healthStatus.status}">
          <span class="status-dot"></span>
          System {healthStatus.status}
        </div>
      {/if}
    </div>

    {#if loading}
      <div class="loading">
        <div class="spinner"></div>
        <p>Loading dashboard...</p>
      </div>
    {:else if error}
      <div class="error">
        <AlertCircle size={24} />
        <p>{error}</p>
        <button on:click={loadDashboardData} class="btn btn-primary">
          Retry
        </button>
      </div>
    {:else}
      <!-- Stats Cards -->
      <div class="stats-grid">
        <div class="stat-card">
          <div class="stat-content">
            <div class="stat-icon">
              <Monitor size={24} />
            </div>
            <div class="stat-details">
              <h3>Total Devices</h3>
              <div class="stat-number">{deviceStats.total}</div>
            </div>
          </div>
          <div class="stat-breakdown">
            <span class="stat-item">
              <span class="stat-dot online"></span>
              {deviceStats.online} Online
            </span>
            <span class="stat-item">
              <span class="stat-dot offline"></span>
              {deviceStats.offline} Offline
            </span>
            <span class="stat-item">
              <span class="stat-dot pending"></span>
              {deviceStats.pending} Pending
            </span>
          </div>
        </div>

        <div class="stat-card">
          <div class="stat-content">
            <div class="stat-icon">
              <Shield size={24} />
            </div>
            <div class="stat-details">
              <h3>Active Policies</h3>
              <div class="stat-number">12</div>
            </div>
          </div>
        </div>

        <div class="stat-card">
          <div class="stat-content">
            <div class="stat-icon">
              <Package size={24} />
            </div>
            <div class="stat-details">
              <h3>Applications</h3>
              <div class="stat-number">8</div>
            </div>
          </div>
        </div>

        <div class="stat-card">
          <div class="stat-content">
            <div class="stat-icon">
              <Users size={24} />
            </div>
            <div class="stat-details">
              <h3>Device Groups</h3>
              <div class="stat-number">5</div>
            </div>
          </div>
        </div>
      </div>

      <!-- License Status -->
      {#if licenseStatus}
        <div class="license-status">
          <h2>License Status</h2>
          <div class="license-card">
            <div class="license-info">
              <h3>{licenseStatus.tier.charAt(0).toUpperCase() + licenseStatus.tier.slice(1)} License</h3>
              <p>
                {licenseStatus.devices_enrolled} / {licenseStatus.devices_limit} devices enrolled
              </p>
              {#if licenseStatus.expires_at}
                <p class="text-sm text-gray-500">
                  Expires: {new Date(licenseStatus.expires_at).toLocaleDateString()}
                </p>
              {/if}
            </div>
            <div class="license-progress">
              <div class="progress-bar">
                <div 
                  class="progress-fill" 
                  style="width: {(licenseStatus.devices_enrolled / licenseStatus.devices_limit) * 100}%"
                ></div>
              </div>
            </div>
          </div>
        </div>
      {/if}

      <!-- Content Grid -->
      <div class="content-grid">
        <!-- Recent Devices -->
        <div class="content-card">
          <div class="card-header">
            <h2>Recent Devices</h2>
            <a href="/devices" class="link">View all</a>
          </div>
          <div class="device-list">
            {#each devices.slice(0, 5) as device}
              <div class="device-item">
                <div class="device-info">
                  <div class="device-name">{device.hostname}</div>
                  <div class="device-details">
                    {device.platform} • {device.os_version}
                  </div>
                </div>
                <div class="device-status">
                  <svelte:component 
                    this={getStatusIcon(device.status)} 
                    size={16} 
                    class={getStatusColor(device.status)}
                  />
                  <span class={getStatusColor(device.status)}>
                    {device.status}
                  </span>
                </div>
              </div>
            {/each}
          </div>
        </div>

        <!-- Recent Activity -->
        <div class="content-card">
          <div class="card-header">
            <h2>Recent Activity</h2>
          </div>
          <div class="activity-list">
            {#each recentActivity as activity}
              <div class="activity-item">
                <div class="activity-icon">
                  <Monitor size={16} />
                </div>
                <div class="activity-content">
                  <div class="activity-message">{activity.message}</div>
                  <div class="activity-time">{activity.time}</div>
                </div>
              </div>
            {/each}
          </div>
        </div>
      </div>
    {/if}
  </div>
</Layout>

<style>
  .dashboard {
    padding: 2rem;
    max-width: 1200px;
    margin: 0 auto;
  }

  .dashboard-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 2rem;
  }

  .dashboard-header h1 {
    font-size: 2rem;
    font-weight: 700;
    color: var(--text-primary);
    margin: 0;
  }

  .dashboard-header p {
    color: var(--text-secondary);
    margin: 0.25rem 0 0 0;
  }

  .health-indicator {
    display: flex;
    align-items: center;
    padding: 0.5rem 1rem;
    border-radius: 9999px;
    font-size: 0.875rem;
    font-weight: 500;
  }

  .health-indicator.healthy {
    background-color: #dcfce7;
    color: #16a34a;
  }

  .health-indicator.degraded {
    background-color: #fef3c7;
    color: #d97706;
  }

  .health-indicator.unhealthy {
    background-color: #fee2e2;
    color: #dc2626;
  }

  .status-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    margin-right: 0.5rem;
  }

  .health-indicator.healthy .status-dot {
    background-color: #16a34a;
  }

  .health-indicator.degraded .status-dot {
    background-color: #d97706;
  }

  .health-indicator.unhealthy .status-dot {
    background-color: #dc2626;
  }

  .loading {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: 4rem;
    color: var(--text-secondary);
  }

  .spinner {
    width: 2rem;
    height: 2rem;
    border: 2px solid #e2e8f0;
    border-top: 2px solid var(--primary-color);
    border-radius: 50%;
    animation: spin 1s linear infinite;
    margin-bottom: 1rem;
  }

  @keyframes spin {
    to { transform: rotate(360deg); }
  }

  .error {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: 4rem;
    color: var(--danger-color);
  }

  .error p {
    margin: 1rem 0;
  }

  .stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 1.5rem;
    margin-bottom: 2rem;
  }

  .stat-card {
    background: var(--surface-color);
    border-radius: 0.75rem;
    padding: 1.5rem;
    box-shadow: var(--shadow);
    border: 1px solid var(--border-color);
  }

  .stat-content {
    display: flex;
    align-items: center;
    margin-bottom: 1rem;
  }

  .stat-icon {
    background: var(--primary-color);
    color: white;
    padding: 0.75rem;
    border-radius: 0.5rem;
    margin-right: 1rem;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .stat-details h3 {
    font-size: 0.875rem;
    font-weight: 500;
    color: var(--text-secondary);
    margin: 0 0 0.25rem 0;
  }

  .stat-number {
    font-size: 2rem;
    font-weight: 700;
    color: var(--text-primary);
  }

  .stat-breakdown {
    display: flex;
    gap: 1rem;
    flex-wrap: wrap;
  }

  .stat-item {
    display: flex;
    align-items: center;
    font-size: 0.875rem;
    color: var(--text-secondary);
  }

  .stat-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    margin-right: 0.25rem;
  }

  .stat-dot.online {
    background-color: var(--success-color);
  }

  .stat-dot.offline {
    background-color: var(--danger-color);
  }

  .stat-dot.pending {
    background-color: var(--warning-color);
  }

  .license-status {
    margin-bottom: 2rem;
  }

  .license-status h2 {
    font-size: 1.25rem;
    font-weight: 600;
    color: var(--text-primary);
    margin-bottom: 1rem;
  }

  .license-card {
    background: var(--surface-color);
    border-radius: 0.75rem;
    padding: 1.5rem;
    box-shadow: var(--shadow);
    border: 1px solid var(--border-color);
  }

  .license-info h3 {
    font-size: 1.125rem;
    font-weight: 600;
    color: var(--text-primary);
    margin: 0 0 0.5rem 0;
  }

  .license-info p {
    margin: 0.25rem 0;
    color: var(--text-secondary);
  }

  .license-progress {
    margin-top: 1rem;
  }

  .progress-bar {
    width: 100%;
    height: 8px;
    background-color: #e2e8f0;
    border-radius: 4px;
    overflow: hidden;
  }

  .progress-fill {
    height: 100%;
    background-color: var(--primary-color);
    transition: width 0.3s ease;
  }

  .content-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
    gap: 1.5rem;
  }

  .content-card {
    background: var(--surface-color);
    border-radius: 0.75rem;
    box-shadow: var(--shadow);
    border: 1px solid var(--border-color);
    overflow: hidden;
  }

  .card-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 1.5rem 1.5rem 1rem 1.5rem;
  }

  .card-header h2 {
    font-size: 1.125rem;
    font-weight: 600;
    color: var(--text-primary);
    margin: 0;
  }

  .link {
    font-size: 0.875rem;
    color: var(--primary-color);
    text-decoration: none;
    font-weight: 500;
  }

  .link:hover {
    text-decoration: underline;
  }

  .device-list {
    padding: 0 1.5rem 1.5rem 1.5rem;
  }

  .device-item {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 0.75rem 0;
    border-bottom: 1px solid var(--border-color);
  }

  .device-item:last-child {
    border-bottom: none;
  }

  .device-name {
    font-weight: 500;
    color: var(--text-primary);
  }

  .device-details {
    font-size: 0.875rem;
    color: var(--text-secondary);
    margin-top: 0.25rem;
  }

  .device-status {
    display: flex;
    align-items: center;
    font-size: 0.875rem;
    font-weight: 500;
  }

  .device-status :global(svg) {
    margin-right: 0.25rem;
  }

  .activity-list {
    padding: 0 1.5rem 1.5rem 1.5rem;
  }

  .activity-item {
    display: flex;
    align-items: flex-start;
    padding: 0.75rem 0;
    border-bottom: 1px solid var(--border-color);
  }

  .activity-item:last-child {
    border-bottom: none;
  }

  .activity-icon {
    background: #f1f5f9;
    color: var(--secondary-color);
    padding: 0.5rem;
    border-radius: 50%;
    margin-right: 0.75rem;
    flex-shrink: 0;
  }

  .activity-message {
    font-weight: 500;
    color: var(--text-primary);
    margin-bottom: 0.25rem;
  }

  .activity-time {
    font-size: 0.875rem;
    color: var(--text-secondary);
  }

  .btn {
    padding: 0.5rem 1rem;
    border-radius: 0.375rem;
    font-weight: 500;
    text-decoration: none;
    border: none;
    cursor: pointer;
    transition: all 0.2s;
  }

  .btn-primary {
    background-color: var(--primary-color);
    color: white;
  }

  .btn-primary:hover {
    background-color: var(--primary-hover);
  }

  @media (max-width: 768px) {
    .dashboard {
      padding: 1rem;
    }

    .dashboard-header {
      flex-direction: column;
      align-items: flex-start;
      gap: 1rem;
    }

    .stats-grid {
      grid-template-columns: 1fr;
    }

    .content-grid {
      grid-template-columns: 1fr;
    }
  }
</style>
