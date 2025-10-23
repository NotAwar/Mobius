<script lang="ts">
  import Layout from '$lib/Layout.svelte';
  import { onMount } from 'svelte';
  import { apiClient, type Device } from '$lib/api';
  import { 
    Monitor, 
    Search, 
    Filter, 
    Plus, 
    MoreVertical, 
    CheckCircle, 
    XCircle, 
    AlertCircle,
    Lock,
    Unlock,
    Trash2,
    Settings,
    RefreshCw
  } from 'lucide-svelte';

  let loading = true;
  let error: string | null = null;
  let devices: Device[] = [];
  let totalDevices = 0;
  let searchQuery = '';
  let selectedPlatform = '';
  let selectedStatus = '';
  let currentPage = 1;
  let itemsPerPage = 20;
  let showFilters = false;
  let selectedDevices: Set<string> = new Set();
  let actionLoading: { [key: string]: boolean } = {};

  // Pagination
  $: totalPages = Math.ceil(totalDevices / itemsPerPage);
  $: offset = (currentPage - 1) * itemsPerPage;

  onMount(async () => {
    await loadDevices();
  });

  async function loadDevices() {
    loading = true;
    error = null;

    try {
      const params: any = {
        limit: itemsPerPage,
        offset,
      };

      if (searchQuery.trim()) {
        params.search = searchQuery.trim();
      }
      
      if (selectedPlatform) {
        params.platform = selectedPlatform;
      }
      
      if (selectedStatus) {
        params.status = selectedStatus;
      }

      const response = await apiClient.getDevices(params);
      devices = response.devices;
      totalDevices = response.total;
    } catch (err) {
      console.error('Failed to load devices:', err);
      error = 'Failed to load devices. Please try again.';
    } finally {
      loading = false;
    }
  }

  function handleSearch() {
    currentPage = 1;
    loadDevices();
  }

  function handleFilterChange() {
    currentPage = 1;
    loadDevices();
  }

  function clearFilters() {
    searchQuery = '';
    selectedPlatform = '';
    selectedStatus = '';
    currentPage = 1;
    loadDevices();
  }

  function toggleDeviceSelection(deviceId: string) {
    if (selectedDevices.has(deviceId)) {
      selectedDevices.delete(deviceId);
    } else {
      selectedDevices.add(deviceId);
    }
    selectedDevices = selectedDevices;
  }

  function selectAllDevices() {
    if (selectedDevices.size === devices.length) {
      selectedDevices.clear();
    } else {
      selectedDevices = new Set(devices.map(d => d.id));
    }
    selectedDevices = selectedDevices;
  }

  async function performDeviceAction(deviceId: string, action: string) {
    actionLoading[deviceId] = true;
    actionLoading = { ...actionLoading };

    try {
      switch (action) {
        case 'lock':
          await apiClient.lockDevice(deviceId);
          break;
        case 'unlock':
          await apiClient.unlockDevice(deviceId);
          break;
        case 'wipe':
          if (confirm('Are you sure you want to wipe this device? This action cannot be undone.')) {
            await apiClient.wipeDevice(deviceId);
          }
          break;
        case 'unenroll':
          if (confirm('Are you sure you want to unenroll this device?')) {
            await apiClient.unenrollDevice(deviceId);
          }
          break;
      }
      
      // Reload devices to reflect changes
      await loadDevices();
    } catch (err) {
      console.error(`Failed to ${action} device:`, err);
      error = `Failed to ${action} device. Please try again.`;
    } finally {
      delete actionLoading[deviceId];
      actionLoading = { ...actionLoading };
    }
  }

  function getStatusColor(status: string) {
    switch (status) {
      case 'online': return 'text-green-600 bg-green-50';
      case 'offline': return 'text-red-600 bg-red-50';
      case 'pending': return 'text-yellow-600 bg-yellow-50';
      default: return 'text-gray-600 bg-gray-50';
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

  function getPlatformIcon(platform: string) {
    switch (platform.toLowerCase()) {
      case 'windows': return '🖥️';
      case 'macos': return '🍎';
      case 'linux': return '🐧';
      case 'android': return '🤖';
      case 'ios': return '📱';
      default: return '💻';
    }
  }

  function goToPage(page: number) {
    currentPage = page;
    loadDevices();
  }

  function formatDate(dateString: string) {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  }
</script>

<Layout>
  <div class="devices-page">
    <!-- Header -->
    <div class="page-header">
      <div>
        <h1>Devices</h1>
        <p>Manage and monitor all enrolled devices</p>
      </div>
      
      <div class="header-actions">
        <button on:click={loadDevices} class="btn btn-secondary" disabled={loading}>
          <RefreshCw size={16} class={loading ? 'spinning' : ''} />
          Refresh
        </button>
        <button class="btn btn-primary">
          <Plus size={16} />
          Enroll Device
        </button>
      </div>
    </div>

    <!-- Search and Filters -->
    <div class="search-filters">
      <div class="search-bar">
        <Search size={16} />
        <input
          type="text"
          placeholder="Search devices by hostname, platform, or user..."
          bind:value={searchQuery}
          on:input={handleSearch}
        />
      </div>
      
      <button
        on:click={() => showFilters = !showFilters}
        class="btn btn-secondary"
        class:active={showFilters}
      >
        <Filter size={16} />
        Filters
      </button>
    </div>

    <!-- Filter Panel -->
    {#if showFilters}
      <div class="filter-panel">
        <div class="filter-group">
          <label for="platform-filter">Platform</label>
          <select id="platform-filter" bind:value={selectedPlatform} on:change={handleFilterChange}>
            <option value="">All Platforms</option>
            <option value="windows">Windows</option>
            <option value="macos">macOS</option>
            <option value="linux">Linux</option>
            <option value="android">Android</option>
            <option value="ios">iOS</option>
          </select>
        </div>
        
        <div class="filter-group">
          <label for="status-filter">Status</label>
          <select id="status-filter" bind:value={selectedStatus} on:change={handleFilterChange}>
            <option value="">All Statuses</option>
            <option value="online">Online</option>
            <option value="offline">Offline</option>
            <option value="pending">Pending</option>
          </select>
        </div>
        
        <button on:click={clearFilters} class="btn btn-ghost">
          Clear Filters
        </button>
      </div>
    {/if}

    <!-- Bulk Actions -->
    {#if selectedDevices.size > 0}
      <div class="bulk-actions">
        <span>{selectedDevices.size} device{selectedDevices.size !== 1 ? 's' : ''} selected</span>
        <div class="bulk-buttons">
          <button class="btn btn-secondary">Assign Policy</button>
          <button class="btn btn-danger">Bulk Actions</button>
        </div>
      </div>
    {/if}

    <!-- Loading State -->
    {#if loading}
      <div class="loading">
        <div class="spinner"></div>
        <p>Loading devices...</p>
      </div>
    {:else if error}
      <div class="error">
        <AlertCircle size={24} />
        <p>{error}</p>
        <button on:click={loadDevices} class="btn btn-primary">
          Retry
        </button>
      </div>
    {:else}
      <!-- Devices Table -->
      <div class="devices-table">
        <table>
          <thead>
            <tr>
              <th>
                <input
                  type="checkbox"
                  checked={selectedDevices.size === devices.length && devices.length > 0}
                  on:change={selectAllDevices}
                />
              </th>
              <th>Device</th>
              <th>Platform</th>
              <th>Status</th>
              <th>Last Seen</th>
              <th>Enrolled</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {#each devices as device}
              <tr>
                <td>
                  <input
                    type="checkbox"
                    checked={selectedDevices.has(device.id)}
                    on:change={() => toggleDeviceSelection(device.id)}
                  />
                </td>
                <td>
                  <div class="device-info">
                    <div class="device-name">{device.hostname}</div>
                    <div class="device-details">
                      {device.uuid}
                      {#if device.enrolled_user}
                        • {device.enrolled_user}
                      {/if}
                    </div>
                  </div>
                </td>
                <td>
                  <div class="platform-info">
                    <span class="platform-icon">{getPlatformIcon(device.platform)}</span>
                    <div>
                      <div class="platform-name">{device.platform}</div>
                      <div class="os-version">{device.os_version}</div>
                    </div>
                  </div>
                </td>
                <td>
                  <div class="status-badge {getStatusColor(device.status)}">
                    <svelte:component this={getStatusIcon(device.status)} size={12} />
                    {device.status}
                  </div>
                </td>
                <td>
                  <div class="date-info">
                    {formatDate(device.last_seen)}
                  </div>
                </td>
                <td>
                  <div class="date-info">
                    {formatDate(device.enrollment_date)}
                  </div>
                </td>
                <td>
                  <div class="device-actions">
                    {#if actionLoading[device.id]}
                      <div class="action-spinner"></div>
                    {:else}
                      <button
                        on:click={() => performDeviceAction(device.id, 'lock')}
                        class="action-btn"
                        title="Lock Device"
                      >
                        <Lock size={14} />
                      </button>
                      <button
                        on:click={() => performDeviceAction(device.id, 'unlock')}
                        class="action-btn"
                        title="Unlock Device"
                      >
                        <Unlock size={14} />
                      </button>
                      <button
                        class="action-btn"
                        title="Device Settings"
                      >
                        <Settings size={14} />
                      </button>
                      <button
                        on:click={() => performDeviceAction(device.id, 'unenroll')}
                        class="action-btn danger"
                        title="Unenroll Device"
                      >
                        <Trash2 size={14} />
                      </button>
                    {/if}
                  </div>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>

        {#if devices.length === 0}
          <div class="empty-state">
            <Monitor size={48} />
            <h3>No devices found</h3>
            <p>No devices match your current search criteria.</p>
          </div>
        {/if}
      </div>

      <!-- Pagination -->
      {#if totalPages > 1}
        <div class="pagination">
          <button
            on:click={() => goToPage(currentPage - 1)}
            disabled={currentPage === 1}
            class="btn btn-secondary"
          >
            Previous
          </button>
          
          <div class="page-numbers">
            {#each Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
              const startPage = Math.max(1, currentPage - 2);
              return startPage + i;
            }) as page}
              {#if page <= totalPages}
                <button
                  on:click={() => goToPage(page)}
                  class="page-btn {page === currentPage ? 'active' : ''}"
                >
                  {page}
                </button>
              {/if}
            {/each}
          </div>
          
          <button
            on:click={() => goToPage(currentPage + 1)}
            disabled={currentPage === totalPages}
            class="btn btn-secondary"
          >
            Next
          </button>
        </div>
      {/if}

      <!-- Results Info -->
      <div class="results-info">
        Showing {offset + 1}-{Math.min(offset + itemsPerPage, totalDevices)} of {totalDevices} devices
      </div>
    {/if}
  </div>
</Layout>

<style>
  .devices-page {
    padding: 2rem;
    max-width: 1400px;
    margin: 0 auto;
  }

  .page-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 2rem;
  }

  .page-header h1 {
    font-size: 2rem;
    font-weight: 700;
    color: var(--text-primary);
    margin: 0;
  }

  .page-header p {
    color: var(--text-secondary);
    margin: 0.25rem 0 0 0;
  }

  .header-actions {
    display: flex;
    gap: 1rem;
  }

  .search-filters {
    display: flex;
    gap: 1rem;
    margin-bottom: 1.5rem;
  }

  .search-bar {
    position: relative;
    flex: 1;
    max-width: 400px;
  }

  .search-bar :global(svg) {
    position: absolute;
    left: 0.75rem;
    top: 50%;
    transform: translateY(-50%);
    color: var(--text-secondary);
  }

  .search-bar input {
    width: 100%;
    padding: 0.75rem 0.75rem 0.75rem 2.5rem;
    border: 1px solid var(--border-color);
    border-radius: 0.5rem;
    font-size: 0.875rem;
  }

  .search-bar input:focus {
    outline: none;
    border-color: var(--primary-color);
    box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
  }

  .filter-panel {
    display: flex;
    gap: 1rem;
    padding: 1rem;
    background: var(--surface-color);
    border: 1px solid var(--border-color);
    border-radius: 0.5rem;
    margin-bottom: 1.5rem;
    align-items: end;
  }

  .filter-group {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  .filter-group label {
    font-size: 0.875rem;
    font-weight: 500;
    color: var(--text-primary);
  }

  .filter-group select {
    padding: 0.5rem;
    border: 1px solid var(--border-color);
    border-radius: 0.375rem;
    font-size: 0.875rem;
    background: white;
  }

  .bulk-actions {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 1rem;
    background: var(--primary-color);
    color: white;
    border-radius: 0.5rem;
    margin-bottom: 1.5rem;
  }

  .bulk-buttons {
    display: flex;
    gap: 0.5rem;
  }

  .devices-table {
    background: var(--surface-color);
    border-radius: 0.75rem;
    border: 1px solid var(--border-color);
    overflow: hidden;
    box-shadow: var(--shadow);
  }

  table {
    width: 100%;
    border-collapse: collapse;
  }

  th {
    background: #f8fafc;
    padding: 1rem;
    text-align: left;
    font-weight: 600;
    color: var(--text-primary);
    border-bottom: 1px solid var(--border-color);
    font-size: 0.875rem;
  }

  td {
    padding: 1rem;
    border-bottom: 1px solid var(--border-color);
  }

  tbody tr:hover {
    background: #f8fafc;
  }

  .device-info .device-name {
    font-weight: 500;
    color: var(--text-primary);
    margin-bottom: 0.25rem;
  }

  .device-info .device-details {
    font-size: 0.75rem;
    color: var(--text-secondary);
  }

  .platform-info {
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }

  .platform-icon {
    font-size: 1.25rem;
  }

  .platform-name {
    font-weight: 500;
    color: var(--text-primary);
    text-transform: capitalize;
  }

  .os-version {
    font-size: 0.75rem;
    color: var(--text-secondary);
  }

  .status-badge {
    display: inline-flex;
    align-items: center;
    gap: 0.25rem;
    padding: 0.25rem 0.5rem;
    border-radius: 9999px;
    font-size: 0.75rem;
    font-weight: 500;
    text-transform: capitalize;
  }

  .date-info {
    font-size: 0.875rem;
    color: var(--text-secondary);
  }

  .device-actions {
    display: flex;
    gap: 0.25rem;
    align-items: center;
  }

  .action-btn {
    padding: 0.25rem;
    border: none;
    background: none;
    border-radius: 0.25rem;
    cursor: pointer;
    color: var(--text-secondary);
    transition: all 0.2s;
  }

  .action-btn:hover {
    background: #f1f5f9;
    color: var(--text-primary);
  }

  .action-btn.danger:hover {
    background: #fee2e2;
    color: #dc2626;
  }

  .action-spinner {
    width: 1rem;
    height: 1rem;
    border: 2px solid #e2e8f0;
    border-top: 2px solid var(--primary-color);
    border-radius: 50%;
    animation: spin 1s linear infinite;
  }

  .empty-state {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: 3rem;
    color: var(--text-secondary);
  }

  .empty-state h3 {
    margin: 1rem 0 0.5rem 0;
    color: var(--text-primary);
  }

  .pagination {
    display: flex;
    justify-content: center;
    align-items: center;
    gap: 0.5rem;
    margin-top: 2rem;
  }

  .page-numbers {
    display: flex;
    gap: 0.25rem;
  }

  .page-btn {
    padding: 0.5rem 0.75rem;
    border: 1px solid var(--border-color);
    background: white;
    border-radius: 0.375rem;
    cursor: pointer;
    font-size: 0.875rem;
    transition: all 0.2s;
  }

  .page-btn:hover {
    background: #f8fafc;
  }

  .page-btn.active {
    background: var(--primary-color);
    color: white;
    border-color: var(--primary-color);
  }

  .results-info {
    text-align: center;
    margin-top: 1rem;
    font-size: 0.875rem;
    color: var(--text-secondary);
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

  @keyframes spin {
    to { transform: rotate(360deg); }
  }

  .btn {
    padding: 0.5rem 1rem;
    border-radius: 0.375rem;
    font-weight: 500;
    text-decoration: none;
    border: none;
    cursor: pointer;
    transition: all 0.2s;
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.875rem;
  }

  .btn:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  .btn-primary {
    background-color: var(--primary-color);
    color: white;
  }

  .btn-primary:hover:not(:disabled) {
    background-color: var(--primary-hover);
  }

  .btn-secondary {
    background-color: white;
    color: var(--text-primary);
    border: 1px solid var(--border-color);
  }

  .btn-secondary:hover:not(:disabled) {
    background-color: #f8fafc;
  }

  .btn-secondary.active {
    background-color: var(--primary-color);
    color: white;
    border-color: var(--primary-color);
  }

  .btn-danger {
    background-color: var(--danger-color);
    color: white;
  }

  .btn-danger:hover:not(:disabled) {
    background-color: #dc2626;
  }

  .btn-ghost {
    background-color: transparent;
    color: var(--text-secondary);
  }

  .btn-ghost:hover {
    background-color: #f1f5f9;
    color: var(--text-primary);
  }

  :global(.spinning) {
    animation: spin 1s linear infinite;
  }

  @media (max-width: 768px) {
    .devices-page {
      padding: 1rem;
    }

    .page-header {
      flex-direction: column;
      align-items: flex-start;
      gap: 1rem;
    }

    .search-filters {
      flex-direction: column;
    }

    .search-bar {
      max-width: none;
    }

    .filter-panel {
      flex-direction: column;
      align-items: stretch;
    }

    .devices-table {
      overflow-x: auto;
    }

    table {
      min-width: 800px;
    }
  }
</style>
