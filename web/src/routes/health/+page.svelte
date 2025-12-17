<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { apiRequest } from '$lib/api';

  let healthData: any = null;
  let detailedHealthData: any = null;
  let loading = true;
  let error = '';
  let autoRefresh = true;
  let refreshInterval = 5000;
  let intervalId: number | null = null;

  interface ServiceHealth {
    status: string;
    healthy: boolean;
    data?: any;
    error?: string;
  }

  interface DetailedHealth {
    status: string;
    timestamp: string;
    services: Record<string, ServiceHealth>;
  }

  async function fetchHealthData() {
    try {
      loading = true;
      error = '';
      
      // Fetch basic health
      const basicResponse = await apiRequest('/health');
      healthData = basicResponse;
      
      // Fetch detailed health
      const detailedResponse = await apiRequest('/health/detailed');
      detailedHealthData = detailedResponse as DetailedHealth;
      
    } catch (err: any) {
      error = err.message || 'Failed to fetch health data';
      console.error('Health fetch error:', err);
    } finally {
      loading = false;
    }
  }

  function startAutoRefresh() {
    if (autoRefresh && !intervalId) {
      intervalId = window.setInterval(fetchHealthData, refreshInterval);
    }
  }

  function stopAutoRefresh() {
    if (intervalId) {
      clearInterval(intervalId);
      intervalId = null;
    }
  }

  $: {
    if (autoRefresh) {
      startAutoRefresh();
    } else {
      stopAutoRefresh();
    }
  }

  onMount(() => {
    fetchHealthData();
    if (autoRefresh) {
      startAutoRefresh();
    }
  });

  onDestroy(() => {
    stopAutoRefresh();
  });

  function getStatusColor(status: string): string {
    switch (status?.toLowerCase()) {
      case 'healthy':
      case 'ok':
        return 'text-green-400';
      case 'degraded':
        return 'text-yellow-400';
      case 'unhealthy':
      case 'error':
        return 'text-red-400';
      default:
        return 'text-gray-400';
    }
  }

  function getStatusBgColor(status: string): string {
    switch (status?.toLowerCase()) {
      case 'healthy':
      case 'ok':
        return 'bg-green-500/20 border-green-500/50';
      case 'degraded':
        return 'bg-yellow-500/20 border-yellow-500/50';
      case 'unhealthy':
      case 'error':
        return 'bg-red-500/20 border-red-500/50';
      default:
        return 'bg-gray-500/20 border-gray-500/50';
    }
  }

  function getServiceIcon(serviceName: string): string {
    switch (serviceName) {
      case 'cluster':
        return '⚙️';
      case 'postgres':
        return '🐘';
      case 'headscale':
        return '🔒';
      default:
        return '📦';
    }
  }
</script>

<div class="container mx-auto px-6 py-8">
  <!-- Header -->
  <div class="flex justify-between items-center mb-8">
    <div>
      <h1 class="text-3xl font-bold bg-linear-to-r from-green-400 via-emerald-500 to-teal-500 bg-clip-text text-transparent">
        System Health
      </h1>
      <p class="text-gray-400 mt-2">Real-time health monitoring for all services</p>
    </div>
    
    <div class="flex items-center gap-4">
      <label class="flex items-center gap-2 text-sm">
        <input
          type="checkbox"
          bind:checked={autoRefresh}
          class="w-4 h-4 rounded bg-gray-700 border-gray-600 text-green-500 focus:ring-green-500"
        />
        <span class="text-gray-300">Auto-refresh</span>
      </label>
      
      <button
        on:click={fetchHealthData}
        disabled={loading}
        class="px-4 py-2 rounded-lg bg-linear-to-r from-green-500 to-emerald-600 text-white font-medium hover:from-green-600 hover:to-emerald-700 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
      >
        {#if loading}
          <span class="animate-pulse">Refreshing...</span>
        {:else}
          Refresh
        {/if}
      </button>
    </div>
  </div>

  {#if error}
    <div class="bg-red-500/10 border border-red-500/50 rounded-lg p-4 mb-6">
      <p class="text-red-400">⚠️ {error}</p>
    </div>
  {/if}

  <!-- Overall Status -->
  {#if healthData}
    <div class="mb-8">
      <div class="bg-gray-800/50 backdrop-blur-sm rounded-xl p-6 border border-gray-700/50 {getStatusBgColor(healthData.status)}">
        <div class="flex items-center justify-between">
          <div>
            <div class="text-sm text-gray-400 mb-1">Overall System Status</div>
            <div class="text-3xl font-bold {getStatusColor(healthData.status)}">
              {healthData.status?.toUpperCase() || 'UNKNOWN'}
            </div>
          </div>
          <div class="text-6xl">
            {healthData.status?.toLowerCase() === 'healthy' ? '✅' : healthData.status?.toLowerCase() === 'degraded' ? '⚠️' : '❌'}
          </div>
        </div>
        {#if healthData.timestamp}
          <div class="text-xs text-gray-500 mt-4">
            Last checked: {new Date(healthData.timestamp).toLocaleString()}
          </div>
        {/if}
      </div>
    </div>
  {/if}

  <!-- Detailed Service Health -->
  {#if detailedHealthData?.services}
    <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
      {#each Object.entries(detailedHealthData.services) as [serviceName, sh]}
        {@const serviceHealth = sh as ServiceHealth}
        <div class="bg-gray-800/50 backdrop-blur-sm rounded-xl p-6 border border-gray-700/50 hover:border-gray-600 transition-all {getStatusBgColor(serviceHealth.status)}">
          <div class="flex items-start justify-between mb-4">
            <div>
              <div class="text-2xl mb-2">{getServiceIcon(serviceName)}</div>
              <h3 class="text-xl font-semibold text-white capitalize">{serviceName}</h3>
            </div>
            <div class="text-2xl">
              {serviceHealth.healthy ? '✅' : '❌'}
            </div>
          </div>
          
          <div class="space-y-2">
            <div class="flex justify-between items-center">
              <span class="text-gray-400 text-sm">Status</span>
              <span class="font-medium {getStatusColor(serviceHealth.status)}">
                {serviceHealth.status?.toUpperCase() || 'UNKNOWN'}
              </span>
            </div>
            
            {#if serviceHealth.error}
              <div class="mt-3 p-3 bg-red-500/10 rounded-lg">
                <div class="text-xs text-red-400 wrap-break-word">
                  {serviceHealth.error}
                </div>
              </div>
            {/if}
            
            {#if serviceHealth.data}
              <div class="mt-4 space-y-2">
                <div class="text-xs text-gray-500 uppercase tracking-wider">Details</div>
                <div class="bg-gray-900/50 rounded-lg p-3 max-h-40 overflow-y-auto">
                  <pre class="text-xs text-gray-300 font-mono">{JSON.stringify(serviceHealth.data, null, 2)}</pre>
                </div>
              </div>
            {/if}
          </div>
        </div>
      {/each}
    </div>
  {/if}

  <!-- Probes Section -->
  <div class="mt-8">
    <h2 class="text-2xl font-bold text-white mb-4">Kubernetes Probes</h2>
    <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
      <!-- Liveness Probe -->
      <div class="bg-gray-800/50 backdrop-blur-sm rounded-xl p-6 border border-gray-700/50">
        <div class="flex items-center gap-3 mb-4">
          <div class="text-3xl">💓</div>
          <div>
            <h3 class="text-lg font-semibold text-white">Liveness Probe</h3>
            <p class="text-sm text-gray-400">Indicates if the container is running</p>
          </div>
        </div>
        <div class="text-sm text-gray-400">
          <code class="bg-gray-900/50 px-2 py-1 rounded">GET /api/v1/health/live</code>
        </div>
      </div>

      <!-- Readiness Probe -->
      <div class="bg-gray-800/50 backdrop-blur-sm rounded-xl p-6 border border-gray-700/50">
        <div class="flex items-center gap-3 mb-4">
          <div class="text-3xl">🎯</div>
          <div>
            <h3 class="text-lg font-semibold text-white">Readiness Probe</h3>
            <p class="text-sm text-gray-400">Indicates if the container is ready to serve traffic</p>
          </div>
        </div>
        <div class="text-sm text-gray-400">
          <code class="bg-gray-900/50 px-2 py-1 rounded">GET /api/v1/health/ready</code>
        </div>
      </div>
    </div>
  </div>

  <!-- API Endpoints Reference -->
  <div class="mt-8">
    <h2 class="text-2xl font-bold text-white mb-4">Health Check Endpoints</h2>
    <div class="bg-gray-800/50 backdrop-blur-sm rounded-xl p-6 border border-gray-700/50">
      <div class="space-y-4">
        <div class="flex items-start gap-4 pb-4 border-b border-gray-700">
          <span class="px-2 py-1 bg-green-500/20 text-green-400 text-xs font-mono rounded">GET</span>
          <div class="flex-1">
            <code class="text-green-400">/api/v1/health</code>
            <p class="text-sm text-gray-400 mt-1">Basic health check - returns overall system status</p>
          </div>
        </div>
        
        <div class="flex items-start gap-4 pb-4 border-b border-gray-700">
          <span class="px-2 py-1 bg-green-500/20 text-green-400 text-xs font-mono rounded">GET</span>
          <div class="flex-1">
            <code class="text-green-400">/api/v1/health/detailed</code>
            <p class="text-sm text-gray-400 mt-1">Detailed health check - includes status of all services</p>
          </div>
        </div>
        
        <div class="flex items-start gap-4 pb-4 border-b border-gray-700">
          <span class="px-2 py-1 bg-green-500/20 text-green-400 text-xs font-mono rounded">GET</span>
          <div class="flex-1">
            <code class="text-green-400">/api/v1/health/live</code>
            <p class="text-sm text-gray-400 mt-1">Liveness probe - for Kubernetes liveness checks</p>
          </div>
        </div>
        
        <div class="flex items-start gap-4">
          <span class="px-2 py-1 bg-green-500/20 text-green-400 text-xs font-mono rounded">GET</span>
          <div class="flex-1">
            <code class="text-green-400">/api/v1/health/ready</code>
            <p class="text-sm text-gray-400 mt-1">Readiness probe - for Kubernetes readiness checks</p>
          </div>
        </div>
      </div>
    </div>
  </div>
</div>
