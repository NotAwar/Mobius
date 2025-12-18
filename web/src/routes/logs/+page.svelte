<script lang="ts">
	import { onMount } from 'svelte';
	import { apiRequest } from '$lib/api';

	interface LogEntry {
		id: string;
		timestamp: string;
		action: string;
		resource_type: string;
		method?: string;
		endpoint?: string;
		status_code?: number;
		ip_address?: string;
		request_id?: string;
		duration_ms?: number;
		error_message?: string;
	}

	let logs: LogEntry[] = $state([]);
	let sources: string[] = $state([]);
	let loading = $state(true);
	let selectedSource = $state('all');
	let selectedLevel = $state('all');
	let searchTerm = $state('');
	let autoRefresh = $state(true);
	let refreshInterval: ReturnType<typeof setInterval> | null = null;
	let error = $state('');

	const filteredLogs = $derived(() => {
		let filtered = logs;
		
		if (selectedSource !== 'all') {
			filtered = filtered.filter((log) => log.resource_type === selectedSource);
		}
		
		if (selectedLevel !== 'all') {
			filtered = filtered.filter((log) => {
				if (!log.status_code) return false;
				switch (selectedLevel) {
					case 'error': return log.status_code >= 400;
					case 'warning': return log.status_code >= 300 && log.status_code < 400;
					case 'success': return log.status_code >= 200 && log.status_code < 300;
					case 'info': return log.status_code < 300;
					default: return true;
				}
			});
		}
		
		if (searchTerm) {
			filtered = filtered.filter((log) =>
				log.action?.toLowerCase().includes(searchTerm.toLowerCase()) ||
				log.endpoint?.toLowerCase().includes(searchTerm.toLowerCase())
			);
		}
		
		return filtered;
	});

	async function fetchLogs() {
		try {
			loading = true;
			error = '';
			
			// Fetch logs and sources
			const [logsData, sourcesData] = await Promise.all([
				apiRequest(`/audit/logs?limit=100&source=${selectedSource !== 'all' ? selectedSource : ''}&level=${selectedLevel !== 'all' ? selectedLevel : ''}&search=${searchTerm}`),
				sources.length === 0 ? apiRequest('/audit/sources') : Promise.resolve({ sources })
			]);
			
			logs = logsData.logs || [];
			if (sourcesData.sources) {
				sources = sourcesData.sources;
			}
		} catch (err) {
			error = err instanceof Error ? err.message : 'Failed to fetch logs';
			console.error('Failed to fetch logs:', err);
		} finally {
			loading = false;
		}
	}

	function getLevelColor(statusCode?: number) {
		if (!statusCode) return 'bg-gray-100 text-gray-800 dark:bg-gray-900/30 dark:text-gray-300';
		
		if (statusCode >= 500) return 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300';
		if (statusCode >= 400) return 'bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-300';
		if (statusCode >= 300) return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300';
		if (statusCode >= 200) return 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300';
		return 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-300';
	}

	function getLevelIcon(statusCode?: number) {
		if (!statusCode) return 'ℹ️';
		
		if (statusCode >= 500) return '❌';
		if (statusCode >= 400) return '🚫';
		if (statusCode >= 300) return '⚠️';
		if (statusCode >= 200) return '✅';
		return 'ℹ️';
	}

	function getLogMessage(log: LogEntry): string {
		return log.error_message || `${log.method || 'GET'} ${log.endpoint || log.action} - ${log.status_code || 'N/A'}`;
	}

	function formatTimestamp(timestamp: string) {
		const date = new Date(timestamp);
		return date.toLocaleString();
	}

	function clearLogs() {
		if (confirm('Are you sure you want to clear all logs?')) {
			logs = [];
		}
	}

	function exportLogs() {
		const dataStr = JSON.stringify(logs, null, 2);
		const dataBlob = new Blob([dataStr], { type: 'application/json' });
		const url = URL.createObjectURL(dataBlob);
		const link = document.createElement('a');
		link.href = url;
		link.download = `mobius-logs-${new Date().toISOString()}.json`;
		link.click();
		URL.revokeObjectURL(url);
	}

	onMount(() => {
		fetchLogs();
		
		if (autoRefresh) {
			refreshInterval = setInterval(fetchLogs, 5000);
		}

		return () => {
			if (refreshInterval) clearInterval(refreshInterval);
		};
	});

	$effect(() => {
		if (refreshInterval) clearInterval(refreshInterval);
		
		if (autoRefresh) {
			refreshInterval = setInterval(fetchLogs, 5000);
		}
	});
</script>

<!-- Hero Section -->
<div class="mb-6 rounded-2xl bg-linear-to-br from-slate-700 via-gray-800 to-zinc-900 p-6 text-white shadow-2xl">
	<div class="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
		<div>
			<h1 class="mb-2 flex items-center gap-3 text-3xl font-bold">
				<span class="text-4xl">📋</span>
				System Logs
			</h1>
			<p class="text-gray-300">
				Monitor and troubleshoot system events - {filteredLogs().length} {filteredLogs().length === 1 ? 'entry' : 'entries'}
			</p>
		</div>
		<div class="flex items-center gap-3">
			<label class="flex items-center gap-2 rounded-lg bg-white/10 px-3 py-2 backdrop-blur">
				<input
					type="checkbox"
					bind:checked={autoRefresh}
					class="rounded"
				/>
				<span class="text-sm">Auto-refresh</span>
			</label>
		</div>
	</div>
</div>

<!-- Controls -->
<div class="mb-6 rounded-xl bg-white p-6 shadow-lg dark:bg-gray-800">
	<div class="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
		<div class="flex flex-1 flex-col gap-3 sm:flex-row">
			<input
				type="text"
				bind:value={searchTerm}
				placeholder="Search logs..."
				class="flex-1 rounded-lg border border-gray-300 px-4 py-2 text-sm dark:border-gray-600 dark:bg-gray-700 dark:text-white"
			/>
			<select
				bind:value={selectedSource}
				class="rounded-lg border border-gray-300 px-4 py-2 text-sm dark:border-gray-600 dark:bg-gray-700 dark:text-white"
			>
				<option value="all">All Sources</option>
				{#each sources as source}
					<option value={source}>{source}</option>
				{/each}
			</select>
			<select
				bind:value={selectedLevel}
				class="rounded-lg border border-gray-300 px-4 py-2 text-sm dark:border-gray-600 dark:bg-gray-700 dark:text-white"
			>
				<option value="all">All Levels</option>
				<option value="info">Info</option>
				<option value="success">Success</option>
				<option value="warning">Warning</option>
				<option value="error">Error</option>
			</select>
		</div>
		<div class="flex gap-2">
			<button
				onclick={exportLogs}
				class="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white transition hover:bg-blue-700"
			>
				📥 Export
			</button>
			<button
				onclick={clearLogs}
				class="rounded-lg bg-[rgba(239, 68, 68, 0.1)] border border-[#ef4444] px-4 py-2 text-sm font-medium text-[#ef4444] transition hover:bg-[rgba(239, 68, 68, 0.2)]"
			>
				🗑️ Clear
			</button>
		</div>
	</div>
</div>

<!-- Stats -->
<div class="mb-6 grid grid-cols-2 gap-4 md:grid-cols-5">
	<div class="rounded-xl bg-white p-4 shadow-lg dark:bg-gray-800">
		<div class="text-2xl font-bold text-[#FFFFF0]">{logs.length}</div>
		<div class="text-sm text-gray-600 dark:text-gray-400">Total Logs</div>
	</div>
	<div class="rounded-xl bg-blue-50 p-4 dark:bg-blue-900/20">
		<div class="text-2xl font-bold text-blue-600 dark:text-blue-400">
			{logs.filter((l) => l.status_code && l.status_code < 300).length}
		</div>
		<div class="text-sm text-gray-600 dark:text-gray-400">Info</div>
	</div>
	<div class="rounded-xl bg-green-50 p-4 dark:bg-green-900/20">
		<div class="text-2xl font-bold text-green-600 dark:text-green-400">
			{logs.filter((l) => l.status_code && l.status_code >= 200 && l.status_code < 300).length}
		</div>
		<div class="text-sm text-gray-600 dark:text-gray-400">Success</div>
	</div>
	<div class="rounded-xl bg-yellow-50 p-4 dark:bg-yellow-900/20">
		<div class="text-2xl font-bold text-yellow-600 dark:text-yellow-400">
			{logs.filter((l) => l.status_code && l.status_code >= 300 && l.status_code < 400).length}
		</div>
		<div class="text-sm text-gray-600 dark:text-gray-400">Warnings</div>
	</div>
	<div class="rounded-xl bg-red-50 p-4 dark:bg-red-900/20">
		<div class="text-2xl font-bold text-red-600 dark:text-red-400">
			{logs.filter((l) => l.status_code && l.status_code >= 400).length}
		</div>
		<div class="text-sm text-gray-600 dark:text-gray-400">Errors</div>
	</div>
</div>

<!-- Logs Display -->
{#if loading}
	<div class="flex items-center justify-center py-12">
		<div class="text-center">
			<div class="mb-4 inline-block h-12 w-12 animate-spin rounded-full border-4 border-gray-200 border-t-gray-600"></div>
			<p class="text-gray-600 dark:text-gray-400">Loading logs...</p>
		</div>
	</div>
{:else if filteredLogs().length === 0}
	<div class="rounded-xl bg-white p-12 text-center shadow-lg dark:bg-gray-800">
		<div class="mb-4 text-6xl">📋</div>
		<p class="mb-2 text-lg font-medium text-[#FFFFF0]">No Logs Found</p>
		<p class="text-gray-600 dark:text-gray-400">
			{searchTerm || selectedSource !== 'all' || selectedLevel !== 'all'
				? 'Try adjusting your filters'
				: 'System logs will appear here'}
		</p>
	</div>
{:else}
	<div class="rounded-xl bg-white shadow-lg dark:bg-gray-800">
		<div class="max-h-150 overflow-y-auto">
			<div class="divide-y divide-gray-200 dark:divide-gray-700">
				{#each filteredLogs() as log}
					<div class="p-4 transition-colors hover:bg-gray-50 dark:hover:bg-gray-700/50">
						<div class="flex items-start gap-4">
							<div class="text-2xl">{getLevelIcon(log.status_code)}</div>
							<div class="flex-1">
								<div class="mb-1 flex flex-wrap items-center gap-2">
									<span class="rounded-full px-3 py-1 text-xs font-semibold {getLevelColor(log.status_code)}">
										{log.status_code || 'N/A'}
									</span>
									<span class="rounded-full bg-blue-100 px-3 py-1 text-xs font-medium text-blue-800 dark:bg-blue-900/30 dark:text-blue-300">
										{log.method || 'GET'}
									</span>
									<span class="rounded-full bg-gray-100 px-3 py-1 text-xs font-medium text-gray-700 dark:bg-gray-700 dark:text-gray-300">
										{log.resource_type}
									</span>
									<span class="text-xs text-gray-500 dark:text-gray-400">
										{formatTimestamp(log.timestamp)}
									</span>
									{#if log.duration_ms}
										<span class="text-xs text-gray-500 dark:text-gray-400">
											{log.duration_ms}ms
										</span>
									{/if}
								</div>
								<p class="text-sm font-medium text-gray-900 dark:text-gray-100 mb-1">{log.action}</p>
								{#if log.endpoint}
									<p class="text-xs text-gray-600 dark:text-gray-400 font-mono">{log.endpoint}</p>
								{/if}
								{#if log.error_message}
									<p class="text-xs text-red-600 dark:text-red-400 mt-2">{log.error_message}</p>
								{/if}
								{#if log.request_id}
									<p class="text-xs text-gray-500 dark:text-gray-500 mt-1">Request ID: {log.request_id}</p>
								{/if}
							</div>
						</div>
					</div>
				{/each}
			</div>
		</div>
	</div>
{/if}
