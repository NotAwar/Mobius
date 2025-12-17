<script lang="ts">
	import { onMount } from 'svelte';

	interface Client {
		id: string;
		hostname: string;
		os_type: string;
		ip_address?: string;
		status: string;
		last_check_in?: string;
	}

	let stats = $state({
		totalClients: 0,
		onlineClients: 0,
		offlineClients: 0,
		totalGroups: 0,
		recentClients: [] as Client[]
	});

	let loading = $state(true);
	let error = $state<string | null>(null);

	async function fetchDashboardData() {
		try {
			loading = true;
			error = null;

			// Fetch clients
			const clientsRes = await fetch('http://localhost:3001/api/v1/clients?limit=5');
			if (clientsRes.ok) {
				const data = await clientsRes.json();
				stats.totalClients = data.total || 0;
				stats.recentClients = data.clients || [];
				
				// Calculate online/offline
				stats.onlineClients = data.clients.filter((c: Client) => c.status === 'online').length;
				stats.offlineClients = data.clients.filter((c: Client) => c.status === 'offline').length;
			}

			// Fetch groups
			const groupsRes = await fetch('http://localhost:3001/api/v1/clients/groups');
			if (groupsRes.ok) {
				const data = await groupsRes.json();
				stats.totalGroups = data.total || 0;
			}

		} catch (err) {
			error = err instanceof Error ? err.message : 'Failed to load dashboard data';
			console.error('Error:', err);
		} finally {
			loading = false;
		}
	}

	onMount(() => {
		fetchDashboardData();
		const interval = setInterval(fetchDashboardData, 30000);
		return () => clearInterval(interval);
	});

	const healthPercentage = $derived(() => {
		if (stats.totalClients === 0) return 0;
		return Math.round((stats.onlineClients / stats.totalClients) * 100);
	});
</script>

<!-- Header Section -->
<div class="mb-8">
	<div class="flex items-center justify-between">
		<div>
			<h1 class="text-3xl font-bold text-white mb-2">MDM Dashboard</h1>
			<p class="text-[#94a3b8]">Monitor and manage your client devices</p>
		</div>
		<img src="/assets/Mobius-Logo-Text_1.png" alt="Mobius" class="h-12" />
	</div>
</div>

{#if error}
	<div class="mb-6 rounded-lg bg-[#ef4444]/10 border border-[#ef4444]/20 p-4">
		<div class="flex items-center gap-3">
			<svg class="h-5 w-5 text-[#ef4444]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
				<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
			</svg>
			<span class="text-[#ef4444]">{error}</span>
		</div>
	</div>
{/if}

<!-- Stats Grid -->
<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
	<!-- Total Clients -->
	<div class="bg-[#31413e] border border-[#334155] rounded-lg p-6">
		<div class="flex items-center justify-between mb-4">
			<h3 class="text-[#94a3b8] text-sm font-medium">Total Clients</h3>
			<svg class="h-8 w-8 text-[#d4af37]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
				<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
			</svg>
		</div>
		<p class="text-4xl font-bold text-white mb-2">{stats.totalClients}</p>
		<p class="text-[#64748b] text-sm">Registered devices</p>
	</div>

	<!-- Online Clients -->
	<div class="bg-[#31413e] border border-[#334155] rounded-lg p-6">
		<div class="flex items-center justify-between mb-4">
			<h3 class="text-[#94a3b8] text-sm font-medium">Online</h3>
			<svg class="h-8 w-8 text-[#4ade80]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
				<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
			</svg>
		</div>
		<p class="text-4xl font-bold text-white mb-2">{stats.onlineClients}</p>
		<div class="flex items-center gap-2">
			<div class="h-2 w-2 rounded-full bg-[#4ade80] animate-pulse"></div>
			<p class="text-[#4ade80] text-sm">Active now</p>
		</div>
	</div>

	<!-- Offline Clients -->
	<div class="bg-[#31413e] border border-[#334155] rounded-lg p-6">
		<div class="flex items-center justify-between mb-4">
			<h3 class="text-[#94a3b8] text-sm font-medium">Offline</h3>
			<svg class="h-8 w-8 text-[#fbbf24]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
				<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
			</svg>
		</div>
		<p class="text-4xl font-bold text-white mb-2">{stats.offlineClients}</p>
		<p class="text-[#64748b] text-sm">Disconnected</p>
	</div>

	<!-- Client Groups -->
	<div class="bg-[#31413e] border border-[#334155] rounded-lg p-6">
		<div class="flex items-center justify-between mb-4">
			<h3 class="text-[#94a3b8] text-sm font-medium">Groups</h3>
			<svg class="h-8 w-8 text-[#60a5fa]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
				<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z" />
			</svg>
		</div>
		<p class="text-4xl font-bold text-white mb-2">{stats.totalGroups}</p>
		<p class="text-[#64748b] text-sm">Configured groups</p>
	</div>
</div>

<!-- System Health & Quick Actions -->
<div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
	<div class="bg-[#31413e] border border-[#334155] rounded-lg p-6">
		<h3 class="text-white text-lg font-semibold mb-4">System Health</h3>
		<div class="space-y-4">
			<div>
				<div class="flex items-center justify-between mb-2">
					<span class="text-[#94a3b8] text-sm">Device Connectivity</span>
					<span class="text-white font-semibold">{healthPercentage()}%</span>
				</div>
				<div class="h-2 bg-[#1c2f38] rounded-full overflow-hidden">
					<div class="h-full bg-[#4ade80] transition-all duration-500" style="width: {healthPercentage()}%"></div>
				</div>
			</div>
		</div>
	</div>

	<div class="bg-[#31413e] border border-[#334155] rounded-lg p-6">
		<h3 class="text-white text-lg font-semibold mb-4">Quick Actions</h3>
		<div class="grid grid-cols-2 gap-3">
			<a href="/clients" class="flex items-center gap-2 p-3 bg-[#1c2f38] hover:bg-[#d4af37]/10 border border-[#334155] rounded-lg transition-colors">
				<svg class="h-5 w-5 text-[#d4af37]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
					<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6v6m0 0v6m0-6h6m-6 0H6" />
				</svg>
				<span class="text-[#94a3b8] text-sm">Add Client</span>
			</a>
			<a href="/groups" class="flex items-center gap-2 p-3 bg-[#1c2f38] hover:bg-[#d4af37]/10 border border-[#334155] rounded-lg transition-colors">
				<svg class="h-5 w-5 text-[#d4af37]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
					<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z" />
				</svg>
				<span class="text-[#94a3b8] text-sm">Manage Groups</span>
			</a>
			<a href="/osquery" class="flex items-center gap-2 p-3 bg-[#1c2f38] hover:bg-[#d4af37]/10 border border-[#334155] rounded-lg transition-colors">
				<svg class="h-5 w-5 text-[#d4af37]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
					<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16l2.879-2.879m0 0a3 3 0 104.243-4.242 3 3 0 00-4.243 4.242zM21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
				</svg>
				<span class="text-[#94a3b8] text-sm">Run Query</span>
			</a>
			<a href="/audit" class="flex items-center gap-2 p-3 bg-[#1c2f38] hover:bg-[#d4af37]/10 border border-[#334155] rounded-lg transition-colors">
				<svg class="h-5 w-5 text-[#d4af37]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
					<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
				</svg>
				<span class="text-[#94a3b8] text-sm">View Logs</span>
			</a>
		</div>
	</div>
</div>

<!-- Recently Active Clients -->
<div class="bg-[#31413e] border border-[#334155] rounded-lg p-6">
	<div class="flex items-center justify-between mb-6">
		<h3 class="text-white text-lg font-semibold">Recently Active Clients</h3>
		<a href="/clients" class="text-[#d4af37] hover:text-[#d4af37]/80 text-sm font-medium">View all →</a>
	</div>

	{#if loading}
		<div class="text-center py-8">
			<div class="inline-block h-8 w-8 animate-spin rounded-full border-4 border-[#334155] border-t-[#d4af37]"></div>
			<p class="text-[#94a3b8] mt-4">Loading clients...</p>
		</div>
	{:else if stats.recentClients.length === 0}
		<div class="text-center py-8">
			<svg class="h-16 w-16 text-[#64748b] mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
				<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
			</svg>
			<p class="text-[#94a3b8]">No clients registered yet</p>
			<a href="/enrollment" class="inline-block mt-4 px-4 py-2 bg-[#d4af37] hover:bg-[#d4af37]/90 text-[#1c2f38] rounded-lg font-medium transition-colors">
				Enroll First Client
			</a>
		</div>
	{:else}
		<div class="overflow-x-auto">
			<table class="w-full">
				<thead>
					<tr class="border-b border-[#334155]">
						<th class="text-left py-3 px-4 text-[#94a3b8] font-medium text-sm">Hostname</th>
						<th class="text-left py-3 px-4 text-[#94a3b8] font-medium text-sm">OS</th>
						<th class="text-left py-3 px-4 text-[#94a3b8] font-medium text-sm">IP Address</th>
						<th class="text-left py-3 px-4 text-[#94a3b8] font-medium text-sm">Status</th>
						<th class="text-left py-3 px-4 text-[#94a3b8] font-medium text-sm">Last Seen</th>
					</tr>
				</thead>
				<tbody>
					{#each stats.recentClients as client}
						<tr class="border-b border-[#334155]/50 hover:bg-[#1c2f38] transition-colors">
							<td class="py-3 px-4">
								<a href="/clients/{client.id}" class="text-white hover:text-[#d4af37] font-medium">
									{client.hostname}
								</a>
							</td>
							<td class="py-3 px-4">
								<span class="text-[#94a3b8]">{client.os_type}</span>
							</td>
							<td class="py-3 px-4">
								<span class="text-[#94a3b8] font-mono text-sm">{client.ip_address || 'N/A'}</span>
							</td>
							<td class="py-3 px-4">
								{#if client.status === 'online'}
									<span class="inline-flex items-center gap-1.5 px-2 py-1 bg-[#4ade80]/10 text-[#4ade80] rounded text-xs font-medium">
										<div class="h-1.5 w-1.5 rounded-full bg-[#4ade80]"></div>
										Online
									</span>
								{:else}
									<span class="inline-flex items-center gap-1.5 px-2 py-1 bg-[#64748b]/10 text-[#64748b] rounded text-xs font-medium">
										<div class="h-1.5 w-1.5 rounded-full bg-[#64748b]"></div>
										Offline
									</span>
								{/if}
							</td>
							<td class="py-3 px-4">
								<span class="text-[#94a3b8] text-sm">
									{client.last_check_in ? new Date(client.last_check_in).toLocaleString() : 'Never'}
								</span>
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
	{/if}
</div>
