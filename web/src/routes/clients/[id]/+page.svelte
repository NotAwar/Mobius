<script lang="ts">
	import { page } from '$app/stores';
	import { onMount } from 'svelte';

	let clientId = '';
	let client: any = null;
	let loading = true;
	let error = '';
	let activeTab = 'overview';

	// Data for different tabs
	let hardware: any = null;
	let checkIns: any[] = [];
	let osqueryResults: any[] = [];
	let events: any[] = [];
	let groups: any[] = [];
	let configuration: any = null;

	// Edit modes
	let editingTags = false;
	let newTag = '';

	$: clientId = $page.params.id;

	onMount(() => {
		fetchClient();
		// Auto-refresh every 30 seconds
		const interval = setInterval(fetchClient, 30000);
		return () => clearInterval(interval);
	});

	async function fetchClient() {
		try {
			const res = await fetch(`http://localhost:3001/api/v1/clients/${clientId}`);
			if (!res.ok) throw new Error('Client not found');
			
			const data = await res.json();
			client = data.client;
			
			// Fetch additional data based on active tab
			if (activeTab === 'hardware') await fetchHardware();
			if (activeTab === 'checkins') await fetchCheckIns();
			if (activeTab === 'osquery') await fetchOSQueryResults();
			if (activeTab === 'events') await fetchEvents();
			if (activeTab === 'groups') await fetchGroups();
			if (activeTab === 'config') await fetchConfiguration();
		} catch (err: any) {
			error = err.message;
		} finally {
			loading = false;
		}
	}

	async function fetchHardware() {
		try {
			const res = await fetch(`http://localhost:3001/api/v1/clients/${clientId}/hardware`);
			if (res.ok) {
				const data = await res.json();
				hardware = data.hardware;
			}
		} catch (err) {
			console.error('Failed to fetch hardware:', err);
		}
	}

	async function fetchCheckIns() {
		try {
			const res = await fetch(`http://localhost:3001/api/v1/clients/${clientId}/check-ins`);
			if (res.ok) {
				const data = await res.json();
				checkIns = data.check_ins || [];
			}
		} catch (err) {
			console.error('Failed to fetch check-ins:', err);
		}
	}

	async function fetchOSQueryResults() {
		try {
			const res = await fetch(`http://localhost:3001/api/v1/osquery/clients/${clientId}/results`);
			if (res.ok) {
				const data = await res.json();
				osqueryResults = data.results || [];
			}
		} catch (err) {
			console.error('Failed to fetch OSQuery results:', err);
		}
	}

	async function fetchEvents() {
		try {
			const res = await fetch(`http://localhost:3001/api/v1/clients/${clientId}/events`);
			if (res.ok) {
				const data = await res.json();
				events = data.events || [];
			}
		} catch (err) {
			console.error('Failed to fetch events:', err);
		}
	}

	async function fetchGroups() {
		try {
			const res = await fetch(`http://localhost:3001/api/v1/clients/${clientId}/groups`);
			if (res.ok) {
				const data = await res.json();
				groups = data.groups || [];
			}
		} catch (err) {
			console.error('Failed to fetch groups:', err);
		}
	}

	async function fetchConfiguration() {
		try {
			const res = await fetch(`http://localhost:3001/api/v1/clients/${clientId}/configuration`);
			if (res.ok) {
				const data = await res.json();
				configuration = data.configuration;
			}
		} catch (err) {
			console.error('Failed to fetch configuration:', err);
		}
	}

	async function addTag() {
		if (!newTag.trim()) return;
		try {
			const res = await fetch(`http://localhost:3001/api/v1/clients/${clientId}/tags`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ tag: newTag.trim() })
			});
			if (res.ok) {
				newTag = '';
				await fetchClient();
			}
		} catch (err) {
			console.error('Failed to add tag:', err);
		}
	}

	async function removeTag(tag: string) {
		try {
			const res = await fetch(`http://localhost:3001/api/v1/clients/${clientId}/tags/${tag}`, {
				method: 'DELETE'
			});
			if (res.ok) {
				await fetchClient();
			}
		} catch (err) {
			console.error('Failed to remove tag:', err);
		}
	}

	async function executeCommand(command: string) {
		// TODO: Implement SSH command execution
		alert(`Executing: ${command}`);
	}

	async function deleteClient() {
		if (!confirm('Are you sure you want to delete this client? This action cannot be undone.')) return;
		try {
			const res = await fetch(`http://localhost:3001/api/v1/clients/${clientId}`, {
				method: 'DELETE'
			});
			if (res.ok) {
				window.location.href = '/clients';
			}
		} catch (err) {
			alert('Failed to delete client');
		}
	}

	function formatDate(date: string | null) {
		if (!date) return 'Never';
		return new Date(date).toLocaleString();
	}

	function formatUptime(seconds: number) {
		const days = Math.floor(seconds / 86400);
		const hours = Math.floor((seconds % 86400) / 3600);
		const minutes = Math.floor((seconds % 3600) / 60);
		return `${days}d ${hours}h ${minutes}m`;
	}

	function getStatusColor(status: string) {
		switch (status) {
			case 'online': return 'bg-green-100 text-green-800';
			case 'offline': return 'bg-gray-100 text-gray-800';
			case 'pending': return 'bg-yellow-100 text-yellow-800';
			default: return 'bg-gray-100 text-gray-800';
		}
	}

	function getOSIcon(os: string) {
		switch (os.toLowerCase()) {
			case 'linux': return '🐧';
			case 'darwin': return '🍎';
			case 'windows': return '🪟';
			default: return '💻';
		}
	}

	$: if (activeTab) {
		if (activeTab === 'hardware' && !hardware) fetchHardware();
		if (activeTab === 'checkins' && checkIns.length === 0) fetchCheckIns();
		if (activeTab === 'osquery' && osqueryResults.length === 0) fetchOSQueryResults();
		if (activeTab === 'events' && events.length === 0) fetchEvents();
		if (activeTab === 'groups' && groups.length === 0) fetchGroups();
		if (activeTab === 'config' && !configuration) fetchConfiguration();
	}
</script>

<div class="p-6">
	{#if loading}
		<div class="flex justify-center items-center h-64">
			<div class="animate-spin rounded-full h-12 w-12 border-4 border-[#31413e] border-t-transparent"></div>
		</div>
	{:else if error}
		<div class="bg-red-50 border border-red-200 rounded-lg p-8 text-center">
			<p class="text-red-800 mb-4">{error}</p>
			<a href="/clients" class="text-[#d4af37] hover:underline">← Back to clients</a>
		</div>
	{:else if client}
		<!-- Header -->
		<div class="mb-6 flex items-center justify-between">
			<div>
				<a href="/clients" class="text-[#d4af37] hover:underline text-sm mb-2 inline-block">← Back to clients</a>
				<h1 class="text-3xl font-bold text-[#1c2f38] font-['Montserrat'] flex items-center gap-3">
					<span class="text-4xl">{getOSIcon(client.os_type)}</span>
					{client.hostname}
					<span class="inline-flex items-center px-3 py-1 rounded text-sm font-medium {getStatusColor(client.status)}">
						{client.status}
					</span>
				</h1>
				<p class="text-gray-600 mt-2">
					{client.os_type} {client.os_version || ''} • 
					Last seen: {formatDate(client.last_check_in)}
				</p>
			</div>
			<button
				on:click={deleteClient}
				class="px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg transition-colors"
			>
				Delete Client
			</button>
		</div>

		<!-- Tabs -->
		<div class="border-b border-gray-200 mb-6">
			<nav class="flex gap-6">
				<button
					on:click={() => activeTab = 'overview'}
					class="pb-3 border-b-2 transition-colors {activeTab === 'overview' ? 'border-[#d4af37] text-[#1c2f38]' : 'border-transparent text-gray-500 hover:text-gray-700'}"
				>
					Overview
				</button>
				<button
					on:click={() => activeTab = 'hardware'}
					class="pb-3 border-b-2 transition-colors {activeTab === 'hardware' ? 'border-[#d4af37] text-[#1c2f38]' : 'border-transparent text-gray-500 hover:text-gray-700'}"
				>
					Hardware
				</button>
				<button
					on:click={() => activeTab = 'groups'}
					class="pb-3 border-b-2 transition-colors {activeTab === 'groups' ? 'border-[#d4af37] text-[#1c2f38]' : 'border-transparent text-gray-500 hover:text-gray-700'}"
				>
					Tags & Groups
				</button>
				<button
					on:click={() => activeTab = 'config'}
					class="pb-3 border-b-2 transition-colors {activeTab === 'config' ? 'border-[#d4af37] text-[#1c2f38]' : 'border-transparent text-gray-500 hover:text-gray-700'}"
				>
					Configuration
				</button>
				<button
					on:click={() => activeTab = 'checkins'}
					class="pb-3 border-b-2 transition-colors {activeTab === 'checkins' ? 'border-[#d4af37] text-[#1c2f38]' : 'border-transparent text-gray-500 hover:text-gray-700'}"
				>
					Check-Ins
				</button>
				<button
					on:click={() => activeTab = 'osquery'}
					class="pb-3 border-b-2 transition-colors {activeTab === 'osquery' ? 'border-[#d4af37] text-[#1c2f38]' : 'border-transparent text-gray-500 hover:text-gray-700'}"
				>
					OSQuery Results
				</button>
				<button
					on:click={() => activeTab = 'events'}
					class="pb-3 border-b-2 transition-colors {activeTab === 'events' ? 'border-[#d4af37] text-[#1c2f38]' : 'border-transparent text-gray-500 hover:text-gray-700'}"
				>
					Events
				</button>
			</nav>
		</div>

		<!-- Tab Content -->
		{#if activeTab === 'overview'}
			<div class="grid grid-cols-1 md:grid-cols-2 gap-6">
				<!-- System Information -->
				<div class="bg-white rounded-lg border border-gray-200 p-6">
					<h3 class="text-lg font-semibold text-[#1c2f38] mb-4">System Information</h3>
					<dl class="space-y-3">
						<div class="flex justify-between">
							<dt class="text-gray-600">Hostname</dt>
							<dd class="font-medium text-[#1c2f38]">{client.hostname}</dd>
						</div>
						<div class="flex justify-between">
							<dt class="text-gray-600">IP Address</dt>
							<dd class="font-medium text-[#1c2f38]">{client.ip_address || 'N/A'}</dd>
						</div>
						<div class="flex justify-between">
							<dt class="text-gray-600">MAC Address</dt>
							<dd class="font-medium text-[#1c2f38]">{client.mac_address || 'N/A'}</dd>
						</div>
						<div class="flex justify-between">
							<dt class="text-gray-600">Operating System</dt>
							<dd class="font-medium text-[#1c2f38]">{client.os_type} {client.os_version || ''}</dd>
						</div>
						<div class="flex justify-between">
							<dt class="text-gray-600">Client Version</dt>
							<dd class="font-medium text-[#1c2f38]">{client.client_version || 'Unknown'}</dd>
						</div>
						<div class="flex justify-between">
							<dt class="text-gray-600">Enrolled</dt>
							<dd class="font-medium text-[#1c2f38]">{formatDate(client.created_at)}</dd>
						</div>
					</dl>
				</div>

				<!-- Quick Actions -->
				<div class="bg-white rounded-lg border border-gray-200 p-6">
					<h3 class="text-lg font-semibold text-[#1c2f38] mb-4">Quick Actions</h3>
					<div class="space-y-2">
						<button
							on:click={() => executeCommand('restart')}
							class="w-full px-4 py-2 bg-[#31413e] hover:bg-[#1c2f38] text-white rounded-lg transition-colors text-left"
						>
							Restart Client Service
						</button>
						<button
							on:click={() => executeCommand('update')}
							class="w-full px-4 py-2 bg-[#31413e] hover:bg-[#1c2f38] text-white rounded-lg transition-colors text-left"
						>
							Update Client
						</button>
						<button
							on:click={() => executeCommand('collect-logs')}
							class="w-full px-4 py-2 bg-[#31413e] hover:bg-[#1c2f38] text-white rounded-lg transition-colors text-left"
						>
							Collect Logs
						</button>
						<button
							on:click={() => activeTab = 'osquery'}
							class="w-full px-4 py-2 bg-[#d4af37] hover:bg-[#c19a28] text-white rounded-lg transition-colors text-left"
						>
							Run OSQuery
						</button>
					</div>
				</div>

				<!-- Tags -->
				<div class="bg-white rounded-lg border border-gray-200 p-6">
					<div class="flex justify-between items-center mb-4">
						<h3 class="text-lg font-semibold text-[#1c2f38]">Tags</h3>
						<button
							on:click={() => editingTags = !editingTags}
							class="text-[#d4af37] hover:text-[#c19a28] text-sm"
						>
							{editingTags ? 'Done' : 'Edit'}
						</button>
					</div>
					<div class="flex flex-wrap gap-2 mb-4">
						{#if client.tags && client.tags.length > 0}
							{#each client.tags as tag}
								<span class="inline-flex items-center gap-1 bg-gray-100 text-gray-700 px-3 py-1 rounded">
									{tag}
									{#if editingTags}
										<button on:click={() => removeTag(tag)} class="text-red-500 hover:text-red-700">×</button>
									{/if}
								</span>
							{/each}
						{:else}
							<span class="text-sm text-gray-400">No tags</span>
						{/if}
					</div>
					{#if editingTags}
						<div class="flex gap-2">
							<input
								type="text"
								bind:value={newTag}
								on:keydown={(e) => e.key === 'Enter' && addTag()}
								placeholder="Add tag..."
								class="flex-1 px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-[#d4af37]"
							/>
							<button
								on:click={addTag}
								class="px-4 py-2 bg-[#d4af37] hover:bg-[#c19a28] text-white rounded-lg"
							>
								Add
							</button>
						</div>
					{/if}
				</div>

				<!-- Recent Activity -->
				<div class="bg-white rounded-lg border border-gray-200 p-6">
					<h3 class="text-lg font-semibold text-[#1c2f38] mb-4">Recent Activity</h3>
					{#if events.length > 0}
						<div class="space-y-3">
							{#each events.slice(0, 5) as event}
								<div class="flex items-start gap-3 text-sm">
									<span class="text-gray-400">{formatDate(event.timestamp)}</span>
									<span class="text-gray-700">{event.message}</span>
								</div>
							{/each}
						</div>
					{:else}
						<p class="text-sm text-gray-400">No recent events</p>
					{/if}
				</div>
			</div>

		{:else if activeTab === 'hardware'}
			<div class="bg-white rounded-lg border border-gray-200 p-6">
				<h3 class="text-lg font-semibold text-[#1c2f38] mb-4">Hardware Information</h3>
				{#if hardware}
					<dl class="grid grid-cols-1 md:grid-cols-2 gap-4">
						<div>
							<dt class="text-gray-600 text-sm">CPU</dt>
							<dd class="font-medium text-[#1c2f38] mt-1">{hardware.cpu_model || 'N/A'}</dd>
							<dd class="text-sm text-gray-500">{hardware.cpu_cores || 0} cores @ {hardware.cpu_speed || 0} MHz</dd>
						</div>
						<div>
							<dt class="text-gray-600 text-sm">Memory</dt>
							<dd class="font-medium text-[#1c2f38] mt-1">{hardware.memory_total ? (hardware.memory_total / 1024 / 1024 / 1024).toFixed(2) + ' GB' : 'N/A'}</dd>
						</div>
						<div>
							<dt class="text-gray-600 text-sm">Disk</dt>
							<dd class="font-medium text-[#1c2f38] mt-1">{hardware.disk_total ? (hardware.disk_total / 1024 / 1024 / 1024).toFixed(2) + ' GB' : 'N/A'}</dd>
							<dd class="text-sm text-gray-500">Used: {hardware.disk_used ? (hardware.disk_used / 1024 / 1024 / 1024).toFixed(2) + ' GB' : '0 GB'}</dd>
						</div>
						<div>
							<dt class="text-gray-600 text-sm">Uptime</dt>
							<dd class="font-medium text-[#1c2f38] mt-1">{hardware.uptime ? formatUptime(hardware.uptime) : 'N/A'}</dd>
						</div>
					</dl>
				{:else}
					<p class="text-gray-400">No hardware information available</p>
				{/if}
			</div>

		{:else if activeTab === 'groups'}
			<div class="bg-white rounded-lg border border-gray-200 p-6">
				<h3 class="text-lg font-semibold text-[#1c2f38] mb-4">Groups</h3>
				{#if groups.length > 0}
					<div class="space-y-2">
						{#each groups as group}
							<div class="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
								<span class="font-medium text-[#1c2f38]">{group.name}</span>
								<button class="text-red-500 hover:text-red-700 text-sm">Remove</button>
							</div>
						{/each}
					</div>
				{:else}
					<p class="text-gray-400">Not in any groups</p>
				{/if}
			</div>

		{:else if activeTab === 'config'}
			<div class="bg-white rounded-lg border border-gray-200 p-6">
				<h3 class="text-lg font-semibold text-[#1c2f38] mb-4">Configuration</h3>
				{#if configuration}
					<pre class="bg-gray-50 p-4 rounded-lg overflow-x-auto text-sm">{JSON.stringify(configuration, null, 2)}</pre>
				{:else}
					<p class="text-gray-400">No configuration available</p>
				{/if}
			</div>

		{:else if activeTab === 'checkins'}
			<div class="bg-white rounded-lg border border-gray-200 p-6">
				<h3 class="text-lg font-semibold text-[#1c2f38] mb-4">Check-In History</h3>
				{#if checkIns.length > 0}
					<table class="w-full">
						<thead class="bg-gray-50">
							<tr>
								<th class="px-4 py-2 text-left text-xs font-medium text-gray-500">Timestamp</th>
								<th class="px-4 py-2 text-left text-xs font-medium text-gray-500">IP Address</th>
								<th class="px-4 py-2 text-left text-xs font-medium text-gray-500">Status</th>
							</tr>
						</thead>
						<tbody class="divide-y divide-gray-200">
							{#each checkIns as checkIn}
								<tr>
									<td class="px-4 py-3 text-sm">{formatDate(checkIn.timestamp)}</td>
									<td class="px-4 py-3 text-sm">{checkIn.ip_address}</td>
									<td class="px-4 py-3 text-sm">
										<span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium {getStatusColor(checkIn.status)}">
											{checkIn.status}
										</span>
									</td>
								</tr>
							{/each}
						</tbody>
					</table>
				{:else}
					<p class="text-gray-400">No check-ins recorded</p>
				{/if}
			</div>

		{:else if activeTab === 'osquery'}
			<div class="bg-white rounded-lg border border-gray-200 p-6">
				<div class="flex items-center justify-between mb-4">
					<h3 class="text-lg font-semibold text-[#1c2f38]">OSQuery Results</h3>
					<a href="/osquery?client={clientId}" class="text-[#d4af37] hover:text-[#c19a28] text-sm">
						Run New Query →
					</a>
				</div>
				{#if osqueryResults.length > 0}
					<div class="space-y-4">
						{#each osqueryResults as result}
							<div class="border border-gray-200 rounded-lg p-4">
								<div class="flex justify-between items-start mb-2">
									<span class="font-medium text-[#1c2f38]">{result.query_name}</span>
									<span class="text-xs text-gray-500">{formatDate(result.timestamp)}</span>
								</div>
								<pre class="bg-gray-50 p-3 rounded text-xs overflow-x-auto">{JSON.stringify(result.results, null, 2)}</pre>
							</div>
						{/each}
					</div>
				{:else}
					<p class="text-gray-400">No OSQuery results yet</p>
				{/if}
			</div>

		{:else if activeTab === 'events'}
			<div class="bg-white rounded-lg border border-gray-200 p-6">
				<h3 class="text-lg font-semibold text-[#1c2f38] mb-4">Activity Events</h3>
				{#if events.length > 0}
					<div class="space-y-3">
						{#each events as event}
							<div class="flex items-start gap-3 p-3 bg-gray-50 rounded-lg">
								<span class="text-xs text-gray-500 whitespace-nowrap">{formatDate(event.timestamp)}</span>
								<span class="text-sm text-gray-700">{event.message}</span>
							</div>
						{/each}
					</div>
				{:else}
					<p class="text-gray-400">No events recorded</p>
				{/if}
			</div>
		{/if}
	{/if}
</div>
