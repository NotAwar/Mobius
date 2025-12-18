<script lang="ts">
	import { onMount } from 'svelte';

	let clients: any[] = [];
	let loading = true;
	let error = '';
	
	// Filters
	let statusFilter = '';
	let osFilter = '';
	let tagFilter = '';
	let searchQuery = '';
	
	// Pagination
	let currentPage = 1;
	let pageSize = 50;
	let totalClients = 0;
	
	// Bulk actions
	let selectedClients: Set<string> = new Set();
	let bulkActionMode = false;
	
	// Available groups for bulk actions
	let availableGroups: any[] = [];

	onMount(() => {
		Promise.all([fetchClients(), fetchGroups()]);
		// Set up auto-refresh every 30 seconds
		const interval = setInterval(fetchClients, 30000);
		return () => clearInterval(interval);
	});

	async function fetchClients() {
		try {
			const params = new URLSearchParams({
				limit: pageSize.toString(),
				offset: ((currentPage - 1) * pageSize).toString()
			});
			
			if (statusFilter) params.append('status', statusFilter);
			if (osFilter) params.append('os_type', osFilter);
			if (tagFilter) params.append('tag', tagFilter);
			
			const res = await fetch(`http://localhost:3001/api/v1/clients?${params}`);
			if (!res.ok) throw new Error('Failed to fetch clients');
			
			const data = await res.json();
			clients = data.clients || [];
			totalClients = data.total || 0;
			
			// Filter by search query if present
			if (searchQuery) {
				clients = clients.filter(c => 
					c.hostname?.toLowerCase().includes(searchQuery.toLowerCase()) ||
					c.ip_address?.includes(searchQuery) ||
					c.mac_address?.toLowerCase().includes(searchQuery.toLowerCase())
				);
			}
		} catch (err: any) {
			error = err.message;
		} finally {
			loading = false;
		}
	}

	async function fetchGroups() {
		try {
			const res = await fetch('http://localhost:3001/api/v1/clients/groups');
			if (!res.ok) return;
			const data = await res.json();
			availableGroups = data.groups || [];
		} catch (err) {
			console.error('Failed to fetch groups:', err);
		}
	}

	function handleFilterChange() {
		currentPage = 1;
		fetchClients();
	}

	function handleSearch(e: Event) {
		const target = e.target as HTMLInputElement;
		searchQuery = target.value;
		handleFilterChange();
	}

	function toggleClientSelection(clientId: string) {
		if (selectedClients.has(clientId)) {
			selectedClients.delete(clientId);
		} else {
			selectedClients.add(clientId);
		}
		selectedClients = selectedClients; // Trigger reactivity
	}

	function selectAll() {
		if (selectedClients.size === clients.length) {
			selectedClients.clear();
		} else {
			clients.forEach(c => selectedClients.add(c.id));
		}
		selectedClients = selectedClients;
	}

	async function bulkAddToGroup(groupId: string) {
		// TODO: Implement bulk add to group
		alert(`Adding ${selectedClients.size} clients to group ${groupId}`);
	}

	async function bulkRunQuery() {
		// TODO: Implement bulk query execution
		alert(`Running query on ${selectedClients.size} clients`);
	}

	async function bulkDelete() {
		if (!confirm(`Are you sure you want to delete ${selectedClients.size} clients?`)) return;
		// TODO: Implement bulk delete
		alert(`Deleting ${selectedClients.size} clients`);
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

	function formatLastSeen(lastSeen: string | null) {
		if (!lastSeen) return 'Never';
		const date = new Date(lastSeen);
		const now = new Date();
		const diff = now.getTime() - date.getTime();
		const minutes = Math.floor(diff / 60000);
		
		if (minutes < 1) return 'Just now';
		if (minutes < 60) return `${minutes}m ago`;
		const hours = Math.floor(minutes / 60);
		if (hours < 24) return `${hours}h ago`;
		const days = Math.floor(hours / 24);
		return `${days}d ago`;
	}

	function exportToCSV() {
		const headers = ['Hostname', 'IP Address', 'MAC Address', 'OS', 'Status', 'Last Seen'];
		const rows = clients.map(c => [
			c.hostname,
			c.ip_address || '',
			c.mac_address || '',
			c.os_type,
			c.status,
			c.last_check_in || 'Never'
		]);
		
		const csv = [headers, ...rows].map(row => row.join(',')).join('\n');
		const blob = new Blob([csv], { type: 'text/csv' });
		const url = URL.createObjectURL(blob);
		const a = document.createElement('a');
		a.href = url;
		a.download = `clients-${new Date().toISOString()}.csv`;
		a.click();
	}

	$: totalPages = Math.ceil(totalClients / pageSize);
</script>

<div class="p-6">
	<!-- Header -->
	<div class="mb-6">
		<h1 class="text-3xl font-bold text-[#1c2f38] font-['Montserrat']">Clients</h1>
		<p class="text-gray-600 mt-2">Manage and monitor all connected devices</p>
	</div>

	<!-- Error Banner -->
	{#if error}
		<div class="mb-4 bg-red-50 border border-red-200 rounded-lg p-4">
			<p class="text-red-800">{error}</p>
		</div>
	{/if}

	<!-- Filters & Search Bar -->
	<div class="mb-6 bg-white rounded-lg border border-gray-200 p-4">
		<div class="grid grid-cols-1 md:grid-cols-5 gap-4">
			<!-- Search -->
			<div class="md:col-span-2">
				<input
					type="text"
					placeholder="Search by hostname, IP, or MAC address..."
					on:input={handleSearch}
					class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-[#d4af37]"
				/>
			</div>

			<!-- Status Filter -->
			<select
				bind:value={statusFilter}
				on:change={handleFilterChange}
				class="px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-[#d4af37]"
			>
				<option value="">All Status</option>
				<option value="online">Online</option>
				<option value="offline">Offline</option>
				<option value="pending">Pending</option>
			</select>

			<!-- OS Filter -->
			<select
				bind:value={osFilter}
				on:change={handleFilterChange}
				class="px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-[#d4af37]"
			>
				<option value="">All OS</option>
				<option value="linux">Linux</option>
				<option value="darwin">macOS</option>
				<option value="windows">Windows</option>
			</select>

			<!-- Actions -->
			<button
				on:click={exportToCSV}
				class="px-4 py-2 bg-[#31413e] hover:bg-[#1c2f38] text-white rounded-lg transition-colors"
			>
				Export CSV
			</button>
		</div>
	</div>

	<!-- Bulk Actions Bar -->
	{#if selectedClients.size > 0}
		<div class="mb-4 bg-[#d4af37] rounded-lg p-4 flex items-center justify-between">
			<span class="text-[#1c2f38] font-semibold">
				{selectedClients.size} client{selectedClients.size !== 1 ? 's' : ''} selected
			</span>
			<div class="flex gap-3">
				<select
					on:change={(e) => bulkAddToGroup(e.currentTarget.value)}
					class="px-4 py-2 bg-white text-[#1c2f38] rounded-lg"
				>
					<option value="">Add to Group...</option>
					{#each availableGroups as group}
						<option value={group.id}>{group.name}</option>
					{/each}
				</select>
				<button
					on:click={bulkRunQuery}
					class="px-4 py-2 bg-white text-[#1c2f38] rounded-lg hover:bg-gray-100"
				>
					Run Query
				</button>
				<button
					on:click={bulkDelete}
					class="px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700"
				>
					Delete
				</button>
				<button
					on:click={() => { selectedClients.clear(); selectedClients = selectedClients; }}
					class="px-4 py-2 bg-gray-600 text-white rounded-lg hover:bg-gray-700"
				>
					Clear
				</button>
			</div>
		</div>
	{/if}

	<!-- Clients Table -->
	{#if loading}
		<div class="flex justify-center items-center h-64">
			<div class="animate-spin rounded-full h-12 w-12 border-4 border-[#31413e] border-t-transparent"></div>
		</div>
	{:else if clients.length === 0}
		<div class="bg-gray-50 rounded-lg p-12 text-center">
			<p class="text-gray-500 mb-4">No clients found</p>
			<p class="text-sm text-gray-400">
				{#if statusFilter || osFilter || searchQuery}
					Try adjusting your filters
				{:else}
					Enroll clients to see them here
				{/if}
			</p>
		</div>
	{:else}
		<div class="bg-white rounded-lg border border-gray-200 overflow-hidden">
			<table class="w-full">
				<thead class="bg-[#31413e] text-white">
					<tr>
						<th class="px-4 py-3 text-left">
							<input
								type="checkbox"
								checked={selectedClients.size === clients.length}
								on:change={selectAll}
								class="rounded"
							/>
						</th>
						<th class="px-6 py-3 text-left text-sm font-semibold">Hostname</th>
						<th class="px-6 py-3 text-left text-sm font-semibold">OS</th>
						<th class="px-6 py-3 text-left text-sm font-semibold">IP Address</th>
						<th class="px-6 py-3 text-left text-sm font-semibold">Status</th>
						<th class="px-6 py-3 text-left text-sm font-semibold">Last Seen</th>
						<th class="px-6 py-3 text-left text-sm font-semibold">Tags</th>
						<th class="px-6 py-3 text-left text-sm font-semibold">Actions</th>
					</tr>
				</thead>
				<tbody class="divide-y divide-gray-200">
					{#each clients as client}
						<tr class="hover:bg-gray-50">
							<td class="px-4 py-4">
								<input
									type="checkbox"
									checked={selectedClients.has(client.id)}
									on:change={() => toggleClientSelection(client.id)}
									class="rounded"
								/>
							</td>
							<td class="px-6 py-4">
								<a
									href="/clients/{client.id}"
									class="font-medium text-[#1c2f38] hover:text-[#d4af37]"
								>
									{client.hostname}
								</a>
							</td>
							<td class="px-6 py-4">
								<span class="text-2xl" title={client.os_type}>
									{getOSIcon(client.os_type)}
								</span>
								<span class="text-xs text-gray-500 ml-1">{client.os_version || ''}</span>
							</td>
							<td class="px-6 py-4 text-sm text-gray-600">
								{client.ip_address || '-'}
							</td>
							<td class="px-6 py-4">
								<span class="inline-flex items-center px-2.5 py-0.5 rounded text-xs font-medium {getStatusColor(client.status)}">
									{client.status}
								</span>
							</td>
							<td class="px-6 py-4 text-sm text-gray-600">
								{formatLastSeen(client.last_check_in)}
							</td>
							<td class="px-6 py-4">
								{#if client.tags && client.tags.length > 0}
									<div class="flex gap-1 flex-wrap">
										{#each client.tags.slice(0, 2) as tag}
											<span class="text-xs bg-gray-100 text-gray-700 px-2 py-0.5 rounded">{tag}</span>
										{/each}
										{#if client.tags.length > 2}
											<span class="text-xs text-gray-500">+{client.tags.length - 2}</span>
										{/if}
									</div>
								{:else}
									<span class="text-xs text-gray-400">No tags</span>
								{/if}
							</td>
							<td class="px-6 py-4">
								<a
									href="/clients/{client.id}"
									class="text-[#d4af37] hover:text-[#c19a28] text-sm font-medium"
								>
									Details →
								</a>
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>

		<!-- Pagination -->
		<div class="mt-4 flex items-center justify-between">
			<div class="text-sm text-gray-600">
				Showing {((currentPage - 1) * pageSize) + 1} to {Math.min(currentPage * pageSize, totalClients)} of {totalClients} clients
			</div>
			<div class="flex gap-2">
				<button
					on:click={() => { currentPage = Math.max(1, currentPage - 1); fetchClients(); }}
					disabled={currentPage === 1}
					class="px-4 py-2 bg-white border border-gray-300 rounded-lg hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
				>
					Previous
				</button>
				<span class="px-4 py-2 bg-[#31413e] text-white rounded-lg">
					Page {currentPage} of {totalPages}
				</span>
				<button
					on:click={() => { currentPage = Math.min(totalPages, currentPage + 1); fetchClients(); }}
					disabled={currentPage === totalPages}
					class="px-4 py-2 bg-white border border-gray-300 rounded-lg hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
				>
					Next
				</button>
			</div>
		</div>
	{/if}
</div>
