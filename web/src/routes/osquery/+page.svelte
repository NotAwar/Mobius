<script lang="ts">
	import { onMount } from 'svelte';
	import { page } from '$app/stores';

	let query = '';
	let queryName = '';
	let selectedTargets: string[] = [];
	let targetType = 'clients'; // 'clients' or 'groups'
	
	let executing = false;
	let results: any[] = [];
	let error = '';
	
	// Available targets
	let clients: any[] = [];
	let groups: any[] = [];
	
	// Query library
	let savedQueries: any[] = [];
	let showLibrary = false;
	let showSaveModal = false;
	
	// Pre-populate from URL params
	$: {
		const clientParam = $page.url.searchParams.get('client');
		const groupParam = $page.url.searchParams.get('group');
		
		if (clientParam && !selectedTargets.includes(clientParam)) {
			selectedTargets = [clientParam];
			targetType = 'clients';
		} else if (groupParam && !selectedTargets.includes(groupParam)) {
			selectedTargets = [groupParam];
			targetType = 'groups';
		}
	}

	onMount(async () => {
		await Promise.all([fetchClients(), fetchGroups(), fetchSavedQueries()]);
	});

	async function fetchClients() {
		try {
			const res = await fetch('http://localhost:3001/api/v1/clients?status=online');
			if (res.ok) {
				const data = await res.json();
				clients = data.clients || [];
			}
		} catch (err) {
			console.error('Failed to fetch clients:', err);
		}
	}

	async function fetchGroups() {
		try {
			const res = await fetch('http://localhost:3001/api/v1/clients/groups');
			if (res.ok) {
				const data = await res.json();
				groups = data.groups || [];
			}
		} catch (err) {
			console.error('Failed to fetch groups:', err);
		}
	}

	async function fetchSavedQueries() {
		try {
			const res = await fetch('http://localhost:3001/api/v1/osquery/queries');
			if (res.ok) {
				const data = await res.json();
				savedQueries = data.queries || [];
			}
		} catch (err) {
			console.error('Failed to fetch saved queries:', err);
		}
	}

	async function executeQuery() {
		if (!query.trim() || selectedTargets.length === 0) {
			error = 'Please enter a query and select at least one target';
			return;
		}

		executing = true;
		error = '';
		results = [];

		try {
			// First, create the query if it doesn't exist
			let queryId = null;
			if (queryName.trim()) {
				const createRes = await fetch('http://localhost:3001/api/v1/osquery/queries', {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({
						name: queryName.trim(),
						query: query.trim(),
						description: ''
					})
				});
				if (createRes.ok) {
					const data = await createRes.json();
					queryId = data.query.id;
				}
			}

			// Execute the query on selected targets
			const execRes = await fetch('http://localhost:3001/api/v1/osquery/execute', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({
					query: query.trim(),
					query_id: queryId,
					target_type: targetType,
					target_ids: selectedTargets
				})
			});

			if (!execRes.ok) throw new Error('Failed to execute query');

			const data = await execRes.json();
			results = data.results || [];
		} catch (err: any) {
			error = err.message;
		} finally {
			executing = false;
		}
	}

	async function saveQuery() {
		if (!queryName.trim() || !query.trim()) return;

		try {
			const res = await fetch('http://localhost:3001/api/v1/osquery/queries', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({
					name: queryName.trim(),
					query: query.trim(),
					description: ''
				})
			});

			if (res.ok) {
				showSaveModal = false;
				queryName = '';
				await fetchSavedQueries();
			}
		} catch (err) {
			alert('Failed to save query');
		}
	}

	function loadQuery(savedQuery: any) {
		query = savedQuery.query;
		queryName = savedQuery.name;
		showLibrary = false;
	}

	function toggleTarget(id: string) {
		if (selectedTargets.includes(id)) {
			selectedTargets = selectedTargets.filter(t => t !== id);
		} else {
			selectedTargets = [...selectedTargets, id];
		}
	}

	function selectAllTargets() {
		const targets = targetType === 'clients' ? clients : groups;
		if (selectedTargets.length === targets.length) {
			selectedTargets = [];
		} else {
			selectedTargets = targets.map(t => t.id);
		}
	}

	function exportResults() {
		if (results.length === 0) return;

		// Get all unique keys from results
		const keys = Array.from(new Set(results.flatMap(r => Object.keys(r.results || {}))));
		const headers = ['Client', 'Timestamp', ...keys];
		
		const rows = results.map(r => [
			r.client_hostname || r.client_id,
			new Date(r.timestamp).toISOString(),
			...keys.map(k => JSON.stringify(r.results?.[k] || ''))
		]);

		const csv = [headers, ...rows].map(row => row.join(',')).join('\n');
		const blob = new Blob([csv], { type: 'text/csv' });
		const url = URL.createObjectURL(blob);
		const a = document.createElement('a');
		a.href = url;
		a.download = `osquery-results-${new Date().toISOString()}.csv`;
		a.click();
	}

	// Common OSQuery queries
	const commonQueries = [
		{ name: 'Running Processes', query: 'SELECT pid, name, path, cmdline FROM processes;' },
		{ name: 'Logged In Users', query: 'SELECT user, tty, time, host FROM logged_in_users;' },
		{ name: 'Listening Ports', query: 'SELECT pid, port, protocol, address FROM listening_ports;' },
		{ name: 'Installed Programs', query: 'SELECT name, version, install_location FROM programs;' },
		{ name: 'System Information', query: 'SELECT * FROM system_info;' },
		{ name: 'Network Interfaces', query: 'SELECT interface, address, mask, type FROM interface_addresses;' },
		{ name: 'Startup Items', query: 'SELECT name, path, source FROM startup_items;' },
		{ name: 'USB Devices', query: 'SELECT vendor, model, serial FROM usb_devices;' }
	];
</script>

<div class="p-6">
	<!-- Header -->
	<div class="mb-6">
		<h1 class="text-3xl font-bold text-[#1c2f38] font-['Montserrat']">OSQuery Execution</h1>
		<p class="text-gray-600 mt-2">Run SQL queries against client systems using OSQuery</p>
	</div>

	<div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
		<!-- Query Editor (Left/Main) -->
		<div class="lg:col-span-2 space-y-6">
			<!-- Query Input -->
			<div class="bg-white rounded-lg border border-gray-200 p-6">
				<div class="flex items-center justify-between mb-4">
					<h2 class="text-lg font-semibold text-[#1c2f38]">SQL Query</h2>
					<div class="flex gap-2">
						<button
							on:click={() => showLibrary = !showLibrary}
							class="px-4 py-2 bg-gray-100 hover:bg-gray-200 text-gray-700 rounded-lg text-sm"
						>
							{showLibrary ? 'Hide' : 'Show'} Library
						</button>
						<button
							on:click={() => showSaveModal = true}
							disabled={!query.trim()}
							class="px-4 py-2 bg-[#31413e] hover:bg-[#1c2f38] text-white rounded-lg text-sm disabled:opacity-50"
						>
							Save Query
						</button>
					</div>
				</div>

				<!-- Query Library Dropdown -->
				{#if showLibrary}
					<div class="mb-4 bg-gray-50 rounded-lg p-4">
						<h3 class="text-sm font-medium text-gray-700 mb-3">Common Queries</h3>
						<div class="grid grid-cols-2 gap-2">
							{#each commonQueries as commonQuery}
								<button
									on:click={() => { query = commonQuery.query; showLibrary = false; }}
									class="text-left px-3 py-2 bg-white hover:bg-gray-100 border border-gray-200 rounded text-sm"
								>
									{commonQuery.name}
								</button>
							{/each}
						</div>

						{#if savedQueries.length > 0}
							<h3 class="text-sm font-medium text-gray-700 mt-4 mb-3">Saved Queries</h3>
							<div class="space-y-2">
								{#each savedQueries as savedQuery}
									<button
										on:click={() => loadQuery(savedQuery)}
										class="w-full text-left px-3 py-2 bg-white hover:bg-gray-100 border border-gray-200 rounded text-sm"
									>
										{savedQuery.name}
									</button>
								{/each}
							</div>
						{/if}
					</div>
				{/if}

				<div class="mb-4">
					<input
						type="text"
						bind:value={queryName}
						placeholder="Query name (optional)"
						class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-[#d4af37] mb-2"
					/>
					<textarea
						bind:value={query}
						placeholder="SELECT * FROM system_info;"
						rows="8"
						class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-[#d4af37] font-mono text-sm"
					></textarea>
				</div>

				<button
					on:click={executeQuery}
					disabled={executing || !query.trim() || selectedTargets.length === 0}
					class="w-full px-6 py-3 bg-[#d4af37] hover:bg-[#c19a28] text-white rounded-lg font-medium disabled:opacity-50 disabled:cursor-not-allowed"
				>
					{executing ? 'Executing...' : `Execute Query on ${selectedTargets.length} ${targetType === 'clients' ? 'Client(s)' : 'Group(s)'}`}
				</button>
			</div>

			<!-- Results -->
			<div class="bg-white rounded-lg border border-gray-200 p-6">
				<div class="flex items-center justify-between mb-4">
					<h2 class="text-lg font-semibold text-[#1c2f38]">Results</h2>
					{#if results.length > 0}
						<button
							on:click={exportResults}
							class="px-4 py-2 bg-[#31413e] hover:bg-[#1c2f38] text-white rounded-lg text-sm"
						>
							Export CSV
						</button>
					{/if}
				</div>

				{#if error}
					<div class="bg-red-50 border border-red-200 rounded-lg p-4 mb-4">
						<p class="text-red-800">{error}</p>
					</div>
				{/if}

				{#if executing}
					<div class="flex justify-center items-center h-32">
						<div class="animate-spin rounded-full h-8 w-8 border-4 border-[#31413e] border-t-transparent"></div>
					</div>
				{:else if results.length > 0}
					<div class="space-y-4 max-h-96 overflow-y-auto">
						{#each results as result}
							<div class="border border-gray-200 rounded-lg p-4">
								<div class="flex justify-between items-start mb-2">
									<div>
										<span class="font-medium text-[#1c2f38]">{result.client_hostname || result.client_id}</span>
										<span class="ml-2 text-xs {result.success ? 'text-green-600' : 'text-red-600'}">
											{result.success ? '✓ Success' : '✗ Failed'}
										</span>
									</div>
									<span class="text-xs text-gray-500">{new Date(result.timestamp).toLocaleString()}</span>
								</div>
								{#if result.success}
									<pre class="bg-gray-50 p-3 rounded text-xs overflow-x-auto">{JSON.stringify(result.results, null, 2)}</pre>
								{:else}
									<p class="text-red-600 text-sm">{result.error || 'Query failed'}</p>
								{/if}
							</div>
						{/each}
					</div>
				{:else}
					<p class="text-gray-400 text-center py-8">No results yet. Execute a query to see results here.</p>
				{/if}
			</div>
		</div>

		<!-- Target Selection (Right) -->
		<div class="space-y-6">
			<!-- Target Type Selector -->
			<div class="bg-white rounded-lg border border-gray-200 p-6">
				<h2 class="text-lg font-semibold text-[#1c2f38] mb-4">Target Selection</h2>
				
				<div class="flex gap-2 mb-4">
					<button
						on:click={() => { targetType = 'clients'; selectedTargets = []; }}
						class="flex-1 px-4 py-2 rounded-lg {targetType === 'clients' ? 'bg-[#d4af37] text-white' : 'bg-gray-100 text-gray-700'}"
					>
						Clients
					</button>
					<button
						on:click={() => { targetType = 'groups'; selectedTargets = []; }}
						class="flex-1 px-4 py-2 rounded-lg {targetType === 'groups' ? 'bg-[#d4af37] text-white' : 'bg-gray-100 text-gray-700'}"
					>
						Groups
					</button>
				</div>

				<div class="flex items-center justify-between mb-3">
					<span class="text-sm text-gray-600">{selectedTargets.length} selected</span>
					<button
						on:click={selectAllTargets}
						class="text-sm text-[#d4af37] hover:text-[#c19a28]"
					>
						{selectedTargets.length === (targetType === 'clients' ? clients : groups).length ? 'Deselect All' : 'Select All'}
					</button>
				</div>

				<div class="max-h-96 overflow-y-auto space-y-2">
					{#if targetType === 'clients'}
						{#if clients.length === 0}
							<p class="text-sm text-gray-400">No online clients</p>
						{:else}
							{#each clients as client}
								<label class="flex items-center gap-3 p-3 bg-gray-50 hover:bg-gray-100 rounded-lg cursor-pointer">
									<input
										type="checkbox"
										checked={selectedTargets.includes(client.id)}
										on:change={() => toggleTarget(client.id)}
										class="rounded"
									/>
									<div class="flex-1">
										<div class="font-medium text-sm text-[#1c2f38]">{client.hostname}</div>
										<div class="text-xs text-gray-500">{client.os_type} • {client.ip_address || 'N/A'}</div>
									</div>
								</label>
							{/each}
						{/if}
					{:else}
						{#if groups.length === 0}
							<p class="text-sm text-gray-400">No groups created</p>
						{:else}
							{#each groups as group}
								<label class="flex items-center gap-3 p-3 bg-gray-50 hover:bg-gray-100 rounded-lg cursor-pointer">
									<input
										type="checkbox"
										checked={selectedTargets.includes(group.id)}
										on:change={() => toggleTarget(group.id)}
										class="rounded"
									/>
									<div class="flex-1">
										<div class="font-medium text-sm text-[#1c2f38]">{group.name}</div>
										<div class="text-xs text-gray-500">{group.client_count || 0} clients</div>
									</div>
								</label>
							{/each}
						{/if}
					{/if}
				</div>
			</div>

			<!-- Query Tips -->
			<div class="bg-[#1c2f38] text-white rounded-lg p-6">
				<h3 class="font-semibold mb-3">Query Tips</h3>
				<ul class="space-y-2 text-sm">
					<li>• Use standard SQL syntax</li>
					<li>• Results limited to 100 rows per client</li>
					<li>• Queries timeout after 30 seconds</li>
					<li>• Use WHERE clauses to filter results</li>
					<li>• JOIN multiple tables for complex queries</li>
				</ul>
				<a
					href="https://osquery.io/schema/"
					target="_blank"
					class="inline-block mt-4 text-[#d4af37] hover:underline text-sm"
				>
					View OSQuery Schema →
				</a>
			</div>
		</div>
	</div>
</div>

<!-- Save Query Modal -->
{#if showSaveModal}
	<!-- svelte-ignore a11y_click_events_have_key_events -->
	<!-- svelte-ignore a11y_no_static_element_interactions -->
	<div class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50" on:click={() => showSaveModal = false}>
		<div class="bg-white rounded-lg p-6 w-full max-w-md" on:click|stopPropagation role="dialog" aria-modal="true" tabindex="-1">
			<h2 class="text-2xl font-bold text-[#1c2f38] mb-4">Save Query</h2>
			
			<div class="space-y-4">
				<div>
					<label for="query-name" class="block text-sm font-medium text-gray-700 mb-1">Query Name *</label>
					<input
						id="query-name"
						type="text"
						bind:value={queryName}
						placeholder="My Custom Query"
						class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-[#d4af37]"
					/>
				</div>

				<div>
					<label for="query-text" class="block text-sm font-medium text-gray-700 mb-1">Query</label>
					<textarea
						id="query-text"
						bind:value={query}
						rows="6"
						readonly
						class="w-full px-4 py-2 border border-gray-300 rounded-lg bg-gray-50 font-mono text-sm"
					></textarea>
				</div>
			</div>

			<div class="flex gap-3 mt-6">
				<button
					on:click={() => showSaveModal = false}
					class="flex-1 px-4 py-2 bg-gray-200 hover:bg-gray-300 text-gray-800 rounded-lg"
				>
					Cancel
				</button>
				<button
					on:click={saveQuery}
					disabled={!queryName.trim()}
					class="flex-1 px-4 py-2 bg-[#d4af37] hover:bg-[#c19a28] text-white rounded-lg disabled:opacity-50"
				>
					Save Query
				</button>
			</div>
		</div>
	</div>
{/if}
