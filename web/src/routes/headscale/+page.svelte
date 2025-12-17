<script lang="ts">
	import { onMount } from 'svelte';

	interface User {
		name: string;
		createdAt: string;
	}

	interface Node {
		name: string;
		user: string;
		lastSeen: string;
		online: boolean;
	}

	let users: User[] = [];
	let nodes: Node[] = [];
	let loading = true;
	let error: string | null = null;
	let showCreateUserForm = false;
	let newUserName = '';
	let creating = false;

	async function fetchHeadscaleData() {
		try {
			const [usersRes, nodesRes] = await Promise.all([
				fetch('http://localhost:3000/api/v1/headscale/users'),
				fetch('http://localhost:3000/api/v1/headscale/nodes')
			]);

			if (!usersRes.ok || !nodesRes.ok) {
				throw new Error('Failed to fetch Headscale data');
			}

			const usersData = await usersRes.json();
			const nodesData = await nodesRes.json();

			users = usersData.users || [];
			nodes = nodesData.nodes || [];
			loading = false;
		} catch (err) {
			error = err instanceof Error ? err.message : 'Unknown error';
			loading = false;
		}
	}

	async function createUser() {
		if (!newUserName.trim()) return;

		creating = true;
		try {
			const res = await fetch('http://localhost:3000/api/v1/headscale/users', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ name: newUserName })
			});

			if (!res.ok) throw new Error('Failed to create user');

			newUserName = '';
			showCreateUserForm = false;
			await fetchHeadscaleData();
		} catch (err) {
			error = err instanceof Error ? err.message : 'Unknown error';
		} finally {
			creating = false;
		}
	}

	onMount(() => {
		fetchHeadscaleData();
		const interval = setInterval(fetchHeadscaleData, 10000);
		return () => clearInterval(interval);
	});
</script>

<div class="min-h-screen bg-gradient-to-br from-purple-50 to-blue-50 dark:from-gray-900 dark:to-gray-800">
	<header class="bg-white dark:bg-gray-800 shadow">
		<div class="mx-auto max-w-7xl px-4 py-6 sm:px-6 lg:px-8">
			<div class="flex items-center justify-between">
				<h1 class="text-3xl font-bold tracking-tight text-gray-900 dark:text-white">
					🌐 Headscale VPN
				</h1>
				<a
					href="/"
					class="rounded-lg bg-purple-600 px-4 py-2 text-white transition hover:bg-purple-700"
				>
					← Back to Dashboard
				</a>
			</div>
		</div>
	</header>

	<main class="mx-auto max-w-7xl px-4 py-6 sm:px-6 lg:px-8">
		{#if error}
			<div class="mb-4 rounded-lg bg-red-50 p-4 dark:bg-red-900/20">
				<p class="text-red-800 dark:text-red-200">Error: {error}</p>
			</div>
		{/if}

		{#if loading}
			<div class="flex items-center justify-center py-12">
				<div class="h-32 w-32 animate-spin rounded-full border-b-2 border-purple-600"></div>
			</div>
		{:else}
			<!-- Users Section -->
			<div class="mb-8 rounded-lg bg-white p-6 shadow dark:bg-gray-800">
				<div class="mb-4 flex items-center justify-between">
					<h2 class="text-xl font-semibold text-gray-900 dark:text-white">VPN Users</h2>
					<button
						onclick={() => (showCreateUserForm = !showCreateUserForm)}
						class="rounded-lg bg-blue-600 px-4 py-2 text-white transition hover:bg-blue-700"
					>
						{showCreateUserForm ? 'Cancel' : '+ Create User'}
					</button>
				</div>

				{#if showCreateUserForm}
					<div class="mb-4 rounded-lg bg-gray-50 p-4 dark:bg-gray-700">
						<form
							onsubmit={(e) => {
								e.preventDefault();
								createUser();
							}}
							class="flex gap-4"
						>
							<input
								type="text"
								bind:value={newUserName}
								placeholder="User name"
								class="flex-1 rounded-lg border border-gray-300 px-4 py-2 dark:border-gray-600 dark:bg-gray-800 dark:text-white"
								required
							/>
							<button
								type="submit"
								disabled={creating}
								class="rounded-lg bg-green-600 px-6 py-2 text-white transition hover:bg-green-700 disabled:opacity-50"
							>
								{creating ? 'Creating...' : 'Create'}
							</button>
						</form>
					</div>
				{/if}

				{#if users.length === 0}
					<p class="text-center text-gray-600 dark:text-gray-400">
						No users found. Create one to get started!
					</p>
				{:else}
					<div class="overflow-x-auto">
						<table class="w-full">
							<thead class="border-b border-gray-200 dark:border-gray-700">
								<tr>
									<th class="pb-3 text-left text-sm font-medium text-gray-600 dark:text-gray-300"
										>Name</th
									>
									<th class="pb-3 text-left text-sm font-medium text-gray-600 dark:text-gray-300"
										>Created</th
									>
								</tr>
							</thead>
							<tbody>
								{#each users as user}
									<tr class="border-b border-gray-100 dark:border-gray-700/50">
										<td class="py-3 text-sm font-medium text-gray-900 dark:text-gray-100"
											>{user.name}</td
										>
										<td class="py-3 text-sm text-gray-600 dark:text-gray-400">{user.createdAt}</td>
									</tr>
								{/each}
							</tbody>
						</table>
					</div>
				{/if}
			</div>

			<!-- Nodes Section -->
			<div class="rounded-lg bg-white p-6 shadow dark:bg-gray-800">
				<h2 class="mb-4 text-xl font-semibold text-gray-900 dark:text-white">Connected Nodes</h2>
				{#if nodes.length === 0}
					<p class="text-center text-gray-600 dark:text-gray-400">No nodes connected</p>
				{:else}
					<div class="overflow-x-auto">
						<table class="w-full">
							<thead class="border-b border-gray-200 dark:border-gray-700">
								<tr>
									<th class="pb-3 text-left text-sm font-medium text-gray-600 dark:text-gray-300"
										>Name</th
									>
									<th class="pb-3 text-left text-sm font-medium text-gray-600 dark:text-gray-300"
										>User</th
									>
									<th class="pb-3 text-left text-sm font-medium text-gray-600 dark:text-gray-300"
										>Status</th
									>
									<th class="pb-3 text-left text-sm font-medium text-gray-600 dark:text-gray-300"
										>Last Seen</th
									>
								</tr>
							</thead>
							<tbody>
								{#each nodes as node}
									<tr class="border-b border-gray-100 dark:border-gray-700/50">
										<td class="py-3 text-sm font-medium text-gray-900 dark:text-gray-100"
											>{node.name}</td
										>
										<td class="py-3 text-sm text-gray-600 dark:text-gray-400">{node.user}</td>
										<td class="py-3 text-sm">
											<span
												class="inline-flex items-center gap-1 rounded-full px-2 py-1 text-xs font-semibold {node.online
													? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300'
													: 'bg-gray-100 text-gray-800 dark:bg-gray-900/30 dark:text-gray-300'}"
											>
												<span class="h-2 w-2 rounded-full {node.online ? 'bg-green-500' : 'bg-gray-500'}"
												></span>
												{node.online ? 'Online' : 'Offline'}
											</span>
										</td>
										<td class="py-3 text-sm text-gray-600 dark:text-gray-400">{node.lastSeen}</td>
									</tr>
								{/each}
							</tbody>
						</table>
					</div>
				{/if}
			</div>
		{/if}
	</main>
</div>
