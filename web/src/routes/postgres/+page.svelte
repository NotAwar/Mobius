<script lang="ts">
	import { onMount } from 'svelte';

	interface Database {
		name: string;
		size: string;
		status: string;
	}

	let databases: Database[] = [];
	let loading = true;
	let error: string | null = null;
	let showCreateForm = false;
	let newDbName = '';
	let creating = false;

	async function fetchDatabases() {
		try {
			const res = await fetch('http://localhost:3000/api/v1/postgres/databases');
			if (!res.ok) throw new Error('Failed to fetch databases');

			const data = await res.json();
			databases = data.databases || [];
			loading = false;
		} catch (err) {
			error = err instanceof Error ? err.message : 'Unknown error';
			loading = false;
		}
	}

	async function createDatabase() {
		if (!newDbName.trim()) return;

		creating = true;
		try {
			const res = await fetch('http://localhost:3000/api/v1/postgres/databases', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ name: newDbName })
			});

			if (!res.ok) throw new Error('Failed to create database');

			newDbName = '';
			showCreateForm = false;
			await fetchDatabases();
		} catch (err) {
			error = err instanceof Error ? err.message : 'Unknown error';
		} finally {
			creating = false;
		}
	}

	async function deleteDatabase(name: string) {
		if (!confirm(`Are you sure you want to delete database "${name}"?`)) return;

		try {
			const res = await fetch(`http://localhost:3000/api/v1/postgres/databases/${name}`, {
				method: 'DELETE'
			});

			if (!res.ok) throw new Error('Failed to delete database');

			await fetchDatabases();
		} catch (err) {
			error = err instanceof Error ? err.message : 'Unknown error';
		}
	}

	onMount(() => {
		fetchDatabases();
		const interval = setInterval(fetchDatabases, 10000);
		return () => clearInterval(interval);
	});
</script>

<div class="min-h-screen bg-gradient-to-br from-purple-50 to-blue-50 dark:from-gray-900 dark:to-gray-800">
	<header class="bg-white dark:bg-gray-800 shadow">
		<div class="mx-auto max-w-7xl px-4 py-6 sm:px-6 lg:px-8">
			<div class="flex items-center justify-between">
				<h1 class="text-3xl font-bold tracking-tight text-gray-900 dark:text-white">
					🗄️ PostgreSQL Management
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

		<div class="mb-6 flex items-center justify-between">
			<h2 class="text-xl font-semibold text-gray-900 dark:text-white">Databases</h2>
			<button
				onclick={() => (showCreateForm = !showCreateForm)}
				class="rounded-lg bg-blue-600 px-4 py-2 text-white transition hover:bg-blue-700"
			>
				{showCreateForm ? 'Cancel' : '+ Create Database'}
			</button>
		</div>

		{#if showCreateForm}
			<div class="mb-6 rounded-lg bg-white p-6 shadow dark:bg-gray-800">
				<h3 class="mb-4 text-lg font-semibold text-gray-900 dark:text-white">
					Create New Database
				</h3>
				<form
					onsubmit={(e) => {
						e.preventDefault();
						createDatabase();
					}}
					class="flex gap-4"
				>
					<input
						type="text"
						bind:value={newDbName}
						placeholder="Database name"
						class="flex-1 rounded-lg border border-gray-300 px-4 py-2 dark:border-gray-600 dark:bg-gray-700 dark:text-white"
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

		{#if loading}
			<div class="flex items-center justify-center py-12">
				<div class="h-32 w-32 animate-spin rounded-full border-b-2 border-purple-600"></div>
			</div>
		{:else}
			<div class="rounded-lg bg-white p-6 shadow dark:bg-gray-800">
				{#if databases.length === 0}
					<p class="text-center text-gray-600 dark:text-gray-400">
						No databases found. Create one to get started!
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
										>Size</th
									>
									<th class="pb-3 text-left text-sm font-medium text-gray-600 dark:text-gray-300"
										>Status</th
									>
									<th class="pb-3 text-right text-sm font-medium text-gray-600 dark:text-gray-300"
										>Actions</th
									>
								</tr>
							</thead>
							<tbody>
								{#each databases as db}
									<tr class="border-b border-gray-100 dark:border-gray-700/50">
										<td class="py-3 text-sm font-medium text-gray-900 dark:text-gray-100"
											>{db.name}</td
										>
										<td class="py-3 text-sm text-gray-600 dark:text-gray-400">{db.size}</td>
										<td class="py-3 text-sm">
											<span
												class="inline-flex rounded-full px-2 py-1 text-xs font-semibold {db.status ===
												'running'
													? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300'
													: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300'}"
											>
												{db.status}
											</span>
										</td>
										<td class="py-3 text-right">
											<button
												onclick={() => deleteDatabase(db.name)}
												class="rounded bg-red-600 px-3 py-1 text-sm text-white transition hover:bg-red-700"
											>
												Delete
											</button>
										</td>
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
