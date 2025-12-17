<script lang="ts">
	import { onMount } from 'svelte';
	import {
		fetchClusterStatus,
		fetchPostgresStatus,
		fetchHeadscaleStatus,
		clusterStatus,
		postgresStatus,
		headscaleStatus
	} from '$lib/api';

	let loading = true;

	onMount(async () => {
		await Promise.all([fetchClusterStatus(), fetchPostgresStatus(), fetchHeadscaleStatus()]);
		loading = false;

		// Refresh every 5 seconds
		const interval = setInterval(async () => {
			await Promise.all([fetchClusterStatus(), fetchPostgresStatus(), fetchHeadscaleStatus()]);
		}, 5000);

		return () => clearInterval(interval);
	});
</script>

<div class="min-h-screen bg-gradient-to-br from-purple-50 to-blue-50 dark:from-gray-900 dark:to-gray-800">
	<header class="bg-white dark:bg-gray-800 shadow">
		<div class="mx-auto max-w-7xl px-4 py-6 sm:px-6 lg:px-8">
			<h1 class="text-3xl font-bold tracking-tight text-gray-900 dark:text-white">
				🚀 Mobius Dashboard
			</h1>
		</div>
	</header>

	<main class="mx-auto max-w-7xl px-4 py-6 sm:px-6 lg:px-8">
		{#if loading}
			<div class="flex items-center justify-center py-12">
				<div class="h-32 w-32 animate-spin rounded-full border-b-2 border-purple-600"></div>
			</div>
		{:else}
			<div class="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
				<!-- Cluster Status Card -->
				<div class="rounded-lg bg-white p-6 shadow dark:bg-gray-800">
					<div class="flex items-center justify-between">
						<h2 class="text-lg font-semibold text-gray-900 dark:text-white">Kubernetes Cluster</h2>
						<div
							class="h-3 w-3 rounded-full {$clusterStatus?.ready
								? 'bg-green-500'
								: 'bg-red-500'}"
						></div>
					</div>
					{#if $clusterStatus}
						<div class="mt-4 space-y-2">
							<p class="text-sm text-gray-600 dark:text-gray-300">
								Status: <span class="font-medium">{$clusterStatus.status}</span>
							</p>
							<p class="text-sm text-gray-600 dark:text-gray-300">
								Nodes: <span class="font-medium">{$clusterStatus.nodes}</span>
							</p>
							<p class="text-sm text-gray-600 dark:text-gray-300">
								Version: <span class="font-medium">{$clusterStatus.version}</span>
							</p>
						</div>
					{/if}
				</div>

				<!-- PostgreSQL Status Card -->
				<div class="rounded-lg bg-white p-6 shadow dark:bg-gray-800">
					<div class="flex items-center justify-between">
						<h2 class="text-lg font-semibold text-gray-900 dark:text-white">PostgreSQL</h2>
						<div
							class="h-3 w-3 rounded-full {$postgresStatus?.ready
								? 'bg-green-500'
								: 'bg-red-500'}"
						></div>
					</div>
					{#if $postgresStatus}
						<div class="mt-4 space-y-2">
							<p class="text-sm text-gray-600 dark:text-gray-300">
								Status: <span class="font-medium">{$postgresStatus.status}</span>
							</p>
							<p class="text-sm text-gray-600 dark:text-gray-300">
								Operator: <span class="font-medium">{$postgresStatus.operator}</span>
							</p>
							<p class="text-sm text-gray-600 dark:text-gray-300">
								Databases: <span class="font-medium">{$postgresStatus.databases}</span>
							</p>
						</div>
					{/if}
				</div>

				<!-- Headscale Status Card -->
				<div class="rounded-lg bg-white p-6 shadow dark:bg-gray-800">
					<div class="flex items-center justify-between">
						<h2 class="text-lg font-semibold text-gray-900 dark:text-white">Headscale VPN</h2>
						<div
							class="h-3 w-3 rounded-full {$headscaleStatus?.ready
								? 'bg-green-500'
								: 'bg-red-500'}"
						></div>
					</div>
					{#if $headscaleStatus}
						<div class="mt-4 space-y-2">
							<p class="text-sm text-gray-600 dark:text-gray-300">
								Status: <span class="font-medium">{$headscaleStatus.status}</span>
							</p>
							<p class="text-sm text-gray-600 dark:text-gray-300">
								Users: <span class="font-medium">{$headscaleStatus.users}</span>
							</p>
							<p class="text-sm text-gray-600 dark:text-gray-300">
								Nodes: <span class="font-medium">{$headscaleStatus.nodes}</span>
							</p>
						</div>
					{/if}
				</div>
			</div>

			<!-- Quick Actions -->
			<div class="mt-8 rounded-lg bg-white p-6 shadow dark:bg-gray-800">
				<h2 class="mb-4 text-lg font-semibold text-gray-900 dark:text-white">Quick Actions</h2>
				<div class="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
					<a
						href="/cluster"
						class="rounded-lg bg-purple-600 px-4 py-2 text-center text-white transition hover:bg-purple-700"
					>
						View Cluster Nodes
					</a>
					<a
						href="/postgres"
						class="rounded-lg bg-blue-600 px-4 py-2 text-center text-white transition hover:bg-blue-700"
					>
						Manage Databases
					</a>
					<a
						href="/headscale"
						class="rounded-lg bg-green-600 px-4 py-2 text-center text-white transition hover:bg-green-700"
					>
						VPN Users
					</a>
					<button
						class="rounded-lg bg-orange-600 px-4 py-2 text-white transition hover:bg-orange-700"
						onclick={() => window.location.reload()}
					>
						Refresh Status
					</button>
				</div>
			</div>
		{/if}
	</main>
</div>
