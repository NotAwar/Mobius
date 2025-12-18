<script lang="ts">
	import { onMount } from 'svelte';
	import { apiRequest } from '$lib/api';

	interface Node {
		name: string;
		status: string;
		role: string;
	}

	interface Pod {
		name: string;
		namespace: string;
		status: string;
		restarts: number;
	}

	let nodes: Node[] = [];
	let pods: Pod[] = [];
	let loading = true;
	let error: string | null = null;

	async function fetchClusterData() {
		try {
			const [nodesData, podsData] = await Promise.all([
				apiRequest('/cluster/nodes'),
				apiRequest('/cluster/pods')
			]);

			nodes = nodesData.nodes || [];
			pods = podsData.pods || [];
			loading = false;
		} catch (err) {
			error = err instanceof Error ? err.message : 'Unknown error';
			loading = false;
		}
	}

	onMount(() => {
		fetchClusterData();
		const interval = setInterval(fetchClusterData, 10000);
		return () => clearInterval(interval);
	});
</script>

<div class="min-h-screen bg-[#1c2f38]">
	<header class="bg-[rgba(212, 175, 55, 0.1)] border border-[rgba(212, 175, 55, 0.3)] shadow">
		<div class="mx-auto max-w-7xl px-4 py-6 sm:px-6 lg:px-8">
			<div class="flex items-center justify-between">
				<h1 class="text-3xl font-bold tracking-tight text-[#FFFFF0]">
					⚙️ Kubernetes Cluster
				</h1>
				<a
					href="/"
					class="rounded-lg bg-[#d4af37] px-4 py-2 text-[#1c2f38] font-semibold transition hover:bg-[#e8c35a]"
				>
					← Back to Dashboard
				</a>
			</div>
		</div>
	</header>

	<main class="mx-auto max-w-7xl px-4 py-6 sm:px-6 lg:px-8">
		{#if loading}
			<div class="flex items-center justify-center py-12">
				<div class="h-32 w-32 animate-spin rounded-full border-b-2 border-[#d4af37]"></div>
			</div>
		{:else if error}
			<div class="rounded-lg bg-[rgba(239, 68, 68, 0.1)] border border-[rgba(239, 68, 68, 0.3)] p-4">
				<p class="text-[#ef4444]">Error: {error}</p>
			</div>
		{:else}
			<!-- Nodes Section -->
			<div class="mb-8 rounded-lg bg-[rgba(212, 175, 55, 0.1)] border border-[rgba(212, 175, 55, 0.3)] p-6">
				<h2 class="mb-4 text-xl font-semibold text-[#FFFFF0]">Cluster Nodes</h2>
				<div class="overflow-x-auto">
					<table class="w-full">
						<thead class="border-b border-[rgba(212, 175, 55, 0.2)]">
							<tr>
								<th class="pb-3 text-left text-sm font-medium text-[#FFFFF0]"
									>Name</th
								>
								<th class="pb-3 text-left text-sm font-medium text-[#FFFFF0]"
									>Status</th
								>
								<th class="pb-3 text-left text-sm font-medium text-[#FFFFF0]"
									>Role</th
								>
							</tr>
						</thead>
						<tbody>
							{#each nodes as node}
								<tr class="border-b border-gray-100 dark:border-gray-700/50">
									<td class="py-3 text-sm text-gray-900 dark:text-gray-100">{node.name}</td>
									<td class="py-3 text-sm">
										<span
											class="inline-flex rounded-full px-2 py-1 text-xs font-semibold {node.status ===
											'Ready'
												? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300'
												: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300'}"
										>
											{node.status}
										</span>
									</td>
									<td class="py-3 text-sm text-gray-900 dark:text-gray-100">{node.role}</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			</div>

			<!-- Pods Section -->
			<div class="rounded-lg bg-[rgba(212, 175, 55, 0.1)] border border-[rgba(212, 175, 55, 0.3)] p-6">
				<h2 class="mb-4 text-xl font-semibold text-[#FFFFF0]">Running Pods</h2>
				{#if pods.length === 0}
					<p class="text-gray-600 dark:text-gray-400">No pods running</p>
				{:else}
					<div class="overflow-x-auto">
						<table class="w-full">
							<thead class="border-b border-[rgba(212, 175, 55, 0.2)]">
								<tr>
									<th class="pb-3 text-left text-sm font-medium text-[#FFFFF0]"
										>Name</th
									>
									<th class="pb-3 text-left text-sm font-medium text-[#FFFFF0]"
										>Namespace</th
									>
									<th class="pb-3 text-left text-sm font-medium text-[#FFFFF0]"
										>Status</th
									>
									<th class="pb-3 text-left text-sm font-medium text-[#FFFFF0]"
										>Restarts</th
									>
								</tr>
							</thead>
							<tbody>
								{#each pods as pod}
									<tr class="border-b border-gray-100 dark:border-gray-700/50">
										<td class="py-3 text-sm text-gray-900 dark:text-gray-100">{pod.name}</td>
										<td class="py-3 text-sm text-gray-600 dark:text-gray-400">{pod.namespace}</td>
										<td class="py-3 text-sm">
											<span
												class="inline-flex rounded-full px-2 py-1 text-xs font-semibold {pod.status ===
												'Running'
													? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300'
													: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300'}"
											>
												{pod.status}
											</span>
										</td>
										<td class="py-3 text-sm text-gray-900 dark:text-gray-100">{pod.restarts}</td>
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
