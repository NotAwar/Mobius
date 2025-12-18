<script lang="ts">
	import { onMount } from 'svelte';

	let enrollmentKeys: any[] = [];
	let loading = true;
	let error = '';
	let showCreateModal = false;

	// Create key form
	let keyName = '';
	let keyExpires = '';
	let keyMaxUses = 1;
	let keyTags: string[] = [];
	let keyGroupIds: string[] = [];
	let creating = false;

	// Generated key display
	let generatedKey = '';
	let showKeyModal = false;

	// Available groups
	let availableGroups: any[] = [];

	onMount(async () => {
		await Promise.all([fetchEnrollmentKeys(), fetchGroups()]);
	});

	async function fetchEnrollmentKeys() {
		try {
			const res = await fetch('http://localhost:3001/api/v1/clients/enrollment-keys');
			if (!res.ok) throw new Error('Failed to fetch enrollment keys');
			const data = await res.json();
			enrollmentKeys = data.keys || [];
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

	async function createEnrollmentKey() {
		creating = true;
		error = '';

		try {
			const res = await fetch('http://localhost:3001/api/v1/clients/enrollment-keys', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({
					name: keyName,
					expires_at: keyExpires ? new Date(keyExpires).toISOString() : null,
					max_uses: keyMaxUses,
					tags: keyTags.filter(t => t.trim()),
					group_ids: keyGroupIds
				})
			});

			if (!res.ok) throw new Error('Failed to create enrollment key');

			const data = await res.json();
			generatedKey = data.key;
			showKeyModal = true;
			showCreateModal = false;

			// Reset form
			keyName = '';
			keyExpires = '';
			keyMaxUses = 1;
			keyTags = [];
			keyGroupIds = [];

			await fetchEnrollmentKeys();
		} catch (err: any) {
			error = err.message;
		} finally {
			creating = false;
		}
	}

	async function revokeKey(keyId: string) {
		if (!confirm('Are you sure you want to revoke this enrollment key?')) return;

		try {
			const res = await fetch(`http://localhost:3001/api/v1/clients/enrollment-keys/${keyId}`, {
				method: 'DELETE'
			});
			if (!res.ok) throw new Error('Failed to revoke key');
			await fetchEnrollmentKeys();
		} catch (err: any) {
			error = err.message;
		}
	}

	function copyToClipboard(text: string) {
		navigator.clipboard.writeText(text);
	}

	function addTag() {
		keyTags = [...keyTags, ''];
	}

	function removeTag(index: number) {
		keyTags = keyTags.filter((_, i) => i !== index);
	}

	function formatDate(dateStr: string) {
		return new Date(dateStr).toLocaleString();
	}
</script>

<div class="p-6">
	<!-- Header -->
	<div class="mb-6">
		<h1 class="text-3xl font-bold text-[#1c2f38] font-['Montserrat']">Client Enrollment</h1>
		<p class="text-gray-600 mt-2">Manage enrollment keys and onboard new clients</p>
	</div>

	<!-- Error Banner -->
	{#if error}
		<div class="mb-4 bg-red-50 border border-red-200 rounded-lg p-4">
			<p class="text-red-800">{error}</p>
		</div>
	{/if}

	<!-- Action Buttons -->
	<div class="mb-6 flex gap-4">
		<button
			on:click={() => (showCreateModal = true)}
			class="bg-[#d4af37] hover:bg-[#c19a28] text-[#1c2f38] font-semibold px-6 py-2 rounded-lg transition-colors"
		>
			+ Create Enrollment Key
		</button>
		<button
			on:click={() => window.location.href = '/enrollment/download'}
			class="bg-[#31413e] hover:bg-[#1c2f38] text-white px-6 py-2 rounded-lg transition-colors"
		>
			Download Client Installer
		</button>
	</div>

	<!-- Enrollment Keys Table -->
	{#if loading}
		<div class="flex justify-center items-center h-64">
			<div class="animate-spin rounded-full h-12 w-12 border-4 border-[#31413e] border-t-transparent"></div>
		</div>
	{:else if enrollmentKeys.length === 0}
		<div class="bg-gray-50 rounded-lg p-12 text-center">
			<p class="text-gray-500 mb-4">No enrollment keys created yet</p>
			<button
				on:click={() => (showCreateModal = true)}
				class="text-[#d4af37] hover:text-[#c19a28] font-semibold"
			>
				Create your first enrollment key →
			</button>
		</div>
	{:else}
		<div class="bg-white rounded-lg border border-gray-200 overflow-hidden">
			<table class="w-full">
				<thead class="bg-[#31413e] text-white">
					<tr>
						<th class="px-6 py-3 text-left text-sm font-semibold">Name</th>
						<th class="px-6 py-3 text-left text-sm font-semibold">Key</th>
						<th class="px-6 py-3 text-left text-sm font-semibold">Created</th>
						<th class="px-6 py-3 text-left text-sm font-semibold">Expires</th>
						<th class="px-6 py-3 text-left text-sm font-semibold">Uses</th>
						<th class="px-6 py-3 text-left text-sm font-semibold">Status</th>
						<th class="px-6 py-3 text-left text-sm font-semibold">Actions</th>
					</tr>
				</thead>
				<tbody class="divide-y divide-gray-200">
					{#each enrollmentKeys as key}
						<tr class="hover:bg-gray-50">
							<td class="px-6 py-4">
								<div>
									<p class="font-medium text-[#1c2f38]">{key.name}</p>
									{#if key.tags && key.tags.length > 0}
										<div class="flex gap-1 mt-1">
											{#each key.tags as tag}
												<span class="text-xs bg-gray-100 text-gray-700 px-2 py-0.5 rounded">{tag}</span>
											{/each}
										</div>
									{/if}
								</div>
							</td>
							<td class="px-6 py-4">
								<code class="text-xs bg-gray-100 px-2 py-1 rounded font-mono">
									{key.key.substring(0, 20)}...
								</code>
								<button
									on:click={() => copyToClipboard(key.key)}
									class="ml-2 text-[#d4af37] hover:text-[#c19a28] text-sm"
									title="Copy to clipboard"
								>
									Copy
								</button>
							</td>
							<td class="px-6 py-4 text-sm text-gray-600">{formatDate(key.created_at)}</td>
							<td class="px-6 py-4 text-sm text-gray-600">
								{key.expires_at ? formatDate(key.expires_at) : 'Never'}
							</td>
							<td class="px-6 py-4 text-sm text-gray-600">
								{key.used_count || 0} / {key.max_uses || '∞'}
							</td>
							<td class="px-6 py-4">
								{#if key.revoked}
									<span class="inline-flex items-center px-2.5 py-0.5 rounded text-xs font-medium bg-red-100 text-red-800">
										Revoked
									</span>
								{:else if key.expires_at && new Date(key.expires_at) < new Date()}
									<span class="inline-flex items-center px-2.5 py-0.5 rounded text-xs font-medium bg-gray-100 text-gray-800">
										Expired
									</span>
								{:else if key.max_uses && key.used_count >= key.max_uses}
									<span class="inline-flex items-center px-2.5 py-0.5 rounded text-xs font-medium bg-gray-100 text-gray-800">
										Used Up
									</span>
								{:else}
									<span class="inline-flex items-center px-2.5 py-0.5 rounded text-xs font-medium bg-green-100 text-green-800">
										Active
									</span>
								{/if}
							</td>
							<td class="px-6 py-4">
								<button
									on:click={() => revokeKey(key.id)}
									class="text-red-600 hover:text-red-800 text-sm font-medium"
								>
									Revoke
								</button>
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
	{/if}

	<!-- Installation Instructions -->
	<div class="mt-8 bg-[#31413e] rounded-lg p-6 text-white">
		<h2 class="text-xl font-bold mb-4 font-['Montserrat']">Enrollment Instructions</h2>
		
		<div class="space-y-4">
			<div>
				<h3 class="font-semibold mb-2">Linux / macOS:</h3>
				<pre class="bg-[#1c2f38] p-4 rounded overflow-x-auto text-sm"><code>curl -sSL https://mobius.example.com/install.sh | sudo bash -s -- --enroll-key YOUR_KEY</code></pre>
			</div>

			<div>
				<h3 class="font-semibold mb-2">Windows (PowerShell as Admin):</h3>
				<pre class="bg-[#1c2f38] p-4 rounded overflow-x-auto text-sm"><code>iwr -useb https://mobius.example.com/install.ps1 | iex; Install-MobiusClient -EnrollKey "YOUR_KEY"</code></pre>
			</div>

			<div>
				<h3 class="font-semibold mb-2">Manual Installation:</h3>
				<ol class="list-decimal list-inside space-y-1 text-sm">
					<li>Download the client binary for your platform</li>
					<li>Run: <code class="bg-[#1c2f38] px-2 py-0.5 rounded">mobius-client --server https://mobius.example.com --enroll-key YOUR_KEY</code></li>
					<li>The client will automatically configure and start</li>
				</ol>
			</div>
		</div>
	</div>
</div>

<!-- Create Key Modal -->
{#if showCreateModal}
	<div class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
		<div class="bg-white rounded-lg p-6 max-w-md w-full mx-4">
			<h2 class="text-2xl font-bold text-[#1c2f38] mb-4 font-['Montserrat']">Create Enrollment Key</h2>

			<div class="space-y-4">
				<div>
					<label for="key-name" class="block text-sm font-medium text-gray-700 mb-1">Key Name</label>
					<input
						id="key-name"
						type="text"
						bind:value={keyName}
						placeholder="e.g., Production Servers"
						class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-[#d4af37]"
						required
					/>
				</div>

				<div>
					<label for="expires-at" class="block text-sm font-medium text-gray-700 mb-1">Expires At (optional)</label>
					<input
						id="expires-at"
						type="datetime-local"
						bind:value={keyExpires}
						class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-[#d4af37]"
					/>
				</div>

				<div>
					<label for="max-uses" class="block text-sm font-medium text-gray-700 mb-1">Max Uses</label>
					<input
						id="max-uses"
						type="number"
						bind:value={keyMaxUses}
						min="1"
						class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-[#d4af37]"
					/>
					<p class="text-xs text-gray-500 mt-1">0 = unlimited uses</p>
				</div>

				<div>
					<label for="auto-groups" class="block text-sm font-medium text-gray-700 mb-1">Auto-assign Groups (optional)</label>
					<select
						id="auto-groups"
						multiple
						bind:value={keyGroupIds}
						class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-[#d4af37]"
						size="4"
					>
						{#each availableGroups as group}
							<option value={group.id}>{group.name}</option>
						{/each}
					</select>
				</div>

				<div>
					<label for="key-tags-0" class="block text-sm font-medium text-gray-700 mb-1">Tags (optional)</label>
					<div class="space-y-2">
						{#each keyTags as tag, i}
							<div class="flex gap-2">
								<input
									id="key-tags-{i}"
									type="text"
									bind:value={keyTags[i]}
									placeholder="Tag name"
									class="flex-1 px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-[#d4af37]"
								/>
								<button
									on:click={() => removeTag(i)}
									class="px-3 py-2 bg-red-100 text-red-700 rounded-lg hover:bg-red-200"
								>
									Remove
								</button>
							</div>
						{/each}
						<button
							on:click={addTag}
							class="text-[#d4af37] hover:text-[#c19a28] text-sm font-medium"
						>
							+ Add Tag
						</button>
					</div>
				</div>
			</div>

			<div class="mt-6 flex gap-3">
				<button
					on:click={createEnrollmentKey}
					disabled={creating || !keyName}
					class="flex-1 bg-[#d4af37] hover:bg-[#c19a28] disabled:bg-gray-300 disabled:cursor-not-allowed text-[#1c2f38] font-semibold py-2 rounded-lg transition-colors"
				>
					{creating ? 'Creating...' : 'Create Key'}
				</button>
				<button
					on:click={() => (showCreateModal = false)}
					class="flex-1 bg-gray-200 hover:bg-gray-300 text-gray-800 font-semibold py-2 rounded-lg transition-colors"
				>
					Cancel
				</button>
			</div>
		</div>
	</div>
{/if}

<!-- Generated Key Modal -->
{#if showKeyModal}
	<div class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
		<div class="bg-white rounded-lg p-6 max-w-lg w-full mx-4">
			<h2 class="text-2xl font-bold text-[#1c2f38] mb-4 font-['Montserrat']">Enrollment Key Created</h2>

			<div class="bg-yellow-50 border border-yellow-200 rounded-lg p-4 mb-4">
				<p class="text-sm text-yellow-800 font-medium mb-2">⚠️ Save this key securely!</p>
				<p class="text-xs text-yellow-700">This key will not be shown again. Copy it now.</p>
			</div>

			<div class="bg-gray-50 rounded-lg p-4 mb-4">
				<code class="text-sm font-mono break-all">{generatedKey}</code>
			</div>

			<div class="flex gap-3">
				<button
					on:click={() => copyToClipboard(generatedKey)}
					class="flex-1 bg-[#d4af37] hover:bg-[#c19a28] text-[#1c2f38] font-semibold py-2 rounded-lg transition-colors"
				>
					Copy to Clipboard
				</button>
				<button
					on:click={() => (showKeyModal = false)}
					class="flex-1 bg-gray-200 hover:bg-gray-300 text-gray-800 font-semibold py-2 rounded-lg transition-colors"
				>
					Close
				</button>
			</div>
		</div>
	</div>
{/if}
