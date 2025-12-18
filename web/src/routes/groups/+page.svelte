<script lang="ts">
	import { onMount } from 'svelte';

	let groups: any[] = [];
	let loading = true;
	let error = '';
	
	// Modal states
	let showCreateModal = false;
	let showEditModal = false;
	let showDeleteModal = false;
	let selectedGroup: any = null;
	
	// Form data
	let groupName = '';
	let groupDescription = '';
	let groupTags: string[] = [];
	let newTag = '';

	onMount(async () => {
		await fetchGroups();
	});

	async function fetchGroups() {
		try {
			const res = await fetch('http://localhost:3001/api/v1/clients/groups');
			if (!res.ok) throw new Error('Failed to fetch groups');
			
			const data = await res.json();
			groups = data.groups || [];
		} catch (err: any) {
			error = err.message;
		} finally {
			loading = false;
		}
	}

	async function createGroup() {
		if (!groupName.trim()) return;
		
		try {
			const res = await fetch('http://localhost:3001/api/v1/clients/groups', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({
					name: groupName.trim(),
					description: groupDescription.trim(),
					tags: groupTags
				})
			});
			
			if (!res.ok) throw new Error('Failed to create group');
			
			resetForm();
			showCreateModal = false;
			await fetchGroups();
		} catch (err: any) {
			alert(err.message);
		}
	}

	async function updateGroup() {
		if (!selectedGroup || !groupName.trim()) return;
		
		try {
			const res = await fetch(`http://localhost:3001/api/v1/clients/groups/${selectedGroup.id}`, {
				method: 'PUT',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({
					name: groupName.trim(),
					description: groupDescription.trim(),
					tags: groupTags
				})
			});
			
			if (!res.ok) throw new Error('Failed to update group');
			
			resetForm();
			showEditModal = false;
			selectedGroup = null;
			await fetchGroups();
		} catch (err: any) {
			alert(err.message);
		}
	}

	async function deleteGroup() {
		if (!selectedGroup) return;
		
		try {
			const res = await fetch(`http://localhost:3001/api/v1/clients/groups/${selectedGroup.id}`, {
				method: 'DELETE'
			});
			
			if (!res.ok) throw new Error('Failed to delete group');
			
			showDeleteModal = false;
			selectedGroup = null;
			await fetchGroups();
		} catch (err: any) {
			alert(err.message);
		}
	}

	function openEditModal(group: any) {
		selectedGroup = group;
		groupName = group.name;
		groupDescription = group.description || '';
		groupTags = group.tags || [];
		showEditModal = true;
	}

	function openDeleteModal(group: any) {
		selectedGroup = group;
		showDeleteModal = true;
	}

	function resetForm() {
		groupName = '';
		groupDescription = '';
		groupTags = [];
		newTag = '';
	}

	function addTag() {
		if (!newTag.trim()) return;
		if (groupTags.includes(newTag.trim())) return;
		
		groupTags = [...groupTags, newTag.trim()];
		newTag = '';
	}

	function removeTag(tag: string) {
		groupTags = groupTags.filter(t => t !== tag);
	}

	function closeModal() {
		showCreateModal = false;
		showEditModal = false;
		showDeleteModal = false;
		selectedGroup = null;
		resetForm();
	}
</script>

<div class="p-6">
	<!-- Header -->
	<div class="mb-6 flex items-center justify-between">
		<div>
			<h1 class="text-3xl font-bold text-[#1c2f38] font-['Montserrat']">Client Groups</h1>
			<p class="text-gray-600 mt-2">Organize clients into groups for easier management</p>
		</div>
		<button
			on:click={() => showCreateModal = true}
			class="px-6 py-2 bg-[#d4af37] hover:bg-[#c19a28] text-white rounded-lg transition-colors font-medium"
		>
			+ Create Group
		</button>
	</div>

	<!-- Error Banner -->
	{#if error}
		<div class="mb-4 bg-red-50 border border-red-200 rounded-lg p-4">
			<p class="text-red-800">{error}</p>
		</div>
	{/if}

	<!-- Groups List -->
	{#if loading}
		<div class="flex justify-center items-center h-64">
			<div class="animate-spin rounded-full h-12 w-12 border-4 border-[#31413e] border-t-transparent"></div>
		</div>
	{:else if groups.length === 0}
		<div class="bg-gray-50 rounded-lg p-12 text-center">
			<p class="text-gray-500 mb-4">No groups created yet</p>
			<button
				on:click={() => showCreateModal = true}
				class="px-6 py-2 bg-[#d4af37] hover:bg-[#c19a28] text-white rounded-lg transition-colors"
			>
				Create Your First Group
			</button>
		</div>
	{:else}
		<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
			{#each groups as group}
				<div class="bg-white rounded-lg border border-gray-200 p-6 hover:shadow-lg transition-shadow">
					<div class="flex items-start justify-between mb-4">
						<div class="flex-1">
							<h3 class="text-lg font-semibold text-[#1c2f38] mb-1">{group.name}</h3>
							<p class="text-sm text-gray-600">{group.description || 'No description'}</p>
						</div>
						<div class="flex gap-2">
							<button
								on:click={() => openEditModal(group)}
								class="text-[#d4af37] hover:text-[#c19a28] text-sm"
							>
								Edit
							</button>
							<button
								on:click={() => openDeleteModal(group)}
								class="text-red-500 hover:text-red-700 text-sm"
							>
								Delete
							</button>
						</div>
					</div>

					<!-- Client Count -->
					<div class="flex items-center gap-2 mb-4 text-sm text-gray-600">
						<span>👥</span>
						<span>{group.client_count || 0} clients</span>
					</div>

					<!-- Tags -->
					{#if group.tags && group.tags.length > 0}
						<div class="flex flex-wrap gap-2 mb-4">
							{#each group.tags as tag}
								<span class="text-xs bg-gray-100 text-gray-700 px-2 py-0.5 rounded">{tag}</span>
							{/each}
						</div>
					{/if}

					<!-- Actions -->
					<div class="flex gap-2 pt-4 border-t border-gray-100">
						<a
							href="/clients?group={group.id}"
							class="flex-1 px-3 py-2 bg-[#31413e] hover:bg-[#1c2f38] text-white text-center text-sm rounded-lg transition-colors"
						>
							View Clients
						</a>
						<a
							href="/osquery?group={group.id}"
							class="flex-1 px-3 py-2 bg-[#d4af37] hover:bg-[#c19a28] text-white text-center text-sm rounded-lg transition-colors"
						>
							Run Query
						</a>
					</div>

					<!-- Metadata -->
					<div class="mt-4 pt-4 border-t border-gray-100 text-xs text-gray-500">
						<div class="flex justify-between">
							<span>Created: {new Date(group.created_at).toLocaleDateString()}</span>
						</div>
					</div>
				</div>
			{/each}
		</div>
	{/if}
</div>

<!-- Create Group Modal -->
{#if showCreateModal}
	<!-- svelte-ignore a11y_click_events_have_key_events -->
	<!-- svelte-ignore a11y_no_static_element_interactions -->
	<div class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50" on:click={closeModal}>
		<div class="bg-white rounded-lg p-6 w-full max-w-md" on:click|stopPropagation role="dialog" aria-modal="true" tabindex="-1">
			<h2 class="text-2xl font-bold text-[#1c2f38] mb-4">Create Group</h2>
			
			<div class="space-y-4">
				<div>
					<label for="create-group-name" class="block text-sm font-medium text-gray-700 mb-1">Group Name *</label>
					<input
						id="create-group-name"
						type="text"
						bind:value={groupName}
						placeholder="Engineering Workstations"
						class="w-full px-4 py-2 border border-[rgba(212, 175, 55, 0.3)] rounded-lg bg-[#1c2f38] text-[#FFFFF0] focus:outline-none focus:ring-2 focus:ring-[rgba(212, 175, 55, 0.3)]"
					/>
				</div>

				<div>
					<label for="create-description" class="block text-sm font-medium text-gray-700 mb-1">Description</label>
					<textarea						id="create-description"						bind:value={groupDescription}
						placeholder="Group description..."
						rows="3"
						class="w-full px-4 py-2 border border-[rgba(212, 175, 55, 0.3)] rounded-lg bg-[#1c2f38] text-[#FFFFF0] focus:outline-none focus:ring-2 focus:ring-[rgba(212, 175, 55, 0.3)]"
					></textarea>
				</div>

			<fieldset>
				<legend class="block text-sm font-medium text-gray-700 mb-1">Tags</legend>
					<div class="flex flex-wrap gap-2 mb-2">
						{#each groupTags as tag}
							<span class="inline-flex items-center gap-1 bg-gray-100 text-gray-700 px-3 py-1 rounded">
								{tag}
								<button on:click={() => removeTag(tag)} class="text-red-500 hover:text-red-700">×</button>
							</span>
						{/each}
					</div>
					<div class="flex gap-2">
						<input
							type="text"
							bind:value={newTag}
							on:keydown={(e) => e.key === 'Enter' && addTag()}
							placeholder="Add tag..."
							class="flex-1 px-3 py-2 border border-[rgba(212, 175, 55, 0.3)] rounded-lg bg-[#1c2f38] text-[#FFFFF0] focus:outline-none focus:ring-2 focus:ring-[rgba(212, 175, 55, 0.3)]"
						/>
						<button
							on:click={addTag}
							class="px-4 py-2 bg-[#d4af37] hover:bg-[#c19a28] text-white rounded-lg"
						>
							Add
						</button>
					</div>
				</fieldset>
			</div>

			<div class="flex gap-3 mt-6">
				<button
					on:click={closeModal}
					class="flex-1 px-4 py-2 bg-[rgba(212, 175, 55, 0.1)] border border-[rgba(212, 175, 55, 0.3)] hover:bg-[rgba(212, 175, 55, 0.15)] text-[#FFFFF0] rounded-lg"
				>
					Cancel
				</button>
				<button
					on:click={createGroup}
					disabled={!groupName.trim()}
					class="flex-1 px-4 py-2 bg-[#d4af37] hover:bg-[#c19a28] text-white rounded-lg disabled:opacity-50 disabled:cursor-not-allowed"
				>
					Create Group
				</button>
			</div>
		</div>
	</div>
{/if}

<!-- Edit Group Modal -->
{#if showEditModal && selectedGroup}
	<!-- svelte-ignore a11y_click_events_have_key_events -->
	<!-- svelte-ignore a11y_no_static_element_interactions -->
	<div class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50" on:click={closeModal}>
		<div class="bg-white rounded-lg p-6 w-full max-w-md" on:click|stopPropagation role="dialog" aria-modal="true" tabindex="-1">
			<h2 class="text-2xl font-bold text-[#1c2f38] mb-4">Edit Group</h2>
			
			<div class="space-y-4">
				<div>
					<label for="edit-group-name" class="block text-sm font-medium text-gray-700 mb-1">Group Name *</label>
					<input
						id="edit-group-name"
						type="text"
						bind:value={groupName}
						class="w-full px-4 py-2 border border-[rgba(212, 175, 55, 0.3)] rounded-lg bg-[#1c2f38] text-[#FFFFF0] focus:outline-none focus:ring-2 focus:ring-[rgba(212, 175, 55, 0.3)]"
					/>
				</div>

				<div>
					<label for="edit-description" class="block text-sm font-medium text-gray-700 mb-1">Description</label>
					<textarea
						id="edit-description"
						bind:value={groupDescription}
						rows="3"
						class="w-full px-4 py-2 border border-[rgba(212, 175, 55, 0.3)] rounded-lg bg-[#1c2f38] text-[#FFFFF0] focus:outline-none focus:ring-2 focus:ring-[rgba(212, 175, 55, 0.3)]"
					></textarea>
				</div>

			<fieldset>
				<legend class="block text-sm font-medium text-gray-700 mb-1">Tags</legend>
					<div class="flex flex-wrap gap-2 mb-2">
						{#each groupTags as tag}
							<span class="inline-flex items-center gap-1 bg-gray-100 text-gray-700 px-3 py-1 rounded">
								{tag}
								<button on:click={() => removeTag(tag)} class="text-red-500 hover:text-red-700">×</button>
							</span>
						{/each}
					</div>
					<div class="flex gap-2">
						<input
							type="text"
							bind:value={newTag}
							on:keydown={(e) => e.key === 'Enter' && addTag()}
							placeholder="Add tag..."
							class="flex-1 px-3 py-2 border border-[rgba(212, 175, 55, 0.3)] rounded-lg bg-[#1c2f38] text-[#FFFFF0] focus:outline-none focus:ring-2 focus:ring-[rgba(212, 175, 55, 0.3)]"
						/>
						<button
							on:click={addTag}
							class="px-4 py-2 bg-[#d4af37] hover:bg-[#c19a28] text-white rounded-lg"
						>
							Add
						</button>
					</div>
				</fieldset>
			</div>

			<div class="flex gap-3 mt-6">
				<button
					on:click={closeModal}
					class="flex-1 px-4 py-2 bg-[rgba(212, 175, 55, 0.1)] border border-[rgba(212, 175, 55, 0.3)] hover:bg-[rgba(212, 175, 55, 0.15)] text-[#FFFFF0] rounded-lg"
				>
					Cancel
				</button>
				<button
					on:click={updateGroup}
					disabled={!groupName.trim()}
					class="flex-1 px-4 py-2 bg-[#d4af37] hover:bg-[#c19a28] text-white rounded-lg disabled:opacity-50 disabled:cursor-not-allowed"
				>
					Save Changes
				</button>
			</div>
		</div>
	</div>
{/if}

<!-- Delete Confirmation Modal -->
{#if showDeleteModal && selectedGroup}
	<!-- svelte-ignore a11y_click_events_have_key_events -->
	<!-- svelte-ignore a11y_no_static_element_interactions -->
	<div class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50" on:click={closeModal}>
		<div class="bg-white rounded-lg p-6 w-full max-w-md" on:click|stopPropagation role="dialog" aria-modal="true" tabindex="-1">
			<h2 class="text-2xl font-bold text-red-600 mb-4">Delete Group</h2>
			<p class="text-gray-700 mb-6">
				Are you sure you want to delete the group <strong>"{selectedGroup.name}"</strong>?
				This action cannot be undone. Clients in this group will not be deleted.
			</p>

			<div class="flex gap-3">
				<button
					on:click={closeModal}
					class="flex-1 px-4 py-2 bg-[rgba(212, 175, 55, 0.1)] border border-[rgba(212, 175, 55, 0.3)] hover:bg-[rgba(212, 175, 55, 0.15)] text-[#FFFFF0] rounded-lg"
				>
					Cancel
				</button>
				<button
					on:click={deleteGroup}
					class="flex-1 px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg"
				>
					Delete Group
				</button>
			</div>
		</div>
	</div>
{/if}
