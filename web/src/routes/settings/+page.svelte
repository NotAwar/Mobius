<script lang="ts">
	import { onMount } from 'svelte';

	let settings = $state({
		apiUrl: 'http://localhost:3001',
		refreshInterval: 5000,
		theme: 'system',
		notifications: true,
		autoRefresh: true
	});

	let saved = $state(false);

	function saveSettings() {
		localStorage.setItem('mobius-settings', JSON.stringify(settings));
		saved = true;
		setTimeout(() => {
			saved = false;
		}, 3000);
	}

	function loadSettings() {
		const stored = localStorage.getItem('mobius-settings');
		if (stored) {
			settings = JSON.parse(stored);
		}
	}

	function resetSettings() {
		if (confirm('Are you sure you want to reset all settings to default?')) {
			settings = {
				apiUrl: 'http://localhost:3001',
				refreshInterval: 5000,
				theme: 'system',
				notifications: true,
				autoRefresh: true
			};
			localStorage.removeItem('mobius-settings');
			saved = true;
			setTimeout(() => {
				saved = false;
			}, 3000);
		}
	}

	onMount(() => {
		loadSettings();
	});
</script>

<!-- Hero Section -->
<div class="mb-6 rounded-2xl bg-[rgba(212, 175, 55, 0.1)] border border-[rgba(212, 175, 55, 0.3)] p-6 text-white shadow-2xl">
	<div class="flex items-center justify-between">
		<div>
			<h1 class="mb-2 flex items-center gap-3 text-3xl font-bold">
				<span class="text-4xl">⚙️</span>
				Settings
			</h1>
			<p class="text-gray-300">Configure your Mobius dashboard preferences</p>
		</div>
		{#if saved}
			<div class="rounded-lg bg-green-500 px-4 py-2 font-medium text-white">
				✓ Settings Saved
			</div>
		{/if}
	</div>
</div>

<div class="grid grid-cols-1 gap-6 lg:grid-cols-2">
	<!-- General Settings -->
	<div class="rounded-xl bg-white p-6 shadow-lg dark:bg-gray-800">
		<h2 class="mb-4 text-xl font-bold text-[#FFFFF0]">General Settings</h2>
		
		<div class="space-y-4">
			<div>
				<label for="api-url" class="mb-2 block text-sm font-medium text-[#FFFFF0]">
					API URL
				</label>
				<input
					id="api-url"
					type="url"
					bind:value={settings.apiUrl}
					placeholder="http://localhost:3001"
					class="w-full rounded-lg border border-gray-300 px-4 py-2 dark:border-gray-600 dark:bg-gray-700 dark:text-white"
				/>
				<p class="mt-1 text-xs text-gray-500 dark:text-gray-400">
					The base URL for the Mobius API server
				</p>
			</div>

			<div>
				<label for="refresh-interval" class="mb-2 block text-sm font-medium text-[#FFFFF0]">
					Refresh Interval: {settings.refreshInterval / 1000}s
				</label>
				<input
					id="refresh-interval"
					type="range"
					bind:value={settings.refreshInterval}
					min="1000"
					max="30000"
					step="1000"
					class="w-full"
				/>
				<p class="mt-1 text-xs text-gray-500 dark:text-gray-400">
					How often to refresh dashboard data (1-30 seconds)
				</p>
			</div>

			<div class="flex items-center justify-between rounded-lg border border-gray-200 p-4 dark:border-gray-700">
				<div>
					<div class="font-medium text-[#FFFFF0]">Auto-refresh</div>
					<div class="text-sm text-gray-500 dark:text-gray-400">
						Automatically refresh data at set intervals
					</div>
				</div>
				<label class="relative inline-flex cursor-pointer items-center">
					<input
						type="checkbox"
						bind:checked={settings.autoRefresh}
						class="peer sr-only"
					/>
					<div class="peer h-6 w-11 rounded-full bg-gray-300 after:absolute after:left-0.5 after:top-0.5 after:h-5 after:w-5 after:rounded-full after:border after:border-gray-300 after:bg-white after:transition-all after:content-[''] peer-checked:bg-purple-600 peer-checked:after:translate-x-full peer-checked:after:border-white dark:bg-gray-600"></div>
				</label>
			</div>

			<div class="flex items-center justify-between rounded-lg border border-gray-200 p-4 dark:border-gray-700">
				<div>
					<div class="font-medium text-[#FFFFF0]">Notifications</div>
					<div class="text-sm text-gray-500 dark:text-gray-400">
						Show system notifications for important events
					</div>
				</div>
				<label class="relative inline-flex cursor-pointer items-center">
					<input
						type="checkbox"
						bind:checked={settings.notifications}
						class="peer sr-only"
					/>
					<div class="peer h-6 w-11 rounded-full bg-gray-300 after:absolute after:left-0.5 after:top-0.5 after:h-5 after:w-5 after:rounded-full after:border after:border-gray-300 after:bg-white after:transition-all after:content-[''] peer-checked:bg-purple-600 peer-checked:after:translate-x-full peer-checked:after:border-white dark:bg-gray-600"></div>
				</label>
			</div>
		</div>
	</div>

	<!-- Appearance -->
	<div class="rounded-xl bg-white p-6 shadow-lg dark:bg-gray-800">
		<h2 class="mb-4 text-xl font-bold text-[#FFFFF0]">Appearance</h2>
		
		<div class="space-y-4">
			<fieldset>
				<legend class="mb-2 block text-sm font-medium text-[#FFFFF0]">
					Theme
				</legend>
				<div class="grid grid-cols-3 gap-3">
					<button
						onclick={() => (settings.theme = 'light')}
						class="rounded-lg border-2 p-4 transition-all {settings.theme === 'light'
							? 'border-[#d4af37] bg-purple-50 dark:bg-purple-900/20'
							: 'border-gray-300 hover:border-gray-400 dark:border-gray-600'}"
					>
						<div class="mb-2 text-2xl">☀️</div>
						<div class="text-sm font-medium text-[#FFFFF0]">Light</div>
					</button>
					<button
						onclick={() => (settings.theme = 'dark')}
						class="rounded-lg border-2 p-4 transition-all {settings.theme === 'dark'
							? 'border-[#d4af37] bg-purple-50 dark:bg-purple-900/20'
							: 'border-gray-300 hover:border-gray-400 dark:border-gray-600'}"
					>
						<div class="mb-2 text-2xl">🌙</div>
						<div class="text-sm font-medium text-[#FFFFF0]">Dark</div>
					</button>
					<button
						onclick={() => (settings.theme = 'system')}
						class="rounded-lg border-2 p-4 transition-all {settings.theme === 'system'
							? 'border-[#d4af37] bg-purple-50 dark:bg-purple-900/20'
							: 'border-gray-300 hover:border-gray-400 dark:border-gray-600'}"
					>
						<div class="mb-2 text-2xl">💻</div>
						<div class="text-sm font-medium text-[#FFFFF0]">System</div>
					</button>
				</div>
			</fieldset>
		</div>
	</div>

	<!-- System Information -->
	<div class="rounded-xl bg-white p-6 shadow-lg dark:bg-gray-800">
		<h2 class="mb-4 text-xl font-bold text-[#FFFFF0]">System Information</h2>
		
		<div class="space-y-3">
			<div class="flex items-center justify-between rounded-lg bg-gray-50 p-3 dark:bg-gray-700">
				<span class="text-sm text-[#FFFFF0]">Version</span>
				<span class="font-mono text-sm font-medium text-[#FFFFF0]">1.0.0</span>
			</div>
			<div class="flex items-center justify-between rounded-lg bg-gray-50 p-3 dark:bg-gray-700">
				<span class="text-sm text-[#FFFFF0]">Build Date</span>
				<span class="font-mono text-sm font-medium text-[#FFFFF0]">2025-12-17</span>
			</div>
			<div class="flex items-center justify-between rounded-lg bg-gray-50 p-3 dark:bg-gray-700">
				<span class="text-sm text-[#FFFFF0]">Environment</span>
				<span class="font-mono text-sm font-medium text-[#FFFFF0]">Development</span>
			</div>
			<div class="flex items-center justify-between rounded-lg bg-gray-50 p-3 dark:bg-gray-700">
				<span class="text-sm text-[#FFFFF0]">UI Port</span>
				<span class="font-mono text-sm font-medium text-[#FFFFF0]">3000</span>
			</div>
			<div class="flex items-center justify-between rounded-lg bg-gray-50 p-3 dark:bg-gray-700">
				<span class="text-sm text-[#FFFFF0]">API Port</span>
				<span class="font-mono text-sm font-medium text-[#FFFFF0]">3001</span>
			</div>
		</div>
	</div>

	<!-- About -->
	<div class="rounded-xl bg-white p-6 shadow-lg dark:bg-gray-800">
		<h2 class="mb-4 text-xl font-bold text-[#FFFFF0]">About Mobius</h2>
		
		<div class="space-y-4">
			<div class="rounded-lg from-purple-50 to-blue-50 p-4 dark:from-purple-900/20 dark:to-blue-900/20">
				<div class="mb-2 flex items-center gap-3">
					<div class="flex h-12 w-12 items-center justify-center rounded-lg from-purple-600 to-blue-600">
						<span class="text-2xl font-bold text-white">M</span>
					</div>
					<div>
						<div class="font-bold text-[#FFFFF0]">Mobius</div>
						<div class="text-sm text-gray-600 dark:text-gray-400">Infrastructure Manager</div>
					</div>
				</div>
				<p class="text-sm text-gray-600 dark:text-gray-400">
					A comprehensive infrastructure management platform for Kubernetes, PostgreSQL, and VPN mesh networking.
				</p>
			</div>

			<div class="space-y-2 text-sm text-gray-600 dark:text-gray-400">
				<div class="flex items-center gap-2">
					<span>⚙️</span>
					<span>Kubernetes management via KIND</span>
				</div>
				<div class="flex items-center gap-2">
					<span>🗄️</span>
					<span>PostgreSQL via CloudNativePG</span>
				</div>
				<div class="flex items-center gap-2">
					<span>🌐</span>
					<span>VPN mesh networking with Headscale</span>
				</div>
			</div>
		</div>
	</div>
</div>

<!-- Action Buttons -->
<div class="mt-6 flex gap-4">
	<button
		onclick={saveSettings}
		class="flex-1 rounded-lg bg-linear-to-r from-purple-600 to-blue-600 py-3 font-medium text-white shadow-lg transition-all hover:from-purple-700 hover:to-blue-700 hover:shadow-xl"
	>
		💾 Save Settings
	</button>
	<button
		onclick={resetSettings}
		class="rounded-lg border-2 border-gray-300 px-6 py-3 font-medium text-gray-700 transition-all hover:bg-gray-50 dark:border-gray-600 dark:text-gray-300 dark:hover:bg-gray-700"
	>
		🔄 Reset to Defaults
	</button>
</div>
