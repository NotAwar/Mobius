<script lang="ts">
	import '../app.css';
	import { page } from '$app/stores';

	let { children } = $props();

	// MDM-focused navigation structure
	const navSections = [
		{
			title: 'Device Management',
			items: [
				{ href: '/', label: 'Dashboard' },
				{ href: '/clients', label: 'Clients' },
				{ href: '/groups', label: 'Client Groups' },
				{ href: '/enrollment', label: 'Enrollment' }
			]
		},
		{
			title: 'Monitoring',
			items: [
				{ href: '/osquery', label: 'OSQuery' },
				{ href: '/queries', label: 'Queries' },
				{ href: '/health', label: 'Health Status' }
			]
		},
		{
			title: 'Administration',
			items: [
				{ href: '/users', label: 'Users & Roles' },
				{ href: '/audit', label: 'Audit Logs' },
				{ href: '/settings', label: 'Settings' }
			]
		},
		{
			title: 'Infrastructure',
			items: [
				{ href: '/cluster', label: 'Kubernetes' },
				{ href: '/postgres', label: 'Database' },
				{ href: '/headscale', label: 'VPN' }
			]
		}
	];

	let mobileMenuOpen = $state(false);
</script>

<div class="min-h-screen bg-[#1c2f38]">
	<!-- Sidebar Navigation -->
	<aside class="fixed inset-y-0 left-0 z-50 w-64 transform bg-[rgba(212, 175, 55, 0.1)] shadow-xl transition-transform duration-300 ease-in-out border-r border-[rgba(212, 175, 55, 0.3)] lg:translate-x-0 {mobileMenuOpen ? 'translate-x-0' : '-translate-x-full'}">
		<div class="flex h-full flex-col">
			<!-- Logo -->
			<div class="flex h-16 items-center gap-3 border-b border-[rgba(212, 175, 55, 0.2)] px-6">
				<img src="/assets/Mobius_Logo.png" alt="Mobius" class="h-10 w-10" />
				<div>
					<h1 class="text-xl font-bold text-[#FFFFF0] font-heading">Mobius</h1>
					<p class="text-xs text-[#FFFFF0]">MDM Platform</p>
				</div>
			</div>

			<!-- Navigation -->
			<nav class="flex-1 space-y-6 px-3 py-4 overflow-y-auto">
				{#each navSections as section}
					<div>
					<h3 class="px-3 mb-2 text-xs font-semibold text-[#d4af37] uppercase tracking-wider">
						{section.title}
					</h3>
					<div class="space-y-1">
						{#each section.items as item}
							<a
								href={item.href}
								class="flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-all {$page.url.pathname === item.href
									? 'bg-[#d4af37] text-[#1c2f38] shadow-lg font-semibold'
									: 'text-[#FFFFF0] hover:bg-[rgba(212, 175, 55, 0.15)] hover:text-[#FFFFF0]'}"
									onclick={() => (mobileMenuOpen = false)}
								>
									<span>{item.label}</span>
								</a>
							{/each}
						</div>
					</div>
				{/each}
			</nav>

			<!-- Footer -->
			<div class="border-t border-[rgba(212, 175, 55, 0.3)] p-4">
				<div class="text-xs text-[rgba(255, 255, 240, 0.7)]">
					<div class="mb-2 flex items-center justify-between">
						<span class="text-[#FFFFF0]">v1.0.0</span>
						<div class="flex gap-1 items-center">
							<div class="h-2 w-2 rounded-full bg-[#10b981]"></div>
							<span class="text-[#10b981] font-medium">Online</span>
						</div>
					</div>
					<p class="text-[rgba(255, 255, 240, 0.7)]">© 2025 Mobius</p>
				</div>
			</div>
		</div>
	</aside>

	<!-- Mobile Menu Button -->
	<button
		class="fixed left-4 top-4 z-40 rounded-lg bg-[rgba(212, 175, 55, 0.1)] border border-[rgba(212, 175, 55, 0.3)] p-2 shadow-lg lg:hidden hover:border-[#d4af37] transition-all"
		onclick={() => (mobileMenuOpen = !mobileMenuOpen)}
	>
		<svg class="h-6 w-6 text-[#FFFFF0]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
			{#if mobileMenuOpen}
				<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
			{:else}
				<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16" />
			{/if}
		</svg>
	</button>

	<!-- Main Content -->
	<div class="lg:pl-64">
		<!-- Top Bar -->
		<header class="sticky top-0 z-30 border-b border-[rgba(212, 175, 55, 0.2)] bg-[rgba(212, 175, 55, 0.1)]/95 backdrop-blur-sm">
			<div class="flex h-16 items-center justify-between px-6">
				<div class="flex items-center gap-4">
					<h2 class="text-xl font-semibold text-[#FFFFF0]">
						{#if $page.url.pathname === '/'}
							Dashboard
					{:else if $page.url.pathname.includes('/clients')}
						Client Management
					{:else if $page.url.pathname.includes('/groups')}
						Client Groups
					{:else if $page.url.pathname.includes('/enrollment')}
						Client Enrollment
					{:else if $page.url.pathname.includes('/osquery')}
						OSQuery Management
					{:else if $page.url.pathname.includes('/queries')}
						Query Management
					{:else if $page.url.pathname.includes('/users')}
						User & Role Management
					{:else if $page.url.pathname.includes('/audit')}
							Audit Logs
						{:else if $page.url.pathname === '/cluster'}
							Kubernetes Cluster
						{:else if $page.url.pathname === '/postgres'}
							PostgreSQL Database
						{:else if $page.url.pathname === '/headscale'}
							Headscale VPN
						{:else if $page.url.pathname === '/health'}
							System Health
						{:else if $page.url.pathname === '/settings'}
							Settings
						{/if}
					</h2>
				</div>
				
				<div class="flex items-center gap-4">
					<button class="text-[#FFFFF0] hover:text-[#FFFFF0] transition-colors" aria-label="Notifications">
						<svg class="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
							<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9" />
						</svg>
					</button>
					
					<div class="h-8 w-8 rounded-full bg-[#d4af37] flex items-center justify-center text-[#1c2f38] font-semibold text-sm shadow-lg">
						A
					</div>
				</div>
			</div>
		</header>

		<!-- Page Content -->
		<main class="p-6">
			{@render children()}
		</main>
	</div>

	<!-- Mobile Menu Overlay -->
	{#if mobileMenuOpen}
		<!-- svelte-ignore a11y_click_events_have_key_events -->
		<!-- svelte-ignore a11y_no_static_element_interactions -->
		<div
			class="fixed inset-0 z-40 bg-[#1c2f38]/50 backdrop-blur-sm lg:hidden"
			onclick={() => (mobileMenuOpen = false)}
			role="button"
			tabindex="0"
			onkeydown={(e) => e.key === 'Escape' && (mobileMenuOpen = false)}
		></div>
	{/if}
</div>

<style>
	:global(body) {
		font-family: 'Ubuntu', sans-serif;
	}
	:global(h1, h2, h3, h4, h5, h6) {
		font-family: 'Montserrat', sans-serif;
	}
</style>

