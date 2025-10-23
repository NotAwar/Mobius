<script lang="ts">
  import { onMount } from 'svelte';
  import { page } from '$app/stores';
  import { goto } from '$app/navigation';
  import { apiClient } from '$lib/api';
  import {
    Monitor,
    Shield,
    Package,
    Users,
    Settings,
    LogOut,
    Menu,
    X,
    Bell,
    Search
  } from 'lucide-svelte';

  let sidebarOpen = false;
  let user: any = null;
  let notifications: any[] = [];

  const navigation = [
    { name: 'Dashboard', href: '/', icon: Monitor },
    { name: 'Devices', href: '/devices', icon: Monitor },
    { name: 'Policies', href: '/policies', icon: Shield },
    { name: 'Applications', href: '/applications', icon: Package },
    { name: 'Groups', href: '/groups', icon: Users },
    { name: 'Settings', href: '/settings', icon: Settings },
  ];

  onMount(() => {
    // Check authentication
    if (!apiClient.isAuthenticated()) {
      goto('/login');
      return;
    }

    // Load user data (this would typically come from a user store or API)
    user = {
      name: 'Admin User',
      email: 'admin@mobius.local',
      role: 'Administrator'
    };
  });

  function handleLogout() {
    apiClient.logout();
    goto('/login');
  }

  function toggleSidebar() {
    sidebarOpen = !sidebarOpen;
  }

  $: currentPath = $page.url.pathname;
</script>

<div class="admin-layout">
  <!-- Mobile sidebar overlay -->
  {#if sidebarOpen}
    <div class="fixed inset-0 z-40 lg:hidden">
      <div class="fixed inset-0 bg-gray-600 bg-opacity-75" on:click={toggleSidebar} on:keydown={(e) => e.key === 'Escape' && toggleSidebar()} role="button" tabindex="0"></div>      
      <div class="fixed inset-y-0 left-0 z-50 w-64 bg-white shadow-lg">
        <!-- Mobile sidebar content -->
        <div class="flex h-16 items-center justify-between px-4 border-b">
          <h1 class="text-xl font-bold text-gray-900">Mobius MDM</h1>
          <button on:click={toggleSidebar} class="text-gray-400 hover:text-gray-600">
            <X size={24} />
          </button>
        </div>
        
        <nav class="mt-4 px-4">
          {#each navigation as item}
            <a
              href={item.href}
              class="nav-item {currentPath === item.href ? 'active' : ''}"
              on:click={toggleSidebar}
            >
              <svelte:component this={item.icon} size={20} />
              {item.name}
            </a>
          {/each}
        </nav>
      </div>
    </div>
  {/if}

  <!-- Desktop sidebar -->
  <div class="hidden lg:fixed lg:inset-y-0 lg:flex lg:w-64 lg:flex-col">
    <div class="flex flex-col flex-grow bg-white border-r border-gray-200 shadow-sm">
      <!-- Logo -->
      <div class="flex h-16 items-center px-6 border-b border-gray-200">
        <h1 class="text-xl font-bold text-gray-900">Mobius MDM</h1>
      </div>
      
      <!-- Navigation -->
      <nav class="mt-4 flex-1 px-4 space-y-1">
        {#each navigation as item}
          <a
            href={item.href}
            class="nav-item {currentPath === item.href ? 'active' : ''}"
          >
            <svelte:component this={item.icon} size={20} />
            {item.name}
          </a>
        {/each}
      </nav>
      
      <!-- User section -->
      {#if user}
        <div class="p-4 border-t border-gray-200">
          <div class="flex items-center">
            <div class="w-8 h-8 bg-blue-500 rounded-full flex items-center justify-center text-white text-sm font-medium">
              {user.name.charAt(0)}
            </div>
            <div class="ml-3 flex-1 min-w-0">
              <p class="text-sm font-medium text-gray-900 truncate">{user.name}</p>
              <p class="text-xs text-gray-500 truncate">{user.role}</p>
            </div>
            <button
              on:click={handleLogout}
              class="ml-2 text-gray-400 hover:text-gray-600"
              title="Logout"
            >
              <LogOut size={16} />
            </button>
          </div>
        </div>
      {/if}
    </div>
  </div>

  <!-- Main content -->
  <div class="lg:pl-64 flex flex-col flex-1">
    <!-- Top bar -->
    <div class="sticky top-0 z-10 bg-white border-b border-gray-200 shadow-sm">
      <div class="flex h-16 items-center justify-between px-4 sm:px-6 lg:px-8">
        <!-- Mobile menu button -->
        <button
          on:click={toggleSidebar}
          class="lg:hidden text-gray-400 hover:text-gray-600"
        >
          <Menu size={24} />
        </button>
        
        <!-- Search (placeholder) -->
        <div class="flex-1 max-w-md ml-4 lg:ml-0">
          <div class="relative">
            <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
              <Search size={16} class="text-gray-400" />
            </div>
            <input
              type="text"
              placeholder="Search devices, policies..."
              class="block w-full pl-10 pr-3 py-2 border border-gray-300 rounded-md leading-5 bg-white placeholder-gray-500 focus:outline-none focus:placeholder-gray-400 focus:ring-1 focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
            />
          </div>
        </div>
        
        <!-- Notifications -->
        <div class="ml-4 flex items-center">
          <button class="text-gray-400 hover:text-gray-600 relative">
            <Bell size={20} />
            {#if notifications.length > 0}
              <span class="absolute -top-1 -right-1 h-4 w-4 bg-red-500 rounded-full text-xs text-white flex items-center justify-center">
                {notifications.length}
              </span>
            {/if}
          </button>
        </div>
      </div>
    </div>
    
    <!-- Page content -->
    <main class="flex-1">
      <slot />
    </main>
  </div>
</div>

<style>
  .admin-layout {
    display: flex;
    height: 100vh;
    background-color: var(--background-color);
  }

  .nav-item {
    display: flex;
    align-items: center;
    padding: 0.75rem 1rem;
    text-decoration: none;
    color: var(--text-secondary);
    border-radius: 0.5rem;
    font-weight: 500;
    transition: all 0.2s;
    margin-bottom: 0.25rem;
  }

  .nav-item:hover {
    background-color: #f1f5f9;
    color: var(--text-primary);
  }

  .nav-item.active {
    background-color: var(--primary-color);
    color: white;
  }

  .nav-item :global(svg) {
    margin-right: 0.75rem;
    flex-shrink: 0;
  }
</style>
