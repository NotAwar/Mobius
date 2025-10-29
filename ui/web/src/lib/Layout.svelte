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
    <div class="mobile-overlay">
      <div class="overlay-backdrop" on:click={toggleSidebar} on:keydown={(e) => e.key === 'Escape' && toggleSidebar()} role="button" tabindex="0"></div>      
      <div class="mobile-sidebar sidebar">
        <!-- Mobile sidebar content -->
        <div class="logo-header mobile-header">
          <img src="/logo.png" alt="Mobius MDM" class="logo-img" />
          <button on:click={toggleSidebar} class="close-mobile-btn">
            <X size={24} />
          </button>
        </div>
        
        <nav class="nav-container">
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
  <div class="desktop-sidebar-wrapper">
    <div class="sidebar">
      <!-- Logo -->
      <div class="logo-header">
        <img src="/logo.png" alt="Mobius MDM" class="logo-img" />
      </div>
      
      <!-- Navigation -->
      <nav class="nav-container">
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
        <div class="user-section">
          <div class="user-info">
            <div class="user-avatar">
              {user.name.charAt(0)}
            </div>
            <div class="user-details">
              <p class="user-name">{user.name}</p>
              <p class="user-role">{user.role}</p>
            </div>
            <button
              on:click={handleLogout}
              class="logout-btn"
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
  <div class="main-content-wrapper">
    <!-- Top bar -->
    <div class="top-bar">
      <div class="top-bar-inner">
        <!-- Mobile menu button -->
        <button
          on:click={toggleSidebar}
          class="mobile-menu-btn"
        >
          <Menu size={24} />
        </button>
        
        <!-- Search (placeholder) -->
        <div class="search-wrapper">
          <div class="search-input-wrapper">
            <div class="search-icon">
              <Search size={16} />
            </div>
            <input
              type="text"
              placeholder="Search devices, policies..."
              class="search-input"
            />
          </div>
        </div>
        
        <!-- Notifications -->
        <div class="notifications-wrapper">
          <button class="notification-btn">
            <Bell size={20} />
            {#if notifications.length > 0}
              <span class="notification-badge">
                {notifications.length}
              </span>
            {/if}
          </button>
        </div>
      </div>
    </div>
    
    <!-- Page content -->
    <main class="page-content">
      <slot />
    </main>
  </div>
</div>

<style>
  .admin-layout {
    display: flex;
    height: 100vh;
    background-color: var(--background-color);
    overflow: hidden;
  }

  /* Mobile Overlay */
  .mobile-overlay {
    position: fixed;
    inset: 0;
    z-index: 1000;
    display: none;
  }

  .overlay-backdrop {
    position: fixed;
    inset: 0;
    background-color: rgba(0, 0, 0, 0.5);
  }

  .mobile-sidebar {
    position: fixed;
    top: 0;
    left: 0;
    bottom: 0;
    width: 16rem;
    z-index: 1001;
  }

  .mobile-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 0 1rem;
    height: 4rem;
  }

  .close-mobile-btn {
    background: none;
    border: none;
    color: rgba(255, 255, 255, 0.7);
    cursor: pointer;
    padding: 0.5rem;
    display: flex;
    align-items: center;
    transition: color 0.2s;
  }

  .close-mobile-btn:hover {
    color: var(--brand-gold);
  }

  /* Desktop Sidebar */
  .desktop-sidebar-wrapper {
    position: fixed;
    top: 0;
    left: 0;
    bottom: 0;
    width: 16rem;
    display: none;
  }

  .sidebar {
    display: flex;
    flex-direction: column;
    height: 100%;
    background-color: var(--brand-blue);
    border-right: 1px solid rgba(212, 175, 55, 0.1);
    box-shadow: 2px 0 8px rgba(0, 0, 0, 0.1);
  }

  .logo-header {
    display: flex;
    align-items: center;
    padding: 0 1.5rem;
    height: 4rem;
    border-bottom: 1px solid rgba(212, 175, 55, 0.2);
    background-color: rgba(0, 0, 0, 0.1);
  }

  .logo-header img {
    filter: brightness(0) invert(1);
    object-fit: contain;
  }

  .logo-img {
    max-width: 100%;
    height: 2.5rem;
  }

  .nav-container {
    flex: 1;
    padding: 1rem;
    overflow-y: auto;
  }

  .nav-item {
    display: flex;
    align-items: center;
    padding: 0.75rem 1rem;
    text-decoration: none;
    color: rgba(255, 255, 255, 0.7);
    border-radius: 0.5rem;
    font-weight: 500;
    font-family: var(--font-body);
    transition: all 0.2s;
    margin-bottom: 0.25rem;
  }

  .nav-item:hover {
    background-color: rgba(212, 175, 55, 0.1);
    color: #ffffff;
  }

  .nav-item.active {
    background-color: var(--brand-gold);
    color: var(--brand-blue);
    box-shadow: var(--shadow-gold);
  }

  .nav-item :global(svg) {
    margin-right: 0.75rem;
    flex-shrink: 0;
  }

  .user-section {
    padding: 1rem;
    border-top: 1px solid rgba(212, 175, 55, 0.2);
    background-color: rgba(0, 0, 0, 0.1);
  }

  .user-info {
    display: flex;
    align-items: center;
  }

  .user-avatar {
    width: 2rem;
    height: 2rem;
    background: linear-gradient(135deg, var(--brand-gold), #c29d2f);
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    color: var(--brand-blue);
    font-size: 0.875rem;
    font-weight: 600;
    font-family: var(--font-heading);
    flex-shrink: 0;
  }

  .user-details {
    margin-left: 0.75rem;
    flex: 1;
    min-width: 0;
  }

  .user-name {
    color: #ffffff;
    font-family: var(--font-body);
    font-size: 0.875rem;
    font-weight: 500;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .user-role {
    color: var(--brand-gold);
    font-family: var(--font-body);
    font-size: 0.75rem;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .logout-btn {
    margin-left: 0.5rem;
    background: none;
    border: none;
    color: rgba(255, 255, 255, 0.5);
    cursor: pointer;
    padding: 0.25rem;
    display: flex;
    align-items: center;
    transition: color 0.2s;
  }

  .logout-btn:hover {
    color: var(--brand-gold);
  }

  /* Main Content Area */
  .main-content-wrapper {
    flex: 1;
    display: flex;
    flex-direction: column;
    margin-left: 0;
    width: 100%;
  }

  .top-bar {
    position: sticky;
    top: 0;
    z-index: 100;
    background-color: white;
    border-bottom: 1px solid #e2e8f0;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
  }

  .top-bar-inner {
    display: flex;
    align-items: center;
    justify-content: space-between;
    height: 4rem;
    padding: 0 1rem;
  }

  .mobile-menu-btn {
    display: flex;
    align-items: center;
    background: none;
    border: none;
    color: #64748b;
    cursor: pointer;
    padding: 0.5rem;
    transition: color 0.2s;
  }

  .mobile-menu-btn:hover {
    color: var(--brand-blue);
  }

  .search-wrapper {
    flex: 1;
    max-width: 28rem;
    margin-left: 1rem;
  }

  .search-input-wrapper {
    position: relative;
  }

  .search-icon {
    position: absolute;
    left: 0.75rem;
    top: 50%;
    transform: translateY(-50%);
    color: #94a3b8;
    pointer-events: none;
    display: flex;
    align-items: center;
  }

  .search-input {
    width: 100%;
    padding: 0.5rem 0.75rem 0.5rem 2.5rem;
    border: 1px solid #cbd5e1;
    border-radius: 0.375rem;
    background-color: white;
    font-size: 0.875rem;
    line-height: 1.25rem;
    color: var(--brand-blue);
    transition: all 0.2s;
  }

  .search-input::placeholder {
    color: #94a3b8;
  }

  .search-input:focus {
    outline: none;
    border-color: var(--brand-blue);
    box-shadow: 0 0 0 3px rgba(28, 47, 56, 0.1);
  }

  .notifications-wrapper {
    margin-left: 1rem;
    display: flex;
    align-items: center;
  }

  .notification-btn {
    position: relative;
    background: none;
    border: none;
    color: #64748b;
    cursor: pointer;
    padding: 0.5rem;
    display: flex;
    align-items: center;
    transition: color 0.2s;
  }

  .notification-btn:hover {
    color: var(--brand-blue);
  }

  .notification-badge {
    position: absolute;
    top: 0;
    right: 0;
    height: 1rem;
    width: 1rem;
    background-color: #ef4444;
    border-radius: 50%;
    font-size: 0.75rem;
    color: white;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .page-content {
    flex: 1;
    overflow-y: auto;
    background-color: var(--background-color);
  }

  /* Responsive Styles */
  @media (max-width: 1023px) {
    /* Mobile: Show overlay when open */
    .mobile-overlay {
      display: block;
    }

    /* Mobile: Hide desktop sidebar */
    .desktop-sidebar-wrapper {
      display: none;
    }

    /* Mobile: Show menu button */
    .mobile-menu-btn {
      display: flex;
    }

    /* Mobile: Reduce search wrapper margin */
    .search-wrapper {
      margin-left: 0.5rem;
    }
  }

  @media (min-width: 1024px) {
    /* Desktop: Hide mobile overlay */
    .mobile-overlay {
      display: none !important;
    }

    /* Desktop: Show desktop sidebar */
    .desktop-sidebar-wrapper {
      display: flex;
      flex-direction: column;
    }

    /* Desktop: Hide mobile menu button */
    .mobile-menu-btn {
      display: none;
    }

    /* Desktop: Add left margin to main content */
    .main-content-wrapper {
      margin-left: 16rem;
    }

    /* Desktop: Search wrapper no left margin */
    .search-wrapper {
      margin-left: 0;
    }
  }
</style>
