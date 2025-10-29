<script lang="ts">
  import Layout from '$lib/Layout.svelte';
  import { onMount } from 'svelte';
  import { apiClient } from '$lib/api';
  import { goto } from '$app/navigation';
  import { Settings as SettingsIcon, Save } from 'lucide-svelte';

  let loading = false;

  onMount(async () => {
    if (!apiClient.isAuthenticated()) {
      goto('/login');
      return;
    }
  });
</script>

<Layout>
  <div class="page-container">
    <div class="page-header">
      <div>
        <h1>Settings</h1>
        <p>Configure your Mobius MDM system</p>
      </div>
    </div>

    <div class="empty-state">
      <SettingsIcon size={48} />
      <h2>Settings Coming Soon</h2>
      <p>System configuration and preferences will be available here.</p>
    </div>
  </div>
</Layout>

<style>
  .page-container {
    padding: 2rem;
  }

  .page-header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    margin-bottom: 2rem;
  }

  .page-header h1 {
    font-size: 2rem;
    font-weight: 300;
    margin-bottom: 0.5rem;
    color: #1c2f38;
  }

  .page-header p {
    color: #64748b;
  }

  .empty-state {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: 4rem 2rem;
    text-align: center;
  }

  .empty-state :global(svg) {
    color: #cbd5e1;
    margin-bottom: 1rem;
  }

  .empty-state h2 {
    font-size: 1.5rem;
    margin-bottom: 0.5rem;
    color: #1c2f38;
  }

  .empty-state p {
    color: #64748b;
  }
</style>
