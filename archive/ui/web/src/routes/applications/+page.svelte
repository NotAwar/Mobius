<script lang="ts">
  import Layout from '$lib/Layout.svelte';
  import { onMount } from 'svelte';
  import { apiClient } from '$lib/api';
  import { goto } from '$app/navigation';
  import { Package, Plus } from 'lucide-svelte';

  let applications: any[] = [];
  let loading = true;

  onMount(async () => {
    if (!apiClient.isAuthenticated()) {
      goto('/login');
      return;
    }

    try {
      const response = await apiClient.getApplications();
      applications = response.applications;
    } catch (err) {
      console.error('Failed to load applications:', err);
    } finally {
      loading = false;
    }
  });
</script>

<Layout>
  <div class="page-container">
    <div class="page-header">
      <div>
        <h1>Applications</h1>
        <p>Manage and deploy applications to your devices</p>
      </div>
      <button class="btn btn-primary" disabled>
        <Plus size={16} />
        Add Application
      </button>
    </div>

    {#if loading}
      <div class="loading">
        <div class="spinner"></div>
        <p>Loading applications...</p>
      </div>
    {:else if applications.length === 0}
      <div class="empty-state">
        <Package size={48} />
        <h2>No Applications Yet</h2>
        <p>Add applications to deploy them to your managed devices.</p>
        <button class="btn btn-primary" disabled>
          <Plus size={16} />
          Add Your First Application
        </button>
      </div>
    {:else}
      <div class="content">
        <p>Applications will be displayed here.</p>
      </div>
    {/if}
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

  .loading, .empty-state {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: 4rem 2rem;
    text-align: center;
  }

  .spinner {
    width: 40px;
    height: 40px;
    border: 4px solid #e2e8f0;
    border-top-color: #d4af37;
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
  }

  @keyframes spin {
    to { transform: rotate(360deg); }
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
    margin-bottom: 1.5rem;
  }

  .btn {
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.625rem 1.25rem;
    border-radius: 0.5rem;
    font-weight: 500;
    transition: all 0.2s;
    cursor: pointer;
    border: none;
  }

  .btn-primary {
    background: #d4af37;
    color: #1c2f38;
  }

  .btn-primary:hover:not(:disabled) {
    background: #c19d2f;
  }

  .btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
</style>
