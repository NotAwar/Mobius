<script lang="ts">
  import { goto } from '$app/navigation';
  import { onMount } from 'svelte';

  onMount(() => {
    // Redirect to main dashboard for now
    goto('/');
  });
</script>

<h1>Policies</h1>
<p>This page will contain policy management features.</p>
