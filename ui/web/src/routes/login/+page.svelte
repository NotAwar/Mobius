<script lang="ts">
  import { goto } from '$app/navigation';
  import { onMount } from 'svelte';
  import { apiClient } from '$lib/api';
  import { Eye, EyeOff, AlertCircle } from 'lucide-svelte';

  let email = 'admin@mobius.local';
  let password = 'admin123';
  let showPassword = false;
  let loading = false;
  let error: string | null = null;

  onMount(() => {
    // If already authenticated, redirect to dashboard
    if (apiClient.isAuthenticated()) {
      goto('/');
    }
  });

  async function handleLogin(event: Event) {
    event.preventDefault();
    loading = true;
    error = null;

    try {
      await apiClient.login({ email, password });
      goto('/');
    } catch (err: any) {
      console.error('Login failed:', err);
      if (err.response?.status === 401) {
        error = 'Invalid email or password';
      } else if (err.response?.status === 429) {
        error = 'Too many login attempts. Please try again later.';
      } else {
        error = 'Login failed. Please check your connection and try again.';
      }
    } finally {
      loading = false;
    }
  }

  function togglePasswordVisibility() {
    showPassword = !showPassword;
  }
</script>

<svelte:head>
  <title>Login - Mobius MDM</title>
</svelte:head>

<div class="login-container">
  <div class="login-card">
    <!-- Logo/Header -->
    <div class="login-header">
      <img src="/logo.png" alt="Mobius Logo" class="login-logo" />
      <h1>Mobius MDM</h1>
      <p>Mobile Device Management</p>
    </div>

    <!-- Login Form -->
    <form on:submit={handleLogin} class="login-form">
      <h2>Sign In</h2>
      <p class="login-subtitle">Access your MDM admin panel</p>

      {#if error}
        <div class="error-message">
          <AlertCircle size={16} />
          {error}
        </div>
      {/if}

      <div class="form-group">
        <label for="email">Email Address</label>
        <input
          id="email"
          type="email"
          bind:value={email}
          required
          disabled={loading}
          autocomplete="email"
          placeholder="Enter your email"
        />
      </div>

      <div class="form-group">
        <label for="password">Password</label>
        <div class="password-input">
          <input
            id="password"
            type={showPassword ? 'text' : 'password'}
            bind:value={password}
            required
            disabled={loading}
            autocomplete="current-password"
            placeholder="Enter your password"
          />
          <button
            type="button"
            on:click={togglePasswordVisibility}
            class="password-toggle"
            disabled={loading}
          >
            {#if showPassword}
              <EyeOff size={16} />
            {:else}
              <Eye size={16} />
            {/if}
          </button>
        </div>
      </div>

      <button type="submit" class="login-button" disabled={loading}>
        {#if loading}
          <div class="spinner"></div>
          Signing In...
        {:else}
          Sign In
        {/if}
      </button>

      <!-- Demo credentials info -->
      <div class="demo-info">
        <p><strong>Demo Credentials:</strong></p>
        <p>Email: admin@mobius.local</p>
        <p>Password: admin123</p>
      </div>
    </form>

    <!-- Footer -->
    <div class="login-footer">
      <p>&copy; 2025 Mobius MDM. All rights reserved.</p>
    </div>
  </div>
</div>

<style>
  .login-container {
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    background: linear-gradient(135deg, var(--brand-blue) 0%, #0f1f27 100%);
    padding: 1rem;
  }

  .login-card {
    background: white;
    border-radius: 1rem;
    box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.3), 0 10px 10px -5px rgba(0, 0, 0, 0.2);
    width: 100%;
    max-width: 480px;
    overflow: hidden;
  }

  .login-header {
    background: var(--brand-blue);
    color: white;
    padding: 2.5rem 2rem;
    text-align: center;
    border-bottom: 3px solid var(--brand-gold);
  }

  .login-logo {
    height: 80px;
    width: auto;
    margin: 0 auto 1.25rem auto;
    display: block;
    filter: brightness(0) invert(1);
  }

  .login-header h1 {
    font-family: 'Montserrat', sans-serif;
    font-size: 2rem;
    font-weight: 300;
    margin: 0 0 0.5rem 0;
    color: var(--brand-gold);
    letter-spacing: 0.05em;
  }

  .login-header p {
    margin: 0;
    opacity: 0.9;
    font-size: 0.875rem;
    font-family: 'Ubuntu', sans-serif;
  }

  .login-form {
    padding: 2.5rem;
  }

  .login-form h2 {
    font-family: 'Montserrat', sans-serif;
    font-size: 1.75rem;
    font-weight: 300;
    color: var(--brand-blue);
    margin: 0 0 0.5rem 0;
    text-align: center;
  }

  .login-subtitle {
    text-align: center;
    color: var(--text-secondary);
    margin: 0 0 2.5rem 0;
    font-size: 0.9375rem;
    font-family: 'Ubuntu', sans-serif;
  }

  .error-message {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    background: #fee2e2;
    color: #dc2626;
    padding: 0.75rem;
    border-radius: 0.5rem;
    margin-bottom: 1.5rem;
    font-size: 0.875rem;
  }

  .form-group {
    margin-bottom: 1.5rem;
  }

  .form-group label {
    display: block;
    font-weight: 500;
    color: var(--brand-blue);
    margin-bottom: 0.5rem;
    font-size: 0.875rem;
    font-family: 'Ubuntu', sans-serif;
  }

  .form-group input {
    width: 100%;
    padding: 0.75rem;
    border: 1px solid var(--border-color);
    border-radius: 0.5rem;
    font-size: 1rem;
    transition: all 0.2s;
    background: white;
    font-family: 'Ubuntu', sans-serif;
  }

  .form-group input:focus {
    outline: none;
    border-color: var(--brand-gold);
    box-shadow: 0 0 0 3px rgba(212, 175, 55, 0.1);
  }

  .form-group input:disabled {
    background-color: #f9fafb;
    color: #6b7280;
    cursor: not-allowed;
  }

  .password-input {
    position: relative;
  }

  .password-input input {
    padding-right: 3rem;
  }

  .password-toggle {
    position: absolute;
    right: 0.75rem;
    top: 50%;
    transform: translateY(-50%);
    background: none;
    border: none;
    color: var(--text-secondary);
    cursor: pointer;
    padding: 0.25rem;
    border-radius: 0.25rem;
    transition: color 0.2s;
  }

  .password-toggle:hover {
    color: var(--brand-gold);
  }

  .password-toggle:disabled {
    cursor: not-allowed;
    opacity: 0.5;
  }

  .login-button {
    width: 100%;
    background: var(--brand-blue);
    color: white;
    border: none;
    padding: 0.875rem;
    border-radius: 0.5rem;
    font-size: 1rem;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.2s;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0.5rem;
    font-family: 'Ubuntu', sans-serif;
  }

  .login-button:hover:not(:disabled) {
    background: var(--brand-gold);
    color: var(--brand-blue);
  }

  .login-button:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  .spinner {
    width: 1rem;
    height: 1rem;
    border: 2px solid transparent;
    border-top: 2px solid currentColor;
    border-radius: 50%;
    animation: spin 1s linear infinite;
  }

  @keyframes spin {
    to { transform: rotate(360deg); }
  }

  .demo-info {
    margin-top: 2rem;
    padding: 1rem;
    background: rgba(212, 175, 55, 0.05);
    border-radius: 0.5rem;
    border: 1px solid rgba(212, 175, 55, 0.2);
  }

  .demo-info p {
    margin: 0.25rem 0;
    font-size: 0.875rem;
    color: var(--text-secondary);
    font-family: 'Ubuntu', sans-serif;
  }

  .demo-info p:first-child {
    color: var(--brand-blue);
    margin-bottom: 0.5rem;
    font-weight: 500;
  }

  .login-footer {
    background: #f8fafc;
    padding: 1rem 2rem;
    border-top: 1px solid var(--border-color);
    text-align: center;
  }

  .login-footer p {
    margin: 0;
    font-size: 0.75rem;
    color: var(--text-secondary);
  }

  @media (max-width: 480px) {
    .login-container {
      padding: 0.5rem;
    }

    .login-header {
      padding: 1.5rem;
    }

    .login-header h1 {
      font-size: 1.75rem;
    }

    .login-form {
      padding: 1.5rem;
    }
  }
</style>
