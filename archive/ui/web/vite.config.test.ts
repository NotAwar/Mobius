import { defineConfig } from 'vitest/config';
import { sveltekit } from '@sveltejs/kit/vite';

export default defineConfig({
  plugins: [sveltekit()],
  test: {
    include: ['src/**/*.{test,spec}.{js,ts}'],
    globals: true,
    environment: 'jsdom',
    setupFiles: ['./src/setupTests.ts'],
    // Force browser environment
    environmentOptions: {
      jsdom: {
        resources: 'usable'
      }
    },
    pool: 'forks',
    // Disable SSR for tests
    alias: {
      '$app/environment': '/src/__mocks__/app/environment.js'
    }
  }
});
