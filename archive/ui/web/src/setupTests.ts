import '@testing-library/jest-dom';
import './lib/test-setup';
import { vi } from 'vitest';

// Mock SvelteKit modules globally
vi.mock('$app/environment', () => ({
  browser: true,
  dev: true,
  building: false,
  version: '1.0.0'
}));

vi.mock('$app/stores', () => ({
  page: {
    subscribe: (callback: any) => {
      callback({ url: { pathname: '/' } });
      return () => {};
    }
  },
  navigating: {
    subscribe: (callback: any) => {
      callback(null);
      return () => {};
    }
  }
}));

vi.mock('$app/navigation', () => ({
  goto: vi.fn(),
  invalidate: vi.fn(),
  invalidateAll: vi.fn(),
  preloadData: vi.fn(),
  preloadCode: vi.fn(),
  beforeNavigate: vi.fn(),
  afterNavigate: vi.fn()
}));
