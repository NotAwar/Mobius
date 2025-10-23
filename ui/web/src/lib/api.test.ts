import { describe, it, expect, beforeEach, vi } from 'vitest';
import { localStorageMock } from './test-setup';

// Mock axios first before any imports
vi.mock('axios', () => {
  const mockAxiosInstance = {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    delete: vi.fn(),
    interceptors: {
      request: { use: vi.fn() },
      response: { use: vi.fn() }
    }
  };
  
  return {
    default: {
      create: vi.fn(() => mockAxiosInstance)
    }
  };
});

import APIClient from '$lib/api';
import axios from 'axios';

// Get the mocked axios instance
const mockedAxios = vi.mocked(axios, true);
const mockAxiosInstance = mockedAxios.create() as any;

describe('API Client', () => {
  let apiClient: APIClient;

  beforeEach(() => {
    // Clear only the mock instance methods
    mockAxiosInstance.get.mockClear();
    mockAxiosInstance.post.mockClear();
    mockAxiosInstance.put.mockClear();
    mockAxiosInstance.delete.mockClear();
    localStorageMock.getItem.mockClear();
    localStorageMock.setItem.mockClear();
    localStorageMock.removeItem.mockClear();
    
    apiClient = new APIClient('http://localhost:8081/api/v1');
  });

  describe('Authentication', () => {
    it('should store token after successful login', async () => {
      const mockResponse = {
        token: 'test-token',
        user: {
          id: '1',
          email: 'admin@mobius.local',
          name: 'Admin User',
          role: 'admin'
        }
      };

      mockAxiosInstance.post.mockResolvedValueOnce({
        data: mockResponse,
        status: 200,
        statusText: 'OK',
        headers: {},
        config: {}
      });

      const result = await apiClient.login({
        email: 'admin@mobius.local',
        password: 'admin123'
      });

      expect(localStorageMock.setItem).toHaveBeenCalledWith('auth_token', 'test-token');
      expect(result).toEqual(mockResponse);
    });

    it('should return true for authenticated user', () => {
      localStorageMock.getItem.mockReturnValue('test-token');
      
      expect(apiClient.isAuthenticated()).toBe(true);
    });

    it('should return false for unauthenticated user', () => {
      localStorageMock.getItem.mockReturnValue(null);
      
      expect(apiClient.isAuthenticated()).toBe(false);
    });

    it('should clear token on logout', async () => {
      await apiClient.logout();
      
      expect(localStorageMock.removeItem).toHaveBeenCalledWith('auth_token');
    });
  });

  describe('Device Management', () => {
    beforeEach(() => {
      localStorageMock.getItem.mockReturnValue('test-token');
    });

    it('should fetch devices with proper parameters', async () => {
      const mockDevices = {
        devices: [
          {
            id: '1',
            uuid: 'device-uuid-1',
            hostname: 'test-device',
            platform: 'windows',
            status: 'online'
          }
        ],
        total: 1
      };

      mockAxiosInstance.get.mockResolvedValueOnce({
        data: mockDevices,
        status: 200,
        statusText: 'OK',
        headers: {},
        config: {}
      });

      const result = await apiClient.getDevices({
        limit: 10,
        platform: 'windows'
      });

      expect(mockAxiosInstance.get).toHaveBeenCalledWith(
        '/devices',
        expect.objectContaining({
          params: {
            limit: 10,
            platform: 'windows'
          }
        })
      );
      expect(result).toEqual(mockDevices);
    });
  });

  describe('Error Handling', () => {
    it('should clear auth token when logout is called', async () => {
      localStorageMock.getItem.mockReturnValue('test-token');
      
      await apiClient.logout();
      
      expect(localStorageMock.removeItem).toHaveBeenCalledWith('auth_token');
    });

    it('should handle API errors gracefully', async () => {
      localStorageMock.getItem.mockReturnValue('test-token');

      mockAxiosInstance.get.mockRejectedValueOnce({
        response: {
          status: 500,
          data: { error: 'Server Error' }
        }
      });

      await expect(apiClient.getDevices()).rejects.toThrow();
    });
  });
});
