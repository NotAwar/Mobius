import axios, { type AxiosInstance, type AxiosResponse } from 'axios';

// Types for API responses
export interface Device {
  id: string;
  uuid: string;
  hostname: string;
  platform: string;
  os_version: string;
  status: 'online' | 'offline' | 'pending';
  last_seen: string;
  enrollment_date: string;
  enrolled_user?: string;
}

export interface Policy {
  id: string;
  name: string;
  description: string;
  platform: string;
  enabled: boolean;
  configuration: Record<string, any>;
  created_at: string;
  updated_at: string;
}

export interface Application {
  id: string;
  name: string;
  version: string;
  platform: string;
  description?: string;
  size?: number;
  created_at: string;
}

export interface DeviceGroup {
  id: string;
  name: string;
  description: string;
  device_count: number;
  created_at: string;
}

export interface LoginRequest {
  email: string;
  password: string;
}

export interface LoginResponse {
  token: string;
  user: {
    id: string;
    email: string;
    name: string;
    role: string;
  };
}

export interface LicenseStatus {
  tier: 'community' | 'professional' | 'enterprise';
  devices_enrolled: number;
  devices_limit: number;
  expires_at?: string;
  features: string[];
}

export interface HealthStatus {
  status: 'healthy' | 'degraded' | 'unhealthy';
  version: string;
  uptime: number;
  database: boolean;
  services: Record<string, boolean>;
}

class APIClient {
  private client: AxiosInstance;
  private baseURL: string;

  constructor(baseURL: string = 'http://localhost:8081/api/v1') {
    this.baseURL = baseURL;
    this.client = axios.create({
      baseURL,
      timeout: 10000,
      headers: {
        'Content-Type': 'application/json',
      },
    });

    // Add request interceptor to include auth token
    this.client.interceptors.request.use((config) => {
      const token = this.getAuthToken();
      if (token) {
        config.headers.Authorization = `Bearer ${token}`;
      }
      return config;
    });

    // Add response interceptor for error handling
    this.client.interceptors.response.use(
      (response) => response,
      (error) => {
        if (error.response?.status === 401) {
          this.clearAuthToken();
          // Redirect to login page or emit auth error event
          window.location.href = '/login';
        }
        return Promise.reject(error);
      }
    );
  }

  // Authentication methods
  private getAuthToken(): string | null {
    return localStorage.getItem('auth_token');
  }

  private setAuthToken(token: string): void {
    localStorage.setItem('auth_token', token);
  }

  private clearAuthToken(): void {
    localStorage.removeItem('auth_token');
  }

  async login(credentials: LoginRequest): Promise<LoginResponse> {
    const response: AxiosResponse<LoginResponse> = await this.client.post('/auth/login', credentials);
    this.setAuthToken(response.data.token);
    return response.data;
  }

  async logout(): Promise<void> {
    this.clearAuthToken();
  }

  isAuthenticated(): boolean {
    return !!this.getAuthToken();
  }

  // Health and system methods
  async getHealth(): Promise<HealthStatus> {
    const response: AxiosResponse<HealthStatus> = await this.client.get('/health');
    return response.data;
  }

  async getLicenseStatus(): Promise<LicenseStatus> {
    const response: AxiosResponse<LicenseStatus> = await this.client.get('/license/status');
    return response.data;
  }

  // Device management methods
  async getDevices(params?: { 
    limit?: number; 
    offset?: number; 
    platform?: string; 
    status?: string;
    search?: string;
  }): Promise<{ devices: Device[]; total: number }> {
    const response = await this.client.get('/devices', { params });
    return response.data;
  }

  async getDevice(deviceId: string): Promise<Device> {
    const response: AxiosResponse<Device> = await this.client.get(`/devices/${deviceId}`);
    return response.data;
  }

  async enrollDevice(deviceData: Partial<Device>): Promise<Device> {
    const response: AxiosResponse<Device> = await this.client.post('/devices', deviceData);
    return response.data;
  }

  async unenrollDevice(deviceId: string): Promise<void> {
    await this.client.delete(`/devices/${deviceId}`);
  }

  async assignDevicePolicies(deviceId: string, policyIds: string[]): Promise<void> {
    await this.client.post(`/devices/${deviceId}/policies`, { policy_ids: policyIds });
  }

  async lockDevice(deviceId: string): Promise<void> {
    await this.client.post(`/devices/${deviceId}/actions/lock`);
  }

  async unlockDevice(deviceId: string): Promise<void> {
    await this.client.post(`/devices/${deviceId}/actions/unlock`);
  }

  async wipeDevice(deviceId: string): Promise<void> {
    await this.client.post(`/devices/${deviceId}/actions/wipe`);
  }

  // Policy management methods
  async getPolicies(): Promise<{ policies: Policy[]; total: number }> {
    const response = await this.client.get('/policies');
    return response.data;
  }

  async getPolicy(policyId: string): Promise<Policy> {
    const response: AxiosResponse<Policy> = await this.client.get(`/policies/${policyId}`);
    return response.data;
  }

  async createPolicy(policyData: Partial<Policy>): Promise<Policy> {
    const response: AxiosResponse<Policy> = await this.client.post('/policies', policyData);
    return response.data;
  }

  async updatePolicy(policyId: string, policyData: Partial<Policy>): Promise<Policy> {
    const response: AxiosResponse<Policy> = await this.client.put(`/policies/${policyId}`, policyData);
    return response.data;
  }

  async deletePolicy(policyId: string): Promise<void> {
    await this.client.delete(`/policies/${policyId}`);
  }

  async assignPolicyToDevice(policyId: string, deviceId: string): Promise<void> {
    await this.client.post(`/policies/${policyId}/devices/${deviceId}`);
  }

  async unassignPolicyFromDevice(policyId: string, deviceId: string): Promise<void> {
    await this.client.delete(`/policies/${policyId}/devices/${deviceId}`);
  }

  // Application management methods
  async getApplications(): Promise<{ applications: Application[]; total: number }> {
    const response = await this.client.get('/applications');
    return response.data;
  }

  async getApplication(appId: string): Promise<Application> {
    const response: AxiosResponse<Application> = await this.client.get(`/applications/${appId}`);
    return response.data;
  }

  async addApplication(appData: FormData): Promise<Application> {
    const response: AxiosResponse<Application> = await this.client.post('/applications', appData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return response.data;
  }

  async updateApplication(appId: string, appData: Partial<Application>): Promise<Application> {
    const response: AxiosResponse<Application> = await this.client.put(`/applications/${appId}`, appData);
    return response.data;
  }

  async deleteApplication(appId: string): Promise<void> {
    await this.client.delete(`/applications/${appId}`);
  }

  // Device Group management methods
  async getDeviceGroups(): Promise<{ groups: DeviceGroup[]; total: number }> {
    const response = await this.client.get('/groups');
    return response.data;
  }

  async createDeviceGroup(groupData: Partial<DeviceGroup>): Promise<DeviceGroup> {
    const response: AxiosResponse<DeviceGroup> = await this.client.post('/groups', groupData);
    return response.data;
  }

  async updateDeviceGroup(groupId: string, groupData: Partial<DeviceGroup>): Promise<DeviceGroup> {
    const response: AxiosResponse<DeviceGroup> = await this.client.put(`/groups/${groupId}`, groupData);
    return response.data;
  }

  async deleteDeviceGroup(groupId: string): Promise<void> {
    await this.client.delete(`/groups/${groupId}`);
  }

  async addDeviceToGroup(groupId: string, deviceId: string): Promise<void> {
    await this.client.post(`/groups/${groupId}/devices/${deviceId}`);
  }

  async removeDeviceFromGroup(groupId: string, deviceId: string): Promise<void> {
    await this.client.delete(`/groups/${groupId}/devices/${deviceId}`);
  }

  // WebSocket connection for real-time updates
  createWebSocket(onMessage?: (data: any) => void): WebSocket {
    const token = this.getAuthToken();
    const wsUrl = this.baseURL.replace('http', 'ws').replace('/api/v1', '') + '/api/v1/ws';
    
    const ws = new WebSocket(`${wsUrl}?token=${token}`);
    
    if (onMessage) {
      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          onMessage(data);
        } catch (error) {
          console.error('Failed to parse WebSocket message:', error);
        }
      };
    }

    ws.onerror = (error) => {
      console.error('WebSocket error:', error);
    };

    ws.onclose = (event) => {
      console.log('WebSocket closed:', event.code, event.reason);
    };

    return ws;
  }
}

// Export singleton instance
export const apiClient = new APIClient();

// Export the class for testing or custom instances
export default APIClient;
