import sendRequest from "services";
import endpoints from "utilities/endpoints";
import { IHost } from "interfaces/host";
import { IUser } from "interfaces/user";

export interface IPortalUser extends IUser {
  devices?: IHost[];
  enrollment_code?: string;
}

export interface IInternalPortalStats {
  total_users: number;
  active_teams: number;
  enrolled_devices: number;
  pending_devices: number;
  system_health: "healthy" | "warning" | "error";
  last_sync: string;
}

export interface IUserDeviceEnrollment {
  enrollment_code: string;
  profile_url: string;
  instructions: string;
}

export default {
  // Internal Portal APIs
  getSystemStats: (): Promise<IInternalPortalStats> => {
    const { INTERNAL_PORTAL_STATS } = endpoints;
    return sendRequest("GET", INTERNAL_PORTAL_STATS);
  },

  getSystemLogs: (limit?: number): Promise<any[]> => {
    const { INTERNAL_PORTAL_LOGS } = endpoints;
    const queryString = limit ? `?limit=${limit}` : "";
    return sendRequest("GET", `${INTERNAL_PORTAL_LOGS}${queryString}`);
  },

  // User Portal APIs
  getUserDevices: (userId: number): Promise<IHost[]> => {
    const { USER_PORTAL_DEVICES } = endpoints;
    return sendRequest("GET", `${USER_PORTAL_DEVICES}?user_id=${userId}`);
  },

  generateEnrollmentCode: (userId: number): Promise<IUserDeviceEnrollment> => {
    const { USER_PORTAL_ENROLLMENT } = endpoints;
    return sendRequest("POST", USER_PORTAL_ENROLLMENT, { user_id: userId });
  },

  downloadEnrollmentProfile: (platform: string, userId: number): Promise<Blob> => {
    const { USER_PORTAL_PROFILE } = endpoints;
    return sendRequest("GET", `${USER_PORTAL_PROFILE}?platform=${platform}&user_id=${userId}`, undefined, "blob");
  },

  requestSupport: (message: string, userId: number): Promise<any> => {
    const { USER_PORTAL_SUPPORT } = endpoints;
    return sendRequest("POST", USER_PORTAL_SUPPORT, { message, user_id: userId });
  },

  // Portal authentication and user management
  getPortalUser: (userId: number): Promise<IPortalUser> => {
    const { PORTAL_USER } = endpoints;
    return sendRequest("GET", `${PORTAL_USER}/${userId}`);
  },

  updatePortalUser: (userId: number, userData: Partial<IPortalUser>): Promise<IPortalUser> => {
    const { PORTAL_USER } = endpoints;
    return sendRequest("PATCH", `${PORTAL_USER}/${userId}`, userData);
  },
};
