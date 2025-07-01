const API_VERSION = "latest";

export default {
  // activities
  ACTIVITIES: `/${API_VERSION}/mobius/activities`,
  HOST_PAST_ACTIVITIES: (id: number): string => {
    return `/${API_VERSION}/mobius/hosts/${id}/activities`;
  },
  HOST_UPCOMING_ACTIVITIES: (id: number): string => {
    return `/${API_VERSION}/mobius/hosts/${id}/activities/upcoming`;
  },
  HOST_CANCEL_ACTIVITY: (hostId: number, uuid: string): string => {
    return `/${API_VERSION}/mobius/hosts/${hostId}/activities/upcoming/${uuid}`;
  },

  CHANGE_PASSWORD: `/${API_VERSION}/mobius/change_password`,

  // Conditional access
  CONDITIONAL_ACCESS_MICROSOFT: `/${API_VERSION}/mobius/conditional-access/microsoft`,
  CONDITIONAL_ACCESS_MICROSOFT_CONFIRM: `/${API_VERSION}/mobius/conditional-access/microsoft/confirm`,

  CONFIG: `/${API_VERSION}/mobius/config`,
  CONFIRM_EMAIL_CHANGE: (token: string): string => {
    return `/${API_VERSION}/mobius/email/change/${token}`;
  },

  DOWNLOAD_INSTALLER: `/${API_VERSION}/mobius/download_installer`,
  ENABLE_USER: (id: number): string => {
    return `/${API_VERSION}/mobius/users/${id}/enable`;
  },
  FORGOT_PASSWORD: `/${API_VERSION}/mobius/forgot_password`,
  GLOBAL_ENROLL_SECRETS: `/${API_VERSION}/mobius/spec/enroll_secret`,
  GLOBAL_POLICIES: `/${API_VERSION}/mobius/policies`,
  GLOBAL_SCHEDULE: `/${API_VERSION}/mobius/schedule`,

  // Device endpoints
  DEVICE_USER_DETAILS: `/${API_VERSION}/mobius/device`,
  DEVICE_SOFTWARE: (token: string) =>
    `/${API_VERSION}/mobius/device/${token}/software`,
  DEVICE_SOFTWARE_INSTALL: (token: string, softwareTitleId: number) =>
    `/${API_VERSION}/mobius/device/${token}/software/install/${softwareTitleId}`,
  DEVICE_SOFTWARE_INSTALL_RESULTS: (token: string, uuid: string) =>
    `/${API_VERSION}/mobius/device/${token}/software/install/${uuid}/results`,
  DEVICE_SOFTWARE_UNINSTALL: (token: string, softwareTitleId: number) =>
    `/${API_VERSION}/mobius/device/${token}/software/uninstall/${softwareTitleId}`,
  DEVICE_SOFTWARE_UNINSTALL_RESULTS: (
    token: string,
    scriptExecutionId: string
  ) =>
    `/${API_VERSION}/mobius/device/${token}/software/uninstall/${scriptExecutionId}/results`,
  DEVICE_VPP_COMMAND_RESULTS: (token: string, uuid: string) =>
    `/${API_VERSION}/mobius/device/${token}/software/commands/${uuid}/results`,
  DEVICE_USER_MDM_ENROLLMENT_PROFILE: (token: string): string => {
    return `/${API_VERSION}/mobius/device/${token}/mdm/apple/manual_enrollment_profile`;
  },
  DEVICE_TRIGGER_LINUX_DISK_ENCRYPTION_KEY_ESCROW: (token: string): string => {
    return `/${API_VERSION}/mobius/device/${token}/mdm/linux/trigger_escrow`;
  },
  DEVICE_CERTIFICATES: (token: string): string => {
    return `/${API_VERSION}/mobius/device/${token}/certificates`;
  },

  // Host endpoints
  HOST_SUMMARY: `/${API_VERSION}/mobius/host_summary`,
  HOST_QUERY_REPORT: (hostId: number, queryId: number) =>
    `/${API_VERSION}/mobius/hosts/${hostId}/queries/${queryId}`,
  HOSTS: `/${API_VERSION}/mobius/hosts`,
  HOSTS_COUNT: `/${API_VERSION}/mobius/hosts/count`,
  HOSTS_DELETE: `/${API_VERSION}/mobius/hosts/delete`,
  HOSTS_REPORT: `/${API_VERSION}/mobius/hosts/report`,
  HOSTS_TRANSFER: `/${API_VERSION}/mobius/hosts/transfer`,
  HOSTS_TRANSFER_BY_FILTER: `/${API_VERSION}/mobius/hosts/transfer/filter`,
  HOST_LOCK: (id: number) => `/${API_VERSION}/mobius/hosts/${id}/lock`,
  HOST_UNLOCK: (id: number) => `/${API_VERSION}/mobius/hosts/${id}/unlock`,
  HOST_WIPE: (id: number) => `/${API_VERSION}/mobius/hosts/${id}/wipe`,
  HOST_RESEND_PROFILE: (hostId: number, profileUUID: string) =>
    `/${API_VERSION}/mobius/hosts/${hostId}/configuration_profiles/${profileUUID}/resend`,
  HOST_SOFTWARE: (id: number) => `/${API_VERSION}/mobius/hosts/${id}/software`,
  HOST_SOFTWARE_PACKAGE_INSTALL: (hostId: number, softwareId: number) =>
    `/${API_VERSION}/mobius/hosts/${hostId}/software/${softwareId}/install`,
  HOST_SOFTWARE_PACKAGE_UNINSTALL: (hostId: number, softwareId: number) =>
    `/${API_VERSION}/mobius/hosts/${hostId}/software/${softwareId}/uninstall`,
  HOST_CERTIFICATES: (id: number) =>
    `/${API_VERSION}/mobius/hosts/${id}/certificates`,

  INVITES: `/${API_VERSION}/mobius/invites`,
  INVITE_VERIFY: (token: string) => `/${API_VERSION}/mobius/invites/${token}`,

  // labels
  LABEL: (id: number) => `/${API_VERSION}/mobius/labels/${id}`,
  LABELS: `/${API_VERSION}/mobius/labels`,
  LABELS_SUMMARY: `/${API_VERSION}/mobius/labels/summary`,
  LABEL_HOSTS: (id: number): string => {
    return `/${API_VERSION}/mobius/labels/${id}/hosts`;
  },
  LABEL_SPEC_BY_NAME: (labelName: string) => {
    return `/${API_VERSION}/mobius/spec/labels/${labelName}`;
  },

  LOGIN: `/${API_VERSION}/mobius/login`,
  CREATE_SESSION: `/${API_VERSION}/mobius/sessions`,
  LOGOUT: `/${API_VERSION}/mobius/logout`,
  MACADMINS: `/${API_VERSION}/mobius/macadmins`,

  /**
   * MDM endpoints
   */

  MDM_SUMMARY: `/${API_VERSION}/mobius/hosts/summary/mdm`,

  MDM_ANDROID_ENTERPRISE: `/${API_VERSION}/mobius/android_enterprise`,
  MDM_ANDROID_SIGNUP_URL: `/${API_VERSION}/mobius/android_enterprise/signup_url`,
  MDM_ANDROID_SSE_URL: `/api/${API_VERSION}/mobius/android_enterprise/signup_sse`,

  // apple mdm endpoints
  MDM_APPLE: `/${API_VERSION}/mobius/mdm/apple`,

  // Apple Business Manager (ABM) endpoints
  MDM_ABM_TOKENS: `/${API_VERSION}/mobius/abm_tokens`,
  MDM_ABM_TOKEN: (id: number) => `/${API_VERSION}/mobius/abm_tokens/${id}`,
  MDM_ABM_TOKEN_RENEW: (id: number) =>
    `/${API_VERSION}/mobius/abm_tokens/${id}/renew`,
  MDM_ABM_TOKEN_TEAMS: (id: number) =>
    `/${API_VERSION}/mobius/abm_tokens/${id}/teams`,
  MDM_APPLE_ABM_PUBLIC_KEY: `/${API_VERSION}/mobius/mdm/apple/abm_public_key`,
  MDM_APPLE_APNS_CERTIFICATE: `/${API_VERSION}/mobius/mdm/apple/apns_certificate`,
  MDM_APPLE_PNS: `/${API_VERSION}/mobius/apns`,
  MDM_APPLE_BM: `/${API_VERSION}/mobius/abm`, // TODO: Deprecated?
  MDM_APPLE_BM_KEYS: `/${API_VERSION}/mobius/mdm/apple/dep/key_pair`,
  MDM_APPLE_VPP_APPS: `/${API_VERSION}/mobius/software/app_store_apps`,
  MDM_REQUEST_CSR: `/${API_VERSION}/mobius/mdm/apple/request_csr`,

  // Apple VPP endpoints
  MDM_APPLE_VPP_TOKEN: `/${API_VERSION}/mobius/mdm/apple/vpp_token`, // TODO: Deprecated?
  MDM_VPP_TOKENS: `/${API_VERSION}/mobius/vpp_tokens`,
  MDM_VPP_TOKEN: (id: number) => `/${API_VERSION}/mobius/vpp_tokens/${id}`,
  MDM_VPP_TOKENS_RENEW: (id: number) =>
    `/${API_VERSION}/mobius/vpp_tokens/${id}/renew`,
  MDM_VPP_TOKEN_TEAMS: (id: number) =>
    `/${API_VERSION}/mobius/vpp_tokens/${id}/teams`,

  // MDM profile endpoints
  MDM_PROFILES: `/${API_VERSION}/mobius/mdm/profiles`,
  MDM_PROFILE: (id: string) => `/${API_VERSION}/mobius/mdm/profiles/${id}`,

  MDM_UPDATE_APPLE_SETTINGS: `/${API_VERSION}/mobius/mdm/apple/settings`,
  PROFILES_STATUS_SUMMARY: `/${API_VERSION}/mobius/configuration_profiles/summary`,
  DISK_ENCRYPTION: `/${API_VERSION}/mobius/disk_encryption`,
  MDM_APPLE_SSO: `/${API_VERSION}/mobius/mdm/sso`,
  MDM_APPLE_ENROLLMENT_PROFILE: (
    token: string,
    ref?: string,
    deviceinfo?: string
  ) => {
    const query = new URLSearchParams({ token });
    ref && query.append("enrollment_reference", ref);
    deviceinfo && query.append("deviceinfo", deviceinfo);

    return `/api/mdm/apple/enroll?${query}`;
  },
  MDM_APPLE_SETUP_ENROLLMENT_PROFILE: `/${API_VERSION}/mobius/mdm/apple/enrollment_profile`,
  MDM_BOOTSTRAP_PACKAGE_METADATA: (teamId: number) =>
    `/${API_VERSION}/mobius/mdm/bootstrap/${teamId}/metadata`,
  MDM_BOOTSTRAP_PACKAGE: `/${API_VERSION}/mobius/bootstrap`,
  MDM_BOOTSTRAP_PACKAGE_SUMMARY: `/${API_VERSION}/mobius/mdm/bootstrap/summary`,
  MDM_SETUP: `/${API_VERSION}/mobius/mdm/apple/setup`,
  MDM_EULA: (token: string) => `/${API_VERSION}/mobius/mdm/setup/eula/${token}`,
  MDM_EULA_UPLOAD: `/${API_VERSION}/mobius/mdm/setup/eula`,
  MDM_EULA_METADATA: `/${API_VERSION}/mobius/mdm/setup/eula/metadata`,
  HOST_MDM: (id: number) => `/${API_VERSION}/mobius/hosts/${id}/mdm`,
  HOST_MDM_UNENROLL: (id: number) =>
    `/${API_VERSION}/mobius/mdm/hosts/${id}/unenroll`,
  HOST_ENCRYPTION_KEY: (id: number) =>
    `/${API_VERSION}/mobius/hosts/${id}/encryption_key`,

  ME: `/${API_VERSION}/mobius/me`,

  // Disk encryption endpoints
  UPDATE_DISK_ENCRYPTION: `/${API_VERSION}/mobius/disk_encryption`,

  // Setup experiece endpoints
  MDM_SETUP_EXPERIENCE: `/${API_VERSION}/mobius/setup_experience`,
  MDM_SETUP_EXPERIENCE_SOFTWARE: `/${API_VERSION}/mobius/setup_experience/software`,
  MDM_SETUP_EXPERIENCE_SCRIPT: `/${API_VERSION}/mobius/setup_experience/script`,

  // OS Version endpoints
  OS_VERSIONS: `/${API_VERSION}/mobius/os_versions`,
  OS_VERSION: (id: number) => `/${API_VERSION}/mobius/os_versions/${id}`,

  OSQUERY_OPTIONS: `/${API_VERSION}/mobius/spec/osquery_options`,
  PACKS: `/${API_VERSION}/mobius/packs`,
  PERFORM_REQUIRED_PASSWORD_RESET: `/${API_VERSION}/mobius/perform_required_password_reset`,
  QUERIES: `/${API_VERSION}/mobius/queries`,
  QUERY_REPORT: (id: number) => `/${API_VERSION}/mobius/queries/${id}/report`,
  RESET_PASSWORD: `/${API_VERSION}/mobius/reset_password`,
  LIVE_QUERY: `/${API_VERSION}/mobius/queries/run`,
  SCHEDULE_QUERY: `/${API_VERSION}/mobius/packs/schedule`,
  SCHEDULED_QUERIES: (packId: number): string => {
    return `/${API_VERSION}/mobius/packs/${packId}/scheduled`;
  },
  SETUP: `/v1/setup`, // not a typo - hasn't been updated yet

  // Software endpoints
  SOFTWARE: `/${API_VERSION}/mobius/software`,
  SOFTWARE_TITLES: `/${API_VERSION}/mobius/software/titles`,
  SOFTWARE_TITLE: (id: number) => `/${API_VERSION}/mobius/software/titles/${id}`,
  EDIT_SOFTWARE_PACKAGE: (id: number) =>
    `/${API_VERSION}/mobius/software/titles/${id}/package`,
  EDIT_SOFTWARE_VPP: (id: number) =>
    `/${API_VERSION}/mobius/software/titles/${id}/app_store_app`,
  SOFTWARE_VERSIONS: `/${API_VERSION}/mobius/software/versions`,
  SOFTWARE_VERSION: (id: number) =>
    `/${API_VERSION}/mobius/software/versions/${id}`,
  SOFTWARE_PACKAGE_ADD: `/${API_VERSION}/mobius/software/package`,
  SOFTWARE_PACKAGE_TOKEN: (id: number) =>
    `/${API_VERSION}/mobius/software/titles/${id}/package/token`,
  SOFTWARE_INSTALL_RESULTS: (uuid: string) =>
    `/${API_VERSION}/mobius/software/install/${uuid}/results`,
  SOFTWARE_PACKAGE_INSTALL: (id: number) =>
    `/${API_VERSION}/mobius/software/packages/${id}`,
  SOFTWARE_AVAILABLE_FOR_INSTALL: (id: number) =>
    `/${API_VERSION}/mobius/software/titles/${id}/available_for_install`,
  SOFTWARE_MOBIUS_MAINTAINED_APPS: `/${API_VERSION}/mobius/software/mobius_maintained_apps`,
  SOFTWARE_MOBIUS_MAINTAINED_APP: (id: number) =>
    `/${API_VERSION}/mobius/software/mobius_maintained_apps/${id}`,

  // AI endpoints
  AUTOFILL_POLICY: `/${API_VERSION}/mobius/autofill/policy`,

  SSO: `/v1/mobius/sso`,
  STATUS_LABEL_COUNTS: `/${API_VERSION}/mobius/host_summary`,
  STATUS_LIVE_QUERY: `/${API_VERSION}/mobius/status/live_query`,
  STATUS_RESULT_STORE: `/${API_VERSION}/mobius/status/result_store`,
  TARGETS: `/${API_VERSION}/mobius/targets`,
  TEAM_POLICIES: (teamId: number): string => {
    return `/${API_VERSION}/mobius/teams/${teamId}/policies`;
  },
  TEAM_SCHEDULE: (teamId: number): string => {
    return `/${API_VERSION}/mobius/teams/${teamId}/schedule`;
  },
  TEAMS: `/${API_VERSION}/mobius/teams`,
  TEAMS_AGENT_OPTIONS: (teamId: number): string => {
    return `/${API_VERSION}/mobius/teams/${teamId}/agent_options`;
  },
  TEAMS_ENROLL_SECRETS: (teamId: number): string => {
    return `/${API_VERSION}/mobius/teams/${teamId}/secrets`;
  },
  TEAM_USERS: (teamId: number): string => {
    return `/${API_VERSION}/mobius/teams/${teamId}/users`;
  },
  TEAMS_TRANSFER_HOSTS: (teamId: number): string => {
    return `/${API_VERSION}/mobius/teams/${teamId}/hosts`;
  },
  UPDATE_USER_ADMIN: (id: number): string => {
    return `/${API_VERSION}/mobius/users/${id}/admin`;
  },
  USER_SESSIONS: (id: number): string => {
    return `/${API_VERSION}/mobius/users/${id}/sessions`;
  },
  USERS: `/${API_VERSION}/mobius/users`,
  USERS_ADMIN: `/${API_VERSION}/mobius/users/admin`,
  VERSION: `/${API_VERSION}/mobius/version`,

  // Vulnerabilities endpoints
  VULNERABILITIES: `/${API_VERSION}/mobius/vulnerabilities`,
  VULNERABILITY: (cve: string) =>
    `/${API_VERSION}/mobius/vulnerabilities/${cve}`,

  // Script endpoints
  HOST_SCRIPTS: (id: number) => `/${API_VERSION}/mobius/hosts/${id}/scripts`,
  SCRIPTS: `/${API_VERSION}/mobius/scripts`,
  SCRIPT: (id: number) => `/${API_VERSION}/mobius/scripts/${id}`,
  SCRIPT_RESULT: (executionId: string) =>
    `/${API_VERSION}/mobius/scripts/results/${executionId}`,
  SCRIPT_RUN: `/${API_VERSION}/mobius/scripts/run`,
  SCRIPT_RUN_BATCH: `/${API_VERSION}/mobius/scripts/run/batch`,
  SCRIPT_RUN_BATCH_SUMMARY: (id: string) =>
    `/${API_VERSION}/mobius/scripts/batch/summary/${id}`,
  COMMANDS_RESULTS: `/${API_VERSION}/mobius/commands/results`,

  // idp endpoints
  SCIM_DETAILS: `/${API_VERSION}/mobius/scim/details`,

  // Portal endpoints
  INTERNAL_PORTAL_STATS: `/${API_VERSION}/mobius/internal-portal/stats`,
  INTERNAL_PORTAL_LOGS: `/${API_VERSION}/mobius/internal-portal/logs`,
  USER_PORTAL_DEVICES: `/${API_VERSION}/mobius/user-portal/devices`,
  USER_PORTAL_ENROLLMENT: `/${API_VERSION}/mobius/user-portal/enrollment`,
  USER_PORTAL_PROFILE: `/${API_VERSION}/mobius/user-portal/profile`,
  USER_PORTAL_SUPPORT: `/${API_VERSION}/mobius/user-portal/support`,
  PORTAL_USER: `/${API_VERSION}/mobius/portal/user`,

  // configuration profile endpoints
  CONFIG_PROFILE: (uuid: string) =>
    `/${API_VERSION}/mobius/configuration_profiles/${uuid}`,
  CONFIG_PROFILE_STATUS: (uuid: string) =>
    `/${API_VERSION}/mobius/configuration_profiles/${uuid}/status`,
  CONFIG_PROFILE_BATCH_RESEND: `/${API_VERSION}/mobius/configuration_profiles/resend/batch`,
};
