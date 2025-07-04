export const APPLE_PLATFORM_DISPLAY_NAMES = {
  darwin: "macOS",
  ios: "iOS",
  ipados: "iPadOS",
} as const;

export type ApplePlatform = keyof typeof APPLE_PLATFORM_DISPLAY_NAMES;
export type AppleDisplayPlatform = typeof APPLE_PLATFORM_DISPLAY_NAMES[keyof typeof APPLE_PLATFORM_DISPLAY_NAMES];

export const PLATFORM_DISPLAY_NAMES = {
  windows: "Windows",
  linux: "Linux",
  chrome: "ChromeOS",
  android: "Android",
  ...APPLE_PLATFORM_DISPLAY_NAMES,
} as const;

export const QUERYABLE_PLATFORMS = [
  "darwin",
  "windows",
  "linux",
  "chrome",
] as const;

export const NON_QUERYABLE_PLATFORMS = ["ios", "ipados", "android"] as const;

export type Platform = keyof typeof PLATFORM_DISPLAY_NAMES;
export type DisplayPlatform = typeof PLATFORM_DISPLAY_NAMES[keyof typeof PLATFORM_DISPLAY_NAMES];
export type QueryableDisplayPlatform = Exclude<
  DisplayPlatform,
  typeof PLATFORM_DISPLAY_NAMES[typeof NON_QUERYABLE_PLATFORMS[number]]
>;

export type QueryablePlatform = typeof QUERYABLE_PLATFORMS[number];

export const isQueryablePlatform = (
  platform: string | undefined
): platform is QueryablePlatform =>
  QUERYABLE_PLATFORMS.includes(platform as QueryablePlatform);

export const SCHEDULED_QUERYABLE_PLATFORMS: ScheduledQueryablePlatform[] = [
  "darwin",
  "windows",
  "linux",
];

export type ScheduledQueryablePlatform = Exclude<QueryablePlatform, "chrome">;

export const isScheduledQueryablePlatform = (
  platform: string | undefined
): platform is ScheduledQueryablePlatform =>
  SCHEDULED_QUERYABLE_PLATFORMS.includes(
    platform as ScheduledQueryablePlatform
  );

// TODO - add "iOS" and "iPadOS" once we support them
export const VULN_SUPPORTED_PLATFORMS: Platform[] = ["darwin", "windows"];

export type SelectedPlatform = QueryablePlatform | "all";

export type CommaSeparatedPlatformString =
  | ""
  | QueryablePlatform
  | `${QueryablePlatform},${QueryablePlatform}`
  | `${QueryablePlatform},${QueryablePlatform},${QueryablePlatform}`
  | `${QueryablePlatform},${QueryablePlatform},${QueryablePlatform},${QueryablePlatform}`;

// TODO: revisit this approach pending resolution of https://github.com/mobiusdm/mobius/issues/3555.
export const MACADMINS_EXTENSION_TABLES: Record<string, QueryablePlatform[]> = {
  file_lines: ["darwin", "linux", "windows"],
  filevault_users: ["darwin"],
  google_chrome_profiles: ["darwin", "linux", "windows"],
  macos_profiles: ["darwin"],
  mdm: ["darwin"],
  munki_info: ["darwin"],
  munki_install: ["darwin"],
  // network_quality: ["darwin"], // TODO: add this table if/when it is incorporated into orbit
  puppet_info: ["darwin", "linux", "windows"],
  puppet_logs: ["darwin", "linux", "windows"],
  puppet_state: ["darwin", "linux", "windows"],
  macadmins_unified_log: ["darwin"],
};

/**
 * Host Linux OSs as defined by the Mobius server.
 *
 * @see https://github.com/mobiusdm/mobius/blob/5a21e2cfb029053ddad0508869eb9f1f23997bf2/server/mobius/hosts.go#L780
 */
export const HOST_LINUX_PLATFORMS = [
  "linux",
  "ubuntu", // covers Kubuntu
  "debian",
  "rhel", // covers Fedora
  "centos",
  "sles",
  "kali",
  "gentoo",
  "amzn",
  "pop",
  "arch",
  "linuxmint",
  "void",
  "nixos",
  "endeavouros",
  "manjaro",
  "opensuse-leap",
  "opensuse-tumbleweed",
  "tuxedo",
  "neon",
] as const;

export const HOST_APPLE_PLATFORMS = ["darwin", "ios", "ipados"] as const;

export type HostPlatform =
  | typeof HOST_LINUX_PLATFORMS[number]
  | typeof HOST_APPLE_PLATFORMS[number]
  | "windows"
  | "chrome"
  | "android";

/**
 * Checks if the provided platform is a Linux-like OS. We can recieve many
 * different types of host platforms so we need a check that will cover all
 * the possible Linux-like platform values.
 */
export const isLinuxLike = (platform: string) => {
  return HOST_LINUX_PLATFORMS.includes(
    platform as typeof HOST_LINUX_PLATFORMS[number]
  );
};

export const isAppleDevice = (platform = "") => {
  return HOST_APPLE_PLATFORMS.includes(
    platform as typeof HOST_APPLE_PLATFORMS[number]
  );
};

export const isIPadOrIPhone = (platform: string | HostPlatform) =>
  ["ios", "ipados"].includes(platform);

export const isAndroid = (
  platform: string | HostPlatform
): platform is "android" => platform === "android";

/** isMobilePlatform checks if the platform is an iPad or iPhone or Android. */
export const isMobilePlatform = (platform: string | HostPlatform) =>
  isIPadOrIPhone(platform) || isAndroid(platform);

export const DISK_ENCRYPTION_SUPPORTED_LINUX_PLATFORMS = [
  "ubuntu", // covers Kubuntu
  "rhel", // *included here to support Fedora systems. Necessary to cross-check with `os_versions` as well to confrim host is Fedora and not another, non-support rhel-like platform.
] as const;

export const isDiskEncryptionSupportedLinuxPlatform = (
  platform: HostPlatform,
  os_version: string
) => {
  const isFedora =
    platform === "rhel" && os_version.toLowerCase().includes("fedora");
  return isFedora || platform === "ubuntu";
};

const DISK_ENCRYPTION_SUPPORTED_PLATFORMS = [
  "darwin",
  "windows",
  "chrome",
  ...DISK_ENCRYPTION_SUPPORTED_LINUX_PLATFORMS,
] as const;

export type DiskEncryptionSupportedPlatform = typeof DISK_ENCRYPTION_SUPPORTED_PLATFORMS[number];

export const platformSupportsDiskEncryption = (
  platform: HostPlatform,
  /** os_version necessary to differentiate Fedora from other rhel-like platforms */
  os_version?: string
) => {
  if (isAndroid(platform)) {
    return false;
  }
  if (platform === "rhel") {
    return !!os_version && os_version.toLowerCase().includes("fedora");
  }
  return DISK_ENCRYPTION_SUPPORTED_PLATFORMS.includes(
    platform as DiskEncryptionSupportedPlatform
  );
};

const OS_SETTINGS_DISPLAY_PLATFORMS = [
  ...DISK_ENCRYPTION_SUPPORTED_PLATFORMS,
  "ios",
  "ipados",
];

export const isOsSettingsDisplayPlatform = (
  platform: HostPlatform,
  os_version: string
) => {
  if (isAndroid(platform)) {
    return false;
  }
  if (platform === "rhel") {
    return !!os_version && os_version.toLowerCase().includes("fedora");
  }
  return OS_SETTINGS_DISPLAY_PLATFORMS.includes(platform);
};
