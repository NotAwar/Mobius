const mobiusMaintainedPackageTypes = ["dmg", "zip"] as const;
const unixPackageTypes = ["pkg", "deb", "rpm", "dmg", "zip", "tar.gz"] as const;
const windowsPackageTypes = ["msi", "exe"] as const;
export const packageTypes = [
  ...unixPackageTypes,
  ...windowsPackageTypes,
] as const;

export type WindowsPackageType = typeof windowsPackageTypes[number];
export type UnixPackageType = typeof unixPackageTypes[number];
export type MobiusMaintainedPackageType = typeof mobiusMaintainedPackageTypes[number];
export type PackageType =
  | WindowsPackageType
  | UnixPackageType
  | MobiusMaintainedPackageType;

export const isWindowsPackageType = (s: any): s is WindowsPackageType => {
  return windowsPackageTypes.includes(s);
};

export const isUnixPackageType = (s: any): s is UnixPackageType => {
  return unixPackageTypes.includes(s);
};

export const isMobiusMaintainedPackageType = (
  s: any
): s is MobiusMaintainedPackageType => {
  return mobiusMaintainedPackageTypes.includes(s);
};

export const isPackageType = (s: any): s is PackageType => {
  return packageTypes.includes(s);
};
