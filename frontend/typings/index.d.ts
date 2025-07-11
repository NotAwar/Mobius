/**
 * A file that contains the custom typings for mobiuss own modules and libraries
 */

// PNG assests
declare module "*.png" {
  const value: string;
  export = value;
}
declare module "*.svg" {
  const value: string;
  export = value;
}

declare module "*.gif" {
  const value: string;
  export = value;
}

declare module "*.pdf" {
  const value: string;
  export = value;
}

declare module "*.mp4" {
  const value: string;
  export = value;
}

declare const featureFlags: {
  [key: string]: type;
};
