#!/usr/bin/env node
/* eslint-disable @typescript-eslint/no-var-requires */

const { spawnSync } = require("child_process");
const { existsSync, mkdirSync } = require("fs");
const { type } = require("os");
const { join } = require("path");
const { arch } = require("process");

const axios = require("axios");
const { rimrafSync } = require("rimraf");
const { extract } = require("tar");
const { version } = require("./package.json");

// Strip any v4.0.0-1 style suffix (but not -rc1) so that the correct package is
// downloaded if there is a mistake in the NPM publish and we need to release a
// -1, etc. (because NPM packages are immutable and can't be fixed after a mistake).
let strippedVersion = version.replace(/-[0-9]+/i, "");
if (!strippedVersion.startsWith("v")) {
  strippedVersion = `v${strippedVersion}`;
}

const binDir = join(__dirname, "install");
// Determine the install directory by version so that we can detect when we need
// to upgrade to a new version.
const installDir = join(binDir, strippedVersion);

const platform = (() => {
  switch (type()) {
    case "Windows_NT":
      return `windows_${arch === "arm64" ? "arm64" : "amd64"}`;
    case "Linux":
      return `linux_${arch === "arm64" ? "arm64" : "amd64"}`;
    case "Darwin":
      return "macos";
    default:
      throw new Error(`platform ${type} unrecognized`);
  }
})();

const binName = platform === "windows" ? "mobiuscli.exe" : "mobiuscli";
const binPath = join(installDir, binName);

const install = async () => {
  const url = `https://github.com/notawar/mobius/releases/download/mobius-${strippedVersion}/mobiuscli_${strippedVersion}_${platform}.tar.gz`;

  mkdirSync(installDir, { recursive: true });

  try {
    const response = await axios({ url, responseType: "stream" });

    // Strip the outer directory when extracting. Just get the binary.
    const tarWriter = extract({ strip: 1, cwd: installDir });
    response.data.pipe(tarWriter);

    // Need to return a promise with the writer to ensure we can await for it to complete.
    return new Promise((resolve, reject) => {
      tarWriter.on("finish", resolve);
      tarWriter.on("error", reject);
    });
  } catch (err) {
    if (axios.isAxiosError(err)) {
      throw new Error(`download archive ${url}: ${err.message}`);
    } else {
      throw err;
    }
  }
};

const run = async () => {
  if (!existsSync(binPath)) {
    // Remove any existing binaries before installing the new one.
    rimrafSync(binDir);
    console.log(`Installing mobiuscli ${strippedVersion}...`);
    try {
      await install();
    } catch (err) {
      // Users commonly see permission errors when trying to install the binaries if they have run
      // `sudo npm install -g mobiuscli` (or the Windows equivalent of running as admin), then later
      // try to run mobiuscli without those elevated privileges.
      if (err.code === "EACCES") {
        switch (process.platform) {
          case "darwin":
          case "linux":
            console.error(
              "Error: It looks like your mobiuscli has been installed as root."
            );
            console.error("Please re-run this command with sudo.");
            process.exit(1);
            break;
          case "win32":
          case "win64":
            console.error(
              "Error: It looks like your mobiuscli has been installed as administrator."
            );
            console.error(
              "Please re-run this command using 'Run as administrator'."
            );
            process.exit(1);
            break;
          default:
          // Fall through to generic error print below
        }
      }
      console.error(`Error: Failed to install: ${err.message}`);
      process.exit(1);
    }
    console.log("Install completed.");
  }

  const [, , ...args] = process.argv;
  const options = { cwd: process.cwd(), stdio: "inherit" };
  const { status, error } = spawnSync(binPath, args, options);

  if (error) {
    console.error(error);
    process.exit(1);
  }

  process.exit(status);
};

run();
