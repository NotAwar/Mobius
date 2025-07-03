#!/bin/bash

set -e

MOBIUSCTL_INSTALL_DIR="${HOME}/.mobiuscli/"


# Check for necessary commands
for cmd in curl tar grep sed; do
    if ! command -v $cmd &> /dev/null; then
        echo "Error: $cmd is not installed." >&2
        exit 1
    fi
done

echo "Fetching the latest version of mobiuscli..."


# Fetch the latest version number from NPM
latest_strippedVersion=$(curl -s "https://registry.npmjs.org/mobiuscli/latest" | grep -o '"version": *"[^"]*"' | cut -d'"' -f4)
echo "Latest version available on NPM: $latest_strippedVersion"

version_gt() {
  test "$(printf '%s\n' "$@" | sort -V | head -n 1)" != "$1";
}

# Determine operating system (Linux or MacOS)
OS="$(uname -s)"

# Determine architecture (x86_64 or arm64)
ARCH="$(uname -m)"
# Standardize x86_64 to amd64
if [[ $ARCH != "arm64" &&
      $ARCH != "aarch64" &&
      $ARCH != "aarch64_be" &&
      $ARCH != "armv8b" &&
      $ARCH != "armv8l"
    ]];
then
  ARCH="amd64";
fi

# Standardize OS name for file download
case "${OS}" in
    Linux*)     OS="linux_${ARCH}" OS_DISPLAY_NAME='Linux';;
    Darwin*)    OS='macos' OS_DISPLAY_NAME='macOS';;
    *)          echo "Unsupported operating system: ${OS}"; exit 1;;
esac

# Create the install directory if it does not exist.
mkdir -p "${MOBIUSCTL_INSTALL_DIR}"

# Construct download URL
# ex: https://github.com/notawar/mobius/releases/download/mobius-v4.43.3/mobiuscli_v4.43.3_macos.zip
DOWNLOAD_URL="https://github.com/notawar/mobius/releases/download/mobius-v${latest_strippedVersion}/mobiuscli_v${latest_strippedVersion}_${OS}.tar.gz"

# Download the latest version of mobiuscli and extract it.
echo "Downloading mobiuscli ${latest_strippedVersion} for ${OS_DISPLAY_NAME}..."
curl -sSL "$DOWNLOAD_URL" | tar -xz -C "$MOBIUSCTL_INSTALL_DIR" --strip-components=1 mobiuscli_v"${latest_strippedVersion}"_${OS}/
echo "mobiuscli installed successfully in ${MOBIUSCTL_INSTALL_DIR}"
echo
echo "To start the local demo:"
echo
echo "1. Start Docker Desktop"
echo "2. To access your Mobius Premium trial, head to mobiusmdm.com/try-mobius and run the command in step 2."

# Verify if the binary is executable
if [[ ! -x "${MOBIUSCTL_INSTALL_DIR}/mobiuscli" ]]; then
    echo "Failed to install or upgrade mobiuscli. Please check your permissions and try running this script again."
    exit 1
fi
