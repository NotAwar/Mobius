#!/bin/bash

set -ex

# This script generates mobius-osquery packages for all supported platforms
# using the specified TUF server.

# Input:
# Values for generating a package for a macOS host:
# PKG_MOBIUS_URL: Mobius server URL.
# PKG_TUF_URL: URL of the TUF server.
#
# Values for generating a package for an Ubuntu host:
# DEB_MOBIUS_URL: Mobius server URL.
# DEB_TUF_URL: URL of the TUF server.
#
# Values for generating a package for a CentOS host:
# RPM_MOBIUS_URL: Mobius server URL.
# RPM_TUF_URL: URL of the TUF server.
#
# Values for generating a package for a Windows host:
# MSI_MOBIUS_URL: Mobius server URL.
# MSI_TUF_URL: URL of the TUF server.
#
# ENROLL_SECRET: Mobius server enroll secret.
# ROOT_KEYS: TUF repository root keys.
# MOBIUS_DESKTOP: Whether to build with Mobius Desktop support.
# INSECURE: Whether to use the --insecure flag.
# USE_MOBIUS_SERVER_CERTIFICATE: Whether to use a custom certificate bundle.
# USE_UPDATE_SERVER_CERTIFICATE: Whether to use a custom certificate bundle.
# MOBIUS_DESKTOP_ALTERNATIVE_BROWSER_HOST: Alternative host:port to use for the Mobius Desktop browser URLs.
# DEBUG: Whether or not to build the package with --debug.

ENABLE_SCRIPTS="1"
if [[ -n $DISABLE_SCRIPTS ]]; then
    ENABLE_SCRIPTS=""
fi

if [ -n "$GENERATE_PKG" ]; then
    echo "Generating pkg..."
    ./build/mobiuscli package \
        --type=pkg \
        ${MOBIUS_DESKTOP:+--mobius-desktop} \
        --mobius-url=$PKG_MOBIUS_URL \
        --enroll-secret=$ENROLL_SECRET \
        ${USE_MOBIUS_SERVER_CERTIFICATE:+--mobius-certificate=./tools/osquery/mobius.crt} \
        ${USE_UPDATE_SERVER_CERTIFICATE:+--update-tls-certificate=./tools/osquery/mobius.crt} \
        ${INSECURE:+--insecure} \
        ${DEBUG:+--debug} \
        --update-roots="$ROOT_KEYS" \
        --update-interval=10s \
        --disable-open-folder \
        ${USE_MOBIUS_CLIENT_CERTIFICATE:+--mobius-tls-client-certificate=./tools/test-orbit-mtls/client.crt} \
        ${USE_MOBIUS_CLIENT_CERTIFICATE:+--mobius-tls-client-key=./tools/test-orbit-mtls/client.key} \
        ${USE_UPDATE_CLIENT_CERTIFICATE:+--update-tls-client-certificate=./tools/test-orbit-mtls/client.crt} \
        ${USE_UPDATE_CLIENT_CERTIFICATE:+--update-tls-client-key=./tools/test-orbit-mtls/client.key} \
        ${MOBIUS_DESKTOP_ALTERNATIVE_BROWSER_HOST:+--mobius-desktop-alternative-browser-host=$MOBIUS_DESKTOP_ALTERNATIVE_BROWSER_HOST} \
        --update-url=$PKG_TUF_URL \
        ${ENABLE_SCRIPTS:+--enable-scripts} \
        --disable-keystore
fi

if [ -n "$GENERATE_DEB" ]; then
    echo "Generating deb (amd64)..."
    ./build/mobiuscli package \
        --type=deb \
        --arch=amd64 \
        ${MOBIUS_DESKTOP:+--mobius-desktop} \
        --mobius-url=$DEB_MOBIUS_URL \
        --enroll-secret=$ENROLL_SECRET \
        ${USE_MOBIUS_SERVER_CERTIFICATE:+--mobius-certificate=./tools/osquery/mobius.crt} \
        ${USE_UPDATE_SERVER_CERTIFICATE:+--update-tls-certificate=./tools/osquery/mobius.crt} \
        ${INSECURE:+--insecure} \
        ${DEBUG:+--debug} \
        --update-roots="$ROOT_KEYS" \
        --update-interval=10s \
        --disable-open-folder \
        ${USE_MOBIUS_CLIENT_CERTIFICATE:+--mobius-tls-client-certificate=./tools/test-orbit-mtls/client.crt} \
        ${USE_MOBIUS_CLIENT_CERTIFICATE:+--mobius-tls-client-key=./tools/test-orbit-mtls/client.key} \
        ${USE_UPDATE_CLIENT_CERTIFICATE:+--update-tls-client-certificate=./tools/test-orbit-mtls/client.crt} \
        ${USE_UPDATE_CLIENT_CERTIFICATE:+--update-tls-client-key=./tools/test-orbit-mtls/client.key} \
        ${MOBIUS_DESKTOP_ALTERNATIVE_BROWSER_HOST:+--mobius-desktop-alternative-browser-host=$MOBIUS_DESKTOP_ALTERNATIVE_BROWSER_HOST} \
        ${ENABLE_SCRIPTS:+--enable-scripts} \
        --update-url=$DEB_TUF_URL
fi

if [ -n "$GENERATE_DEB_ARM64" ]; then
    echo "Generating deb (arm64)..."
    ./build/mobiuscli package \
        --type=deb \
        --arch=arm64 \
        ${MOBIUS_DESKTOP:+--mobius-desktop} \
        --mobius-url=$DEB_MOBIUS_URL \
        --enroll-secret=$ENROLL_SECRET \
        ${USE_MOBIUS_SERVER_CERTIFICATE:+--mobius-certificate=./tools/osquery/mobius.crt} \
        ${USE_UPDATE_SERVER_CERTIFICATE:+--update-tls-certificate=./tools/osquery/mobius.crt} \
        ${INSECURE:+--insecure} \
        ${DEBUG:+--debug} \
        --update-roots="$ROOT_KEYS" \
        --update-interval=10s \
        --disable-open-folder \
        ${USE_MOBIUS_CLIENT_CERTIFICATE:+--mobius-tls-client-certificate=./tools/test-orbit-mtls/client.crt} \
        ${USE_MOBIUS_CLIENT_CERTIFICATE:+--mobius-tls-client-key=./tools/test-orbit-mtls/client.key} \
        ${USE_UPDATE_CLIENT_CERTIFICATE:+--update-tls-client-certificate=./tools/test-orbit-mtls/client.crt} \
        ${USE_UPDATE_CLIENT_CERTIFICATE:+--update-tls-client-key=./tools/test-orbit-mtls/client.key} \
        ${MOBIUS_DESKTOP_ALTERNATIVE_BROWSER_HOST:+--mobius-desktop-alternative-browser-host=$MOBIUS_DESKTOP_ALTERNATIVE_BROWSER_HOST} \
        ${ENABLE_SCRIPTS:+--enable-scripts} \
        --update-url=$DEB_TUF_URL
fi

if [ -n "$GENERATE_RPM" ]; then
    echo "Generating rpm (amd64)..."
    ./build/mobiuscli package \
        --type=rpm \
        --arch=amd64 \
        ${MOBIUS_DESKTOP:+--mobius-desktop} \
        --mobius-url=$RPM_MOBIUS_URL \
        --enroll-secret=$ENROLL_SECRET \
        ${USE_MOBIUS_SERVER_CERTIFICATE:+--mobius-certificate=./tools/osquery/mobius.crt} \
        ${USE_UPDATE_SERVER_CERTIFICATE:+--update-tls-certificate=./tools/osquery/mobius.crt} \
        ${INSECURE:+--insecure} \
        ${DEBUG:+--debug} \
        --update-roots="$ROOT_KEYS" \
        --update-interval=10s \
        --disable-open-folder \
        ${USE_MOBIUS_CLIENT_CERTIFICATE:+--mobius-tls-client-certificate=./tools/test-orbit-mtls/client.crt} \
        ${USE_MOBIUS_CLIENT_CERTIFICATE:+--mobius-tls-client-key=./tools/test-orbit-mtls/client.key} \
        ${USE_UPDATE_CLIENT_CERTIFICATE:+--update-tls-client-certificate=./tools/test-orbit-mtls/client.crt} \
        ${USE_UPDATE_CLIENT_CERTIFICATE:+--update-tls-client-key=./tools/test-orbit-mtls/client.key} \
        ${MOBIUS_DESKTOP_ALTERNATIVE_BROWSER_HOST:+--mobius-desktop-alternative-browser-host=$MOBIUS_DESKTOP_ALTERNATIVE_BROWSER_HOST} \
        ${ENABLE_SCRIPTS:+--enable-scripts} \
        --update-url=$RPM_TUF_URL
fi

if [ -n "$GENERATE_RPM_ARM64" ]; then
    echo "Generating rpm (arm64)..."
    ./build/mobiuscli package \
        --type=rpm \
        --arch=arm64 \
        ${MOBIUS_DESKTOP:+--mobius-desktop} \
        --mobius-url=$RPM_MOBIUS_URL \
        --enroll-secret=$ENROLL_SECRET \
        ${USE_MOBIUS_SERVER_CERTIFICATE:+--mobius-certificate=./tools/osquery/mobius.crt} \
        ${USE_UPDATE_SERVER_CERTIFICATE:+--update-tls-certificate=./tools/osquery/mobius.crt} \
        ${INSECURE:+--insecure} \
        ${DEBUG:+--debug} \
        --update-roots="$ROOT_KEYS" \
        --update-interval=10s \
        --disable-open-folder \
        ${USE_MOBIUS_CLIENT_CERTIFICATE:+--mobius-tls-client-certificate=./tools/test-orbit-mtls/client.crt} \
        ${USE_MOBIUS_CLIENT_CERTIFICATE:+--mobius-tls-client-key=./tools/test-orbit-mtls/client.key} \
        ${USE_UPDATE_CLIENT_CERTIFICATE:+--update-tls-client-certificate=./tools/test-orbit-mtls/client.crt} \
        ${USE_UPDATE_CLIENT_CERTIFICATE:+--update-tls-client-key=./tools/test-orbit-mtls/client.key} \
        ${MOBIUS_DESKTOP_ALTERNATIVE_BROWSER_HOST:+--mobius-desktop-alternative-browser-host=$MOBIUS_DESKTOP_ALTERNATIVE_BROWSER_HOST} \
        ${ENABLE_SCRIPTS:+--enable-scripts} \
        --update-url=$RPM_TUF_URL
fi

if [ -n "$GENERATE_MSI" ]; then
    echo "Generating msi..."
    ./build/mobiuscli package \
        --type=msi \
        ${MOBIUS_DESKTOP:+--mobius-desktop} \
        --mobius-url=$MSI_MOBIUS_URL \
        --enroll-secret=$ENROLL_SECRET \
        ${USE_MOBIUS_SERVER_CERTIFICATE:+--mobius-certificate=./tools/osquery/mobius.crt} \
        ${USE_UPDATE_SERVER_CERTIFICATE:+--update-tls-certificate=./tools/osquery/mobius.crt} \
        ${INSECURE:+--insecure} \
        ${DEBUG:+--debug} \
        --update-roots="$ROOT_KEYS" \
        --update-interval=10s \
        --disable-open-folder \
        ${USE_MOBIUS_CLIENT_CERTIFICATE:+--mobius-tls-client-certificate=./tools/test-orbit-mtls/client.crt} \
        ${USE_MOBIUS_CLIENT_CERTIFICATE:+--mobius-tls-client-key=./tools/test-orbit-mtls/client.key} \
        ${USE_UPDATE_CLIENT_CERTIFICATE:+--update-tls-client-certificate=./tools/test-orbit-mtls/client.crt} \
        ${USE_UPDATE_CLIENT_CERTIFICATE:+--update-tls-client-key=./tools/test-orbit-mtls/client.key} \
        ${MOBIUS_DESKTOP_ALTERNATIVE_BROWSER_HOST:+--mobius-desktop-alternative-browser-host=$MOBIUS_DESKTOP_ALTERNATIVE_BROWSER_HOST} \
        ${ENABLE_SCRIPTS:+--enable-scripts} \
        --update-url=$MSI_TUF_URL
fi

if [ -n "$GENERATE_MSI_ARM64" ]; then
    echo "Generating msi (arm64)..."
    ./build/mobiuscli package \
        --type=msi \
        --arch=arm64 \
        ${MOBIUS_DESKTOP:+--mobius-desktop} \
        --mobius-url=$MSI_MOBIUS_URL \
        --enroll-secret=$ENROLL_SECRET \
        ${USE_MOBIUS_SERVER_CERTIFICATE:+--mobius-certificate=./tools/osquery/mobius.crt} \
        ${USE_UPDATE_SERVER_CERTIFICATE:+--update-tls-certificate=./tools/osquery/mobius.crt} \
        ${INSECURE:+--insecure} \
        ${DEBUG:+--debug} \
        --update-roots="$ROOT_KEYS" \
        --update-interval=10s \
        --disable-open-folder \
        ${USE_MOBIUS_CLIENT_CERTIFICATE:+--mobius-tls-client-certificate=./tools/test-orbit-mtls/client.crt} \
        ${USE_MOBIUS_CLIENT_CERTIFICATE:+--mobius-tls-client-key=./tools/test-orbit-mtls/client.key} \
        ${USE_UPDATE_CLIENT_CERTIFICATE:+--update-tls-client-certificate=./tools/test-orbit-mtls/client.crt} \
        ${USE_UPDATE_CLIENT_CERTIFICATE:+--update-tls-client-key=./tools/test-orbit-mtls/client.key} \
        ${MOBIUS_DESKTOP_ALTERNATIVE_BROWSER_HOST:+--mobius-desktop-alternative-browser-host=$MOBIUS_DESKTOP_ALTERNATIVE_BROWSER_HOST} \
        ${ENABLE_SCRIPTS:+--enable-scripts} \
        --update-url=$MSI_TUF_URL
fi

echo "Packages generated."

if [[ $OSTYPE == 'darwin'* && -n "$INSTALL_PKG" ]]; then
    sudo installer -pkg mobius-osquery.pkg -target /
fi
