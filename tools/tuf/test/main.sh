#!/bin/bash

set -ex

export MOBIUS_ROOT_PASSPHRASE=p4ssphr4s3
export MOBIUS_TARGETS_PASSPHRASE=p4ssphr4s3
export MOBIUS_SNAPSHOT_PASSPHRASE=p4ssphr4s3
export MOBIUS_TIMESTAMP_PASSPHRASE=p4ssphr4s3
export NUDGE=1

if [ -z "$TUF_PATH" ]; then
  TUF_PATH=test_tuf
fi
export TUF_PATH

if [ -z "$TUF_PORT" ]; then
  TUF_PORT=8081
fi
export TUF_PORT

if { [ -n "$GENERATE_PKG" ] || [ -n "$GENERATE_DEB" ] || [ -n "$GENERATE_RPM" ] || [ -n "$GENERATE_MSI" ] ; } && [ -z "$ENROLL_SECRET" ]; then
  echo "Error: To generate packages you must set ENROLL_SECRET variable."
  exit 1
fi

if [ -n "$KEY_EXPIRATION_DURATION" ]; then
  export EXTRA_MOBIUSCTL_LDFLAGS="$EXTRA_MOBIUSCTL_LDFLAGS -X github.com/notawar/mobius/v4/mobiuscli.keyExpirationDuration=$KEY_EXPIRATION_DURATION"
fi
if [ -n "$SNAPSHOT_EXPIRATION_DURATION" ]; then
  export EXTRA_MOBIUSCTL_LDFLAGS="$EXTRA_MOBIUSCTL_LDFLAGS -X github.com/notawar/mobius/v4/mobiuscli.snapshotExpirationDuration=$SNAPSHOT_EXPIRATION_DURATION"
fi
if [ -n "$TARGETS_EXPIRATION_DURATION" ]; then
  export EXTRA_MOBIUSCTL_LDFLAGS="$EXTRA_MOBIUSCTL_LDFLAGS -X github.com/notawar/mobius/v4/mobiuscli.targetsExpirationDuration=$TARGETS_EXPIRATION_DURATION"
fi
if [ -n "$TIMESTAMP_EXPIRATION_DURATION" ]; then
  export EXTRA_MOBIUSCTL_LDFLAGS="$EXTRA_MOBIUSCTL_LDFLAGS -X github.com/notawar/mobius/v4/mobiuscli.timestampExpirationDuration=$TIMESTAMP_EXPIRATION_DURATION"
fi

make mobiuscli
./tools/tuf/test/create_repository.sh

ROOT_KEYS=$(./build/mobiuscli updates roots --path "$TUF_PATH")
export ROOT_KEYS

echo "#########"
echo "To generate packages set the following options in 'mobiuscli package':"
echo "--update-roots='$ROOT_KEYS' --update-url=http://localhost:8081"
echo "You can also pass the above flags to 'mobiuscli preview'."
echo "#########"

if [ -z "$SKIP_SERVER" ]; then
    ./tools/tuf/test/run_server.sh
fi

if [ -n "$GENERATE_PKG" ] || [ -n "$GENERATE_DEB" ] || [ -n "$GENERATE_RPM" ] || [ -n "$GENERATE_MSI" ] || [ -n "$GENERATE_DEB_ARM64" ] || [ -n "$GENERATE_RPM_ARM64" ] || [ -n "$GENERATE_MSI_ARM64" ]; then
    bash ./tools/tuf/test/gen_pkgs.sh
fi
