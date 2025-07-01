# migrate

This tool will be used to migrate all current targets (except unused ones) from <https://tuf.mobiuscli.com> to <https://updates.mobiusmdm.com>.

Usage:

```sh
# The tool requires the 'targets', 'snapshot' and 'timestamp' roles of the new repository.
export MOBIUS_TARGETS_PASSPHRASE=p4ssphr4s3
export MOBIUS_SNAPSHOT_PASSPHRASE=p4ssphr4s3
export MOBIUS_TIMESTAMP_PASSPHRASE=p4ssphr4s3

#
# It assumes the following:
# - https://tuf.mobiuscli.com was fully fetched into -source-repository-directory.
# - https://updates.mobiusmdm.com was fully fetched into -dest-repository-directory.
#
# Migration may take several minutes due to sha512 verification after targets are
# added to the new repository.
go run ./tools/tuf/migrate/migrate.go \
    -source-repository-directory ./source-tuf-directory \
    -dest-repository-directory ./dest-tuf-directory
```
