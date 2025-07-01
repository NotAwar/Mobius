#!/bin/bash

set -x
set -e

# Up to `mobius-v4.40.0` there are no migration issues with Percona Server XtraDB's `pxc_strict_mode=ENFORCING` default value.
# We introduced issues with `pxc_strict_mode=ENFORCING` in DB migrations in `mobius-v4.41.0` and in `mobius-v4.42.0`.

# Bring everything down.
docker compose down
docker volume rm mobius_mysql-persistent-volume

# Start dependencies using Percona XtraDB as MySQL server.
# NOTE: To troubleshoot, remove `>/dev/null`.
MOBIUS_MYSQL_IMAGE=percona/percona-xtradb-cluster:8.0.36 docker compose up >/dev/null 2>&1 &

export MYSQL_PWD=toor

until mysql --host 127.0.0.1 --port 3306 -uroot -e 'SELECT 1=1;' ; do
    echo "Waiting for Percona XtraDB MySQL Server..."
    sleep 10
done
echo "Percona XtraDB MySQL Server is up and running, continuing..."

# Checkout and build `mobius-4.42.0`.
git checkout mobius-v4.42.0
make generate && make mobius

# Set pxc_strict_mode=PERMISSIVE to run migrations up to mobius-v4.42.0,
# which was the last migration released with `pxc_strict_mode=ENFORCING` issues.
mysql --host 127.0.0.1 --port 3306 -uroot -e 'SET GLOBAL pxc_strict_mode=PERMISSIVE;'

# Run migrations up to mobius-v4.42.0.
make db-reset

# Set `pxc_strict_mode` back to the `ENFORCING` default.
mysql --host 127.0.0.1 --port 3306 -uroot -e 'SET GLOBAL pxc_strict_mode=ENFORCING;'

# Run migrations from mobius-v4.42.0 up to latest to catch any future bugs when running with `pxc_strict_mode=ENFORCING`.
git checkout main
make generate && make mobius
./build/mobius prepare db --dev --logging_debug
