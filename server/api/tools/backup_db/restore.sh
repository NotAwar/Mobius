#!/usr/bin/env bash
set -euo pipefail
BACKUP_NAME="${1:-backup.sql.gz}"
docker run --rm -i --network mobius_default ${MOBIUS_MYSQL_IMAGE:-mysql:8.0.36} bash -c 'gzip -dc - | MYSQL_PWD=toor mysql -hmysql -uroot mobius' < ${BACKUP_NAME}
