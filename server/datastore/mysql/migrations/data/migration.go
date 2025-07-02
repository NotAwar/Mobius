package data

import "github.com/notawar/mobius/server/goose"

var MigrationClient = goose.New("migration_status_data", goose.MySqlDialect{})
