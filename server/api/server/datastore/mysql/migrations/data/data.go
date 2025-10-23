// Package data provides database data migrations for Mobius
package data

import (
	"github.com/notawar/mobius/mobius-server/server/goose"
)

// MigrationClient for data migrations
var MigrationClient = goose.New("goose_db_version_data", &goose.MySqlDialect{})
