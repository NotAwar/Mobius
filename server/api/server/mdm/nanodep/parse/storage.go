package parse

import (
	"fmt"

	_ "github.com/go-sql-driver/mysql"
	"github.com/notawar/mobius/mobius-server/server/mdm/nanodep/storage"
	"github.com/notawar/mobius/mobius-server/server/mdm/nanodep/storage/file"
	"github.com/notawar/mobius/mobius-server/server/mdm/nanodep/storage/mysql"
)

// Storage parses a storage name and dsn to determine which and return a storage backend.
func Storage(storageName, dsn string) (storage.AllDEPStorage, error) {
	var store storage.AllDEPStorage
	var err error
	switch storageName {
	case "file":
		if dsn == "" {
			dsn = "db"
		}
		store, err = file.New(dsn)
	case "mysql":
		store, err = mysql.New(mysql.WithDSN(dsn))
	default:
		return nil, fmt.Errorf("unknown storage: %q", storageName)
	}
	return store, err
}
