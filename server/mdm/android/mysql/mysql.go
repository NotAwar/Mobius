// Package mysql is a MySQL implementation of the android.Datastore interface.
package mysql

import (
	"context"

	"github.com/notawar/mobius/server/contexts/ctxdb"
	"github.com/notawar/mobius/server/datastore/mysql/common_mysql"
	"github.com/notawar/mobius/server/mobius"
	"github.com/notawar/mobius/server/mdm/android"
	"github.com/go-kit/log"
	"github.com/jmoiron/sqlx"
)

// Datastore is an implementation of android.Datastore interface backed by MySQL
type Datastore struct {
	logger  log.Logger
	primary *sqlx.DB
	replica mobius.DBReader // so it cannot be used to perform writes
}

// New creates a new Datastore
func New(logger log.Logger, primary *sqlx.DB, replica mobius.DBReader) android.Datastore {
	return &Datastore{
		logger:  logger,
		primary: primary,
		replica: replica,
	}
}

// reader returns the DB instance to use for read-only statements, which is the
// replica unless the primary has been explicitly required via
// ctxdb.RequirePrimary.
func (ds *Datastore) reader(ctx context.Context) mobius.DBReader {
	if ctxdb.IsPrimaryRequired(ctx) {
		return ds.primary
	}
	return ds.replica
}

// Writer returns the DB instance to use for write statements, which is always
// the primary.
func (ds *Datastore) Writer(_ context.Context) *sqlx.DB {
	return ds.primary
}

func (ds *Datastore) WithRetryTxx(ctx context.Context, fn common_mysql.TxFn) (err error) {
	return common_mysql.WithRetryTxx(ctx, ds.Writer(ctx), fn, ds.logger)
}
