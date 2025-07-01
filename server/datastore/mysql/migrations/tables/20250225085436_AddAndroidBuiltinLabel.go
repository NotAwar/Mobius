package tables

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/VividCortex/mysqlerr"
	"github.com/notawar/mobius/v4/server/mobius"
	"github.com/go-sql-driver/mysql"
)

func init() {
	MigrationClient.AddMigration(Up_20250225085436, Down_20250225085436)
}

func Up_20250225085436(tx *sql.Tx) error {
	const stmt = `
		INSERT INTO labels (
			name,
			description,
			query,
			platform,
			label_type,
			label_membership_type,
			created_at,
			updated_at
		) VALUES (?, ?, '', ?, ?, ?, ?, ?)
`

	// hard-coded timestamps are used so that schema.sql is stable
	ts := time.Date(2025, 2, 25, 0, 0, 0, 0, time.UTC)
	_, err := tx.Exec(
		stmt,
		mobius.BuiltinLabelNameAndroid,
		"All Android hosts",
		"android",
		mobius.LabelTypeBuiltIn,
		mobius.LabelMembershipTypeManual,
		ts,
		ts,
	)
	if err != nil {
		if driverErr, ok := err.(*mysql.MySQLError); ok {
			if driverErr.Number == mysqlerr.ER_DUP_ENTRY {
				return fmt.Errorf("a label with the name %q already exists, please rename it before applying this migration: %w", mobius.BuiltinLabelNameAndroid, err)
			}
		}
		return err
	}
	return nil
}

func Down_20250225085436(tx *sql.Tx) error {
	return nil
}
