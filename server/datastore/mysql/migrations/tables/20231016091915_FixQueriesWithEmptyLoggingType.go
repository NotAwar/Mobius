package tables

import (
	"database/sql"
	"fmt"

	"github.com/notawar/mobius/server/mobius"
)

func init() {
	MigrationClient.AddMigration(Up_20231016091915, Down_20231016091915)
}

func Up_20231016091915(tx *sql.Tx) error {
	_, err := tx.Exec(`
		UPDATE queries SET logging_type = ? WHERE logging_type = '';
    `, mobius.LoggingSnapshot)
	if err != nil {
		return fmt.Errorf("failed to update queries logging_type: %w", err)
	}

	return nil
}

func Down_20231016091915(tx *sql.Tx) error {
	return nil
}
