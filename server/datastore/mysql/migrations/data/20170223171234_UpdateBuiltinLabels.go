package data

import (
	"database/sql"

	"github.com/notawar/mobius/server/mobius"
)

func init() {
	MigrationClient.AddMigration(Up_20170223171234, Down_20170223171234)
}

func Labels2() []mobius.Label {
	return []mobius.Label{
		{
			Name:        "All Hosts",
			Query:       "select 1;",
			Description: "All hosts which have enrolled in Mobius",
			LabelType:   mobius.LabelTypeBuiltIn,
		},
		{
			Name:        "macOS",
			Query:       "select 1 from os_version where platform = 'darwin';",
			Description: "All macOS hosts",
			LabelType:   mobius.LabelTypeBuiltIn,
		},
		{
			Name:        "Ubuntu Linux",
			Query:       "select 1 from os_version where platform = 'ubuntu';",
			Description: "All Ubuntu hosts",
			LabelType:   mobius.LabelTypeBuiltIn,
		},
		{
			Name:        "CentOS Linux",
			Query:       "select 1 from os_version where platform = 'centos';",
			Description: "All CentOS hosts",
			LabelType:   mobius.LabelTypeBuiltIn,
		},
		{
			Name:        "MS Windows",
			Query:       "select 1 from os_version where platform = 'windows';",
			Description: "All Windows hosts",
			LabelType:   mobius.LabelTypeBuiltIn,
		},
	}
}

func Up_20170223171234(tx *sql.Tx) error {
	// Remove the old labels
	if err := Down_20161229171615(tx); err != nil {
		return err
	}

	// Insert the new labels
	sql := `
		INSERT INTO labels (
			name,
			description,
			query,
			platform,
			label_type
		) VALUES (?, ?, ?, ?, ?)
`

	for _, label := range Labels2() {
		_, err := tx.Exec(sql, label.Name, label.Description, label.Query, label.Platform, label.LabelType)
		if err != nil {
			return err
		}
	}

	return nil
}

func Down_20170223171234(tx *sql.Tx) error {
	// Remove the new labels
	sql := `
		DELETE FROM labels
		WHERE name = ? AND label_type = ? AND QUERY = ?
`

	for _, label := range Labels2() {
		_, err := tx.Exec(sql, label.Name, label.LabelType, label.Query)
		if err != nil {
			return err
		}
	}

	// Insert the old labels
	if err := Up_20161229171615(tx); err != nil {
		return err
	}

	return nil
}
