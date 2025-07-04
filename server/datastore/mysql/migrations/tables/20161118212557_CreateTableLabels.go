package tables

import (
	"database/sql"
	"fmt"

	"github.com/notawar/mobius/server/mobius"
)

func init() {
	MigrationClient.AddMigration(Up_20161118212557, Down_20161118212557)
}

func Up_20161118212557(tx *sql.Tx) error {
	_, err := tx.Exec(
		"CREATE TABLE `labels` (" +
			"`id` int(10) unsigned NOT NULL AUTO_INCREMENT," +
			"`created_at` timestamp DEFAULT CURRENT_TIMESTAMP," +
			"`updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP," +
			"`deleted_at` timestamp NULL DEFAULT NULL," +
			"`deleted` tinyint(1) NOT NULL DEFAULT FALSE," +
			"`name` varchar(255) NOT NULL," +
			"`description` varchar(255) DEFAULT NULL," +
			"`query` varchar(255) NOT NULL," +
			"`platform` varchar(255) DEFAULT NULL," +
			fmt.Sprintf("`label_type` INT UNSIGNED NOT NULL DEFAULT %d,", mobius.LabelTypeBuiltIn) +
			"PRIMARY KEY (`id`)," +
			"UNIQUE KEY `idx_label_unique_name` (`name`)," +
			"FULLTEXT KEY `labels_search` (`name`)" +
			") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;",
	)
	return err
}

func Down_20161118212557(tx *sql.Tx) error {
	_, err := tx.Exec("DROP TABLE IF EXISTS `labels`;")
	return err
}
