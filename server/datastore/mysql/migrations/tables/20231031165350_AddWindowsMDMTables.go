package tables

import (
	"database/sql"
	"fmt"
)

func init() {
	MigrationClient.AddMigration(Up_20231031165350, Down_20231031165350)
}

func Up_20231031165350(tx *sql.Tx) error {
	_, err := tx.Exec(`
-- This table contains the commands, which may target multiple devices.
CREATE TABLE windows_mdm_commands (
	-- managed and generated by Mobius, and used as CmdID in the MSMDM messages.
	command_uuid     VARCHAR(127) NOT NULL,
	-- the raw XML of the command
	raw_command      MEDIUMTEXT NOT NULL,
	-- the target OMADM URI for the command
	target_loc_uri   VARCHAR(255) NOT NULL,

	created_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	updated_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

	PRIMARY KEY (command_uuid)
) DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;`)
	if err != nil {
		return fmt.Errorf("failed to create windows_mdm_commands table: %w", err)
	}

	_, err = tx.Exec(`
CREATE TABLE windows_mdm_command_queue (
	enrollment_id INT(10) UNSIGNED NOT NULL,
	command_uuid  VARCHAR(127) NOT NULL,

	created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	updated_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

	PRIMARY KEY (enrollment_id, command_uuid),

	FOREIGN KEY (enrollment_id)
		REFERENCES mdm_windows_enrollments (id)
		ON DELETE CASCADE ON UPDATE CASCADE,

	FOREIGN KEY (command_uuid)
		REFERENCES windows_mdm_commands (command_uuid)
		ON DELETE CASCADE ON UPDATE CASCADE
) DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;`)
	if err != nil {
		return fmt.Errorf("failed to create windows_mdm_command_queue table: %w", err)
	}

	_, err = tx.Exec(`
CREATE TABLE windows_mdm_responses (
	id            INT(10) UNSIGNED NOT NULL AUTO_INCREMENT,
	enrollment_id INT(10) UNSIGNED NOT NULL,

	-- the full SyncML, potentially containing results for multiple commands
	raw_response  MEDIUMTEXT NOT NULL,

	created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	updated_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

	PRIMARY KEY (id),

	FOREIGN KEY (enrollment_id)
		REFERENCES mdm_windows_enrollments (id)
		ON DELETE CASCADE ON UPDATE CASCADE
) DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;`)
	if err != nil {
		return fmt.Errorf("failed to create windows_mdm_responses table: %w", err)
	}

	_, err = tx.Exec(`
CREATE TABLE windows_mdm_command_results (
	enrollment_id INT(10) UNSIGNED NOT NULL,
	command_uuid  VARCHAR(127) NOT NULL,

	-- the raw <Results> XML segment for that command, may be empty if the
	-- command had no results to be returned by the device.
	raw_result    MEDIUMTEXT NOT NULL,

	-- FK to the full SyncML response containing this command's result and/or
	-- status.
	response_id   INT(10) UNSIGNED NOT NULL,

	-- this is the status code returned from the MDM device in the
	-- <Status> element corresponding to this command.
	status_code   VARCHAR(31)  NOT NULL,

	created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	updated_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

	PRIMARY KEY (enrollment_id, command_uuid),

	FOREIGN KEY (enrollment_id)
		REFERENCES mdm_windows_enrollments (id)
		ON DELETE CASCADE ON UPDATE CASCADE,

	FOREIGN KEY (command_uuid)
		REFERENCES windows_mdm_commands (command_uuid)
		ON DELETE CASCADE ON UPDATE CASCADE,

	FOREIGN KEY (response_id)
		REFERENCES windows_mdm_responses (id)
		ON DELETE CASCADE ON UPDATE CASCADE
) DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;`)
	if err != nil {
		return fmt.Errorf("failed to create windows_mdm_command_results table: %w", err)
	}

	return nil
}

func Down_20231031165350(tx *sql.Tx) error {
	return nil
}
