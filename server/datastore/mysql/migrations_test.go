package mysql

import (
	"context"
	"os/exec"
	"testing"

	"github.com/notawar/mobius/server/config"
	"github.com/notawar/mobius/server/datastore/mysql/common_mysql/testing_utils"
	"github.com/notawar/mobius/server/datastore/mysql/migrations/tables"
	"github.com/notawar/mobius/server/mobius"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMigrationStatus(t *testing.T) {
	ds := createMySQLDSForMigrationTests(t, t.Name())
	t.Cleanup(func() {
		ds.Close()
	})

	status, err := ds.MigrationStatus(context.Background())
	require.NoError(t, err)
	assert.EqualValues(t, mobius.NoMigrationsCompleted, status.StatusCode)
	assert.Empty(t, status.MissingTable)
	assert.Empty(t, status.MissingData)

	require.Nil(t, ds.MigrateTables(context.Background()))

	status, err = ds.MigrationStatus(context.Background())
	require.NoError(t, err)
	assert.EqualValues(t, mobius.SomeMigrationsCompleted, status.StatusCode)
	assert.NotEmpty(t, status.MissingData)

	require.Nil(t, ds.MigrateData(context.Background()))

	status, err = ds.MigrationStatus(context.Background())
	require.NoError(t, err)
	assert.EqualValues(t, mobius.AllMigrationsCompleted, status.StatusCode)
	assert.Empty(t, status.MissingTable)
	assert.Empty(t, status.MissingData)

	// Insert unknown migration.
	_, err = ds.writer(context.Background()).Exec(`INSERT INTO ` + tables.MigrationClient.TableName + ` (version_id, is_applied) VALUES (1638994765, 1)`)
	require.NoError(t, err)
	status, err = ds.MigrationStatus(context.Background())
	require.NoError(t, err)
	assert.EqualValues(t, mobius.UnknownMigrations, status.StatusCode)
	_, err = ds.writer(context.Background()).Exec(`DELETE FROM ` + tables.MigrationClient.TableName + ` WHERE version_id = 1638994765`)
	require.NoError(t, err)

	status, err = ds.MigrationStatus(context.Background())
	require.NoError(t, err)
	assert.EqualValues(t, mobius.AllMigrationsCompleted, status.StatusCode)
	assert.Empty(t, status.MissingTable)
	assert.Empty(t, status.MissingData)
}

func TestMigrations(t *testing.T) {
	// Create the database (must use raw MySQL client to do this)
	ds := createMySQLDSForMigrationTests(t, t.Name())
	defer ds.Close()

	require.NoError(t, ds.MigrateTables(context.Background()))

	// Dump schema to dumpfile
	cmd := exec.Command( // nolint:gosec // Waive G204 since this is a test file
		"docker", "compose", "exec", "-T", "mysql_test",
		// Command run inside container
		"mysqldump", "-u"+testing_utils.TestUsername, "-p"+testing_utils.TestPassword, "TestMigrations", "--compact", "--skip-comments",
	)

	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "mysqldump: %s", string(output))
}

func createMySQLDSForMigrationTests(t *testing.T, dbName string) *Datastore {
	// Create a datastore client in order to run migrations as usual
	config := config.MysqlConfig{
		Username: testing_utils.TestUsername,
		Password: testing_utils.TestPassword,
		Address:  testing_utils.TestAddress,
		Database: dbName,
	}
	ds, err := newDSWithConfig(t, dbName, config)
	require.NoError(t, err)
	return ds
}
