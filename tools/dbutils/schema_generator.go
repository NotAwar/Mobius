package main

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/WatchBeam/clock"
	"github.com/notawar/mobius/server/config"
	"github.com/notawar/mobius/server/datastore/mysql"
	"github.com/notawar/mobius/server/mdm/android"
	"github.com/go-kit/log"
)

const (
	testUsername = "root"
	testPassword = "toor"
	testAddress  = "localhost:3307"
)

func panicif(err error) {
	if err != nil {
		panic(err)
	}
}

// main requires 2 arguments:
// 1. Path to dumpfile
// 2. Path to Android dumpfile
func main() {
	if len(os.Args) != 3 {
		panic("not enough arguments")
	}
	fmt.Println("dumping schema to", os.Args[1])
	fmt.Println("dumping Android schema to", os.Args[2])

	// Create the database (must use raw MySQL client to do this)
	db, err := sql.Open(
		"mysql",
		fmt.Sprintf("%s:%s@tcp(%s)/?multiStatements=true", testUsername, testPassword, testAddress),
	)
	panicif(err)
	defer db.Close()
	_, err = db.Exec("DROP DATABASE IF EXISTS schemadb; CREATE DATABASE schemadb;")
	panicif(err)

	// Create a datastore client in order to run migrations as usual
	config := config.MysqlConfig{
		Username: testUsername,
		Password: testPassword,
		Address:  testAddress,
		Database: "schemadb",
	}
	ds, err := mysql.New(config, clock.NewMockClock(), mysql.Logger(log.NewNopLogger()), mysql.LimitAttempts(1))
	panicif(err)
	defer ds.Close()
	panicif(ds.MigrateTables(context.Background()))

	// Set created_at/updated_at for migrations and app_config_json to prevent the schema from being changed every time
	// This schema is to test anyway
	fixedDate := time.Date(2020, 01, 01, 01, 01, 01, 01, time.UTC)
	_, err = db.Exec(`USE schemadb`)
	panicif(err)
	_, err = db.Exec(`UPDATE app_config_json SET created_at = ?, updated_at = ?`, fixedDate, fixedDate)
	panicif(err)
	_, err = db.Exec(`UPDATE migration_status_tables SET tstamp = ?`, fixedDate)
	panicif(err)

	// Dump schema to dumpfile
	cmd := exec.Command(
		"docker", "compose", "exec", "-T", "mysql_test",
		// Command run inside container
		"mysqldump", "-u"+testUsername, "-p"+testPassword, "schemadb", "--compact", "--skip-comments",
	)
	var stdoutBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	panicif(cmd.Run())

	panicif(os.WriteFile(os.Args[1], stdoutBuf.Bytes(), 0o655))

	// Dump Android schema
	args := []string{"compose", "exec", "-T", "mysql_test"}
	// Command to run inside container:
	args = append(args, "mysqldump", "-u"+testUsername, "-p"+testPassword, "schemadb")
	args = append(args, android.MySQLTables()...)
	args = append(args, "--compact", "--skip-comments")
	cmd = exec.Command("docker", args...)
	stdoutBuf = bytes.Buffer{}
	cmd.Stdout = &stdoutBuf
	panicif(cmd.Run())
	panicif(os.WriteFile(os.Args[2], stdoutBuf.Bytes(), 0o655))
}
