package mysql

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"text/tabwriter"
	"time"

	"github.com/WatchBeam/clock"
	"github.com/notawar/mobius/server/config"
	"github.com/notawar/mobius/server/contexts/ctxerr"
	"github.com/notawar/mobius/server/datastore/mysql/common_mysql"
	"github.com/notawar/mobius/server/datastore/mysql/common_mysql/testing_utils"
	"github.com/notawar/mobius/server/mobius"
	nanodep_client "github.com/notawar/mobius/server/mdm/nanodep/client"
	mdmtesting "github.com/notawar/mobius/server/mdm/testing_utils"
	"github.com/go-kit/log"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/smallstep/pkcs7"
	"github.com/stretchr/testify/require"
)

func connectMySQL(t testing.TB, testName string, opts *testing_utils.DatastoreTestOptions) *Datastore {
	cfg := testing_utils.MysqlTestConfig(testName)

	// Create datastore client
	var replicaOpt DBOption
	if opts.DummyReplica {
		replicaConf := *cfg
		replicaConf.Database += testing_utils.TestReplicaDatabaseSuffix
		replicaOpt = Replica(&replicaConf)
	}

	// For use with WithMobiusConfig. Note that since we're setting up the DB in a different way
	// than in production, we have to reset the MinSoftwareLastOpenedAtDiff field to its default so
	// it's not overwritten here.
	tc := config.TestConfig()
	tc.Osquery.MinSoftwareLastOpenedAtDiff = defaultMinLastOpenedAtDiff

	// TODO: for some reason we never log datastore messages when running integration tests, why?
	//
	// Changes below assume that we want to follows the same pattern as the rest of the codebase.
	dslogger := log.NewLogfmtLogger(os.Stdout)
	if os.Getenv("MOBIUS_INTEGRATION_TESTS_DISABLE_LOG") != "" {
		dslogger = log.NewNopLogger()
	}

	// set SQL mode to ANSI, as it's a special mode equivalent to:
	// REAL_AS_FLOAT, PIPES_AS_CONCAT, ANSI_QUOTES, IGNORE_SPACE, and
	// ONLY_FULL_GROUP_BY
	//
	// Per the docs:
	// > This mode changes syntax and behavior to conform more closely to
	// standard SQL.
	//
	// https://dev.mysql.com/doc/refman/8.0/en/sql-mode.html#sqlmode_ansi
	ds, err := New(*cfg, clock.NewMockClock(), Logger(dslogger), LimitAttempts(1), replicaOpt, SQLMode("ANSI"), WithMobiusConfig(&tc))
	require.Nil(t, err)

	if opts.DummyReplica {
		setupDummyReplica(t, testName, ds, opts)
	}
	if opts.RealReplica {
		replicaOpts := &common_mysql.DBOptions{
			MinLastOpenedAtDiff: defaultMinLastOpenedAtDiff,
			MaxAttempts:         1,
			Logger:              log.NewNopLogger(),
			SqlMode:             "ANSI",
		}
		setupRealReplica(t, testName, ds, replicaOpts)
	}

	return ds
}

func setupDummyReplica(t testing.TB, testName string, ds *Datastore, opts *testing_utils.DatastoreTestOptions) {
	t.Helper()

	// create the context that will cancel the replication goroutine on test exit
	var cancel func()
	ctx := context.Background()
	if tt, ok := t.(*testing.T); ok {
		if dl, ok := tt.Deadline(); ok {
			ctx, cancel = context.WithDeadline(ctx, dl)
		} else {
			ctx, cancel = context.WithCancel(ctx)
		}
	}
	t.Cleanup(cancel)

	type replicationRun struct {
		forceTables     []string
		replicationDone chan struct{}
	}

	// start the replication goroutine that runs when signalled through a
	// channel, the replication runs in lock-step - the test is in control of
	// when the replication happens, by calling opts.RunReplication(), and when
	// that call returns, the replication is guaranteed to be done. This supports
	// simulating all kinds of replica lag.
	ch := make(chan replicationRun)
	go func() {
		// if it exits because of a panic/failed replication, cancel the context
		// immediately so that RunReplication is unblocked too.
		defer cancel()

		primary := ds.primary
		replica := ds.replica.(*sqlx.DB)
		replicaDB := testName + testing_utils.TestReplicaDatabaseSuffix
		last := time.Now().Add(-time.Minute)

		// drop all foreign keys in the replica, as that causes issues even with
		// FOREIGN_KEY_CHECKS=0
		var fks []struct {
			TableName      string `db:"TABLE_NAME"`
			ConstraintName string `db:"CONSTRAINT_NAME"`
		}
		err := primary.SelectContext(ctx, &fks, `
          SELECT
            TABLE_NAME, CONSTRAINT_NAME
          FROM
            INFORMATION_SCHEMA.KEY_COLUMN_USAGE
          WHERE
            TABLE_SCHEMA = ? AND
            REFERENCED_TABLE_NAME IS NOT NULL`, testName)
		require.NoError(t, err)
		for _, fk := range fks {
			stmt := fmt.Sprintf(`ALTER TABLE %s.%s DROP FOREIGN KEY %s`, replicaDB, fk.TableName, fk.ConstraintName)
			_, err := replica.ExecContext(ctx, stmt)
			// If the FK was already removed do nothing
			if err != nil && strings.Contains(err.Error(), "check that column/key exists") {
				continue
			}

			require.NoError(t, err)
		}

		for {
			select {
			case out := <-ch:
				// identify tables with changes since the last call
				var tables []string
				err := primary.SelectContext(ctx, &tables, `
          SELECT
            table_name
          FROM
            information_schema.tables
          WHERE
            table_schema = ? AND
            table_type = 'BASE TABLE' AND
            update_time >= ?`, testName, last)
				require.NoError(t, err)

				// dedupe and add forced tables
				tableSet := make(map[string]bool, len(tables)+len(out.forceTables))
				for _, tbl := range tables {
					tableSet[tbl] = true
				}
				for _, tbl := range out.forceTables {
					tableSet[tbl] = true
				}
				tables = tables[:0]
				for tbl := range tableSet {
					tables = append(tables, tbl)
				}
				t.Logf("changed tables since %v: %v", last, tables)

				err = primary.GetContext(ctx, &last, `
          SELECT
            MAX(update_time)
          FROM
            information_schema.tables
          WHERE
            table_schema = ? AND
            table_type = 'BASE TABLE'`, testName)
				require.NoError(t, err)
				t.Logf("last update time of primary is now %v", last)

				// replicate by dropping the existing table and re-creating it from
				// the primary.
				for _, tbl := range tables {
					stmt := fmt.Sprintf(`DROP TABLE IF EXISTS %s.%s`, replicaDB, tbl)
					t.Log(stmt)
					_, err = replica.ExecContext(ctx, stmt)
					require.NoError(t, err)
					stmt = fmt.Sprintf(`CREATE TABLE %s.%s LIKE %s.%s`, replicaDB, tbl, testName, tbl)
					t.Log(stmt)
					_, err = replica.ExecContext(ctx, stmt)
					require.NoError(t, err)
					stmt = fmt.Sprintf(`INSERT INTO %s.%s SELECT * FROM %s.%s`, replicaDB, tbl, testName, tbl)
					t.Log(stmt)
					_, err = replica.ExecContext(ctx, stmt)
					require.NoError(t, err)
				}

				out.replicationDone <- struct{}{}
				t.Logf("replication step executed, next will consider updates since %s", last)

			case <-ctx.Done():
				return
			}
		}
	}()

	// set RunReplication to a function that triggers the replication and waits
	// for it to complete.
	opts.RunReplication = func(forceTables ...string) {
		done := make(chan struct{})
		ch <- replicationRun{forceTables, done}
		select {
		case <-done:
		case <-ctx.Done():
		}
	}
}

// we need to keep track of the databases that need replication in order to
// configure the replica to only track those, otherwise the replica worker
// might fail/stop trying to execute statements on databases that don't exist.
//
// this happens because we create a database and import our test dump on the
// leader each time `connectMySQL` is called, but we only do the same on the
// replica when it's enabled via options.
var (
	mu                   sync.Mutex
	databasesToReplicate string
)

func setupRealReplica(t testing.TB, testName string, ds *Datastore, options *common_mysql.DBOptions) {
	t.Helper()
	const replicaUser = "replicator"
	const replicaPassword = "rotacilper"

	t.Cleanup(
		func() {
			// Stop replica
			if out, err := exec.Command(
				"docker", "compose", "exec", "-T", "mysql_replica_test",
				// Command run inside container
				"mysql",
				"-u"+testing_utils.TestUsername, "-p"+testing_utils.TestPassword,
				"-e",
				"STOP REPLICA; RESET REPLICA ALL;",
			).CombinedOutput(); err != nil {
				t.Log(err)
				t.Log(string(out))
			}
		},
	)

	ctx := context.Background()

	// Create replication user
	_, err := ds.primary.ExecContext(ctx, fmt.Sprintf("DROP USER IF EXISTS '%s'", replicaUser))
	require.NoError(t, err)
	_, err = ds.primary.ExecContext(ctx, fmt.Sprintf("CREATE USER '%s'@'%%' IDENTIFIED BY '%s'", replicaUser, replicaPassword))
	require.NoError(t, err)
	_, err = ds.primary.ExecContext(ctx, fmt.Sprintf("GRANT REPLICATION SLAVE ON *.* TO '%s'@'%%'", replicaUser))
	require.NoError(t, err)
	_, err = ds.primary.ExecContext(ctx, "FLUSH PRIVILEGES")
	require.NoError(t, err)

	var version string
	err = ds.primary.GetContext(ctx, &version, "SELECT VERSION()")
	require.NoError(t, err)

	// Retrieve master binary log coordinates
	ms, err := ds.MasterStatus(ctx, version)
	require.NoError(t, err)

	mu.Lock()
	databasesToReplicate = strings.TrimPrefix(databasesToReplicate+fmt.Sprintf(", `%s`", testName), ",")
	mu.Unlock()

	setSourceStmt := fmt.Sprintf(`
			CHANGE REPLICATION SOURCE TO
				GET_SOURCE_PUBLIC_KEY=1,
				SOURCE_HOST='mysql_test',
				SOURCE_USER='%s',
				SOURCE_PASSWORD='%s',
				SOURCE_LOG_FILE='%s',
				SOURCE_LOG_POS=%d
		`, replicaUser, replicaPassword, ms.File, ms.Position)
	if strings.HasPrefix(version, "8.0") {
		setSourceStmt = fmt.Sprintf(`
			CHANGE MASTER TO
				GET_MASTER_PUBLIC_KEY=1,
				MASTER_HOST='mysql_test',
				MASTER_USER='%s',
				MASTER_PASSWORD='%s',
				MASTER_LOG_FILE='%s',
				MASTER_LOG_POS=%d
		`, replicaUser, replicaPassword, ms.File, ms.Position)
	}

	// Configure replica and start replication
	if out, err := exec.Command(
		"docker", "compose", "exec", "-T", "mysql_replica_test",
		// Command run inside container
		"mysql",
		"-u"+testing_utils.TestUsername, "-p"+testing_utils.TestPassword,
		"-e",
		fmt.Sprintf(
			`
			STOP REPLICA;
			RESET REPLICA ALL;
			CHANGE REPLICATION FILTER REPLICATE_DO_DB = ( %s );
			%s;
			START REPLICA;
			`, databasesToReplicate, setSourceStmt,
		),
	).CombinedOutput(); err != nil {
		t.Error(err)
		t.Error(string(out))
		t.FailNow()
	}

	// Connect to the replica
	replicaConfig := config.MysqlConfig{
		Username: testing_utils.TestUsername,
		Password: testing_utils.TestPassword,
		Database: testName,
		Address:  testing_utils.TestReplicaAddress,
	}
	require.NoError(t, checkConfig(&replicaConfig))
	replica, err := NewDB(&replicaConfig, options)
	require.NoError(t, err)
	ds.replica = replica
	ds.readReplicaConfig = &replicaConfig
}

// initializeDatabase loads the dumped schema into a newly created database in
// MySQL. This is much faster than running the full set of migrations on each
// test.
func initializeDatabase(t testing.TB, testName string, opts *testing_utils.DatastoreTestOptions) *Datastore {
	_, filename, _, _ := runtime.Caller(0)
	schemaPath := path.Join(path.Dir(filename), "schema.sql")
	testing_utils.LoadSchema(t, testName, opts, schemaPath)
	return connectMySQL(t, testName, opts)
}

func createMySQLDSWithOptions(t testing.TB, opts *testing_utils.DatastoreTestOptions) *Datastore {
	cleanTestName, opts := testing_utils.ProcessOptions(t, opts)
	ds := initializeDatabase(t, cleanTestName, opts)
	t.Cleanup(func() { ds.Close() })
	return ds
}

func CreateMySQLDSWithReplica(t *testing.T, opts *testing_utils.DatastoreTestOptions) *Datastore {
	if opts == nil {
		opts = new(testing_utils.DatastoreTestOptions)
	}
	opts.RealReplica = true
	const numberOfAttempts = 10
	var ds *Datastore
	for attempt := 0; attempt < numberOfAttempts; {
		attempt++
		ds = createMySQLDSWithOptions(t, opts)
		status, err := ds.ReplicaStatus(context.Background())
		require.NoError(t, err)
		if status["Replica_SQL_Running"] != "Yes" {
			t.Logf("create replica attempt: %d replica status: %+v", attempt, status)
			if lastErr, ok := status["Last_Error"]; ok && lastErr != "" {
				t.Logf("replica not running after attempt %d; Last_Error: %s", attempt, lastErr)
			}
			continue
		}
		break
	}
	require.NotNil(t, ds)
	return ds
}

func CreateMySQLDSWithOptions(t *testing.T, opts *testing_utils.DatastoreTestOptions) *Datastore {
	return createMySQLDSWithOptions(t, opts)
}

func CreateMySQLDS(t testing.TB) *Datastore {
	return createMySQLDSWithOptions(t, nil)
}

func CreateNamedMySQLDS(t *testing.T, name string) *Datastore {
	if _, ok := os.LookupEnv("MYSQL_TEST"); !ok {
		t.Skip("MySQL tests are disabled")
	}

	ds := initializeDatabase(t, name, new(testing_utils.DatastoreTestOptions))
	t.Cleanup(func() { ds.Close() })
	return ds
}

func ExecAdhocSQL(tb testing.TB, ds *Datastore, fn func(q sqlx.ExtContext) error) {
	tb.Helper()
	err := fn(ds.primary)
	require.NoError(tb, err)
}

func ExecAdhocSQLWithError(ds *Datastore, fn func(q sqlx.ExtContext) error) error {
	return fn(ds.primary)
}

// EncryptWithPrivateKey encrypts data with the server private key associated
// with the Datastore.
func EncryptWithPrivateKey(tb testing.TB, ds *Datastore, data []byte) ([]byte, error) {
	return encrypt(data, ds.serverPrivateKey)
}

func TruncateTables(t testing.TB, ds *Datastore, tables ...string) {
	// those tables are seeded with the schema.sql and as such must not
	// be truncated - a more precise approach must be used for those, e.g.
	// delete where id > max before test, or something like that.
	nonEmptyTables := map[string]bool{
		"app_config_json":                  true,
		"mobius_variables":                  true,
		"mdm_apple_declaration_categories": true,
		"mdm_delivery_status":              true,
		"mdm_operation_types":              true,
		"migration_status_tables":          true,
		"osquery_options":                  true,
	}
	testing_utils.TruncateTables(t, ds.writer(context.Background()), ds.logger, nonEmptyTables, tables...)
}

// this is meant to be used for debugging/testing that statement uses an efficient
// plan (e.g. makes use of an index, avoids full scans, etc.) using the data already
// created for tests. Calls to this function should be temporary and removed when
// done investigating the plan, so it is expected that this function will be detected
// as unused.
func explainSQLStatement(w io.Writer, db sqlx.QueryerContext, stmt string, args ...interface{}) { //nolint:deadcode,unused
	var rows []struct {
		ID           int             `db:"id"`
		SelectType   string          `db:"select_type"`
		Table        sql.NullString  `db:"table"`
		Partitions   sql.NullString  `db:"partitions"`
		Type         sql.NullString  `db:"type"`
		PossibleKeys sql.NullString  `db:"possible_keys"`
		Key          sql.NullString  `db:"key"`
		KeyLen       sql.NullInt64   `db:"key_len"`
		Ref          sql.NullString  `db:"ref"`
		Rows         sql.NullInt64   `db:"rows"`
		Filtered     sql.NullFloat64 `db:"filtered"`
		Extra        sql.NullString  `db:"Extra"`
	}
	if err := sqlx.SelectContext(context.Background(), db, &rows, "EXPLAIN "+stmt, args...); err != nil {
		panic(err)
	}
	fmt.Fprint(w, "\n\n", strings.Repeat("-", 60), "\n", stmt, "\n", strings.Repeat("-", 60), "\n")
	tw := tabwriter.NewWriter(w, 0, 1, 1, ' ', tabwriter.Debug)

	fmt.Fprintln(tw, "id\tselect_type\ttable\tpartitions\ttype\tpossible_keys\tkey\tkey_len\tref\trows\tfiltered\textra")
	for _, row := range rows {
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\t%d\t%f\t%s\n", row.ID, row.SelectType, row.Table.String, row.Partitions.String,
			row.Type.String, row.PossibleKeys.String, row.Key.String, row.KeyLen.Int64, row.Ref.String, row.Rows.Int64, row.Filtered.Float64, row.Extra.String)
	}
	if err := tw.Flush(); err != nil {
		panic(err)
	}
}

func DumpTable(t *testing.T, q sqlx.QueryerContext, tableName string, cols ...string) { //nolint: unused
	colList := "*"
	if len(cols) > 0 {
		colList = strings.Join(cols, ", ")
	}
	rows, err := q.QueryContext(context.Background(), fmt.Sprintf(`SELECT %s FROM %s`, colList, tableName))
	require.NoError(t, err)
	defer rows.Close()

	t.Logf(">> dumping table %s:", tableName)

	var anyDst []any
	var strDst []sql.NullString
	var sb strings.Builder
	for rows.Next() {
		if anyDst == nil {
			cols, err := rows.Columns()
			require.NoError(t, err)
			anyDst = make([]any, len(cols))
			strDst = make([]sql.NullString, len(cols))
			for i := 0; i < len(cols); i++ {
				anyDst[i] = &strDst[i]
			}
			t.Logf("%v", cols)
		}
		require.NoError(t, rows.Scan(anyDst...))

		sb.Reset()
		for _, v := range strDst {
			if v.Valid {
				sb.WriteString(v.String)
			} else {
				sb.WriteString("NULL")
			}
			sb.WriteString("\t")
		}
		t.Logf("%s", sb.String())
	}
	require.NoError(t, rows.Err())
	t.Logf("<< dumping table %s completed", tableName)
}

func generateDummyWindowsProfileContents(uuid string) mobius.MDMWindowsProfileContents {
	syncML := generateDummyWindowsProfile(uuid)
	checksum := md5.Sum(syncML)
	return mobius.MDMWindowsProfileContents{
		SyncML:   syncML,
		Checksum: checksum[:],
	}
}

func generateDummyWindowsProfile(uuid string) []byte {
	return []byte(fmt.Sprintf(`<Replace><Target><LocUri>./Device/Foo/%s</LocUri></Target></Replace>`, uuid))
}

// TODO(roberto): update when we have datastore functions and API methods for this
func InsertWindowsProfileForTest(t *testing.T, ds *Datastore, teamID uint) string {
	profUUID := "w" + uuid.NewString()
	prof := generateDummyWindowsProfile(profUUID)
	ExecAdhocSQL(t, ds, func(q sqlx.ExtContext) error {
		stmt := `INSERT INTO mdm_windows_configuration_profiles (profile_uuid, team_id, name, syncml, uploaded_at) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP);`
		_, err := q.ExecContext(context.Background(), stmt, profUUID, teamID, fmt.Sprintf("name-%s", profUUID), prof)
		return err
	})
	return profUUID
}

// GetAggregatedStats retrieves aggregated stats for the given query
func GetAggregatedStats(ctx context.Context, ds *Datastore, aggregate mobius.AggregatedStatsType, id uint) (mobius.AggregatedStats, error) {
	result := mobius.AggregatedStats{}
	stmt := `
	SELECT
		   JSON_EXTRACT(json_value, '$.user_time_p50') as user_time_p50,
		   JSON_EXTRACT(json_value, '$.user_time_p95') as user_time_p95,
		   JSON_EXTRACT(json_value, '$.system_time_p50') as system_time_p50,
		   JSON_EXTRACT(json_value, '$.system_time_p95') as system_time_p95,
		   JSON_EXTRACT(json_value, '$.total_executions') as total_executions
	FROM aggregated_stats WHERE id=? AND type=?
	`
	err := sqlx.GetContext(ctx, ds.reader(ctx), &result, stmt, id, aggregate)
	return result, err
}

// SetOrderedCreatedAtTimestamps enforces an ordered sequence of created_at
// timestamps in a database table. This can be useful in tests instead of
// adding time.Sleep calls to just force specific ordered timestamps for the
// test entries of interest, and it doesn't slow down the unit test.
//
// The first timestamp will be after afterTime, and each provided key will have
// a timestamp incremented by 1s.
func SetOrderedCreatedAtTimestamps(t testing.TB, ds *Datastore, afterTime time.Time, table, keyCol string, keys ...any) time.Time {
	now := afterTime
	for i := 0; i < len(keys); i++ {
		now = now.Add(time.Second)
		ExecAdhocSQL(t, ds, func(q sqlx.ExtContext) error {
			_, err := q.ExecContext(context.Background(),
				fmt.Sprintf(`UPDATE %s SET created_at=? WHERE %s=?`, table, keyCol), now, keys[i])
			return err
		})
	}
	return now
}

func CreateABMKeyCertIfNotExists(t testing.TB, ds *Datastore) {
	certPEM, keyPEM, _, err := GenerateTestABMAssets(t)
	require.NoError(t, err)
	var assets []mobius.MDMConfigAsset
	_, err = ds.GetAllMDMConfigAssetsByName(context.Background(), []mobius.MDMAssetName{
		mobius.MDMAssetABMKey,
	}, nil)
	if err != nil {
		var nfe mobius.NotFoundError
		require.ErrorAs(t, err, &nfe)
		assets = append(assets, mobius.MDMConfigAsset{Name: mobius.MDMAssetABMKey, Value: keyPEM})
	}

	_, err = ds.GetAllMDMConfigAssetsByName(context.Background(), []mobius.MDMAssetName{
		mobius.MDMAssetABMCert,
	}, nil)
	if err != nil {
		var nfe mobius.NotFoundError
		require.ErrorAs(t, err, &nfe)
		assets = append(assets, mobius.MDMConfigAsset{Name: mobius.MDMAssetABMCert, Value: certPEM})
	}

	if len(assets) != 0 {
		err = ds.InsertMDMConfigAssets(context.Background(), assets, ds.writer(context.Background()))
		require.NoError(t, err)
	}
}

// CreateAndSetABMToken creates a new ABM token (using an existing ABM key/cert) and stores it in the DB.
func CreateAndSetABMToken(t testing.TB, ds *Datastore, orgName string) *mobius.ABMToken {
	assets, err := ds.GetAllMDMConfigAssetsByName(context.Background(), []mobius.MDMAssetName{
		mobius.MDMAssetABMKey,
		mobius.MDMAssetABMCert,
	}, nil)
	require.NoError(t, err)

	certPEM := assets[mobius.MDMAssetABMCert].Value

	testBMToken := &nanodep_client.OAuth1Tokens{
		ConsumerKey:       "test_consumer",
		ConsumerSecret:    "test_secret",
		AccessToken:       "test_access_token",
		AccessSecret:      "test_access_secret",
		AccessTokenExpiry: time.Date(2999, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	rawToken, err := json.Marshal(testBMToken)
	require.NoError(t, err)

	smimeToken := fmt.Sprintf(
		"Content-Type: text/plain;charset=UTF-8\r\n"+
			"Content-Transfer-Encoding: 7bit\r\n"+
			"\r\n%s", rawToken,
	)

	block, _ := pem.Decode(certPEM)
	require.NotNil(t, block)
	require.Equal(t, "CERTIFICATE", block.Type)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	encryptedToken, err := pkcs7.Encrypt([]byte(smimeToken), []*x509.Certificate{cert})
	require.NoError(t, err)

	tokenBytes := fmt.Sprintf(
		"Content-Type: application/pkcs7-mime; name=\"smime.p7m\"; smime-type=enveloped-data\r\n"+
			"Content-Transfer-Encoding: base64\r\n"+
			"Content-Disposition: attachment; filename=\"smime.p7m\"\r\n"+
			"Content-Description: S/MIME Encrypted Message\r\n"+
			"\r\n%s", base64.StdEncoding.EncodeToString(encryptedToken))

	tok, err := ds.InsertABMToken(context.Background(), &mobius.ABMToken{EncryptedToken: []byte(tokenBytes), OrganizationName: orgName})
	require.NoError(t, err)
	return tok
}

func SetTestABMAssets(t testing.TB, ds *Datastore, orgName string) *mobius.ABMToken {
	apnsCert, apnsKey, err := GenerateTestCertBytes(mdmtesting.NewTestMDMAppleCertTemplate())
	require.NoError(t, err)

	certPEM, keyPEM, tokenBytes, err := GenerateTestABMAssets(t)
	require.NoError(t, err)
	assets := []mobius.MDMConfigAsset{
		{Name: mobius.MDMAssetABMCert, Value: certPEM},
		{Name: mobius.MDMAssetABMKey, Value: keyPEM},
		{Name: mobius.MDMAssetAPNSCert, Value: apnsCert},
		{Name: mobius.MDMAssetAPNSKey, Value: apnsKey},
		{Name: mobius.MDMAssetCACert, Value: certPEM},
		{Name: mobius.MDMAssetCAKey, Value: keyPEM},
	}

	err = ds.InsertMDMConfigAssets(context.Background(), assets, nil)
	require.NoError(t, err)

	tok, err := ds.InsertABMToken(context.Background(), &mobius.ABMToken{EncryptedToken: tokenBytes, OrganizationName: orgName})
	require.NoError(t, err)

	appCfg, err := ds.AppConfig(context.Background())
	require.NoError(t, err)
	appCfg.MDM.EnabledAndConfigured = true
	appCfg.MDM.AppleBMEnabledAndConfigured = true
	err = ds.SaveAppConfig(context.Background(), appCfg)
	require.NoError(t, err)

	return tok
}

func GenerateTestABMAssets(t testing.TB) ([]byte, []byte, []byte, error) {
	certPEM, keyPEM, err := GenerateTestCertBytes(mdmtesting.NewTestMDMAppleCertTemplate())
	require.NoError(t, err)

	testBMToken := &nanodep_client.OAuth1Tokens{
		ConsumerKey:       "test_consumer",
		ConsumerSecret:    "test_secret",
		AccessToken:       "test_access_token",
		AccessSecret:      "test_access_secret",
		AccessTokenExpiry: time.Date(2999, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	rawToken, err := json.Marshal(testBMToken)
	require.NoError(t, err)

	smimeToken := fmt.Sprintf(
		"Content-Type: text/plain;charset=UTF-8\r\n"+
			"Content-Transfer-Encoding: 7bit\r\n"+
			"\r\n%s", rawToken,
	)

	block, _ := pem.Decode(certPEM)
	require.NotNil(t, block)
	require.Equal(t, "CERTIFICATE", block.Type)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	encryptedToken, err := pkcs7.Encrypt([]byte(smimeToken), []*x509.Certificate{cert})
	require.NoError(t, err)

	tokenBytes := fmt.Sprintf(
		"Content-Type: application/pkcs7-mime; name=\"smime.p7m\"; smime-type=enveloped-data\r\n"+
			"Content-Transfer-Encoding: base64\r\n"+
			"Content-Disposition: attachment; filename=\"smime.p7m\"\r\n"+
			"Content-Description: S/MIME Encrypted Message\r\n"+
			"\r\n%s", base64.StdEncoding.EncodeToString(encryptedToken))

	return certPEM, keyPEM, []byte(tokenBytes), nil
}

func GenerateTestCertBytes(template *x509.Certificate) ([]byte, []byte, error) {
	if template == nil {
		return nil, nil, errors.New("template is nil")
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return certPEM, keyPEM, nil
}

// MasterStatus is a struct that holds the file and position of the master, retrieved by SHOW MASTER STATUS
type MasterStatus struct {
	File     string
	Position uint64
}

func (ds *Datastore) MasterStatus(ctx context.Context, mysqlVersion string) (MasterStatus, error) {
	stmt := "SHOW BINARY LOG STATUS"
	if strings.HasPrefix(mysqlVersion, "8.0") {
		stmt = "SHOW MASTER STATUS"
	}

	rows, err := ds.writer(ctx).Query(stmt)
	if err != nil {
		return MasterStatus{}, ctxerr.Wrap(ctx, err, stmt)
	}
	defer rows.Close()

	// Since we don't control the column names, and we want to be future compatible,
	// we only scan for the columns we care about.
	ms := MasterStatus{}
	// Get the column names from the query
	columns, err := rows.Columns()
	if err != nil {
		return ms, ctxerr.Wrap(ctx, err, "get columns")
	}
	numberOfColumns := len(columns)
	for rows.Next() {
		cols := make([]interface{}, numberOfColumns)
		for i := range cols {
			cols[i] = new(string)
		}
		err := rows.Scan(cols...)
		if err != nil {
			return ms, ctxerr.Wrap(ctx, err, "scan row")
		}
		for i, col := range cols {
			switch columns[i] {
			case "File":
				ms.File = *col.(*string)
			case "Position":
				ms.Position, err = strconv.ParseUint(*col.(*string), 10, 64)
				if err != nil {
					return ms, ctxerr.Wrap(ctx, err, "parse Position")
				}

			}
		}
	}
	if err := rows.Err(); err != nil {
		return ms, ctxerr.Wrap(ctx, err, "rows error")
	}
	if ms.File == "" || ms.Position == 0 {
		return ms, ctxerr.New(ctx, "missing required fields in master status")
	}
	return ms, nil
}

func (ds *Datastore) ReplicaStatus(ctx context.Context) (map[string]interface{}, error) {
	rows, err := ds.reader(ctx).QueryContext(ctx, "SHOW REPLICA STATUS")
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err, "show replica status")
	}
	defer rows.Close()

	// Get the column names from the query
	columns, err := rows.Columns()
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err, "get columns")
	}
	numberOfColumns := len(columns)
	result := make(map[string]interface{}, numberOfColumns)
	for rows.Next() {
		cols := make([]interface{}, numberOfColumns)
		for i := range cols {
			cols[i] = &sql.NullString{}
		}
		err = rows.Scan(cols...)
		if err != nil {
			return result, ctxerr.Wrap(ctx, err, "scan row")
		}
		for i, col := range cols {
			colValue := col.(*sql.NullString)
			if colValue.Valid {
				result[columns[i]] = colValue.String
			} else {
				result[columns[i]] = nil
			}
		}
	}
	if err := rows.Err(); err != nil {
		return result, ctxerr.Wrap(ctx, err, "rows error")
	}
	return result, nil
}

// NormalizeSQL normalizes the SQL statement by removing extra spaces and new lines, etc.
func NormalizeSQL(query string) string {
	query = strings.ToUpper(query)
	query = strings.TrimSpace(query)

	transformations := []struct {
		pattern     *regexp.Regexp
		replacement string
	}{
		{
			// Remove comments
			regexp.MustCompile(`(?m)--.*$|/\*(?s).*?\*/`),
			"",
		},
		{
			// Normalize whitespace
			regexp.MustCompile(`\s+`),
			" ",
		},
		{
			// Replace spaces around ','
			regexp.MustCompile(`\s*,\s*`),
			",",
		},
		{
			// Replace extra spaces before (
			regexp.MustCompile(`\s*\(\s*`),
			" (",
		},
		{
			// Replace extra spaces before (
			regexp.MustCompile(`\s*\)\s*`),
			") ",
		},
	}
	for _, tx := range transformations {
		query = tx.pattern.ReplaceAllString(query, tx.replacement)
	}
	return query
}

func checkUpcomingActivities(t *testing.T, ds *Datastore, host *mobius.Host, execIDs ...string) {
	ctx := t.Context()

	type upcoming struct {
		ExecutionID    string `db:"execution_id"`
		ActivatedAtSet bool   `db:"activated_at_set"`
	}

	var got []upcoming
	ExecAdhocSQL(t, ds, func(q sqlx.ExtContext) error {
		return sqlx.SelectContext(ctx, q, &got,
			`SELECT
					execution_id,
					(activated_at IS NOT NULL) as activated_at_set
				FROM upcoming_activities
				WHERE host_id = ?
				ORDER BY IF(activated_at IS NULL, 0, 1) DESC, priority DESC, created_at ASC`, host.ID)
	})

	var want []upcoming
	if len(execIDs) > 0 {
		want = make([]upcoming, len(execIDs))
		for i, execID := range execIDs {
			want[i] = upcoming{
				ExecutionID:    execID,
				ActivatedAtSet: i == 0,
			}
		}
	}
	require.Equal(t, want, got)
}
