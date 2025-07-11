package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"golang.org/x/text/unicode/norm"

	"github.com/notawar/mobius/server/contexts/ctxerr"
	"github.com/notawar/mobius/server/mobius"
	"github.com/go-kit/log/level"
	"github.com/jmoiron/sqlx"
)

const (
	statsScheduledQueryType = iota
	statsLiveQueryType
)

var querySearchColumns = []string{"q.name"}

func (ds *Datastore) ApplyQueries(ctx context.Context, authorID uint, queries []*mobius.Query, queriesToDiscardResults map[uint]struct{}) error {
	if err := ds.applyQueriesInTx(ctx, authorID, queries); err != nil {
		return ctxerr.Wrap(ctx, err, "apply queries in tx")
	}

	// Opportunistically delete associated query_results.
	//
	// TODO(lucas): We should run this on a transaction but we found
	// performance issues and deadlocks at scale.
	queryIDs := make([]uint, 0, len(queriesToDiscardResults))
	for queryID := range queriesToDiscardResults {
		queryIDs = append(queryIDs, queryID)
	}
	if err := ds.deleteMultipleQueryResults(ctx, queryIDs); err != nil {
		return ctxerr.Wrap(ctx, err, "delete query_results")
	}
	return nil
}

func (ds *Datastore) applyQueriesInTx(ctx context.Context, authorID uint, queries []*mobius.Query) (err error) {
	err = ds.withRetryTxx(ctx, func(tx sqlx.ExtContext) error {
		insertSql := `
			INSERT INTO queries (
				name,
				description,
				query,
				author_id,
				saved,
				observer_can_run,
				team_id,
				team_id_char,
				platform,
				min_osquery_version,
				schedule_interval,
				automations_enabled,
				logging_type,
				discard_data
			) VALUES ( ?, ?, ?, ?, true, ?, ?, ?, ?, ?, ?, ?, ?, ? )
			ON DUPLICATE KEY UPDATE
				name = VALUES(name),
				description = VALUES(description),
				query = VALUES(query),
				author_id = VALUES(author_id),
				saved = VALUES(saved),
				observer_can_run = VALUES(observer_can_run),
				team_id = VALUES(team_id),
				team_id_char = VALUES(team_id_char),
				platform = VALUES(platform),
				min_osquery_version = VALUES(min_osquery_version),
				schedule_interval = VALUES(schedule_interval),
				automations_enabled = VALUES(automations_enabled),
				logging_type = VALUES(logging_type),
				discard_data = VALUES(discard_data)
		`
		for _, q := range queries {
			if err := q.Verify(); err != nil {
				return ctxerr.Wrap(ctx, err)
			}
			stmt, args, err := sqlx.In(insertSql,
				q.Name,
				q.Description,
				q.Query,
				authorID,
				q.ObserverCanRun,
				q.TeamID,
				q.TeamIDStr(),
				q.Platform,
				q.MinOsqueryVersion,
				q.Interval,
				q.AutomationsEnabled,
				q.Logging,
				q.DiscardData,
			)
			if err != nil {
				return ctxerr.Wrap(ctx, err, "exec queries prepare")
			}

			var result sql.Result
			if result, err = tx.ExecContext(ctx, stmt, args...); err != nil {
				return ctxerr.Wrap(ctx, err, "exec queries insert")
			}

			// Get the ID of the row, if it was a new query.
			id, _ := result.LastInsertId()
			// If the ID is 0, it was an update, so we need to get the ID.
			if id == 0 {
				var (
					rows *sql.Rows
					err  error
				)
				// Get the query that was updated.
				if q.TeamID == nil {
					rows, err = tx.QueryContext(ctx, "SELECT id FROM queries WHERE name = ? AND team_id is NULL", q.Name)
				} else {
					rows, err = tx.QueryContext(ctx, "SELECT id FROM queries WHERE name = ? AND team_id = ?", q.Name, q.TeamID)
				}
				if err != nil {
					return ctxerr.Wrap(ctx, err, "select queries id")
				}
				// Get the ID from the rows
				if rows.Next() {
					if err := rows.Scan(&id); err != nil {
						return ctxerr.Wrap(ctx, err, "scan queries id")
					}
				} else {
					return ctxerr.Wrap(ctx, err, "could not find query after update")
				}
				if err = rows.Err(); err != nil {
					return ctxerr.Wrap(ctx, err, "err queries id")
				}
				if err := rows.Close(); err != nil {
					return ctxerr.Wrap(ctx, err, "close queries id")
				}

			}
			//nolint:gosec // dismiss G115
			q.ID = uint(id)

			err = ds.updateQueryLabelsInTx(ctx, q, tx)
			if err != nil {
				return ctxerr.Wrap(ctx, err, "exec queries update labels")
			}
		}
		return nil
	})
	if err != nil {
		return ctxerr.Wrap(ctx, err, "apply queries in tx")
	}
	return nil
}

func (ds *Datastore) deleteMultipleQueryResults(ctx context.Context, queryIDs []uint) (err error) {
	if len(queryIDs) == 0 {
		return nil
	}

	deleteQueryResultsStmt := `DELETE FROM query_results WHERE query_id IN (?)`
	query, args, err := sqlx.In(deleteQueryResultsStmt, queryIDs)
	if err != nil {
		return ctxerr.Wrap(ctx, err, "building delete query_results stmt")
	}
	if _, err := ds.writer(ctx).ExecContext(ctx, query, args...); err != nil {
		return ctxerr.Wrap(ctx, err, "executing delete query_results")
	}
	return nil
}

func (ds *Datastore) QueryByName(
	ctx context.Context,
	teamID *uint,
	name string,
) (*mobius.Query, error) {
	stmt := `
		SELECT
			id,
			team_id,
			name,
			description,
			query,
			author_id,
			saved,
			observer_can_run,
			schedule_interval,
			platform,
			min_osquery_version,
			automations_enabled,
			logging_type,
			discard_data,
			created_at,
			updated_at
		FROM queries
		WHERE name = ?
	`
	args := []interface{}{name}
	whereClause := " AND team_id_char = ''"
	if teamID != nil {
		args = append(args, fmt.Sprint(*teamID))
		whereClause = " AND team_id_char = ?"
	}

	stmt += whereClause
	var query mobius.Query
	err := sqlx.GetContext(ctx, ds.reader(ctx), &query, stmt, args...)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ctxerr.Wrap(ctx, notFound("Query").WithName(name))
		}
		return nil, ctxerr.Wrap(ctx, err, "selecting query by name")
	}

	if err := ds.loadPacksForQueries(ctx, []*mobius.Query{&query}); err != nil {
		return nil, ctxerr.Wrap(ctx, err, "loading packs for query")
	}

	return &query, nil
}

func (ds *Datastore) NewQuery(
	ctx context.Context,
	query *mobius.Query,
	opts ...mobius.OptionalArg,
) (*mobius.Query, error) {
	if err := query.Verify(); err != nil {
		return nil, ctxerr.Wrap(ctx, err)
	}
	queryStatement := `
		INSERT INTO queries (
			name,
			description,
			query,
			saved,
			author_id,
			observer_can_run,
			team_id,
			team_id_char,
			platform,
			min_osquery_version,
			schedule_interval,
			automations_enabled,
			logging_type,
			discard_data
		) VALUES ( ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? )
	`

	result, err := ds.writer(ctx).ExecContext(
		ctx,
		queryStatement,
		query.Name,
		query.Description,
		query.Query,
		query.Saved,
		query.AuthorID,
		query.ObserverCanRun,
		query.TeamID,
		query.TeamIDStr(),
		query.Platform,
		query.MinOsqueryVersion,
		query.Interval,
		query.AutomationsEnabled,
		query.Logging,
		query.DiscardData,
	)

	if err != nil && IsDuplicate(err) {
		return nil, ctxerr.Wrap(ctx, alreadyExists("Query", query.Name))
	} else if err != nil {
		return nil, ctxerr.Wrap(ctx, err, "creating new Query")
	}

	id, _ := result.LastInsertId()
	query.ID = uint(id) //nolint:gosec // dismiss G115
	query.Packs = []mobius.Pack{}

	if err := ds.updateQueryLabels(ctx, query); err != nil {
		return nil, ctxerr.Wrap(ctx, err, "saving labels for query")
	}

	return query, nil
}

func (ds *Datastore) updateQueryLabels(ctx context.Context, query *mobius.Query) error {
	err := ds.withRetryTxx(ctx, func(tx sqlx.ExtContext) error {
		return ds.updateQueryLabelsInTx(ctx, query, tx)
	})
	if err != nil {
		return ctxerr.Wrap(ctx, err, "updating query labels")
	}
	return nil
}

// updates the LabelsIncludeAny for a query, using the string value of
// the label. Labels IDs are populated
func (ds *Datastore) updateQueryLabelsInTx(ctx context.Context, query *mobius.Query, tx sqlx.ExtContext) error {
	if tx == nil {
		return ctxerr.New(ctx, "updateQueryLabelsInTx called with nil tx")
	}

	var err error

	insertLabelSql := `
		INSERT INTO query_labels (
			query_id,
			label_id
		)
		SELECT ?, id
		FROM labels
		WHERE name IN (?)
	`

	deleteLabelStmt := `
		DELETE FROM query_labels
		WHERE query_id = ?
	`

	_, err = tx.ExecContext(ctx, deleteLabelStmt, query.ID)
	if err != nil {
		return ctxerr.Wrap(ctx, err, "removing old query labels")
	}

	if len(query.LabelsIncludeAny) == 0 {
		return nil
	}

	labelNames := []string{}
	for _, label := range query.LabelsIncludeAny {
		labelNames = append(labelNames, label.LabelName)
	}

	labelStmt, args, err := sqlx.In(insertLabelSql, query.ID, labelNames)
	if err != nil {
		return ctxerr.Wrap(ctx, err, "creating query label update statement")
	}

	if _, err := tx.ExecContext(ctx, labelStmt, args...); err != nil {
		return ctxerr.Wrap(ctx, err, "creating query labels")
	}

	if err := loadLabelsForQueries(ctx, tx, []*mobius.Query{query}); err != nil {
		return ctxerr.Wrap(ctx, err, "loading label names for inserted query")
	}

	return nil
}

func (ds *Datastore) SaveQuery(ctx context.Context, q *mobius.Query, shouldDiscardResults bool, shouldDeleteStats bool) (err error) {
	if err := q.Verify(); err != nil {
		return ctxerr.Wrap(ctx, err)
	}

	updateSQL := `
		UPDATE queries
		SET name                = ?,
			description         = ?,
			query               = ?,
			author_id           = ?,
			saved               = ?,
			observer_can_run    = ?,
			team_id             = ?,
			team_id_char        = ?,
			platform            = ?,
			min_osquery_version = ?,
			schedule_interval   = ?,
			automations_enabled = ?,
			logging_type        = ?,
			discard_data		= ?
		WHERE id = ?
	`
	result, err := ds.writer(ctx).ExecContext(
		ctx,
		updateSQL,
		q.Name,
		q.Description,
		q.Query,
		q.AuthorID,
		q.Saved,
		q.ObserverCanRun,
		q.TeamID,
		q.TeamIDStr(),
		q.Platform,
		q.MinOsqueryVersion,
		q.Interval,
		q.AutomationsEnabled,
		q.Logging,
		q.DiscardData,
		q.ID)
	if err != nil {
		return ctxerr.Wrap(ctx, err, "updating query")
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return ctxerr.Wrap(ctx, err, "rows affected updating query")
	}
	if rows == 0 {
		return ctxerr.Wrap(ctx, notFound("Query").WithID(q.ID))
	}

	if shouldDeleteStats {
		// Delete any associated stats asynchronously.
		go ds.deleteQueryStats(context.WithoutCancel(ctx), []uint{q.ID})
	}

	// Opportunistically delete associated query_results.
	//
	// TODO(lucas): We should run this on a transaction but we found
	// performance issues and deadlocks at scale.
	if shouldDiscardResults {
		if err := ds.deleteQueryResults(ctx, q.ID); err != nil {
			return ctxerr.Wrap(ctx, err, "deleting query_results")
		}
	}

	if err := ds.updateQueryLabels(ctx, q); err != nil {
		return ctxerr.Wrap(ctx, err, "updaing query labels")
	}

	return nil
}

func (ds *Datastore) deleteQueryResults(ctx context.Context, queryID uint) error {
	resultsSQL := `DELETE FROM query_results WHERE query_id = ?`
	if _, err := ds.writer(ctx).ExecContext(ctx, resultsSQL, queryID); err != nil {
		return ctxerr.Wrap(ctx, err, "executing delete query_results")
	}
	return nil
}

func (ds *Datastore) DeleteQuery(ctx context.Context, teamID *uint, name string) error {
	selectStmt := "SELECT id FROM queries WHERE name = ?"
	args := []interface{}{name}
	whereClause := " AND team_id_char = ''"
	if teamID != nil {
		args = append(args, fmt.Sprint(*teamID))
		whereClause = " AND team_id_char = ?"
	}
	selectStmt += whereClause
	var queryID uint
	if err := sqlx.GetContext(ctx, ds.writer(ctx), &queryID, selectStmt, args...); err != nil {
		if err == sql.ErrNoRows {
			return ctxerr.Wrap(ctx, notFound("queries").WithName(name))
		}
		return ctxerr.Wrap(ctx, err, "getting query to delete")
	}

	deleteStmt := "DELETE FROM queries WHERE id = ?"
	result, err := ds.writer(ctx).ExecContext(ctx, deleteStmt, queryID)
	if err != nil {
		if isMySQLForeignKey(err) {
			return ctxerr.Wrap(ctx, foreignKey("queries", name))
		}
		return ctxerr.Wrap(ctx, err, "delete queries")
	}
	rows, _ := result.RowsAffected()
	if rows != 1 {
		return ctxerr.Wrap(ctx, notFound("queries").WithName(name))
	}

	// Delete any associated stats asynchronously.
	go ds.deleteQueryStats(context.WithoutCancel(ctx), []uint{queryID})

	// Opportunistically delete associated query_results.
	//
	// TODO(lucas): We should run this on a transaction but we found
	// performance issues and deadlocks at scale.
	if err := ds.deleteQueryResults(ctx, queryID); err != nil {
		return ctxerr.Wrap(ctx, err, "deleting query_results")
	}

	return nil
}

// DeleteQueries deletes the existing query objects with the provided IDs. The
// number of deleted queries is returned along with any error.
func (ds *Datastore) DeleteQueries(ctx context.Context, ids []uint) (uint, error) {
	deleted, err := ds.deleteEntities(ctx, queriesTable, ids)
	if err != nil {
		return deleted, err
	}

	// Delete any associated stats asynchronously.
	go ds.deleteQueryStats(context.WithoutCancel(ctx), ids)

	// Opportunistically delete associated query_results.
	//
	// TODO(lucas): We should run this on a transaction but we found
	// performance issues and deadlocks at scale.
	if err := ds.deleteMultipleQueryResults(ctx, ids); err != nil {
		return deleted, ctxerr.Wrap(ctx, err, "delete multiple query_results")
	}
	return deleted, nil
}

// deleteQueryStats deletes query stats and aggregated stats for saved queries.
// Errors are logged and not returned.
func (ds *Datastore) deleteQueryStats(ctx context.Context, queryIDs []uint) {
	// Delete stats for each host.
	stmt := "DELETE FROM scheduled_query_stats WHERE scheduled_query_id IN (?)"
	stmt, args, err := sqlx.In(stmt, queryIDs)
	if err != nil {
		level.Error(ds.logger).Log("msg", "error creating delete query stats statement", "err", err)
	} else {
		_, err = ds.writer(ctx).ExecContext(ctx, stmt, args...)
		if err != nil {
			level.Error(ds.logger).Log("msg", "error deleting query stats", "err", err)
		}
	}

	// Delete aggregated stats
	stmt = fmt.Sprintf("DELETE FROM aggregated_stats WHERE type = '%s' AND id IN (?)", mobius.AggregatedStatsTypeScheduledQuery)
	stmt, args, err = sqlx.In(stmt, queryIDs)
	if err != nil {
		level.Error(ds.logger).Log("msg", "error creating delete aggregated stats statement", "err", err)
	} else {
		_, err = ds.writer(ctx).ExecContext(ctx, stmt, args...)
		if err != nil {
			level.Error(ds.logger).Log("msg", "error deleting aggregated stats", "err", err)
		}
	}
}

// Query returns a single Query identified by id, if such exists.
func (ds *Datastore) Query(ctx context.Context, id uint) (*mobius.Query, error) {
	return query(ctx, ds.reader(ctx), id)
}

func query(ctx context.Context, db sqlx.QueryerContext, id uint) (*mobius.Query, error) {
	sqlQuery := `
		SELECT
			q.id,
			q.team_id,
			q.name,
			q.description,
			q.query,
			q.author_id,
			q.saved,
			q.observer_can_run,
			q.schedule_interval,
			q.platform,
			q.min_osquery_version,
			q.automations_enabled,
			q.logging_type,
			q.discard_data,
			q.created_at,
			q.updated_at,
			q.discard_data,
			COALESCE(NULLIF(u.name, ''), u.email, '') AS author_name,
			COALESCE(u.email, '') AS author_email,
			JSON_EXTRACT(json_value, '$.user_time_p50') as user_time_p50,
			JSON_EXTRACT(json_value, '$.user_time_p95') as user_time_p95,
			JSON_EXTRACT(json_value, '$.system_time_p50') as system_time_p50,
			JSON_EXTRACT(json_value, '$.system_time_p95') as system_time_p95,
			JSON_EXTRACT(json_value, '$.total_executions') as total_executions
		FROM queries q
		LEFT JOIN users u
			ON q.author_id = u.id
		LEFT JOIN aggregated_stats ag
			ON (ag.id = q.id AND ag.global_stats = ? AND ag.type = ?)
		WHERE q.id = ?
	`
	query := &mobius.Query{}
	if err := sqlx.GetContext(ctx, db, query, sqlQuery, false, mobius.AggregatedStatsTypeScheduledQuery, id); err != nil {
		if err == sql.ErrNoRows {
			return nil, ctxerr.Wrap(ctx, notFound("Query").WithID(id))
		}
		return nil, ctxerr.Wrap(ctx, err, "selecting query")
	}

	if err := loadPacksForQueries(ctx, db, []*mobius.Query{query}); err != nil {
		return nil, ctxerr.Wrap(ctx, err, "loading packs for queries")
	}

	if err := loadLabelsForQueries(ctx, db, []*mobius.Query{query}); err != nil {
		return nil, ctxerr.Wrap(ctx, err, "loading labels for query")
	}

	return query, nil
}

// ListQueries returns a list of queries with sort order and results limit
// determined by passed in mobius.ListOptions, count of total queries returned without limits, and
// pagination metadata
func (ds *Datastore) ListQueries(ctx context.Context, opt mobius.ListQueryOptions) ([]*mobius.Query, int, *mobius.PaginationMetadata, error) {
	getQueriesStmt := `
		SELECT
			q.id,
			q.team_id,
			q.name,
			q.description,
			q.query,
			q.author_id,
			q.saved,
			q.observer_can_run,
			q.schedule_interval,
			q.platform,
			q.min_osquery_version,
			q.automations_enabled,
			q.logging_type,
			q.discard_data,
			q.created_at,
			q.updated_at,
			COALESCE(u.name, '<deleted>') AS author_name,
			COALESCE(u.email, '') AS author_email,
			JSON_EXTRACT(json_value, '$.user_time_p50') as user_time_p50,
			JSON_EXTRACT(json_value, '$.user_time_p95') as user_time_p95,
			JSON_EXTRACT(json_value, '$.system_time_p50') as system_time_p50,
			JSON_EXTRACT(json_value, '$.system_time_p95') as system_time_p95,
			JSON_EXTRACT(json_value, '$.total_executions') as total_executions
		FROM queries q
		LEFT JOIN users u ON (q.author_id = u.id)
		LEFT JOIN aggregated_stats ag ON (ag.id = q.id AND ag.global_stats = ? AND ag.type = ?)
	`

	args := []interface{}{false, mobius.AggregatedStatsTypeScheduledQuery}
	whereClauses := "WHERE saved = true"

	switch {
	case opt.TeamID != nil && opt.MergeInherited:
		args = append(args, *opt.TeamID)
		whereClauses += " AND (team_id = ? OR team_id IS NULL)"
	case opt.TeamID != nil:
		args = append(args, *opt.TeamID)
		whereClauses += " AND team_id = ?"
	default:
		whereClauses += " AND team_id IS NULL"
	}

	if opt.IsScheduled != nil {
		if *opt.IsScheduled {
			whereClauses += " AND (q.schedule_interval>0 AND q.automations_enabled=1)"
		} else {
			whereClauses += " AND (q.schedule_interval=0 OR q.automations_enabled=0)"
		}
	}

	if opt.Platform != nil {
		qs := fmt.Sprintf("%%%s%%", *opt.Platform)
		args = append(args, qs)
		whereClauses += ` AND (q.platform LIKE ? OR q.platform = '')`
	}

	// normalize the name for full Unicode support (Unicode equivalence).
	normMatch := norm.NFC.String(opt.MatchQuery)
	whereClauses, args = searchLike(whereClauses, args, normMatch, querySearchColumns...)

	getQueriesStmt += whereClauses

	// build the count statement before adding pagination constraints
	getQueriesCountStmt := fmt.Sprintf("SELECT COUNT(DISTINCT id) FROM (%s) AS s", getQueriesStmt)

	getQueriesStmt, args = appendListOptionsWithCursorToSQL(getQueriesStmt, args, &opt.ListOptions)

	dbReader := ds.reader(ctx)
	queries := []*mobius.Query{}
	if err := sqlx.SelectContext(ctx, dbReader, &queries, getQueriesStmt, args...); err != nil {
		return nil, 0, nil, ctxerr.Wrap(ctx, err, "listing queries")
	}

	// perform a second query to grab the count
	var count int
	if err := sqlx.GetContext(ctx, dbReader, &count, getQueriesCountStmt, args...); err != nil {
		return nil, 0, nil, ctxerr.Wrap(ctx, err, "get queries count")
	}

	if err := ds.loadPacksForQueries(ctx, queries); err != nil {
		return nil, 0, nil, ctxerr.Wrap(ctx, err, "loading packs for queries")
	}

	if err := ds.loadLabelsForQueries(ctx, queries); err != nil {
		return nil, 0, nil, ctxerr.Wrap(ctx, err, "loading labels for queries")
	}

	var meta *mobius.PaginationMetadata
	if opt.ListOptions.IncludeMetadata {
		meta = &mobius.PaginationMetadata{HasPreviousResults: opt.ListOptions.Page > 0}
		// `appendListOptionsWithCursorToSQL` used above to build the query statement will cause this
		// discrepancy
		if len(queries) > int(opt.ListOptions.PerPage) { //nolint:gosec // dismiss G115
			meta.HasNextResults = true
			queries = queries[:len(queries)-1]
		}
	}

	return queries, count, meta, nil
}

// loadPacksForQueries loads the user packs (aka 2017 packs) associated with the provided queries.
func (ds *Datastore) loadPacksForQueries(ctx context.Context, queries []*mobius.Query) error {
	return loadPacksForQueries(ctx, ds.reader(ctx), queries)
}

func loadPacksForQueries(ctx context.Context, db sqlx.QueryerContext, queries []*mobius.Query) error {
	if len(queries) == 0 {
		return nil
	}

	// packs.pack_type is NULL for user created packs (aka 2017 packs).
	sql := `
		SELECT p.*, sq.query_name AS query_name
		FROM packs p
		JOIN scheduled_queries sq
			ON p.id = sq.pack_id
		WHERE query_name IN (?) AND p.pack_type IS NULL
	`

	// Used to map the results
	name_queries := map[string]*mobius.Query{}
	// Used for the IN clause
	names := []string{}
	for _, q := range queries {
		q.Packs = make([]mobius.Pack, 0)
		names = append(names, q.Name)
		name_queries[q.Name] = q
	}

	query, args, err := sqlx.In(sql, names)
	if err != nil {
		return ctxerr.Wrap(ctx, err, "building query in load packs for queries")
	}

	rows := []struct {
		QueryName string `db:"query_name"`
		mobius.Pack
	}{}

	err = sqlx.SelectContext(ctx, db, &rows, query, args...)
	if err != nil {
		return ctxerr.Wrap(ctx, err, "selecting load packs for queries")
	}

	for _, row := range rows {
		q := name_queries[row.QueryName]
		q.Packs = append(q.Packs, row.Pack)
	}

	return nil
}

func (ds *Datastore) loadLabelsForQueries(ctx context.Context, queries []*mobius.Query) error {
	return loadLabelsForQueries(ctx, ds.reader(ctx), queries)
}

func loadLabelsForQueries(ctx context.Context, db sqlx.QueryerContext, queries []*mobius.Query) error {
	if len(queries) == 0 {
		return nil
	}

	sql := `
		SELECT
			ql.query_id AS query_id,
			ql.label_id AS label_id,
			l.name AS label_name
		FROM query_labels ql
		INNER JOIN labels l ON l.id = ql.label_id
		WHERE ql.query_id IN (?)
	`

	queryIDs := []uint{}
	for _, query := range queries {
		query.LabelsIncludeAny = nil
		queryIDs = append(queryIDs, query.ID)
	}

	stmt, args, err := sqlx.In(sql, queryIDs)
	if err != nil {
		return ctxerr.Wrap(ctx, err, "building query to load labels for queries")
	}

	queryMap := make(map[uint]*mobius.Query, len(queries))
	for _, query := range queries {
		queryMap[query.ID] = query
	}

	rows := []struct {
		QueryID   uint   `db:"query_id"`
		LabelID   uint   `db:"label_id"`
		LabelName string `db:"label_name"`
	}{}

	err = sqlx.SelectContext(ctx, db, &rows, stmt, args...)
	if err != nil {
		return ctxerr.Wrap(ctx, err, "selecting labels for queries")
	}

	for _, row := range rows {
		queryMap[row.QueryID].LabelsIncludeAny = append(queryMap[row.QueryID].LabelsIncludeAny, mobius.LabelIdent{LabelID: row.LabelID, LabelName: row.LabelName})
	}

	return nil
}

func (ds *Datastore) ObserverCanRunQuery(ctx context.Context, queryID uint) (bool, error) {
	sql := `
		SELECT observer_can_run
		FROM queries
		WHERE id = ?
	`
	var observerCanRun bool
	err := sqlx.GetContext(ctx, ds.reader(ctx), &observerCanRun, sql, queryID)
	if err != nil {
		return false, ctxerr.Wrap(ctx, err, "selecting observer_can_run")
	}

	return observerCanRun, nil
}

func (ds *Datastore) ListScheduledQueriesForAgents(ctx context.Context, teamID *uint, hostID *uint, queryReportsDisabled bool) ([]*mobius.Query, error) {
	sqlStmt := `
		SELECT
			q.name,
			q.query,
			q.team_id,
			q.schedule_interval,
			q.platform,
			q.min_osquery_version,
			q.automations_enabled,
			q.logging_type,
			q.discard_data
		FROM queries q
		WHERE q.saved = true
		AND (
			q.schedule_interval > 0 AND
			%s AND
			(
				q.automations_enabled
				OR
				(NOT q.discard_data AND NOT ? AND q.logging_type = ?)
			)
		)%s`

	args := []interface{}{}
	teamSQL := " team_id IS NULL"
	if teamID != nil {
		args = append(args, *teamID)
		teamSQL = " team_id = ?"
	}
	args = append(args, queryReportsDisabled, mobius.LoggingSnapshot)
	labelSQL := ""
	if hostID != nil {
		labelSQL = `
		-- Query has a tag in common with the host
		AND (EXISTS (
			SELECT 1
			FROM query_labels ql
			JOIN label_membership hl ON (hl.host_id = ? AND hl.label_id = ql.label_id)
			WHERE ql.query_id = q.id
		-- Query has no tags
		) OR NOT EXISTS (
			SELECT 1
			FROM query_labels ql
			WHERE ql.query_id = q.id
		))`
		args = append(args, hostID)
	}
	sqlStmt = fmt.Sprintf(sqlStmt, teamSQL, labelSQL)

	results := []*mobius.Query{}
	if err := sqlx.SelectContext(ctx, ds.reader(ctx), &results, sqlStmt, args...); err != nil {
		return nil, ctxerr.Wrap(ctx, err, "list scheduled queries for agents")
	}

	return results, nil
}

func (ds *Datastore) CleanupGlobalDiscardQueryResults(ctx context.Context) error {
	deleteStmt := "DELETE FROM query_results"
	_, err := ds.writer(ctx).ExecContext(ctx, deleteStmt)
	if err != nil {
		return ctxerr.Wrapf(ctx, err, "delete all from query_results")
	}

	return nil
}

// IsSavedQuery returns true if the given query is a saved query.
func (ds *Datastore) IsSavedQuery(ctx context.Context, queryID uint) (bool, error) {
	stmt := `
		SELECT saved
		FROM queries
		WHERE id = ?
	`
	var result bool
	err := sqlx.GetContext(ctx, ds.reader(ctx), &result, stmt, queryID)
	return result, err
}

// GetLiveQueryStats returns the live query stats for the given query and hosts.
func (ds *Datastore) GetLiveQueryStats(ctx context.Context, queryID uint, hostIDs []uint) ([]*mobius.LiveQueryStats, error) {
	stmt, args, err := sqlx.In(
		`SELECT host_id, average_memory, executions, system_time, user_time, wall_time, output_size, last_executed
		FROM scheduled_query_stats
		WHERE host_id IN (?) AND scheduled_query_id = ? AND query_type = ?
	`, hostIDs, queryID, statsLiveQueryType,
	)
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err, "building get live query stats stmt")
	}

	results := []*mobius.LiveQueryStats{}
	if err := sqlx.SelectContext(ctx, ds.reader(ctx), &results, stmt, args...); err != nil {
		return nil, ctxerr.Wrap(ctx, err, "get live query stats")
	}
	return results, nil
}

// UpdateLiveQueryStats writes new stats as a batch
func (ds *Datastore) UpdateLiveQueryStats(ctx context.Context, queryID uint, stats []*mobius.LiveQueryStats) error {
	if len(stats) == 0 {
		return nil
	}

	// Bulk insert/update
	const valueStr = "(?,?,?,?,?,?,?,?,?,?,?,?),"
	stmt := "REPLACE INTO scheduled_query_stats (scheduled_query_id, host_id, query_type, executions, average_memory, system_time, user_time, wall_time, output_size, denylisted, schedule_interval, last_executed) VALUES " +
		strings.Repeat(valueStr, len(stats))
	stmt = strings.TrimSuffix(stmt, ",")

	var args []interface{}
	for _, s := range stats {
		args = append(
			args, queryID, s.HostID, statsLiveQueryType, s.Executions, s.AverageMemory, s.SystemTime, s.UserTime, s.WallTime, s.OutputSize,
			0, 0, s.LastExecuted,
		)
	}
	_, err := ds.writer(ctx).ExecContext(ctx, stmt, args...)
	if err != nil {
		return ctxerr.Wrap(ctx, err, "update live query stats")
	}
	return nil
}

func numSavedQueriesDB(ctx context.Context, db sqlx.QueryerContext) (int, error) {
	var count int
	const stmt = `
		SELECT count(*) FROM queries WHERE saved
  	`
	if err := sqlx.GetContext(ctx, db, &count, stmt); err != nil {
		return 0, err
	}

	return count, nil
}
