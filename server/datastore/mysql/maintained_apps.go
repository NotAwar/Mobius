package mysql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/notawar/mobius/v4/server/contexts/ctxerr"
	"github.com/notawar/mobius set/v4/server/mobius"
	"github.com/jmoiron/sqlx"
)

func (ds *Datastore) UpsertMaintainedApp(ctx context.Context, app *mobius.MaintainedApp) (*mobius.MaintainedApp, error) {
	const upsertStmt = `
INSERT INTO
	mobius_maintained_apps (name, slug, platform, unique_identifier)
VALUES
	(?, ?, ?, ?)
ON DUPLICATE KEY UPDATE
	name = VALUES(name),
	platform = VALUES(platform),
	unique_identifier = VALUES(unique_identifier)
`

	var appID uint
	err := ds.withRetryTxx(ctx, func(tx sqlx.ExtContext) error {
		var err error

		// upsert the maintained app
		res, err := tx.ExecContext(ctx, upsertStmt, app.Name, app.Slug, app.Platform, app.UniqueIdentifier)
		if err != nil {
			return ctxerr.Wrap(ctx, err, "upsert maintained app")
		}
		id, _ := res.LastInsertId()
		appID = uint(id) //nolint:gosec // dismiss G115
		return nil
	})
	if err != nil {
		return nil, err
	}

	app.ID = appID
	return app, nil
}

const teamFMATitlesJoin = `
			team_titles.id software_title_id FROM mobius_maintained_apps fma
			LEFT JOIN (
				SELECT DISTINCT st.id, st.unique_identifier
				FROM software_titles st
				LEFT JOIN
					software_installers si
					ON si.title_id = st.id AND si.global_or_team_id = ?
					AND si.platform IN ('darwin','windows')
				LEFT JOIN
					vpp_apps va
					ON va.title_id = st.id
					AND va.platform = 'darwin'
				LEFT JOIN
					vpp_apps_teams vat
					ON vat.adam_id = va.adam_id
					AND vat.platform = va.platform
					AND vat.global_or_team_id = ?
				WHERE si.id IS NOT NULL OR vat.id IS NOT NULL
			) team_titles ON team_titles.unique_identifier = fma.unique_identifier`

func (ds *Datastore) GetMaintainedAppByID(ctx context.Context, appID uint, teamID *uint) (*mobius.MaintainedApp, error) {
	stmt := `SELECT fma.id, fma.name, fma.platform, fma.unique_identifier, fma.slug, `
	var args []any

	if teamID != nil {
		stmt += teamFMATitlesJoin
		args = []any{teamID, teamID}
	} else {
		stmt += `NULL software_title_id FROM mobius_maintained_apps fma`
	}

	stmt += ` WHERE fma.id = ?`
	args = append(args, appID)

	var app mobius.MaintainedApp
	if err := sqlx.GetContext(ctx, ds.reader(ctx), &app, stmt, args...); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ctxerr.Wrap(ctx, notFound("MaintainedApp"), "no matching maintained app found")
		}

		return nil, ctxerr.Wrap(ctx, err, "getting maintained app by id")
	}

	return &app, nil
}

func (ds *Datastore) GetMaintainedAppBySlug(ctx context.Context, slug string, teamID *uint) (*mobius.MaintainedApp, error) {
	stmt := `SELECT fma.id, fma.name, fma.platform, fma.unique_identifier, fma.slug, `
	var args []any

	if teamID != nil {
		stmt += teamFMATitlesJoin
		args = []any{teamID, teamID}
	} else {
		stmt += `NULL software_title_id FROM mobius_maintained_apps fma`
	}

	stmt += ` WHERE fma.slug = ?`
	args = append(args, slug)

	var app mobius.MaintainedApp
	if err := sqlx.GetContext(ctx, ds.reader(ctx), &app, stmt, args...); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ctxerr.Wrap(ctx, notFound("MaintainedApp"), "no matching maintained app found")
		}

		return nil, ctxerr.Wrap(ctx, err, "getting maintained app by slug")
	}

	return &app, nil
}

func (ds *Datastore) ListAvailableMobiusMaintainedApps(ctx context.Context, teamID *uint, opt mobius.ListOptions) ([]mobius.MaintainedApp, *mobius.PaginationMetadata, error) {
	stmt := `SELECT fma.id, fma.name, fma.platform, fma.slug, `
	var args []any

	if teamID != nil {
		stmt += teamFMATitlesJoin + ` WHERE TRUE`
		args = []any{teamID, teamID}
	} else {
		stmt += `NULL software_title_id FROM mobius_maintained_apps fma`
	}

	if match := opt.MatchQuery; match != "" {
		match = likePattern(match)
		stmt += ` AND (fma.name LIKE ?)`
		args = append(args, match)
	}

	// perform a second query to grab the filtered count. Build the count statement before
	// adding the pagination constraints to the stmt but after including the
	// MatchQuery option sql.
	dbReader := ds.reader(ctx)
	getAppsCountStmt := fmt.Sprintf(`SELECT COUNT(DISTINCT s.id) FROM (%s) AS s`, stmt)
	var filteredCount int
	if err := sqlx.GetContext(ctx, dbReader, &filteredCount, getAppsCountStmt, args...); err != nil {
		return nil, nil, ctxerr.Wrap(ctx, err, "get mobius maintained apps count")
	}

	if filteredCount == 0 { // check if we have nothing in the full apps list, in which case provide an error back
		var totalCount int
		if err := sqlx.GetContext(ctx, dbReader, &totalCount, `SELECT COUNT(id) FROM mobius_maintained_apps`); err != nil {
			return nil, nil, ctxerr.Wrap(ctx, err, "get mobius maintained apps total count")
		}

		if totalCount == 0 {
			return nil, nil, &mobius.NoMaintainedAppsInDatabaseError{}
		}
	}

	stmtPaged, args := appendListOptionsWithCursorToSQL(stmt, args, &opt)

	var avail []mobius.MaintainedApp
	if err := sqlx.SelectContext(ctx, ds.reader(ctx), &avail, stmtPaged, args...); err != nil {
		return nil, nil, ctxerr.Wrap(ctx, err, "selecting available mobius maintained apps")
	}

	meta := &mobius.PaginationMetadata{HasPreviousResults: opt.Page > 0, TotalResults: uint(filteredCount)} //nolint:gosec // dismiss G115
	if len(avail) > int(opt.PerPage) {                                                                     //nolint:gosec // dismiss G115
		meta.HasNextResults = true
		avail = avail[:len(avail)-1]
	}

	return avail, meta, nil
}

func (ds *Datastore) ClearRemovedMobiusMaintainedApps(ctx context.Context, slugsToKeep []string) error {
	stmt := `DELETE FROM mobius_maintained_apps WHERE slug NOT IN (?)`

	var err error
	var args []any
	switch len(slugsToKeep) {
	case 0:
		stmt = `DELETE FROM mobius_maintained_apps`
	default:
		stmt, args, err = sqlx.In(stmt, slugsToKeep)
		if err != nil {
			return ctxerr.Wrap(ctx, err, "building sqlx.In statement for clearing removed maintained apps")
		}
	}

	_, err = ds.writer(ctx).ExecContext(ctx, stmt, args...)
	if err != nil {
		return ctxerr.Wrap(ctx, err, "clearing removed maintained apps")
	}

	return nil
}
