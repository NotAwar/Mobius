package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/notawar/mobius/server/contexts/ctxerr"
	"github.com/notawar/mobius/server/mobius"
	"github.com/jmoiron/sqlx"
)

var inviteSearchColumns = []string{"name", "email"}

// NewInvite generates a new invitation.
func (ds *Datastore) NewInvite(ctx context.Context, i *mobius.Invite) (*mobius.Invite, error) {
	if err := mobius.ValidateRole(i.GlobalRole.Ptr(), i.Teams); err != nil {
		return nil, err
	}

	err := ds.withRetryTxx(ctx, func(tx sqlx.ExtContext) error {
		sqlStmt := `
	INSERT INTO invites ( invited_by, email, name, position, token, sso_enabled, mfa_enabled, global_role )
	  VALUES ( ?, ?, ?, ?, ?, ?, ?, ?)
	`

		result, err := tx.ExecContext(ctx, sqlStmt, i.InvitedBy, i.Email,
			i.Name, i.Position, i.Token, i.SSOEnabled, i.MFAEnabled, i.GlobalRole)
		if err != nil && IsDuplicate(err) {
			return ctxerr.Wrap(ctx, alreadyExists("Invite", i.Email))
		} else if err != nil {
			return ctxerr.Wrap(ctx, err, "create invite")
		}

		id, _ := result.LastInsertId()
		i.ID = uint(id) //nolint:gosec // dismiss G115

		if len(i.Teams) == 0 {
			i.Teams = []mobius.UserTeam{}
			return nil
		}

		// Bulk insert teams
		const valueStr = "(?,?,?),"
		var args []interface{}
		for _, userTeam := range i.Teams {
			args = append(args, i.ID, userTeam.Team.ID, userTeam.Role)
		}
		sql := "INSERT INTO invite_teams (invite_id, team_id, role) VALUES " +
			strings.Repeat(valueStr, len(i.Teams))
		sql = strings.TrimSuffix(sql, ",")
		if _, err := tx.ExecContext(ctx, sql, args...); err != nil {
			return ctxerr.Wrap(ctx, err, "insert teams")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return i, nil
}

// ListInvites lists all invites in the Mobius database. Supply query options
// using the opt parameter. See mobius.ListOptions
func (ds *Datastore) ListInvites(ctx context.Context, opt mobius.ListOptions) ([]*mobius.Invite, error) {
	invites := []*mobius.Invite{}
	query := "SELECT * FROM invites WHERE true"
	query, params := searchLike(query, nil, opt.MatchQuery, inviteSearchColumns...)
	query, params = appendListOptionsWithCursorToSQL(query, params, &opt)

	err := sqlx.SelectContext(ctx, ds.reader(ctx), &invites, query, params...)
	if err == sql.ErrNoRows {
		return nil, ctxerr.Wrap(ctx, notFound("Invite"))
	} else if err != nil {
		return nil, ctxerr.Wrap(ctx, err, "select invite by ID")
	}

	if err := ds.loadTeamsForInvites(ctx, invites); err != nil {
		return nil, ctxerr.Wrap(ctx, err, "load teams")
	}

	return invites, nil
}

// Invite returns Invite identified by id.
func (ds *Datastore) Invite(ctx context.Context, id uint) (*mobius.Invite, error) {
	var invite mobius.Invite
	err := sqlx.GetContext(ctx, ds.reader(ctx), &invite, "SELECT * FROM invites WHERE id = ?", id)
	if err == sql.ErrNoRows {
		return nil, ctxerr.Wrap(ctx, notFound("Invite").WithID(id))
	} else if err != nil {
		return nil, ctxerr.Wrap(ctx, err, "select invite by ID")
	}

	if err := ds.loadTeamsForInvites(ctx, []*mobius.Invite{&invite}); err != nil {
		return nil, ctxerr.Wrap(ctx, err, "load teams")
	}

	return &invite, nil
}

// InviteByEmail finds an Invite with a particular email, if one exists.
func (ds *Datastore) InviteByEmail(ctx context.Context, email string) (*mobius.Invite, error) {
	var invite mobius.Invite
	err := sqlx.GetContext(ctx, ds.reader(ctx), &invite, "SELECT * FROM invites WHERE email = ?", email)
	if err == sql.ErrNoRows {
		return nil, ctxerr.Wrap(ctx, notFound("Invite").
			WithMessage(fmt.Sprintf("with email %s", email)))
	} else if err != nil {
		return nil, ctxerr.Wrap(ctx, err, "sqlx get invite by email")
	}

	if err := ds.loadTeamsForInvites(ctx, []*mobius.Invite{&invite}); err != nil {
		return nil, ctxerr.Wrap(ctx, err, "load teams")
	}

	return &invite, nil
}

// InviteByToken finds an Invite with a particular token, if one exists.
func (ds *Datastore) InviteByToken(ctx context.Context, token string) (*mobius.Invite, error) {
	var invite mobius.Invite
	err := sqlx.GetContext(ctx, ds.reader(ctx), &invite, "SELECT * FROM invites WHERE token = ?", token)
	if err == sql.ErrNoRows {
		return nil, ctxerr.Wrap(ctx, notFound("Invite").
			WithMessage(fmt.Sprintf("with token %s", token)))
	} else if err != nil {
		return nil, ctxerr.Wrap(ctx, err, "sqlx get invite by token")
	}

	if err := ds.loadTeamsForInvites(ctx, []*mobius.Invite{&invite}); err != nil {
		return nil, ctxerr.Wrap(ctx, err, "load teams")
	}

	return &invite, nil
}

func (ds *Datastore) DeleteInvite(ctx context.Context, id uint) error {
	return ds.deleteEntity(ctx, invitesTable, id)
}

func (ds *Datastore) loadTeamsForInvites(ctx context.Context, invites []*mobius.Invite) error {
	inviteIDs := make([]uint, 0, len(invites)+1)
	// Make sure the slice is never empty for IN by filling a nonexistent ID
	inviteIDs = append(inviteIDs, 0)
	idToInvite := make(map[uint]*mobius.Invite, len(invites))
	for _, u := range invites {
		// Initialize empty slice so we get an array in JSON responses instead
		// of null if it is empty
		u.Teams = []mobius.UserTeam{}
		// Track IDs for queries and matching
		inviteIDs = append(inviteIDs, u.ID)
		idToInvite[u.ID] = u
	}

	sql := `
		SELECT ut.team_id AS id, ut.invite_id, ut.role, t.name
		FROM invite_teams ut INNER JOIN teams t ON ut.team_id = t.id
		WHERE ut.invite_id IN (?)
		ORDER BY invite_id, team_id
	`
	sql, args, err := sqlx.In(sql, inviteIDs)
	if err != nil {
		return ctxerr.Wrap(ctx, err, "sqlx.In loadTeamsForInvites")
	}

	var rows []struct {
		mobius.UserTeam
		InviteID uint `db:"invite_id"`
	}
	if err := sqlx.SelectContext(ctx, ds.reader(ctx), &rows, sql, args...); err != nil {
		return ctxerr.Wrap(ctx, err, "get loadTeamsForInvites")
	}

	// Map each row to the appropriate invite
	for _, r := range rows {
		invite := idToInvite[r.InviteID]
		invite.Teams = append(invite.Teams, r.UserTeam)
	}

	return nil
}

func (ds *Datastore) UpdateInvite(ctx context.Context, id uint, i *mobius.Invite) (*mobius.Invite, error) {
	return i, ds.withRetryTxx(ctx, func(tx sqlx.ExtContext) error {
		_, err := tx.ExecContext(ctx,
			`UPDATE invites SET invited_by = ?, email = ?, name = ?, position = ?, sso_enabled = ?, mfa_enabled = ?, global_role = ? WHERE id = ?`,
			i.InvitedBy, i.Email, i.Name, i.Position, i.SSOEnabled, i.MFAEnabled, i.GlobalRole, id,
		)
		if err != nil {
			return ctxerr.Wrap(ctx, err, "updating invite")
		}

		_, err = tx.ExecContext(ctx, `DELETE FROM invite_teams WHERE invite_id = ?`, id)
		if err != nil {
			return ctxerr.Wrap(ctx, err, "deleting invite teams")
		}

		for _, team := range i.Teams {
			_, err = tx.ExecContext(ctx, `INSERT INTO invite_teams(invite_id, team_id, role) VALUES(?, ?, ?)`, id, team.ID, team.Role)
			if err != nil {
				return ctxerr.Wrap(ctx, err, "updating invite teams")
			}
		}
		return nil
	})
}
