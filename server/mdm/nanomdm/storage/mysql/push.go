package mysql

import (
	"context"
	"errors"
	"strings"

	"github.com/notawar/mobius/server/mdm/nanomdm/mdm"
)

// RetrievePushInfo retreives push info for identifiers ids.
//
// Note that we may return fewer results than input. The user of this
// method needs to reconcile that with their requested ids.
func (s *MySQLStorage) RetrievePushInfo(ctx context.Context, ids []string) (map[string]*mdm.Push, error) {
	if len(ids) < 1 {
		return nil, errors.New("no ids provided")
	}
	qs := "?" + strings.Repeat(", ?", len(ids)-1)
	args := make([]interface{}, len(ids))
	for i, v := range ids {
		args[i] = v
	}
	//nolint:gosec
	rows, err := s.db.QueryContext(
		ctx,
		`SELECT id, topic, push_magic, token_hex FROM nano_enrollments WHERE id IN (`+qs+`);`,
		args...,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	pushInfos := make(map[string]*mdm.Push)
	for rows.Next() {
		push := new(mdm.Push)
		var id, token string
		if err := rows.Scan(&id, &push.Topic, &push.PushMagic, &token); err != nil {
			return nil, err
		}
		// convert from hex
		if err := push.SetTokenString(token); err != nil {
			return nil, err
		}
		pushInfos[id] = push
	}
	return pushInfos, rows.Err()
}
