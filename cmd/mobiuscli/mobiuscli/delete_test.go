package mobiuscli

import (
	"context"
	"testing"
	"time"

	"github.com/notawar/mobius/v4/cmd/mobiuscli/mobiuscli/testing_utils"
	"github.com/notawar/mobius set/v4/server/mobius"
	"github.com/stretchr/testify/assert"
)

func TestDeleteLabel(t *testing.T) {
	_, ds := testing_utils.RunServerWithMockedDS(t)

	var deletedLabel string
	ds.DeleteLabelFunc = func(ctx context.Context, name string) error {
		deletedLabel = name
		return nil
	}

	name := writeTmpYml(t, `---
apiVersion: v1
kind: label
spec:
  name: pending_updates
  query: select 1;
  platforms:
    - darwin
`)

	assert.Equal(t, "", RunAppForTest(t, []string{"delete", "-f", name}))
	assert.True(t, ds.DeleteLabelFuncInvoked)
	assert.Equal(t, "pending_updates", deletedLabel)
}

func TestDeletePack(t *testing.T) {
	_, ds := testing_utils.RunServerWithMockedDS(t)

	var deletedPack string
	ds.DeletePackFunc = func(ctx context.Context, name string) error {
		deletedPack = name
		return nil
	}
	ds.PackByNameFunc = func(ctx context.Context, name string, opts ...mobius.OptionalArg) (*mobius.Pack, bool, error) {
		if name != "pack1" {
			return nil, false, nil
		}
		return &mobius.Pack{
			ID:          7,
			Name:        "pack1",
			Description: "some desc",
			Platform:    "darwin",
			Disabled:    false,
		}, true, nil
	}
	ds.NewActivityFunc = func(
		ctx context.Context, user *mobius.User, activity mobius.ActivityDetails, details []byte, createdAt time.Time,
	) error {
		return nil
	}

	name := writeTmpYml(t, `---
apiVersion: v1
kind: pack
spec:
  description: some desc
  disabled: false
  id: 7
  name: pack1
  platform: darwin
  targets:
    labels: null
`)

	assert.Equal(t, "", RunAppForTest(t, []string{"delete", "-f", name}))
	assert.True(t, ds.DeletePackFuncInvoked)
	assert.Equal(t, "pack1", deletedPack)
}

func TestDeleteQuery(t *testing.T) {
	_, ds := testing_utils.RunServerWithMockedDS(t)

	var deletedQuery string
	ds.DeleteQueryFunc = func(ctx context.Context, teamID *uint, name string) error {
		deletedQuery = name
		return nil
	}
	ds.QueryByNameFunc = func(ctx context.Context, teamID *uint, name string) (*mobius.Query, error) {
		if name != "query1" {
			return nil, nil
		}
		return &mobius.Query{
			ID:             33,
			Name:           "query1",
			Description:    "some desc",
			Query:          "select 1;",
			Saved:          false,
			ObserverCanRun: false,
		}, nil
	}
	ds.NewActivityFunc = func(
		ctx context.Context, user *mobius.User, activity mobius.ActivityDetails, details []byte, createdAt time.Time,
	) error {
		return nil
	}

	name := writeTmpYml(t, `---
apiVersion: v1
kind: query
spec:
  description: some desc
  name: query1
  query: select 1;
`)

	assert.Equal(t, "", RunAppForTest(t, []string{"delete", "-f", name}))
	assert.True(t, ds.DeleteQueryFuncInvoked)
	assert.Equal(t, "query1", deletedQuery)
}
