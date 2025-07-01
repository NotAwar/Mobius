package mysql

import (
	"context"
	"testing"
	"time"

	"github.com/notawar/mobius/v4/server/ptr"

	"github.com/notawar/mobius set/v4/server/mobius"
	"github.com/notawar/mobius set/v4/server/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnicode(t *testing.T) {
	ds := CreateMySQLDS(t)
	defer ds.Close()

	l1 := mobius.LabelSpec{
		Name:  "測試",
		Query: "query foo",
	}
	err := ds.ApplyLabelSpecs(context.Background(), []*mobius.LabelSpec{&l1})
	require.Nil(t, err)
	l1.ID = labelIDFromName(t, ds, l1.Name)

	filter := mobius.TeamFilter{User: test.UserAdmin}
	label, _, err := ds.Label(context.Background(), l1.ID, filter)
	require.Nil(t, err)
	assert.Equal(t, "測試", label.Name)

	host, err := ds.NewHost(context.Background(), &mobius.Host{
		Hostname:        "🍌",
		DetailUpdatedAt: time.Now(),
		LabelUpdatedAt:  time.Now(),
		PolicyUpdatedAt: time.Now(),
		SeenTime:        time.Now(),
	})
	require.Nil(t, err)

	host, err = ds.Host(context.Background(), host.ID)
	require.Nil(t, err)
	assert.Equal(t, "🍌", host.Hostname)

	user, err := ds.NewUser(context.Background(), &mobius.User{
		Name:       "🍱",
		Email:      "test@example.com",
		Password:   []byte{},
		GlobalRole: ptr.String(mobius.RoleObserver),
	})
	require.Nil(t, err)

	user, err = ds.UserByID(context.Background(), user.ID)
	require.Nil(t, err)
	assert.Equal(t, "🍱", user.Name)

	pack := test.NewPack(t, ds, "👨🏾‍🚒")

	pack, err = ds.Pack(context.Background(), pack.ID)
	require.Nil(t, err)
	assert.Equal(t, "👨🏾‍🚒", pack.Name)
}
