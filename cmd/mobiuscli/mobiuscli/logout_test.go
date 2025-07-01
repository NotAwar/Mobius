package mobiuscli

import (
	"context"
	"testing"
	"time"

	"github.com/notawar/mobius/v4/cmd/mobiuscli/mobiuscli/testing_utils"
	"github.com/notawar/mobius set/v4/server/mobius"
	"github.com/stretchr/testify/assert"
)

func TestLogout(t *testing.T) {
	_, ds := testing_utils.RunServerWithMockedDS(t)

	ds.SessionByIDFunc = func(ctx context.Context, id uint) (*mobius.Session, error) {
		return &mobius.Session{
			ID:         333,
			AccessedAt: time.Now(),
			UserID:     123,
			Key:        "12344321",
		}, nil
	}
	ds.DestroySessionFunc = func(ctx context.Context, session *mobius.Session) error {
		return nil
	}

	assert.Equal(t, "", RunAppForTest(t, []string{"logout"}))
	assert.True(t, ds.DestroySessionFuncInvoked)
}
