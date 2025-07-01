package test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/notawar/mobius/v4/server/mobius"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func SetOrbitEnrollment(t *testing.T, h *mobius.Host, ds mobius.Datastore) string {
	orbitKey := uuid.New().String()
	_, err := ds.EnrollOrbit(context.Background(), false, mobius.OrbitHostInfo{
		HardwareUUID:   *h.OsqueryHostID,
		HardwareSerial: h.HardwareSerial,
	}, orbitKey, h.TeamID)
	require.NoError(t, err)
	err = ds.SetOrUpdateHostOrbitInfo(
		context.Background(), h.ID, "1.22.0", sql.NullString{String: "42", Valid: true}, sql.NullBool{Bool: true, Valid: true},
	)
	require.NoError(t, err)
	return orbitKey
}
