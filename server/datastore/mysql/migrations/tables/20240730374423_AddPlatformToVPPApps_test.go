package tables

import (
	"testing"

	"github.com/notawar/mobius/server/mobius"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUp_20240730374423(t *testing.T) {
	db := applyUpToPrev(t)

	adamID := "a"
	execNoErr(
		t, db, `INSERT INTO vpp_apps (adam_id) VALUES (?)`, adamID,
	)

	vppAppsID := 1
	execNoErr(
		t, db, `INSERT INTO vpp_apps_teams (id, adam_id) VALUES (?,?)`, vppAppsID, adamID,
	)

	// Apply current migration.
	applyNext(t, db)

	var platform mobius.AppleDevicePlatform
	require.NoError(t, db.Get(&platform, `SELECT platform FROM vpp_apps WHERE adam_id = ?`, adamID))
	assert.Equal(t, mobius.MacOSPlatform, platform)

	require.NoError(t, db.Get(&platform, `SELECT platform FROM vpp_apps_teams WHERE adam_id = ?`, adamID))
	assert.Equal(t, mobius.MacOSPlatform, platform)

	// Try to insert the same adam_id again but for a different platform.
	execNoErr(
		t, db, `INSERT INTO vpp_apps (adam_id, platform) VALUES (?,?)`, adamID, mobius.IOSPlatform,
	)
	execNoErr(
		t, db, `INSERT INTO vpp_apps_teams (id, adam_id, platform) VALUES (?,?,?)`, vppAppsID+1, adamID, mobius.IOSPlatform,
	)

}
