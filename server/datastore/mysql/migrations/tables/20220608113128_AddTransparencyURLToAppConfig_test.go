package tables

import (
	"encoding/json"
	"testing"

	"github.com/notawar/mobius/server/mobius"
	"github.com/stretchr/testify/require"
)

func TestUp_20220608113128(t *testing.T) {
	db := applyUpToPrev(t)

	var prevRaw []byte
	var prevConfig mobius.AppConfig
	err := db.Get(&prevRaw, `SELECT json_value FROM app_config_json`)
	require.NoError(t, err)

	err = json.Unmarshal(prevRaw, &prevConfig)
	require.NoError(t, err)
	require.Empty(t, prevConfig.MobiusDesktop.TransparencyURL)

	applyNext(t, db)

	var newRaw []byte
	var newConfig mobius.AppConfig
	err = db.Get(&newRaw, `SELECT json_value FROM app_config_json`)
	require.NoError(t, err)

	err = json.Unmarshal(newRaw, &newConfig)
	require.NoError(t, err)
	require.Equal(t, "", newConfig.MobiusDesktop.TransparencyURL)
}
