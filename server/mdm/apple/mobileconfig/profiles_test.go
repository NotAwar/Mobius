package mobileconfig

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
	"howett.net/plist"
)

func TestMobiusdProfileTemplate(t *testing.T) {
	cases := []MobiusdProfileOptions{
		{},
		{PayloadType: "", EnrollSecret: "", ServerURL: "", PayloadName: ""},
		{PayloadType: "test.example", EnrollSecret: "abc", ServerURL: "https://test.example", PayloadName: "test.example"},
	}

	for _, c := range cases {
		// execute template
		var prof bytes.Buffer
		err := MobiusdProfileTemplate.Execute(&prof, c)
		require.NoError(t, err)

		// unmarshal plist and check values
		var out map[string]any
		_, err = plist.Unmarshal(prof.Bytes(), &out)
		require.NoError(t, err)
		contents, ok := out["PayloadContent"].([]any)
		require.True(t, ok)
		pc, ok := contents[0].(map[string]any)
		require.True(t, ok)
		require.Equal(t, c.EnrollSecret, pc["EnrollSecret"])
		require.Equal(t, c.ServerURL, pc["MobiusURL"])
		require.Equal(t, c.PayloadType, pc["PayloadType"])
		require.Equal(t, c.PayloadName, pc["PayloadDisplayName"])
		// script execution is always enabled
		enableScripts, ok := pc["EnableScripts"].(bool)
		require.True(t, ok)
		require.True(t, enableScripts)

	}
}
