package mobius_test

import (
	"encoding/json"
	"testing"

	"github.com/notawar/mobius/v4/server/mobius"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTargetTypeJSON(t *testing.T) {
	testCases := []struct {
		expected  mobius.TargetType
		shouldErr bool
	}{
		{mobius.TargetLabel, false},
		{mobius.TargetHost, false},
		{mobius.TargetTeam, false},
		{mobius.TargetType(37), true},
	}
	for _, tt := range testCases {
		t.Run(tt.expected.String(), func(t *testing.T) {
			b, err := json.Marshal(tt.expected)
			require.NoError(t, err)
			var target mobius.TargetType
			err = json.Unmarshal(b, &target)
			if tt.shouldErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, target)
			}
		})
	}
}
