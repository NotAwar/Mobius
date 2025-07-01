package capabilities

import (
	"context"
	"net/http"
	"testing"

	"github.com/notawar/mobius/v4/server/mobius"
	"github.com/stretchr/testify/require"
)

func TestCapabilitiesExist(t *testing.T) {
	cases := []struct {
		name string
		in   string
		out  mobius.CapabilityMap
	}{
		{"empty", "", mobius.CapabilityMap{}},
		{"one", "test", mobius.CapabilityMap{mobius.Capability("test"): struct{}{}}},
		{
			"many",
			"test,foo,bar",
			mobius.CapabilityMap{
				mobius.Capability("test"): struct{}{},
				mobius.Capability("foo"):  struct{}{},
				mobius.Capability("bar"):  struct{}{},
			},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			r := http.Request{
				Header: http.Header{mobius.CapabilitiesHeader: []string{tt.in}},
			}
			ctx := NewContext(context.Background(), &r)
			mp, ok := FromContext(ctx)
			require.True(t, ok)
			require.Equal(t, tt.out, mp)
		})
	}
}

func TestCapabilitiesNotExist(t *testing.T) {
	mp, ok := FromContext(context.Background())
	require.False(t, ok)
	require.Nil(t, mp)
}
