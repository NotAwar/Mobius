package license

import (
	"context"
	"testing"

	"github.com/notawar/mobius/server/mobius"
	"github.com/stretchr/testify/require"
)

func TestIsPremium(t *testing.T) {
	cases := []struct {
		desc string
		ctx  context.Context
		want bool
	}{
		{"no license", context.Background(), false},
		{"free license", NewContext(context.Background(), &mobius.LicenseInfo{Tier: mobius.TierFree}), false},
		{"premium license", NewContext(context.Background(), &mobius.LicenseInfo{Tier: mobius.TierPremium}), true},
	}
	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			got := IsPremium(c.ctx)
			require.Equal(t, c.want, got)
		})
	}
}
