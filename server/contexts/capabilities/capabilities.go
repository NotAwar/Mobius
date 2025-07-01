package capabilities

import (
	"context"
	"net/http"

	"github.com/notawar/mobius/v4/server/mobius"
)

type key int

const capabilitiesKey key = 0

// NewContext creates a new context with the given capabilities.
func NewContext(ctx context.Context, r *http.Request) context.Context {
	capabilities := mobius.CapabilityMap{}
	capabilities.PopulateFromString(r.Header.Get(mobius.CapabilitiesHeader))
	return context.WithValue(ctx, capabilitiesKey, capabilities)
}

// FromContext returns the capabilities in the request if present.
func FromContext(ctx context.Context) (mobius.CapabilityMap, bool) {
	v, ok := ctx.Value(capabilitiesKey).(mobius.CapabilityMap)
	return v, ok
}
