// Package host enables setting and reading
// the current host from context
package host

import (
	"context"

	"github.com/notawar/mobius/server/mobius"
)

type key int

const hostKey key = 0

// NewContext returns a new context carrying the current osquery host.
func NewContext(ctx context.Context, host *mobius.Host) context.Context {
	return context.WithValue(ctx, hostKey, host)
}

// FromContext extracts the osquery host from context if present.
func FromContext(ctx context.Context) (*mobius.Host, bool) {
	host, ok := ctx.Value(hostKey).(*mobius.Host)
	return host, ok
}
