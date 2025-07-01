package update

import "github.com/notawar/mobius/v4/server/mobius"

// OrbitConfigFetcher allows fetching Orbit configuration.
type OrbitConfigFetcher interface {
	// GetConfig returns the Orbit configuration.
	GetConfig() (*mobius.OrbitConfig, error)
}
