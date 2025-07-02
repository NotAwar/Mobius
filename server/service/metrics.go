package service

import (
	"github.com/notawar/mobius/server/mobius"
	"github.com/go-kit/kit/metrics"
)

type metricsMiddleware struct {
	mobius.Service
	requestCount   metrics.Counter
	requestLatency metrics.Histogram
}

// NewMetricsService service takes an existing service and wraps it
// with instrumentation middleware.
func NewMetricsService(
	svc mobius.Service,
	requestCount metrics.Counter,
	requestLatency metrics.Histogram,
) mobius.Service {
	return metricsMiddleware{
		Service:        svc,
		requestCount:   requestCount,
		requestLatency: requestLatency,
	}
}
