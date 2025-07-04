package scepclient

import (
	"time"

	scepserver "github.com/notawar/mobius/server/mdm/scep/server"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
)

// Client is a SCEP Client
type Client interface {
	scepserver.Service
	Supports(capacity string) bool
}

// New creates a SCEP Client.
func New(
	serverURL string,
	logger log.Logger,
	timeout *time.Duration,
) (Client, error) {
	endpoints, err := scepserver.MakeClientEndpoints(serverURL, timeout)
	if err != nil {
		return nil, err
	}
	logger = level.Info(logger)
	endpoints.GetEndpoint = scepserver.EndpointLoggingMiddleware(logger)(endpoints.GetEndpoint)
	endpoints.PostEndpoint = scepserver.EndpointLoggingMiddleware(logger)(endpoints.PostEndpoint)
	return endpoints, nil
}
