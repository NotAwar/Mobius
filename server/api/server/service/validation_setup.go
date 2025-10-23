package service

import (
	"context"
	"errors"
	"net/url"
	"strings"

	"github.com/notawar/mobius/mobius-server/server/contexts/ctxerr"
	"github.com/notawar/mobius/mobius-server/server/mobius"
)

func (mw validationMiddleware) NewAppConfig(ctx context.Context, payload mobius.AppConfig) (*mobius.AppConfig, error) {
	invalid := &mobius.InvalidArgumentError{}
	var serverURLString string
	if payload.ServerSettings.ServerURL == "" {
		invalid.Append("server_url", "missing required argument")
	} else {
		serverURLString = cleanupURL(payload.ServerSettings.ServerURL)
	}
	if err := ValidateServerURL(serverURLString); err != nil {
		invalid.Append("server_url", err.Error())
	}
	if invalid.HasErrors() {
		return nil, ctxerr.Wrap(ctx, invalid)
	}
	return mw.Service.NewAppConfig(ctx, payload)
}

func ValidateServerURL(urlString string) error {
	// Basic URL validation - checks scheme and host presence
	// Future enhancements could include port validation, path restrictions, etc.

	// no valid scheme provided
	if !(strings.HasPrefix(urlString, "http://") || strings.HasPrefix(urlString, "https://")) {
		return errors.New(mobius.InvalidServerURLMsg)
	}

	// valid scheme provided - require host
	parsed, err := url.Parse(urlString)
	if err != nil {
		return err
	}
	if parsed.Host == "" {
		return errors.New(mobius.InvalidServerURLMsg)
	}

	return nil
}
