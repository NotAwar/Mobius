package service

import (
	"context"
	"errors"
	"net/url"
	"strings"

	"github.com/notawar/mobius/v4/server/contexts/ctxerr"
	"github.com/notawar/mobius/v4/server/mobius"
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
	// TODO - implement more robust URL validation here

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
