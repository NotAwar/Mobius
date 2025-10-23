package service

import (
	"context"
	"encoding/json"
	"fmt"

	kithttp "github.com/go-kit/kit/transport/http"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/notawar/mobius/mobius-server/server/contexts/logging"
	"github.com/notawar/mobius/mobius-server/server/mobius"
	middleware_log "github.com/notawar/mobius/mobius-server/server/service/middleware/log"

	"github.com/go-kit/kit/endpoint"
	authz_ctx "github.com/notawar/mobius/mobius-server/server/contexts/authz"
	hostctx "github.com/notawar/mobius/mobius-server/server/contexts/host"
)

func logJSON(logger log.Logger, v interface{}, key string) {
	jsonV, err := json.Marshal(v)
	if err != nil {
		level.Debug(logger).Log("err", fmt.Errorf("marshaling %s for debug: %w", key, err))
		return
	}
	level.Debug(logger).Log(key, string(jsonV))
}

// instrumentHostLogger adds host ID, IP information, and extras to the context logger.
func instrumentHostLogger(ctx context.Context, hostID uint, extras ...interface{}) {
	remoteAddr, _ := ctx.Value(kithttp.ContextKeyRequestRemoteAddr).(string)
	xForwardedFor, _ := ctx.Value(kithttp.ContextKeyRequestXForwardedFor).(string)
	logging.WithExtras(
		logging.WithNoUser(ctx),
		append(extras,
			"host_id", hostID,
			"ip_addr", remoteAddr,
			"x_for_ip_addr", xForwardedFor,
		)...,
	)
}

func authenticatedDevice(svc mobius.Service, logger log.Logger, next endpoint.Endpoint) endpoint.Endpoint {
	authDeviceFunc := func(ctx context.Context, request interface{}) (interface{}, error) {
		token, err := getDeviceAuthToken(request)
		if err != nil {
			return nil, err
		}

		host, debug, err := svc.AuthenticateDevice(ctx, token)
		if err != nil {
			logging.WithErr(ctx, err)
			return nil, err
		}

		hlogger := log.With(logger, "host_id", host.ID)
		if debug {
			logJSON(hlogger, request, "request")
		}

		ctx = hostctx.NewContext(ctx, host)
		instrumentHostLogger(ctx, host.ID)
		if ac, ok := authz_ctx.FromContext(ctx); ok {
			ac.SetAuthnMethod(authz_ctx.AuthnDeviceToken)
		}

		resp, err := next(ctx, request)
		if err != nil {
			return nil, err
		}

		if debug {
			logJSON(hlogger, request, "response")
		}
		return resp, nil
	}
	return middleware_log.Logged(authDeviceFunc)
}

func getDeviceAuthToken(r interface{}) (string, error) {
	if dat, ok := r.(interface{ deviceAuthToken() string }); ok {
		return dat.deviceAuthToken(), nil
	}
	return "", mobius.NewAuthRequiredError("request type does not implement deviceAuthToken method. This is likely a Mobius programmer error.")
}

// authenticatedHost wraps an endpoint, checks the validity of the node_key
// provided in the request, and attaches the corresponding osquery host to the
// context for the request
func authenticatedHost(svc mobius.Service, logger log.Logger, next endpoint.Endpoint) endpoint.Endpoint {
	authHostFunc := func(ctx context.Context, request interface{}) (interface{}, error) {
		nodeKey, err := getNodeKey(request)
		if err != nil {
			return nil, err
		}

		host, debug, err := svc.AuthenticateHost(ctx, nodeKey)
		if err != nil {
			logging.WithErr(ctx, err)
			return nil, err
		}

		hlogger := log.With(logger, "host_id", host.ID)
		if debug {
			logJSON(hlogger, request, "request")
		}

		ctx = hostctx.NewContext(ctx, host)
		instrumentHostLogger(ctx, host.ID)
		if ac, ok := authz_ctx.FromContext(ctx); ok {
			ac.SetAuthnMethod(authz_ctx.AuthnHostToken)
		}

		resp, err := next(ctx, request)
		if err != nil {
			return nil, err
		}

		if debug {
			logJSON(hlogger, resp, "response")
		}
		return resp, nil
	}
	return middleware_log.Logged(authHostFunc)
}



func getNodeKey(r interface{}) (string, error) {
	if hnk, ok := r.(interface{ hostNodeKey() string }); ok {
		return hnk.hostNodeKey(), nil
	}
	return "", newOsqueryError("request type does not implement hostNodeKey method. This is likely a Mobius programmer error.")
}
