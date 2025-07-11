package service

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"reflect"

	"github.com/notawar/mobius/server/contexts/capabilities"
	"github.com/notawar/mobius/server/mobius"
	"github.com/notawar/mobius/server/service/middleware/auth"
	eu "github.com/notawar/mobius/server/service/middleware/endpoint_utils"
	"github.com/go-kit/kit/endpoint"
	kithttp "github.com/go-kit/kit/transport/http"
	"github.com/go-kit/log"
	"github.com/gorilla/mux"
)

func makeDecoder(iface interface{}) kithttp.DecodeRequestFunc {
	return eu.MakeDecoder(iface, jsonDecode, parseCustomTags, isBodyDecoder, decodeBody)
}

// A value that implements bodyDecoder takes control of decoding the request body.
type bodyDecoder interface {
	DecodeBody(ctx context.Context, r io.Reader, u url.Values, c []*x509.Certificate) error
}

func decodeBody(ctx context.Context, r *http.Request, v reflect.Value, body io.Reader) error {
	bd := v.Interface().(bodyDecoder)
	var certs []*x509.Certificate
	if (r.TLS != nil) && (r.TLS.PeerCertificates != nil) {
		certs = r.TLS.PeerCertificates
	}

	if err := bd.DecodeBody(ctx, body, r.URL.Query(), certs); err != nil {
		return err
	}
	return nil
}

func parseCustomTags(urlTagValue string, r *http.Request, field reflect.Value) (bool, error) {
	switch urlTagValue {
	case "list_options":
		opts, err := listOptionsFromRequest(r)
		if err != nil {
			return false, err
		}
		field.Set(reflect.ValueOf(opts))
		return true, nil

	case "user_options":
		opts, err := userListOptionsFromRequest(r)
		if err != nil {
			return false, err
		}
		field.Set(reflect.ValueOf(opts))
		return true, nil

	case "host_options":
		opts, err := hostListOptionsFromRequest(r)
		if err != nil {
			return false, err
		}
		field.Set(reflect.ValueOf(opts))
		return true, nil

	case "carve_options":
		opts, err := carveListOptionsFromRequest(r)
		if err != nil {
			return false, err
		}
		field.Set(reflect.ValueOf(opts))
		return true, nil
	}
	return false, nil
}

func jsonDecode(body io.Reader, req any) error {
	return json.NewDecoder(body).Decode(req)
}

func isBodyDecoder(v reflect.Value) bool {
	_, ok := v.Interface().(bodyDecoder)
	return ok
}

// Compile-time check to ensure that endpointer implements Endpointer.
var _ eu.Endpointer[eu.HandlerFunc] = &endpointer{}

type endpointer struct {
	svc mobius.Service
}

func (e *endpointer) CallHandlerFunc(f eu.HandlerFunc, ctx context.Context, request interface{},
	svc interface{}) (mobius.Errorer, error) {
	return f(ctx, request, svc.(mobius.Service))
}

func (e *endpointer) Service() interface{} {
	return e.svc
}

func newUserAuthenticatedEndpointer(svc mobius.Service, opts []kithttp.ServerOption, r *mux.Router,
	versions ...string) *eu.CommonEndpointer[eu.HandlerFunc] {
	return &eu.CommonEndpointer[eu.HandlerFunc]{
		EP: &endpointer{
			svc: svc,
		},
		MakeDecoderFn: makeDecoder,
		EncodeFn:      encodeResponse,
		Opts:          opts,
		AuthFunc:      auth.AuthenticatedUser,
		MobiusService:  svc,
		Router:        r,
		Versions:      versions,
	}
}

func newNoAuthEndpointer(svc mobius.Service, opts []kithttp.ServerOption, r *mux.Router,
	versions ...string) *eu.CommonEndpointer[eu.HandlerFunc] {
	return &eu.CommonEndpointer[eu.HandlerFunc]{
		EP: &endpointer{
			svc: svc,
		},
		MakeDecoderFn: makeDecoder,
		EncodeFn:      encodeResponse,
		Opts:          opts,
		AuthFunc:      auth.UnauthenticatedRequest,
		MobiusService:  svc,
		Router:        r,
		Versions:      versions,
	}
}

func badRequest(msg string) error {
	return &mobius.BadRequestError{Message: msg}
}

func newDeviceAuthenticatedEndpointer(svc mobius.Service, logger log.Logger, opts []kithttp.ServerOption, r *mux.Router,
	versions ...string) *eu.CommonEndpointer[eu.HandlerFunc] {
	authFunc := func(svc mobius.Service, next endpoint.Endpoint) endpoint.Endpoint {
		return authenticatedDevice(svc, logger, next)
	}

	// Inject the mobius.CapabilitiesHeader header to the response for device endpoints
	opts = append(opts, capabilitiesResponseFunc(mobius.GetServerDeviceCapabilities()))
	// Add the capabilities reported by the device to the request context
	opts = append(opts, capabilitiesContextFunc())

	return &eu.CommonEndpointer[eu.HandlerFunc]{
		EP: &endpointer{
			svc: svc,
		},
		MakeDecoderFn: makeDecoder,
		EncodeFn:      encodeResponse,
		Opts:          opts,
		AuthFunc:      authFunc,
		MobiusService:  svc,
		Router:        r,
		Versions:      versions,
	}

}

func newHostAuthenticatedEndpointer(svc mobius.Service, logger log.Logger, opts []kithttp.ServerOption, r *mux.Router,
	versions ...string) *eu.CommonEndpointer[eu.HandlerFunc] {
	authFunc := func(svc mobius.Service, next endpoint.Endpoint) endpoint.Endpoint {
		return authenticatedHost(svc, logger, next)
	}
	return &eu.CommonEndpointer[eu.HandlerFunc]{
		EP: &endpointer{
			svc: svc,
		},
		MakeDecoderFn: makeDecoder,
		EncodeFn:      encodeResponse,
		Opts:          opts,
		AuthFunc:      authFunc,
		MobiusService:  svc,
		Router:        r,
		Versions:      versions,
	}
}

func newOrbitAuthenticatedEndpointer(svc mobius.Service, logger log.Logger, opts []kithttp.ServerOption, r *mux.Router,
	versions ...string) *eu.CommonEndpointer[eu.HandlerFunc] {
	authFunc := func(svc mobius.Service, next endpoint.Endpoint) endpoint.Endpoint {
		return authenticatedOrbitHost(svc, logger, next)
	}

	// Inject the mobius.Capabilities header to the response for Orbit hosts
	opts = append(opts, capabilitiesResponseFunc(mobius.GetServerOrbitCapabilities()))
	// Add the capabilities reported by Orbit to the request context
	opts = append(opts, capabilitiesContextFunc())

	return &eu.CommonEndpointer[eu.HandlerFunc]{
		EP: &endpointer{
			svc: svc,
		},
		MakeDecoderFn: makeDecoder,
		EncodeFn:      encodeResponse,
		Opts:          opts,
		AuthFunc:      authFunc,
		MobiusService:  svc,
		Router:        r,
		Versions:      versions,
	}
}

func capabilitiesResponseFunc(capabilities mobius.CapabilityMap) kithttp.ServerOption {
	return kithttp.ServerAfter(func(ctx context.Context, w http.ResponseWriter) context.Context {
		writeCapabilitiesHeader(w, capabilities)
		return ctx
	})
}

func capabilitiesContextFunc() kithttp.ServerOption {
	return kithttp.ServerBefore(capabilities.NewContext)
}

func writeCapabilitiesHeader(w http.ResponseWriter, capabilities mobius.CapabilityMap) {
	if len(capabilities) == 0 {
		return
	}

	w.Header().Set(mobius.CapabilitiesHeader, capabilities.String())
}
