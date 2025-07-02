package auth

import (
	"context"
	"net/http"

	"github.com/notawar/mobius/server/contexts/authz"
	"github.com/notawar/mobius/server/contexts/token"
	"github.com/notawar/mobius/server/contexts/viewer"
	"github.com/notawar/mobius/server/mobius"
	"github.com/notawar/mobius/server/service/middleware/log"
	"github.com/go-kit/kit/endpoint"
)

// AuthViewer creates an authenticated viewer by validating the session key.
func AuthViewer(ctx context.Context, sessionKey string, svc mobius.Service) (*viewer.Viewer, error) {
	session, err := svc.GetSessionByKey(ctx, sessionKey)
	if err != nil {
		return nil, mobius.NewAuthRequiredError(err.Error())
	}
	user, err := svc.UserUnauthorized(ctx, session.UserID)
	if err != nil {
		return nil, mobius.NewAuthRequiredError(err.Error())
	}
	return &viewer.Viewer{User: user, Session: session}, nil
}

// AuthenticatedUser wraps an endpoint, requires that the Mobius user is
// authenticated, and populates the context with a Viewer struct for that user.
//
// If auth fails or the user must reset their password, an error is returned.
func AuthenticatedUser(svc mobius.Service, next endpoint.Endpoint) endpoint.Endpoint {
	authUserFunc := func(ctx context.Context, request interface{}) (interface{}, error) {
		// first check if already successfully set
		if v, ok := viewer.FromContext(ctx); ok {
			if v.User.IsAdminForcedPasswordReset() {
				return nil, mobius.ErrPasswordResetRequired
			}

			return next(ctx, request)
		}

		// if not successful, try again this time with errors
		sessionKey, ok := token.FromContext(ctx)
		if !ok {
			return nil, mobius.NewAuthHeaderRequiredError("no auth token")
		}

		v, err := AuthViewer(ctx, string(sessionKey), svc)
		if err != nil {
			return nil, err
		}

		if v.User.IsAdminForcedPasswordReset() {
			return nil, mobius.ErrPasswordResetRequired
		}

		ctx = viewer.NewContext(ctx, *v)
		if ac, ok := authz.FromContext(ctx); ok {
			ac.SetAuthnMethod(authz.AuthnUserToken)
		}
		return next(ctx, request)
	}

	return log.Logged(authUserFunc)
}

func UnauthenticatedRequest(_ mobius.Service, next endpoint.Endpoint) endpoint.Endpoint {
	return log.Logged(next)
}

// errorHandler has the same signature as http.Error
type errorHandler func(w http.ResponseWriter, detail string, status int)

func AuthenticatedUserMiddleware(svc mobius.Service, errHandler errorHandler, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// first check if already successfully set
		if v, ok := viewer.FromContext(r.Context()); ok {
			if v.User.IsAdminForcedPasswordReset() {
				errHandler(w, mobius.ErrPasswordResetRequired.Error(), http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		// if not successful, try again this time with errors
		sessionKey, ok := token.FromContext(r.Context())
		if !ok {
			errHandler(w, mobius.NewAuthHeaderRequiredError("no auth token").Error(), http.StatusUnauthorized)
			return
		}

		v, err := AuthViewer(r.Context(), string(sessionKey), svc)
		if err != nil {
			errHandler(w, err.Error(), http.StatusUnauthorized)
			return
		}

		if v.User.IsAdminForcedPasswordReset() {
			errHandler(w, mobius.ErrPasswordResetRequired.Error(), http.StatusUnauthorized)
			return
		}

		ctx := viewer.NewContext(r.Context(), *v)
		if ac, ok := authz.FromContext(r.Context()); ok {
			ac.SetAuthnMethod(authz.AuthnUserToken)
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
