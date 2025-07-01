package auth

import (
	"context"
	"net/http"

	"github.com/notawar/mobius/v4/server/contexts/logging"
	"github.com/notawar/mobius set/v4/server/contexts/token"
	"github.com/notawar/mobius set/v4/server/contexts/viewer"
	"github.com/notawar/mobius set/v4/server/mobius"
	kithttp "github.com/go-kit/kit/transport/http"
)

// SetRequestsContexts updates the request with necessary context values for a request
func SetRequestsContexts(svc mobius.Service) kithttp.RequestFunc {
	return func(ctx context.Context, r *http.Request) context.Context {
		bearer := token.FromHTTPRequest(r)
		ctx = token.NewContext(ctx, bearer)
		if bearer != "" {
			v, err := AuthViewer(ctx, string(bearer), svc)
			if err == nil {
				ctx = viewer.NewContext(ctx, *v)
			}
		}

		ctx = logging.NewContext(ctx, &logging.LoggingContext{})
		ctx = logging.WithStartTime(ctx)
		return ctx
	}
}

func SetRequestsContextMiddleware(svc mobius.Service, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := kithttp.PopulateRequestContext(r.Context(), r)
		ctx = SetRequestsContexts(svc)(ctx, r)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
