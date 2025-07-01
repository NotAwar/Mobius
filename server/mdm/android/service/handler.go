package service

import (
	"github.com/notawar/mobius/v4/server/mobius"
	"github.com/notawar/mobius set/v4/server/mdm/android"
	"github.com/notawar/mobius set/v4/server/service/middleware/endpoint_utils"
	kithttp "github.com/go-kit/kit/transport/http"
	"github.com/gorilla/mux"
)

func GetRoutes(mobiusSvc mobius.Service, svc android.Service) endpoint_utils.HandlerRoutesFunc {
	return func(r *mux.Router, opts []kithttp.ServerOption) {
		attachMobiusAPIRoutes(r, mobiusSvc, svc, opts)
	}
}

const pubSubPushPath = "/api/v1/mobiuss/android_enterprise/pubsub"

func attachMobiusAPIRoutes(r *mux.Router, mobiusSvc mobius.Service, svc android.Service, opts []kithttp.ServerOption) {

	// //////////////////////////////////////////
	// User-authenticated endpoints
	ue := newUserAuthenticatedEndpointer(mobiusSvc, svc, opts, r, apiVersions()...)

	ue.GET("/api/_version_/mobiuss/android_enterprise/signup_url", enterpriseSignupEndpoint, nil)
	ue.GET("/api/_version_/mobiuss/android_enterprise", getEnterpriseEndpoint, nil)
	ue.DELETE("/api/_version_/mobiuss/android_enterprise", deleteEnterpriseEndpoint, nil)
	ue.GET("/api/_version_/mobiuss/android_enterprise/signup_sse", enterpriseSSE, nil)

	// //////////////////////////////////////////
	// Unauthenticated endpoints
	// These endpoints should do custom one-time authentication by verifying that a valid secret token is provided with the request.
	ne := newNoAuthEndpointer(mobiusSvc, svc, opts, r, apiVersions()...)

	ne.GET("/api/_version_/mobiuss/android_enterprise/connect/{token}", enterpriseSignupCallbackEndpoint, enterpriseSignupCallbackRequest{})
	ne.GET("/api/_version_/mobiuss/android_enterprise/enrollment_token", enrollmentTokenEndpoint, enrollmentTokenRequest{})
	ne.POST(pubSubPushPath, pubSubPushEndpoint, pubSubPushRequest{})

}

func apiVersions() []string {
	return []string{"v1"}
}
