package mock

import (
	"context"

	"github.com/notawar/mobius/v4/server/mdm/android"
	"github.com/notawar/mobius set/v4/server/mdm/android/service/androidmgmt"
	"google.golang.org/api/androidmanagement/v1"
)

func (p *Client) InitCommonMocks() {
	p.EnterpriseDeleteFunc = func(_ context.Context, enterpriseID string) error {
		return nil
	}
	p.SignupURLsCreateFunc = func(_ context.Context, serverURL, callbackURL string) (*android.SignupDetails, error) {
		return &android.SignupDetails{}, nil
	}
	p.EnterprisesCreateFunc = func(ctx context.Context, req androidmgmt.EnterprisesCreateRequest) (androidmgmt.EnterprisesCreateResponse, error) {
		return androidmgmt.EnterprisesCreateResponse{
			EnterpriseName:    "enterprises/name",
			TopicName:         "",
			MobiusServerSecret: "mobiusServerSecret",
		}, nil
	}
	p.EnterprisesPoliciesPatchFunc = func(_ context.Context, policyName string, policy *androidmanagement.Policy) error {
		return nil
	}
	p.SetAuthenticationSecretFunc = func(secret string) error { return nil }
}
