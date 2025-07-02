package service

import (
	"context"

	"github.com/notawar/mobius/server/mobius"
	"github.com/notawar/mobius/server/service/contract"
)

func getScimDetailsEndpoint(ctx context.Context, _ interface{}, svc mobius.Service) (mobius.Errorer, error) {
	details, err := svc.ScimDetails(ctx)
	if err != nil {
		return contract.ScimDetailsResponse{Err: err}, nil
	}
	return contract.ScimDetailsResponse{
		ScimDetails: details,
	}, nil
}

func (svc *Service) ScimDetails(ctx context.Context) (mobius.ScimDetails, error) {
	// skipauth: No authorization check needed due to implementation returning only license error.
	svc.authz.SkipAuthorization(ctx)
	return mobius.ScimDetails{}, mobius.ErrMissingLicense
}
