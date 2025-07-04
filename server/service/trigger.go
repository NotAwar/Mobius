package service

import (
	"context"

	"github.com/notawar/mobius/server/mobius"
)

type triggerRequest struct {
	Name string `query:"name,optional"`
}

type triggerResponse struct {
	Err error `json:"error,omitempty"`
}

func (r triggerResponse) Error() error { return r.Err }

func triggerEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	_, err := svc.AuthenticatedUser(ctx)
	if err != nil {
		return triggerResponse{Err: err}, nil
	}
	req := request.(*triggerRequest)

	err = svc.TriggerCronSchedule(ctx, req.Name)
	if err != nil {
		return triggerResponse{Err: err}, nil
	}

	return triggerResponse{}, nil
}
