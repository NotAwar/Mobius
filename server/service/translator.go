package service

import (
	"context"
	"fmt"

	"github.com/notawar/mobius/v4/server/mobius"
	"github.com/notawar/mobius/v4/server/service/middleware/endpoint_utils"
)

type translatorRequest struct {
	List []mobius.TranslatePayload `json:"list"`
}

type translatorResponse struct {
	List []mobius.TranslatePayload `json:"list"`
	Err  error                    `json:"error,omitempty"`
}

func (r translatorResponse) Error() error { return r.Err }

func translatorEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*translatorRequest)
	resp, err := svc.Translate(ctx, req.List)
	if err != nil {
		return translatorResponse{Err: err}, nil
	}
	return translatorResponse{List: resp}, nil
}

type translateFunc func(ctx context.Context, ds mobius.Datastore, identifier string) (uint, error)

func translateEmailToUserID(ctx context.Context, ds mobius.Datastore, identifier string) (uint, error) {
	user, err := ds.UserByEmail(ctx, identifier)
	if err != nil {
		return 0, err
	}
	return user.ID, nil
}

func translateLabelToID(ctx context.Context, ds mobius.Datastore, identifier string) (uint, error) {
	labelIDs, err := ds.LabelIDsByName(ctx, []string{identifier})
	if err != nil {
		return 0, err
	}
	return labelIDs[identifier], nil
}

func translateTeamToID(ctx context.Context, ds mobius.Datastore, identifier string) (uint, error) {
	team, err := ds.TeamByName(ctx, identifier)
	if err != nil {
		return 0, err
	}
	return team.ID, nil
}

func translateHostToID(ctx context.Context, ds mobius.Datastore, identifier string) (uint, error) {
	host, err := ds.HostByIdentifier(ctx, identifier)
	if err != nil {
		return 0, err
	}
	return host.ID, nil
}

func (svc *Service) Translate(ctx context.Context, payloads []mobius.TranslatePayload) ([]mobius.TranslatePayload, error) {
	if len(payloads) == 0 {
		// skip auth since there is no case in which this request will make sense with no payloads
		svc.authz.SkipAuthorization(ctx)
		return nil, badRequest("payloads must not be empty")
	}

	var finalPayload []mobius.TranslatePayload

	for _, payload := range payloads {
		var translateFunc translateFunc

		switch payload.Type {
		case mobius.TranslatorTypeUserEmail:
			if err := svc.authz.Authorize(ctx, &mobius.User{}, mobius.ActionRead); err != nil {
				return nil, err
			}
			translateFunc = translateEmailToUserID
		case mobius.TranslatorTypeLabel:
			if err := svc.authz.Authorize(ctx, &mobius.Label{}, mobius.ActionRead); err != nil {
				return nil, err
			}
			translateFunc = translateLabelToID
		case mobius.TranslatorTypeTeam:
			if err := svc.authz.Authorize(ctx, &mobius.Team{}, mobius.ActionRead); err != nil {
				return nil, err
			}
			translateFunc = translateTeamToID
		case mobius.TranslatorTypeHost:
			if err := svc.authz.Authorize(ctx, &mobius.Host{}, mobius.ActionRead); err != nil {
				return nil, err
			}
			translateFunc = translateHostToID
		default:
			// if no supported payload type, this is bad regardless of authorization
			svc.authz.SkipAuthorization(ctx)
			return nil, endpoint_utils.BadRequestErr(
				fmt.Sprintf("Type %s is unknown. ", payload.Type),
				mobius.NewErrorf(
					mobius.ErrNoUnknownTranslate,
					"Type %s is unknown.",
					payload.Type),
			)
		}

		id, err := translateFunc(ctx, svc.ds, payload.Payload.Identifier)
		if err != nil {
			return nil, err
		}
		payload.Payload.ID = id
		finalPayload = append(finalPayload, mobius.TranslatePayload{
			Type:    payload.Type,
			Payload: payload.Payload,
		})
	}

	return finalPayload, nil
}
