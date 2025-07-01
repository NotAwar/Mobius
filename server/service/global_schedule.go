package service

import (
	"context"

	"github.com/notawar/mobius/v4/server/contexts/ctxerr"
	"github.com/notawar/mobius/v4/server/mobius"
	"github.com/notawar/mobius/v4/server/ptr"
)

////////////////////////////////////////////////////////////////////////////////
// Get Global Schedule
////////////////////////////////////////////////////////////////////////////////

type getGlobalScheduleRequest struct {
	ListOptions mobius.ListOptions `url:"list_options"`
}

type getGlobalScheduleResponse struct {
	GlobalSchedule []*mobius.ScheduledQuery `json:"global_schedule"`
	Err            error                   `json:"error,omitempty"`
}

func (r getGlobalScheduleResponse) Error() error { return r.Err }

func getGlobalScheduleEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*getGlobalScheduleRequest)

	gp, err := svc.GetGlobalScheduledQueries(ctx, req.ListOptions)
	if err != nil {
		return getGlobalScheduleResponse{Err: err}, nil
	}

	return getGlobalScheduleResponse{
		GlobalSchedule: gp,
	}, nil
}

func (svc *Service) GetGlobalScheduledQueries(ctx context.Context, opts mobius.ListOptions) ([]*mobius.ScheduledQuery, error) {
	queries, _, _, err := svc.ListQueries(ctx, opts, nil, ptr.Bool(true), false, nil) // teamID == nil means global
	if err != nil {
		return nil, err
	}
	scheduledQueries := make([]*mobius.ScheduledQuery, 0, len(queries))
	for _, query := range queries {
		scheduledQueries = append(scheduledQueries, mobius.ScheduledQueryFromQuery(query))
	}
	return scheduledQueries, nil
}

////////////////////////////////////////////////////////////////////////////////
// Schedule a global query
////////////////////////////////////////////////////////////////////////////////

type globalScheduleQueryRequest struct {
	QueryID  uint    `json:"query_id"`
	Interval uint    `json:"interval"`
	Snapshot *bool   `json:"snapshot"`
	Removed  *bool   `json:"removed"`
	Platform *string `json:"platform"`
	Version  *string `json:"version"`
	Shard    *uint   `json:"shard"`
}

type globalScheduleQueryResponse struct {
	Scheduled *mobius.ScheduledQuery `json:"scheduled,omitempty"`
	Err       error                 `json:"error,omitempty"`
}

func (r globalScheduleQueryResponse) Error() error { return r.Err }

func globalScheduleQueryEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*globalScheduleQueryRequest)

	scheduled, err := svc.GlobalScheduleQuery(ctx, &mobius.ScheduledQuery{
		QueryID:  req.QueryID,
		Interval: req.Interval,
		Snapshot: req.Snapshot,
		Removed:  req.Removed,
		Platform: req.Platform,
		Version:  req.Version,
		Shard:    req.Shard,
	})
	if err != nil {
		return globalScheduleQueryResponse{Err: err}, nil
	}
	return globalScheduleQueryResponse{Scheduled: scheduled}, nil
}

func (svc *Service) GlobalScheduleQuery(ctx context.Context, scheduledQuery *mobius.ScheduledQuery) (*mobius.ScheduledQuery, error) {
	originalQuery, err := svc.ds.Query(ctx, scheduledQuery.QueryID)
	if err != nil {
		setAuthCheckedOnPreAuthErr(ctx)
		return nil, ctxerr.Wrap(ctx, err, "get query")
	}
	if originalQuery.TeamID != nil {
		setAuthCheckedOnPreAuthErr(ctx)
		return nil, ctxerr.New(ctx, "cannot create a global schedule from a team query")
	}
	originalQuery.Name = nameForCopiedQuery(originalQuery.Name)
	newQuery, err := svc.NewQuery(ctx, mobius.ScheduledQueryToQueryPayloadForNewQuery(originalQuery, scheduledQuery))
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err, "create new query")
	}
	return mobius.ScheduledQueryFromQuery(newQuery), nil
}

////////////////////////////////////////////////////////////////////////////////
// Modify Global Schedule
////////////////////////////////////////////////////////////////////////////////

type modifyGlobalScheduleRequest struct {
	ID uint `json:"-" url:"id"`
	mobius.ScheduledQueryPayload
}

type modifyGlobalScheduleResponse struct {
	Scheduled *mobius.ScheduledQuery `json:"scheduled,omitempty"`
	Err       error                 `json:"error,omitempty"`
}

func (r modifyGlobalScheduleResponse) Error() error { return r.Err }

func modifyGlobalScheduleEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*modifyGlobalScheduleRequest)

	sq, err := svc.ModifyGlobalScheduledQueries(ctx, req.ID, req.ScheduledQueryPayload)
	if err != nil {
		return modifyGlobalScheduleResponse{Err: err}, nil
	}

	return modifyGlobalScheduleResponse{
		Scheduled: sq,
	}, nil
}

func (svc *Service) ModifyGlobalScheduledQueries(ctx context.Context, id uint, scheduledQueryPayload mobius.ScheduledQueryPayload) (*mobius.ScheduledQuery, error) {
	query, err := svc.ModifyQuery(ctx, id, mobius.ScheduledQueryPayloadToQueryPayloadForModifyQuery(scheduledQueryPayload))
	if err != nil {
		return nil, err
	}
	return mobius.ScheduledQueryFromQuery(query), nil
}

////////////////////////////////////////////////////////////////////////////////
// Delete Global Schedule
////////////////////////////////////////////////////////////////////////////////

type deleteGlobalScheduleRequest struct {
	ID uint `url:"id"`
}

type deleteGlobalScheduleResponse struct {
	Err error `json:"error,omitempty"`
}

func (r deleteGlobalScheduleResponse) Error() error { return r.Err }

func deleteGlobalScheduleEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*deleteGlobalScheduleRequest)
	err := svc.DeleteGlobalScheduledQueries(ctx, req.ID)
	if err != nil {
		return deleteGlobalScheduleResponse{Err: err}, nil
	}

	return deleteGlobalScheduleResponse{}, nil
}

func (svc *Service) DeleteGlobalScheduledQueries(ctx context.Context, id uint) error {
	return svc.DeleteQueryByID(ctx, id)
}
