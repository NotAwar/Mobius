package service

import (
	"context"

	"github.com/notawar/mobius/server/mobius"
	"gopkg.in/guregu/null.v3"
)

type applyUserRoleSpecsRequest struct {
	Spec *mobius.UsersRoleSpec `json:"spec"`
}

type applyUserRoleSpecsResponse struct {
	Err error `json:"error,omitempty"`
}

func (r applyUserRoleSpecsResponse) Error() error { return r.Err }

func applyUserRoleSpecsEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*applyUserRoleSpecsRequest)
	err := svc.ApplyUserRolesSpecs(ctx, *req.Spec)
	if err != nil {
		return applyUserRoleSpecsResponse{Err: err}, nil
	}
	return applyUserRoleSpecsResponse{}, nil
}

func (svc *Service) ApplyUserRolesSpecs(ctx context.Context, specs mobius.UsersRoleSpec) error {
	if err := svc.authz.Authorize(ctx, &mobius.User{}, mobius.ActionWrite); err != nil {
		return err
	}

	var users []*mobius.User
	for email, spec := range specs.Roles {
		user, err := svc.ds.UserByEmail(ctx, email)
		if err != nil {
			return err
		}
		// If an admin is downgraded, make sure there is at least one other admin
		err = svc.checkAtLeastOneAdmin(ctx, user, spec, email)
		if err != nil {
			return err
		}
		user.GlobalRole = spec.GlobalRole
		var teams []mobius.UserTeam
		for _, team := range spec.Teams {
			t, err := svc.ds.TeamByName(ctx, team.Name)
			if err != nil {
				if mobius.IsNotFound(err) {
					return &mobius.BadRequestError{
						Message:     err.Error(),
						InternalErr: err,
					}
				}
				return err
			}
			teams = append(teams, mobius.UserTeam{
				Team: *t,
				Role: team.Role,
			})
		}
		user.Teams = teams
		users = append(users, user)
	}

	return svc.ds.SaveUsers(ctx, users)
}

func (svc *Service) checkAtLeastOneAdmin(ctx context.Context, user *mobius.User, spec *mobius.UserRoleSpec, email string) error {
	if null.StringFromPtr(user.GlobalRole).ValueOrZero() == mobius.RoleAdmin &&
		null.StringFromPtr(spec.GlobalRole).ValueOrZero() != mobius.RoleAdmin {
		users, err := svc.ds.ListUsers(ctx, mobius.UserListOptions{})
		if err != nil {
			return err
		}
		adminsExceptCurrent := 0
		for _, u := range users {
			if u.Email == email {
				continue
			}
			if null.StringFromPtr(u.GlobalRole).ValueOrZero() == mobius.RoleAdmin {
				adminsExceptCurrent++
			}
		}
		if adminsExceptCurrent == 0 {
			return mobius.NewError(mobius.ErrNoOneAdminNeeded, "You need at least one admin")
		}
	}
	return nil
}
