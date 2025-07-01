package service

import (
	"context"

	"github.com/notawar/mobius/v4/server/authz"
	"github.com/notawar/mobius/v4/server/contexts/ctxerr"
	"github.com/notawar/mobius/v4/server/contexts/license"
	"github.com/notawar/mobius/v4/server/mobius"
	"github.com/notawar/mobius/v4/server/ptr"
)

func (svc *Service) CreateInitialUser(ctx context.Context, p mobius.UserPayload) (*mobius.User, error) {
	// skipauth: Only the initial user creation should be allowed to skip
	// authorization (because there is not yet a user context to check against).
	svc.authz.SkipAuthorization(ctx)

	setupRequired, err := svc.SetupRequired(ctx)
	if err != nil {
		return nil, err
	}
	if !setupRequired {
		return nil, ctxerr.New(ctx, "a user already exists")
	}

	// Initial user should be global admin with no explicit teams
	p.GlobalRole = ptr.String(mobius.RoleAdmin)
	p.Teams = nil

	return svc.NewUser(ctx, p)
}

func (svc *Service) NewUser(ctx context.Context, p mobius.UserPayload) (*mobius.User, error) {
	license, _ := license.FromContext(ctx)
	if license == nil {
		return nil, ctxerr.New(ctx, "license not found")
	}
	if err := mobius.ValidateUserRoles(true, p, *license); err != nil {
		return nil, ctxerr.Wrap(ctx, err, "validate role")
	}
	if !license.IsPremium() {
		p.MFAEnabled = ptr.Bool(false)
	}

	user, err := p.User(svc.config.Auth.SaltKeySize, svc.config.Auth.BcryptCost)
	if err != nil {
		return nil, err
	}

	user, err = svc.ds.NewUser(ctx, user)
	if err != nil {
		return nil, err
	}

	adminUser := authz.UserFromContext(ctx)
	if adminUser == nil {
		// In case of invites the user created herself.
		adminUser = user
	}
	if err := svc.NewActivity(
		ctx,
		adminUser,
		mobius.ActivityTypeCreatedUser{
			UserID:    user.ID,
			UserName:  user.Name,
			UserEmail: user.Email,
		},
	); err != nil {
		return nil, err
	}
	if err := mobius.LogRoleChangeActivities(ctx, svc, adminUser, nil, nil, user); err != nil {
		return nil, err
	}

	return user, nil
}

func (svc *Service) UserUnauthorized(ctx context.Context, id uint) (*mobius.User, error) {
	// Explicitly no authorization check. Should only be used by middleware.
	return svc.ds.UserByID(ctx, id)
}
