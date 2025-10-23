package service

import (
	"context"
	"testing"

	"github.com/notawar/mobius/mobius-server/server/authz"
	"github.com/notawar/mobius/mobius-server/server/config"
	authz_ctx "github.com/notawar/mobius/mobius-server/server/contexts/authz"
	"github.com/notawar/mobius/mobius-server/server/contexts/license"
	"github.com/notawar/mobius/mobius-server/server/contexts/viewer"
	"github.com/notawar/mobius/mobius-server/server/mobius"
)

// TestApplyLicenseEndpointRBAC verifies that only global admins can apply/update licenses.
func TestApplyLicenseEndpointRBAC(t *testing.T) {
	// Helper to build a context with a viewer containing a user with given global role pointer (or nil).
	mkCtx := func(role *string) context.Context {
		v := viewer.Viewer{User: &mobius.User{GlobalRole: role}}
		return viewer.NewContext(context.Background(), v)
	}

	t.Run("unauthenticated (no viewer)", func(t *testing.T) {
		resp, err := applyLicenseEndpoint(context.Background(), applyLicenseRequest{Key: "dummy"}, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Error() == nil {
			t.Fatalf("expected error, got nil")
		}
		if _, ok := resp.Error().(*authz.Forbidden); !ok {
			t.Fatalf("expected authz.Forbidden, got %T", resp.Error())
		}
	})

	t.Run("non-admin user", func(t *testing.T) {
		role := "maintainer" // any non-admin role
		ctx := mkCtx(&role)
		resp, err := applyLicenseEndpoint(ctx, applyLicenseRequest{Key: "dummy"}, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Error() == nil {
			t.Fatalf("expected error, got nil")
		}
		if _, ok := resp.Error().(*authz.Forbidden); !ok {
			t.Fatalf("expected authz.Forbidden, got %T", resp.Error())
		}
	})

	t.Run("admin user", func(t *testing.T) {
		role := mobius.RoleAdmin
		ctx := mkCtx(&role)
		resp, err := applyLicenseEndpoint(ctx, applyLicenseRequest{Key: "dummy"}, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Error() == nil {
			t.Fatalf("expected error (bad request placeholder), got nil")
		}
		if _, ok := resp.Error().(*mobius.BadRequestError); !ok {
			t.Fatalf("expected *mobius.BadRequestError, got %T", resp.Error())
		}
	})
}

// TestServiceLicense covers authorization behavior and ManagedCloud flag in Service.License.
func TestServiceLicense(t *testing.T) {
	// Minimal service with only the fields used by License().
	svc := &Service{authz: authz.Must(), config: config.MobiusConfig{}}

	mkBaseCtx := func() context.Context {
		// Insert a license in context to avoid nil deref inside License().
		return license.NewContext(context.Background(), &mobius.LicenseInfo{})
	}

	t.Run("unauthenticated_user_forbidden", func(t *testing.T) {
		ctx := mkBaseCtx()
		if _, err := svc.License(ctx); err == nil {
			t.Fatalf("expected forbidden error, got nil")
		}
	})

	t.Run("observer_role_allowed", func(t *testing.T) {
		role := "observer"
		v := viewer.Viewer{User: &mobius.User{GlobalRole: &role}}
		ctx := viewer.NewContext(mkBaseCtx(), v)
		lic, err := svc.License(ctx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if lic == nil {
			t.Fatalf("expected license, got nil")
		}
		if lic.ManagedCloud {
			t.Fatalf("expected ManagedCloud=false by default")
		}
	})

	t.Run("device_token_skips_authz", func(t *testing.T) {
		// Build an authz context that indicates device-token authentication.
		authzContext := &authz_ctx.AuthorizationContext{}
		authzContext.SetAuthnMethod(authz_ctx.AuthnDeviceToken)
		ctx := authz_ctx.NewContext(mkBaseCtx(), authzContext)

		lic, err := svc.License(ctx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if lic == nil {
			t.Fatalf("expected license, got nil")
		}
	})

	t.Run("managed_cloud_flag_set_when_configured", func(t *testing.T) {
		svcCloud := &Service{authz: authz.Must(), config: config.MobiusConfig{
			MicrosoftCompliancePartner: config.MicrosoftCompliancePartnerConfig{ProxyAPIKey: "abc"},
		}}
		role := mobius.RoleAdmin
		v := viewer.Viewer{User: &mobius.User{GlobalRole: &role}}
		ctx := viewer.NewContext(mkBaseCtx(), v)
		lic, err := svcCloud.License(ctx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if lic == nil || !lic.ManagedCloud {
			t.Fatalf("expected ManagedCloud=true when MicrosoftCompliancePartner is set")
		}
	})
}
