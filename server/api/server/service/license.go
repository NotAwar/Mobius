package service

import (
	"context"

	"github.com/notawar/mobius/mobius-server/server/authz"
	"github.com/notawar/mobius/mobius-server/server/contexts/viewer"
	"github.com/notawar/mobius/mobius-server/server/mobius"
)

// /////////////////////////////////////////////////////////////////////////////
// License status
// /////////////////////////////////////////////////////////////////////////////

type getLicenseStatusResponse struct {
	License *mobius.LicenseInfo `json:"license,omitempty"`
	Err     error               `json:"error,omitempty"`
}

func (r getLicenseStatusResponse) Error() error { return r.Err }

func getLicenseStatusEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	lic, err := svc.License(ctx)
	if err != nil {
		return getLicenseStatusResponse{Err: err}, nil
	}
	return getLicenseStatusResponse{License: lic}, nil
}

// /////////////////////////////////////////////////////////////////////////////
// Apply/Update license (placeholder for open-source build)
// /////////////////////////////////////////////////////////////////////////////

type applyLicenseRequest struct {
	Key string `json:"key"`
}

type applyLicenseResponse struct {
	License *mobius.LicenseInfo `json:"license,omitempty"`
	Err     error               `json:"error,omitempty"`
}

func (r applyLicenseResponse) Error() error { return r.Err }

func applyLicenseEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	// Admin-only endpoint: require a logged-in global admin.
	if v, ok := viewer.FromContext(ctx); !ok || v.User.GlobalRole == nil || *v.User.GlobalRole != mobius.RoleAdmin {
		return applyLicenseResponse{Err: authz.ForbiddenWithInternal("only global admins can apply or update licenses", nil, "license", mobius.ActionWrite)}, nil
	}
	// In this open-source build, applying/updating a license key via API is not supported.
	// Configure license.key in the server config and restart the service.
	return applyLicenseResponse{
		Err: &mobius.BadRequestError{Message: "applying a license via API is not supported in this build; set license.key in config and restart"},
	}, nil
}
