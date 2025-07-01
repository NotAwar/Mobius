package service

import (
	"context"
	"io"
	"mime/multipart"
	"net/http"

	"github.com/docker/go-units"
	"github.com/notawar/mobius/v4/server/contexts/ctxerr"
	"github.com/notawar/mobius/v4/server/mobius"
	"github.com/notawar/mobius/v4/server/service/middleware/endpoint_utils"
)

//////////////////////////////////////////////////////////////////////////////
// Get App Store apps
//////////////////////////////////////////////////////////////////////////////

type getAppStoreAppsRequest struct {
	TeamID uint `query:"team_id"`
}

type getAppStoreAppsResponse struct {
	AppStoreApps []*mobius.VPPApp `json:"app_store_apps"`
	Err          error           `json:"error,omitempty"`
}

func (r getAppStoreAppsResponse) Error() error { return r.Err }

func getAppStoreAppsEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*getAppStoreAppsRequest)
	apps, err := svc.GetAppStoreApps(ctx, &req.TeamID)
	if err != nil {
		return &getAppStoreAppsResponse{Err: err}, nil
	}

	return &getAppStoreAppsResponse{AppStoreApps: apps}, nil
}

func (svc *Service) GetAppStoreApps(ctx context.Context, teamID *uint) ([]*mobius.VPPApp, error) {
	// skipauth: No authorization check needed due to implementation returning
	// only license error.
	svc.authz.SkipAuthorization(ctx)

	return nil, mobius.ErrMissingLicense
}

//////////////////////////////////////////////////////////////////////////////
// Add App Store apps
//////////////////////////////////////////////////////////////////////////////

type addAppStoreAppRequest struct {
	TeamID           *uint                     `json:"team_id"`
	AppStoreID       string                    `json:"app_store_id"`
	Platform         mobius.AppleDevicePlatform `json:"platform"`
	SelfService      bool                      `json:"self_service"`
	AutomaticInstall bool                      `json:"automatic_install"`
	LabelsIncludeAny []string                  `json:"labels_include_any"`
	LabelsExcludeAny []string                  `json:"labels_exclude_any"`
	Categories       []string                  `json:"categories"`
}

type addAppStoreAppResponse struct {
	TitleID uint  `json:"software_title_id,omitempty"`
	Err     error `json:"error,omitempty"`
}

func (r addAppStoreAppResponse) Error() error { return r.Err }

func addAppStoreAppEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*addAppStoreAppRequest)
	titleID, err := svc.AddAppStoreApp(ctx, req.TeamID, mobius.VPPAppTeam{
		VPPAppID:             mobius.VPPAppID{AdamID: req.AppStoreID, Platform: req.Platform},
		SelfService:          req.SelfService,
		LabelsIncludeAny:     req.LabelsIncludeAny,
		LabelsExcludeAny:     req.LabelsExcludeAny,
		AddAutoInstallPolicy: req.AutomaticInstall,
		Categories:           req.Categories,
	})
	if err != nil {
		return &addAppStoreAppResponse{Err: err}, nil
	}

	return &addAppStoreAppResponse{TitleID: titleID}, nil
}

func (svc *Service) AddAppStoreApp(ctx context.Context, _ *uint, _ mobius.VPPAppTeam) (uint, error) {
	// skipauth: No authorization check needed due to implementation returning
	// only license error.
	svc.authz.SkipAuthorization(ctx)

	return 0, mobius.ErrMissingLicense
}

//////////////////////////////////////////////////////////////////////////////
// Update App Store apps
//////////////////////////////////////////////////////////////////////////////

type updateAppStoreAppRequest struct {
	TitleID          uint     `url:"title_id"`
	TeamID           *uint    `json:"team_id"`
	SelfService      bool     `json:"self_service"`
	LabelsIncludeAny []string `json:"labels_include_any"`
	LabelsExcludeAny []string `json:"labels_exclude_any"`
	Categories       []string `json:"categories"`
}

type updateAppStoreAppResponse struct {
	AppStoreApp *mobius.VPPAppStoreApp `json:"app_store_app,omitempty"`
	Err         error                 `json:"error,omitempty"`
}

func (r updateAppStoreAppResponse) Error() error { return r.Err }

func updateAppStoreAppEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*updateAppStoreAppRequest)

	updatedApp, err := svc.UpdateAppStoreApp(ctx, req.TitleID, req.TeamID, req.SelfService, req.LabelsIncludeAny, req.LabelsExcludeAny, req.Categories)
	if err != nil {
		return updateAppStoreAppResponse{Err: err}, nil
	}

	return updateAppStoreAppResponse{AppStoreApp: updatedApp}, nil
}

func (svc *Service) UpdateAppStoreApp(ctx context.Context, titleID uint, teamID *uint, selfService bool, labelsIncludeAny, labelsExcludeAny, categories []string) (*mobius.VPPAppStoreApp, error) {
	// skipauth: No authorization check needed due to implementation returning
	// only license error.
	svc.authz.SkipAuthorization(ctx)

	return nil, mobius.ErrMissingLicense
}

////////////////////////////////////////////////////////////////////////////////
// POST /api/_version_/vpp_tokens
////////////////////////////////////////////////////////////////////////////////

type uploadVPPTokenRequest struct {
	File *multipart.FileHeader
}

func (uploadVPPTokenRequest) DecodeRequest(ctx context.Context, r *http.Request) (interface{}, error) {
	decoded := uploadVPPTokenRequest{}

	err := r.ParseMultipartForm(512 * units.MiB)
	if err != nil {
		return nil, &mobius.BadRequestError{
			Message:     "failed to parse multipart form",
			InternalErr: err,
		}
	}

	if r.MultipartForm.File["token"] == nil || len(r.MultipartForm.File["token"]) == 0 {
		return nil, &mobius.BadRequestError{
			Message:     "token multipart field is required",
			InternalErr: err,
		}
	}

	decoded.File = r.MultipartForm.File["token"][0]

	return &decoded, nil
}

type uploadVPPTokenResponse struct {
	Err   error             `json:"error,omitempty"`
	Token *mobius.VPPTokenDB `json:"token,omitempty"`
}

func (r uploadVPPTokenResponse) Status() int { return http.StatusAccepted }

func (r uploadVPPTokenResponse) Error() error {
	return r.Err
}

func uploadVPPTokenEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*uploadVPPTokenRequest)
	file, err := req.File.Open()
	if err != nil {
		return uploadVPPTokenResponse{Err: err}, nil
	}
	defer file.Close()

	tok, err := svc.UploadVPPToken(ctx, file)
	if err != nil {
		return uploadVPPTokenResponse{Err: err}, nil
	}

	return uploadVPPTokenResponse{Token: tok}, nil
}

func (svc *Service) UploadVPPToken(ctx context.Context, file io.ReadSeeker) (*mobius.VPPTokenDB, error) {
	// skipauth: No authorization check needed due to implementation returning
	// only license error.
	svc.authz.SkipAuthorization(ctx)

	return nil, mobius.ErrMissingLicense
}

////////////////////////////////////////////////////
// PATCH /api/_version_/mobius/vpp_tokens/%d/renew //
////////////////////////////////////////////////////

type patchVPPTokenRenewRequest struct {
	ID   uint `url:"id"`
	File *multipart.FileHeader
}

func (patchVPPTokenRenewRequest) DecodeRequest(ctx context.Context, r *http.Request) (interface{}, error) {
	decoded := patchVPPTokenRenewRequest{}

	err := r.ParseMultipartForm(512 * units.MiB)
	if err != nil {
		return nil, &mobius.BadRequestError{
			Message:     "failed to parse multipart form",
			InternalErr: err,
		}
	}

	if r.MultipartForm.File["token"] == nil || len(r.MultipartForm.File["token"]) == 0 {
		return nil, &mobius.BadRequestError{
			Message:     "token multipart field is required",
			InternalErr: err,
		}
	}

	decoded.File = r.MultipartForm.File["token"][0]

	id, err := endpoint_utils.UintFromRequest(r, "id")
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err, "failed to parse vpp token id")
	}

	decoded.ID = uint(id) //nolint:gosec // dismiss G115

	return &decoded, nil
}

type patchVPPTokenRenewResponse struct {
	Err   error             `json:"error,omitempty"`
	Token *mobius.VPPTokenDB `json:"token,omitempty"`
}

func (r patchVPPTokenRenewResponse) Status() int { return http.StatusAccepted }

func (r patchVPPTokenRenewResponse) Error() error {
	return r.Err
}

func patchVPPTokenRenewEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*patchVPPTokenRenewRequest)
	file, err := req.File.Open()
	if err != nil {
		return patchVPPTokenRenewResponse{Err: err}, nil
	}
	defer file.Close()

	tok, err := svc.UpdateVPPToken(ctx, req.ID, file)
	if err != nil {
		return patchVPPTokenRenewResponse{Err: err}, nil
	}

	return patchVPPTokenRenewResponse{Token: tok}, nil
}

func (svc *Service) UpdateVPPToken(ctx context.Context, tokenID uint, token io.ReadSeeker) (*mobius.VPPTokenDB, error) {
	// skipauth: No authorization check needed due to implementation returning
	// only license error.
	svc.authz.SkipAuthorization(ctx)

	return nil, mobius.ErrMissingLicense
}

////////////////////////////////////////////////////
// PATCH /api/_version_/mobius/vpp_tokens/%d/teams //
////////////////////////////////////////////////////

type patchVPPTokensTeamsRequest struct {
	ID      uint   `url:"id"`
	TeamIDs []uint `json:"teams"`
}

type patchVPPTokensTeamsResponse struct {
	Token *mobius.VPPTokenDB `json:"token,omitempty"`
	Err   error             `json:"error,omitempty"`
}

func (r patchVPPTokensTeamsResponse) Error() error { return r.Err }

func patchVPPTokensTeams(ctx context.Context, request any, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*patchVPPTokensTeamsRequest)

	tok, err := svc.UpdateVPPTokenTeams(ctx, req.ID, req.TeamIDs)
	if err != nil {
		return patchVPPTokensTeamsResponse{Err: err}, nil
	}
	return patchVPPTokensTeamsResponse{Token: tok}, nil
}

func (svc *Service) UpdateVPPTokenTeams(ctx context.Context, tokenID uint, teamIDs []uint) (*mobius.VPPTokenDB, error) {
	// skipauth: No authorization check needed due to implementation returning
	// only license error.
	svc.authz.SkipAuthorization(ctx)

	return nil, mobius.ErrMissingLicense
}

/////////////////////////////////////////
// GET /api/_version_/mobius/vpp_tokens //
/////////////////////////////////////////

type getVPPTokensRequest struct{}

type getVPPTokensResponse struct {
	Tokens []*mobius.VPPTokenDB `json:"vpp_tokens"`
	Err    error               `json:"error,omitempty"`
}

func (r getVPPTokensResponse) Error() error { return r.Err }

func getVPPTokens(ctx context.Context, request any, svc mobius.Service) (mobius.Errorer, error) {
	tokens, err := svc.GetVPPTokens(ctx)
	if err != nil {
		return getVPPTokensResponse{Err: err}, nil
	}

	if tokens == nil {
		tokens = []*mobius.VPPTokenDB{}
	}

	return getVPPTokensResponse{Tokens: tokens}, nil
}

func (svc *Service) GetVPPTokens(ctx context.Context) ([]*mobius.VPPTokenDB, error) {
	// skipauth: No authorization check needed due to implementation returning
	// only license error.
	svc.authz.SkipAuthorization(ctx)

	return nil, mobius.ErrMissingLicense
}

///////////////////////////////////////////////
// DELETE /api/_version_/mobius/vpp_tokens/%d //
///////////////////////////////////////////////

type deleteVPPTokenRequest struct {
	ID uint `url:"id"`
}

type deleteVPPTokenResponse struct {
	Err error `json:"error,omitempty"`
}

func (r deleteVPPTokenResponse) Error() error { return r.Err }

func (r deleteVPPTokenResponse) Status() int { return http.StatusNoContent }

func deleteVPPToken(ctx context.Context, request any, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*deleteVPPTokenRequest)

	err := svc.DeleteVPPToken(ctx, req.ID)
	if err != nil {
		return deleteVPPTokenResponse{Err: err}, nil
	}

	return deleteVPPTokenResponse{}, nil
}

func (svc *Service) DeleteVPPToken(ctx context.Context, tokenID uint) error {
	// skipauth: No authorization check needed due to implementation returning
	// only license error.
	svc.authz.SkipAuthorization(ctx)

	return mobius.ErrMissingLicense
}
