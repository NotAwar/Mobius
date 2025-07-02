package service

import (
	"context"
	"errors"

	"github.com/notawar/mobius/server/mobius"
	"github.com/notawar/mobius/server/mdm/maintainedapps"
)

type addMobiusMaintainedAppRequest struct {
	TeamID            *uint    `json:"team_id"`
	AppID             uint     `json:"mobius_maintained_app_id"`
	InstallScript     string   `json:"install_script"`
	PreInstallQuery   string   `json:"pre_install_query"`
	PostInstallScript string   `json:"post_install_script"`
	SelfService       bool     `json:"self_service"`
	UninstallScript   string   `json:"uninstall_script"`
	LabelsIncludeAny  []string `json:"labels_include_any"`
	LabelsExcludeAny  []string `json:"labels_exclude_any"`
	AutomaticInstall  bool     `json:"automatic_install"`
}

type addMobiusMaintainedAppResponse struct {
	SoftwareTitleID uint  `json:"software_title_id,omitempty"`
	Err             error `json:"error,omitempty"`
}

func (r addMobiusMaintainedAppResponse) Error() error { return r.Err }

func addMobiusMaintainedAppEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*addMobiusMaintainedAppRequest)
	ctx, cancel := context.WithTimeout(ctx, maintained_apps.InstallerTimeout)
	defer cancel()
	titleId, err := svc.AddMobiusMaintainedApp(
		ctx,
		req.TeamID,
		req.AppID,
		req.InstallScript,
		req.PreInstallQuery,
		req.PostInstallScript,
		req.UninstallScript,
		req.SelfService,
		req.AutomaticInstall,
		req.LabelsIncludeAny,
		req.LabelsExcludeAny,
	)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			err = mobius.NewGatewayTimeoutError("Couldn't add. Request timeout. Please make sure your server and load balancer timeout is long enough.", err)
		}

		return &addMobiusMaintainedAppResponse{Err: err}, nil
	}
	return &addMobiusMaintainedAppResponse{SoftwareTitleID: titleId}, nil
}

func (svc *Service) AddMobiusMaintainedApp(ctx context.Context, _ *uint, _ uint, _, _, _, _ string, _ bool, _ bool, _, _ []string) (uint, error) {
	// skipauth: No authorization check needed due to implementation returning
	// only license error.
	svc.authz.SkipAuthorization(ctx)

	return 0, mobius.ErrMissingLicense
}

type listMobiusMaintainedAppsRequest struct {
	mobius.ListOptions
	TeamID *uint `query:"team_id,optional"`
}

type listMobiusMaintainedAppsResponse struct {
	MobiusMaintainedApps []mobius.MaintainedApp     `json:"mobius_maintained_apps"`
	Meta                *mobius.PaginationMetadata `json:"meta"`
	Err                 error                     `json:"error,omitempty"`
}

func (r listMobiusMaintainedAppsResponse) Error() error { return r.Err }

func listMobiusMaintainedAppsEndpoint(ctx context.Context, request any, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*listMobiusMaintainedAppsRequest)

	apps, meta, err := svc.ListMobiusMaintainedApps(ctx, req.TeamID, req.ListOptions)
	if err != nil {
		return listMobiusMaintainedAppsResponse{Err: err}, nil
	}

	listResp := listMobiusMaintainedAppsResponse{
		MobiusMaintainedApps: apps,
		Meta:                meta,
	}

	return listResp, nil
}

func (svc *Service) ListMobiusMaintainedApps(ctx context.Context, teamID *uint, opts mobius.ListOptions) ([]mobius.MaintainedApp, *mobius.PaginationMetadata, error) {
	// skipauth: No authorization check needed due to implementation returning
	// only license error.
	svc.authz.SkipAuthorization(ctx)

	return nil, nil, mobius.ErrMissingLicense
}

type getMobiusMaintainedAppRequest struct {
	AppID  uint  `url:"app_id"`
	TeamID *uint `query:"team_id,optional"`
}

type getMobiusMaintainedAppResponse struct {
	MobiusMaintainedApp *mobius.MaintainedApp `json:"mobius_maintained_app"`
	Err                error                `json:"error,omitempty"`
}

func (r getMobiusMaintainedAppResponse) Error() error { return r.Err }

func getMobiusMaintainedApp(ctx context.Context, request any, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*getMobiusMaintainedAppRequest)

	app, err := svc.GetMobiusMaintainedApp(ctx, req.AppID, req.TeamID)
	if err != nil {
		return getMobiusMaintainedAppResponse{Err: err}, nil
	}

	return getMobiusMaintainedAppResponse{MobiusMaintainedApp: app}, nil
}

func (svc *Service) GetMobiusMaintainedApp(ctx context.Context, appID uint, teamID *uint) (*mobius.MaintainedApp, error) {
	// skipauth: No authorization check needed due to implementation returning
	// only license error.
	svc.authz.SkipAuthorization(ctx)

	return nil, mobius.ErrMissingLicense
}
