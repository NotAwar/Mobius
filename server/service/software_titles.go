package service

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/notawar/mobius/server/contexts/ctxerr"
	"github.com/notawar/mobius/server/contexts/viewer"
	"github.com/notawar/mobius/server/mobius"
	"github.com/notawar/mobius/server/ptr"
)

/////////////////////////////////////////////////////////////////////////////////
// List Software Titles
/////////////////////////////////////////////////////////////////////////////////

type listSoftwareTitlesRequest struct {
	mobius.SoftwareTitleListOptions
}

type listSoftwareTitlesResponse struct {
	Meta            *mobius.PaginationMetadata       `json:"meta"`
	Count           int                             `json:"count"`
	CountsUpdatedAt *time.Time                      `json:"counts_updated_at"`
	SoftwareTitles  []mobius.SoftwareTitleListResult `json:"software_titles"`
	Err             error                           `json:"error,omitempty"`
}

func (r listSoftwareTitlesResponse) Error() error { return r.Err }

func listSoftwareTitlesEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*listSoftwareTitlesRequest)
	titles, count, meta, err := svc.ListSoftwareTitles(ctx, req.SoftwareTitleListOptions)
	if err != nil {
		return listSoftwareTitlesResponse{Err: err}, nil
	}

	var latest time.Time
	for _, sw := range titles {
		if sw.CountsUpdatedAt != nil && !sw.CountsUpdatedAt.IsZero() && sw.CountsUpdatedAt.After(latest) {
			latest = *sw.CountsUpdatedAt
		}
		// we dont want to include the InstallDuringSetup field in the response
		// for software titles list.
		if sw.SoftwarePackage != nil {
			sw.SoftwarePackage.InstallDuringSetup = nil
		} else if sw.AppStoreApp != nil {
			sw.AppStoreApp.InstallDuringSetup = nil
		}
	}
	if len(titles) == 0 {
		titles = []mobius.SoftwareTitleListResult{}
	}
	listResp := listSoftwareTitlesResponse{
		SoftwareTitles: titles,
		Count:          count,
		Meta:           meta,
	}
	if !latest.IsZero() {
		listResp.CountsUpdatedAt = &latest
	}

	return listResp, nil
}

func (svc *Service) ListSoftwareTitles(
	ctx context.Context,
	opt mobius.SoftwareTitleListOptions,
) ([]mobius.SoftwareTitleListResult, int, *mobius.PaginationMetadata, error) {
	if err := svc.authz.Authorize(ctx, &mobius.AuthzSoftwareInventory{
		TeamID: opt.TeamID,
	}, mobius.ActionRead); err != nil {
		return nil, 0, nil, err
	}

	lic, err := svc.License(ctx)
	if err != nil {
		return nil, 0, nil, ctxerr.Wrap(ctx, err, "get license")
	}

	if opt.TeamID != nil && *opt.TeamID != 0 && !lic.IsPremium() {
		return nil, 0, nil, mobius.ErrMissingLicense
	}

	if !lic.IsPremium() && (opt.MaximumCVSS > 0 || opt.MinimumCVSS > 0 || opt.KnownExploit) {
		return nil, 0, nil, mobius.ErrMissingLicense
	}

	// always include metadata for software titles
	opt.ListOptions.IncludeMetadata = true
	// cursor-based pagination is not supported for software titles
	opt.ListOptions.After = ""

	vc, ok := viewer.FromContext(ctx)
	if !ok {
		return nil, 0, nil, mobius.ErrNoContext
	}

	titles, count, meta, err := svc.ds.ListSoftwareTitles(ctx, opt, mobius.TeamFilter{
		User:            vc.User,
		IncludeObserver: true,
		TeamID:          opt.TeamID,
	})
	if err != nil {
		return nil, 0, nil, err
	}

	return titles, count, meta, nil
}

/////////////////////////////////////////////////////////////////////////////////
// Get a Software Title
/////////////////////////////////////////////////////////////////////////////////

type getSoftwareTitleRequest struct {
	ID     uint  `url:"id"`
	TeamID *uint `query:"team_id,optional"`
}

type getSoftwareTitleResponse struct {
	SoftwareTitle *mobius.SoftwareTitle `json:"software_title,omitempty"`
	Err           error                `json:"error,omitempty"`
}

func (r getSoftwareTitleResponse) Error() error { return r.Err }

func getSoftwareTitleEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*getSoftwareTitleRequest)

	software, err := svc.SoftwareTitleByID(ctx, req.ID, req.TeamID)
	if err != nil {
		return getSoftwareTitleResponse{Err: err}, nil
	}

	return getSoftwareTitleResponse{SoftwareTitle: software}, nil
}

func (svc *Service) SoftwareTitleByID(ctx context.Context, id uint, teamID *uint) (*mobius.SoftwareTitle, error) {
	if err := svc.authz.Authorize(ctx, &mobius.Host{TeamID: teamID}, mobius.ActionList); err != nil {
		return nil, err
	}

	if teamID != nil && *teamID != 0 {
		// This auth check ensures we return 403 if the user doesn't have access to the team
		if err := svc.authz.Authorize(ctx, &mobius.AuthzSoftwareInventory{TeamID: teamID}, mobius.ActionRead); err != nil {
			return nil, err
		}
		exists, err := svc.ds.TeamExists(ctx, *teamID)
		if err != nil {
			return nil, ctxerr.Wrap(ctx, err, "checking if team exists")
		} else if !exists {
			return nil, mobius.NewInvalidArgumentError("team_id", fmt.Sprintf("team %d does not exist", *teamID)).
				WithStatus(http.StatusNotFound)
		}
	}

	vc, ok := viewer.FromContext(ctx)
	if !ok {
		return nil, mobius.ErrNoContext
	}

	// get software by id including team_id data from software_title_host_counts
	software, err := svc.ds.SoftwareTitleByID(ctx, id, teamID, mobius.TeamFilter{
		User:            vc.User,
		IncludeObserver: true,
	})
	if err != nil {
		if mobius.IsNotFound(err) && teamID == nil {
			// here we use a global admin as filter because we want to check if the software exists
			filter := mobius.TeamFilter{User: &mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)}}
			_, err = svc.ds.SoftwareTitleByID(ctx, id, nil, filter)
			if err != nil {
				return nil, ctxerr.Wrap(ctx, err, "checked using a global admin")
			}

			return nil, mobius.NewPermissionError("Error: You don't have permission to view specified software. It is installed on hosts that belong to team you don't have permissions to view.")
		}
		return nil, ctxerr.Wrap(ctx, err, "getting software title by id")
	}

	license, err := svc.License(ctx)
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err, "get license")
	}
	if license.IsPremium() {
		// add software installer data if needed
		if software.SoftwareInstallersCount > 0 {
			meta, err := svc.ds.GetSoftwareInstallerMetadataByTeamAndTitleID(ctx, teamID, id, true)
			if err != nil && !mobius.IsNotFound(err) {
				return nil, ctxerr.Wrap(ctx, err, "get software installer metadata")
			}
			if meta != nil {
				summary, err := svc.ds.GetSummaryHostSoftwareInstalls(ctx, meta.InstallerID)
				if err != nil {
					return nil, ctxerr.Wrap(ctx, err, "get software installer status summary")
				}
				meta.Status = summary
			}
			software.SoftwarePackage = meta
		}

		// add VPP app data if needed
		if software.VPPAppsCount > 0 {
			meta, err := svc.ds.GetVPPAppMetadataByTeamAndTitleID(ctx, teamID, id)
			if err != nil && !mobius.IsNotFound(err) {
				return nil, ctxerr.Wrap(ctx, err, "get VPP app metadata")
			}
			if meta != nil {
				summary, err := svc.ds.GetSummaryHostVPPAppInstalls(ctx, teamID, meta.VPPAppID)
				if err != nil {
					return nil, ctxerr.Wrap(ctx, err, "get VPP app status summary")
				}
				meta.Status = summary
			}
			software.AppStoreApp = meta
		}
	}

	return software, nil
}

/////////////////////////////////////////////////////////////////////////////////
// Update a software title's name
/////////////////////////////////////////////////////////////////////////////////

type updateSoftwareNameRequest struct {
	ID   uint   `url:"id"`
	Name string `json:"name"`
}

type updateSoftwareNameResponse struct {
	Err error `json:"error,omitempty"`
}

func (r updateSoftwareNameResponse) Error() error { return r.Err }
func (r updateSoftwareNameResponse) Status() int  { return http.StatusResetContent }

func updateSoftwareNameEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*updateSoftwareNameRequest)
	return updateSoftwareNameResponse{Err: svc.UpdateSoftwareName(ctx, req.ID, req.Name)}, nil
}

func (svc *Service) UpdateSoftwareName(ctx context.Context, titleID uint, name string) error {
	if err := svc.authz.Authorize(ctx, &mobius.AuthzSoftwareInventory{}, mobius.ActionWrite); err != nil {
		return err
	}
	vc, ok := viewer.FromContext(ctx)
	if !ok {
		return mobius.ErrNoContext
	}

	// get software by id including team_id data from software_title_host_counts
	software, err := svc.ds.SoftwareTitleByID(ctx, titleID, nil, mobius.TeamFilter{
		User: vc.User,
	})
	if err != nil {
		return ctxerr.Wrap(ctx, err, "getting software title by id")
	}
	if software.BundleIdentifier == nil || *software.BundleIdentifier == "" {
		return mobius.NewInvalidArgumentError("id", "only titles with a bundle ID can have their name modified")
	}
	if name == "" {
		return mobius.NewInvalidArgumentError("name", "cannot be empty")
	}

	return svc.ds.UpdateSoftwareTitleName(ctx, titleID, name)
}
