package service

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"time"

	"github.com/notawar/mobius/server/authz"
	"github.com/notawar/mobius/server/contexts/ctxerr"
	"github.com/notawar/mobius/server/mobius"
)

var freeValidVulnSortColumns = []string{
	"cve",
	"hosts_count",
	"host_count_updated_at",
	"created_at",
}

type cveNotFoundError struct{}

var _ mobius.NotFoundError = (*cveNotFoundError)(nil)

func (p cveNotFoundError) Error() string {
	return "This is not a known CVE. None of Mobius’s vulnerability sources are aware of this CVE."
}

func (p cveNotFoundError) IsNotFound() bool {
	return true
}

type listVulnerabilitiesRequest struct {
	mobius.VulnListOptions
}

type listVulnerabilitiesResponse struct {
	Vulnerabilities []mobius.VulnerabilityWithMetadata `json:"vulnerabilities"`
	Count           uint                              `json:"count"`
	CountsUpdatedAt time.Time                         `json:"counts_updated_at"`
	Meta            *mobius.PaginationMetadata         `json:"meta,omitempty"`
	Err             error                             `json:"error,omitempty"`
}

// Allow formats like: CVE-2017-12345, cve-2017-12345
var cveRegex = regexp.MustCompile(`(?i)^CVE-\d{4}-\d{4}\d*$`)

func (r listVulnerabilitiesResponse) Error() error { return r.Err }

func listVulnerabilitiesEndpoint(ctx context.Context, req interface{}, svc mobius.Service) (mobius.Errorer, error) {
	request := req.(*listVulnerabilitiesRequest)
	vulns, meta, err := svc.ListVulnerabilities(ctx, request.VulnListOptions)
	if err != nil {
		return listVulnerabilitiesResponse{Err: err}, nil
	}

	count, err := svc.CountVulnerabilities(ctx, request.VulnListOptions)
	if err != nil {
		return listVulnerabilitiesResponse{Err: err}, nil
	}

	updatedAt := time.Now()
	for _, vuln := range vulns {
		if vuln.HostsCountUpdatedAt.Before(updatedAt) {
			updatedAt = vuln.HostsCountUpdatedAt
		}
	}

	return listVulnerabilitiesResponse{
		Vulnerabilities: vulns,
		Meta:            meta,
		Count:           count,
		CountsUpdatedAt: updatedAt,
	}, nil
}

func (svc *Service) ListVulnerabilities(ctx context.Context, opt mobius.VulnListOptions) ([]mobius.VulnerabilityWithMetadata, *mobius.PaginationMetadata, error) {
	if err := svc.authz.Authorize(ctx, &mobius.AuthzSoftwareInventory{
		TeamID: opt.TeamID,
	}, mobius.ActionRead); err != nil {
		return nil, nil, err
	}

	if len(opt.ValidSortColumns) == 0 {
		opt.ValidSortColumns = freeValidVulnSortColumns
	}

	if !opt.HasValidSortColumn() {
		return nil, nil, badRequest("invalid order key")
	}

	if opt.KnownExploit && !opt.IsEE {
		return nil, nil, mobius.ErrMissingLicense
	}

	vulns, meta, err := svc.ds.ListVulnerabilities(ctx, opt)
	if err != nil {
		return nil, nil, err
	}

	for i, vuln := range vulns {
		vulns[i].DetailsLink = fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", vuln.CVE.CVE)
	}

	return vulns, meta, nil
}

func (svc *Service) CountVulnerabilities(ctx context.Context, opts mobius.VulnListOptions) (uint, error) {
	if err := svc.authz.Authorize(ctx, &mobius.AuthzSoftwareInventory{
		TeamID: opts.TeamID,
	}, mobius.ActionRead); err != nil {
		return 0, err
	}

	return svc.ds.CountVulnerabilities(ctx, opts)
}

func (svc *Service) IsCVEKnownToMobius(ctx context.Context, cve string) (bool, error) {
	return svc.ds.IsCVEKnownToMobius(ctx, cve)
}

type getVulnerabilityRequest struct {
	CVE    string `url:"cve"`
	TeamID *uint  `query:"team_id,optional"`
}

type getVulnerabilityResponse struct {
	Vulnerability *mobius.VulnerabilityWithMetadata `json:"vulnerability"`
	OSVersions    []*mobius.VulnerableOS            `json:"os_versions"`
	Software      []*mobius.VulnerableSoftware      `json:"software"`
	Err           error                            `json:"error,omitempty"`
	statusCode    int
}

func (r getVulnerabilityResponse) Error() error { return r.Err }

func (r getVulnerabilityResponse) Status() int {
	if r.statusCode == 0 {
		return http.StatusOK
	}
	return r.statusCode
}

func getVulnerabilityEndpoint(ctx context.Context, req interface{}, svc mobius.Service) (mobius.Errorer, error) {
	request := req.(*getVulnerabilityRequest)

	vuln, known, err := svc.Vulnerability(ctx, request.CVE, request.TeamID, false)
	if err != nil {
		return getVulnerabilityResponse{Err: err}, nil
	}
	if vuln == nil && known {
		// Return 204 status code if the vulnerability is known to Mobius but does not match any host software/OS
		return getVulnerabilityResponse{statusCode: http.StatusNoContent}, nil
	}

	vuln.DetailsLink = fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", vuln.CVE.CVE)

	osVersions, _, err := svc.ListOSVersionsByCVE(ctx, vuln.CVE.CVE, request.TeamID)
	if err != nil {
		return getVulnerabilityResponse{Err: err}, nil
	}

	software, _, err := svc.ListSoftwareByCVE(ctx, vuln.CVE.CVE, request.TeamID)
	if err != nil {
		return getVulnerabilityResponse{Err: err}, nil
	}

	return getVulnerabilityResponse{
		Vulnerability: vuln,
		OSVersions:    osVersions,
		Software:      software,
	}, nil
}

func (svc *Service) Vulnerability(ctx context.Context, cve string, teamID *uint, useCVSScores bool) (vuln *mobius.VulnerabilityWithMetadata,
	known bool, err error,
) {
	if err := svc.authz.Authorize(ctx, &mobius.AuthzSoftwareInventory{TeamID: teamID}, mobius.ActionRead); err != nil {
		return nil, false, err
	}

	if err := svc.authz.Authorize(ctx, &mobius.Host{TeamID: teamID}, mobius.ActionRead); err != nil {
		return nil, false, err
	}

	if !cveRegex.Match([]byte(cve)) {
		return nil, false, badRequest("That vulnerability (CVE) is not valid. Try updating your search to use CVE format: \"CVE-YYYY-<4 or more digits>\"")
	}

	if teamID != nil && *teamID != 0 {
		exists, err := svc.ds.TeamExists(ctx, *teamID)
		if err != nil {
			return nil, false, ctxerr.Wrap(ctx, err, "checking if team exists")
		} else if !exists {
			return nil, false, authz.ForbiddenWithInternal("team does not exist", nil, nil, nil)
		}
	}

	vuln, err = svc.ds.Vulnerability(ctx, cve, teamID, useCVSScores)
	switch {
	case mobius.IsNotFound(err):
		var errKnown error
		known, errKnown = svc.ds.IsCVEKnownToMobius(ctx, cve)
		if errKnown != nil {
			return nil, false, errKnown
		}
		if !known {
			return nil, false, cveNotFoundError{}
		}
	case err != nil:
		return nil, false, err
	default:
		known = true
	}

	return vuln, known, nil
}

func (svc *Service) ListOSVersionsByCVE(ctx context.Context, cve string, teamID *uint) (result []*mobius.VulnerableOS, updatedAt time.Time, err error) {
	if err := svc.authz.Authorize(ctx, &mobius.Host{TeamID: teamID}, mobius.ActionRead); err != nil {
		return nil, updatedAt, err
	}
	return svc.ds.OSVersionsByCVE(ctx, cve, teamID)
}

func (svc *Service) ListSoftwareByCVE(ctx context.Context, cve string, teamID *uint) (result []*mobius.VulnerableSoftware, updatedAt time.Time, err error) {
	if err := svc.authz.Authorize(ctx, &mobius.AuthzSoftwareInventory{TeamID: teamID}, mobius.ActionRead); err != nil {
		return nil, updatedAt, err
	}
	return svc.ds.SoftwareByCVE(ctx, cve, teamID)
}
