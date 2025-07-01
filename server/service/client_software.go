package service

import (
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/notawar/mobius/v4/server/mobius"
)

// ListSoftwareVersions retrieves the software versions installed on hosts.
func (c *Client) ListSoftwareVersions(query string) ([]mobius.Software, error) {
	verb, path := "GET", "/api/latest/mobius/software/versions"
	var responseBody listSoftwareVersionsResponse
	err := c.authenticatedRequestWithQuery(nil, verb, path, &responseBody, query)
	if err != nil {
		return nil, err
	}
	return responseBody.Software, nil
}

// ListSoftwareTitles retrieves the software titles installed on hosts.
func (c *Client) ListSoftwareTitles(query string) ([]mobius.SoftwareTitleListResult, error) {
	verb, path := "GET", "/api/latest/mobius/software/titles"
	var responseBody listSoftwareTitlesResponse
	err := c.authenticatedRequestWithQuery(nil, verb, path, &responseBody, query)
	if err != nil {
		return nil, err
	}
	return responseBody.SoftwareTitles, nil
}

// GetSoftwareTitleByID retrieves a software title by ID.
//
//nolint:gocritic // ignore captLocal
func (c *Client) GetSoftwareTitleByID(ID uint, teamID *uint) (*mobius.SoftwareTitle, error) {
	var query string
	if teamID != nil {
		query = fmt.Sprintf("team_id=%d", *teamID)
	}
	verb, path := "GET", "/api/latest/mobius/software/titles/"+fmt.Sprint(ID)
	var responseBody getSoftwareTitleResponse
	err := c.authenticatedRequestWithQuery(nil, verb, path, &responseBody, query)
	if err != nil {
		return nil, err
	}
	return responseBody.SoftwareTitle, nil
}

func (c *Client) ApplyNoTeamSoftwareInstallers(softwareInstallers []mobius.SoftwareInstallerPayload, opts mobius.ApplySpecOptions) ([]mobius.SoftwarePackageResponse, error) {
	query, err := url.ParseQuery(opts.RawQuery())
	if err != nil {
		return nil, err
	}
	return c.applySoftwareInstallers(softwareInstallers, query, opts.DryRun)
}

func (c *Client) applySoftwareInstallers(softwareInstallers []mobius.SoftwareInstallerPayload, query url.Values, dryRun bool) ([]mobius.SoftwarePackageResponse, error) {
	path := "/api/latest/mobius/software/batch"
	var resp batchSetSoftwareInstallersResponse
	if err := c.authenticatedRequestWithQuery(map[string]any{"software": softwareInstallers}, "POST", path, &resp, query.Encode()); err != nil {
		return nil, err
	}
	if dryRun && resp.RequestUUID == "" {
		return nil, nil
	}

	requestUUID := resp.RequestUUID
	for {
		var resp batchSetSoftwareInstallersResultResponse
		if err := c.authenticatedRequestWithQuery(nil, "GET", path+"/"+requestUUID, &resp, query.Encode()); err != nil {
			return nil, err
		}
		switch {
		case resp.Status == mobius.BatchSetSoftwareInstallersStatusProcessing:
			time.Sleep(5 * time.Second)
		case resp.Status == mobius.BatchSetSoftwareInstallersStatusFailed:
			return nil, errors.New(resp.Message)
		case resp.Status == mobius.BatchSetSoftwareInstallersStatusCompleted:
			return resp.Packages, nil
		default:
			return nil, fmt.Errorf("unknown status: %q", resp.Status)
		}
	}
}

// InstallSoftware triggers a software installation (VPP or software package)
// on the specified host.
func (c *Client) InstallSoftware(hostID uint, softwareTitleID uint) error {
	verb, path := "POST", fmt.Sprintf("/api/latest/mobius/hosts/%d/software/%d/install", hostID, softwareTitleID)
	var responseBody installSoftwareResponse
	return c.authenticatedRequest(nil, verb, path, &responseBody)
}
