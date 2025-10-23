package service

import (
	"github.com/notawar/mobius/mobius-server/server/mobius"
)

// GetLicenseStatus fetches current license info from the server API.
func (c *Client) GetLicenseStatus() (*mobius.LicenseInfo, error) {
	verb, path := "GET", "/api/latest/mobius/license/status"
	var responseBody struct {
		License *mobius.LicenseInfo `json:"license,omitempty"`
	}
	if err := c.authenticatedRequest(nil, verb, path, &responseBody); err != nil {
		return nil, err
	}
	return responseBody.License, nil
}
