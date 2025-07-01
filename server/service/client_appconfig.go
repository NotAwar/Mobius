package service

import (
	"github.com/notawar/mobius/v4/server/mobius"
	"github.com/notawar/mobius/v4/server/version"
)

// ApplyAppConfig sends the application config to be applied to the Mobius instance.
func (c *Client) ApplyAppConfig(payload interface{}, opts mobius.ApplySpecOptions) error {
	verb, path := "PATCH", "/api/latest/mobius/config"
	var responseBody appConfigResponse
	return c.authenticatedRequestWithQuery(payload, verb, path, &responseBody, opts.RawQuery())
}

// ApplyNoTeamProfiles sends the list of profiles to be applied for the hosts
// in no team.
func (c *Client) ApplyNoTeamProfiles(profiles []mobius.MDMProfileBatchPayload, opts mobius.ApplySpecOptions, assumeEnabled bool) error {
	verb, path := "POST", "/api/latest/mobius/mdm/profiles/batch"
	query := opts.RawQuery()
	if assumeEnabled {
		if query != "" {
			query += "&"
		}
		query += "assume_enabled=true"
	}
	return c.authenticatedRequestWithQuery(map[string]interface{}{"profiles": profiles}, verb, path, nil, query)
}

// GetAppConfig fetches the application config from the server API
func (c *Client) GetAppConfig() (*mobius.EnrichedAppConfig, error) {
	verb, path := "GET", "/api/latest/mobius/config"
	var responseBody mobius.EnrichedAppConfig
	err := c.authenticatedRequest(nil, verb, path, &responseBody)
	return &responseBody, err
}

// GetEnrollSecretSpec fetches the enroll secrets stored on the server
func (c *Client) GetEnrollSecretSpec() (*mobius.EnrollSecretSpec, error) {
	verb, path := "GET", "/api/latest/mobius/spec/enroll_secret"
	var responseBody getEnrollSecretSpecResponse
	err := c.authenticatedRequest(nil, verb, path, &responseBody)
	return responseBody.Spec, err
}

// ApplyEnrollSecretSpec applies the enroll secrets.
func (c *Client) ApplyEnrollSecretSpec(spec *mobius.EnrollSecretSpec, opts mobius.ApplySpecOptions) error {
	req := applyEnrollSecretSpecRequest{Spec: spec}
	verb, path := "POST", "/api/latest/mobius/spec/enroll_secret"
	var responseBody applyEnrollSecretSpecResponse
	return c.authenticatedRequestWithQuery(req, verb, path, &responseBody, opts.RawQuery())
}

func (c *Client) Version() (*version.Info, error) {
	verb, path := "GET", "/api/latest/mobius/version"
	var responseBody versionResponse
	err := c.authenticatedRequest(nil, verb, path, &responseBody)
	return responseBody.Info, err
}
