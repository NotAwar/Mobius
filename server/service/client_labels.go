package service

import (
	"net/url"

	"github.com/notawar/mobius/v4/server/mobius"
)

// ApplyLabels sends the list of Labels to be applied (upserted) to the
// Mobius instance.
func (c *Client) ApplyLabels(specs []*mobius.LabelSpec) error {
	req := applyLabelSpecsRequest{Specs: specs}
	verb, path := "POST", "/api/latest/mobius/spec/labels"
	var responseBody applyLabelSpecsResponse
	return c.authenticatedRequest(req, verb, path, &responseBody)
}

// GetLabel retrieves information about a label by name
func (c *Client) GetLabel(name string) (*mobius.LabelSpec, error) {
	verb, path := "GET", "/api/latest/mobius/spec/labels/"+url.PathEscape(name)
	var responseBody getLabelSpecResponse
	err := c.authenticatedRequest(nil, verb, path, &responseBody)
	return responseBody.Spec, err
}

// GetLabels retrieves the list of all LabelSpecs.
func (c *Client) GetLabels() ([]*mobius.LabelSpec, error) {
	verb, path := "GET", "/api/latest/mobius/spec/labels"
	var responseBody getLabelSpecsResponse
	err := c.authenticatedRequest(nil, verb, path, &responseBody)
	return responseBody.Specs, err
}

// DeleteLabel deletes the label with the matching name.
func (c *Client) DeleteLabel(name string) error {
	verb, path := "DELETE", "/api/latest/mobius/labels/"+url.PathEscape(name)
	var responseBody deleteLabelResponse
	return c.authenticatedRequest(nil, verb, path, &responseBody)
}
