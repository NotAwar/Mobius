package service

import (
	"fmt"

	"github.com/notawar/mobius/v4/server/mobius"
)

// SearchTargets searches for the supplied targets in the Mobius instance.
func (c *Client) SearchTargets(query string, hostIDs, labelIDs []uint) (*mobius.TargetSearchResults, error) {
	req := searchTargetsRequest{
		MatchQuery: query,
		Selected: mobius.HostTargets{
			LabelIDs: labelIDs,
			HostIDs:  hostIDs,
			// TODO handle TeamIDs
		},
	}
	verb, path := "POST", "/api/latest/mobius/targets"
	var responseBody searchTargetsResponse
	err := c.authenticatedRequest(req, verb, path, &responseBody)
	if err != nil {
		return nil, fmt.Errorf("SearchTargets: %s", err)
	}

	hosts := make([]*mobius.Host, len(responseBody.Targets.Hosts))
	for i, h := range responseBody.Targets.Hosts {
		hosts[i] = h.Host
	}

	labels := make([]*mobius.Label, len(responseBody.Targets.Labels))
	for i, h := range responseBody.Targets.Labels {
		labels[i] = h.Label
	}

	return &mobius.TargetSearchResults{
		Hosts:  hosts,
		Labels: labels,
	}, nil
}
