package service

import "github.com/notawar/mobius/server/mobius"

func (c *Client) SaveSecretVariables(secretVariables []mobius.SecretVariable, dryRun bool) error {
	verb, path := "PUT", "/api/latest/mobius/spec/secret_variables"
	params := secretVariablesRequest{
		SecretVariables: secretVariables,
		DryRun:          dryRun,
	}
	var responseBody secretVariablesResponse
	return c.authenticatedRequest(params, verb, path, &responseBody)
}
