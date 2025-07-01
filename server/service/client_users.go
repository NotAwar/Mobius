package service

import (
	"errors"
	"fmt"

	"github.com/notawar/mobius/v4/server/mobius"
)

// CreateUser creates a new user, skipping the invitation process.
//
// The session key (aka API token) is returned only when creating
// API only users.
func (c *Client) CreateUser(p mobius.UserPayload) (*string, error) {
	verb, path := "POST", "/api/latest/mobius/users/admin"
	var responseBody createUserResponse
	if err := c.authenticatedRequest(p, verb, path, &responseBody); err != nil {
		return nil, err
	}
	return responseBody.Token, nil
}

// ListUsers retrieves the list of users.
func (c *Client) ListUsers() ([]mobius.User, error) {
	verb, path := "GET", "/api/latest/mobius/users"
	var responseBody listUsersResponse

	err := c.authenticatedRequest(nil, verb, path, &responseBody)
	if err != nil {
		return nil, err
	}
	return responseBody.Users, nil
}

// ApplyUsersRoleSecretSpec applies the global and team roles for users.
func (c *Client) ApplyUsersRoleSecretSpec(spec *mobius.UsersRoleSpec) error {
	req := applyUserRoleSpecsRequest{Spec: spec}
	verb, path := "POST", "/api/latest/mobius/users/roles/spec"
	var responseBody applyUserRoleSpecsResponse
	return c.authenticatedRequest(req, verb, path, &responseBody)
}

func (c *Client) userIdFromEmail(email string) (uint, error) {
	verb, path := "POST", "/api/latest/mobius/translate"
	var responseBody translatorResponse

	params := translatorRequest{List: []mobius.TranslatePayload{
		{
			Type:    mobius.TranslatorTypeUserEmail,
			Payload: mobius.StringIdentifierToIDPayload{Identifier: email},
		},
	}}

	err := c.authenticatedRequest(&params, verb, path, &responseBody)
	if err != nil {
		return 0, err
	}
	if len(responseBody.List) != 1 {
		return 0, errors.New("Expected 1 item translated, got none")
	}
	return responseBody.List[0].Payload.ID, nil
}

// DeleteUser deletes the user specified by the email
func (c *Client) DeleteUser(email string) error {
	userID, err := c.userIdFromEmail(email)
	if err != nil {
		return err
	}

	verb, path := "DELETE", fmt.Sprintf("/api/latest/mobius/users/%d", userID)
	var responseBody deleteUserResponse
	return c.authenticatedRequest(nil, verb, path, &responseBody)
}

// Me returns the user associated with the current session.
func (c *Client) Me() (*mobius.User, error) {
	verb, path := "GET", "/api/latest/mobius/me"
	var responseBody getUserResponse
	err := c.authenticatedRequest(nil, verb, path, &responseBody)
	return responseBody.User, err
}
