package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/notawar/mobius/pkg/mobiushttp"
	"github.com/notawar/mobius/server/authz"
	"github.com/notawar/mobius/server/contexts/ctxerr"
	"github.com/notawar/mobius/server/contexts/license"
	"github.com/notawar/mobius/server/contexts/viewer"
	"github.com/notawar/mobius/server/mobius"
	"github.com/notawar/mobius/server/ptr"
)

/////////////////////////////////////////////////////////////////////////////////
// Add
/////////////////////////////////////////////////////////////////////////////////

type globalPolicyRequest struct {
	QueryID          *uint    `json:"query_id"`
	Query            string   `json:"query"`
	Name             string   `json:"name"`
	Description      string   `json:"description"`
	Resolution       string   `json:"resolution"`
	Platform         string   `json:"platform"`
	Critical         bool     `json:"critical" premium:"true"`
	LabelsIncludeAny []string `json:"labels_include_any"`
	LabelsExcludeAny []string `json:"labels_exclude_any"`
}

type globalPolicyResponse struct {
	Policy *mobius.Policy `json:"policy,omitempty"`
	Err    error         `json:"error,omitempty"`
}

func (r globalPolicyResponse) Error() error { return r.Err }

func globalPolicyEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*globalPolicyRequest)
	resp, err := svc.NewGlobalPolicy(ctx, mobius.PolicyPayload{
		QueryID:          req.QueryID,
		Query:            req.Query,
		Name:             req.Name,
		Description:      req.Description,
		Resolution:       req.Resolution,
		Platform:         req.Platform,
		Critical:         req.Critical,
		LabelsIncludeAny: req.LabelsIncludeAny,
		LabelsExcludeAny: req.LabelsExcludeAny,
	})
	if err != nil {
		return globalPolicyResponse{Err: err}, nil
	}
	return globalPolicyResponse{Policy: resp}, nil
}

func (svc Service) NewGlobalPolicy(ctx context.Context, p mobius.PolicyPayload) (*mobius.Policy, error) {
	if err := svc.authz.Authorize(ctx, &mobius.Policy{}, mobius.ActionWrite); err != nil {
		return nil, err
	}
	vc, ok := viewer.FromContext(ctx)
	if !ok {
		return nil, errors.New("user must be authenticated to create team policies")
	}
	if err := p.Verify(); err != nil {
		return nil, ctxerr.Wrap(ctx, &mobius.BadRequestError{
			Message: fmt.Sprintf("policy payload verification: %s", err),
		})
	}
	policy, err := svc.ds.NewGlobalPolicy(ctx, ptr.Uint(vc.UserID()), p)
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err, "storing policy")
	}
	// Note: Issue #4191 proposes that we move to SQL transactions for actions so that we can
	// rollback an action in the event of an error writing the associated activity
	if err := svc.NewActivity(
		ctx,
		authz.UserFromContext(ctx),
		mobius.ActivityTypeCreatedPolicy{
			ID:   policy.ID,
			Name: policy.Name,
		},
	); err != nil {
		return nil, ctxerr.Wrap(ctx, err, "create activity for global policy creation")
	}
	return policy, nil
}

/////////////////////////////////////////////////////////////////////////////////
// List
/////////////////////////////////////////////////////////////////////////////////

type listGlobalPoliciesRequest struct {
	Opts mobius.ListOptions `url:"list_options"`
}

type listGlobalPoliciesResponse struct {
	Policies []*mobius.Policy `json:"policies,omitempty"`
	Err      error           `json:"error,omitempty"`
}

func (r listGlobalPoliciesResponse) Error() error { return r.Err }

func listGlobalPoliciesEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*listGlobalPoliciesRequest)
	resp, err := svc.ListGlobalPolicies(ctx, req.Opts)
	if err != nil {
		return listGlobalPoliciesResponse{Err: err}, nil
	}
	return listGlobalPoliciesResponse{Policies: resp}, nil
}

func (svc Service) ListGlobalPolicies(ctx context.Context, opts mobius.ListOptions) ([]*mobius.Policy, error) {
	if err := svc.authz.Authorize(ctx, &mobius.Policy{}, mobius.ActionRead); err != nil {
		return nil, err
	}

	return svc.ds.ListGlobalPolicies(ctx, opts)
}

/////////////////////////////////////////////////////////////////////////////////
// Get by id
/////////////////////////////////////////////////////////////////////////////////

type getPolicyByIDRequest struct {
	PolicyID uint `url:"policy_id"`
}

type getPolicyByIDResponse struct {
	Policy *mobius.Policy `json:"policy"`
	Err    error         `json:"error,omitempty"`
}

func (r getPolicyByIDResponse) Error() error { return r.Err }

func getPolicyByIDEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*getPolicyByIDRequest)
	policy, err := svc.GetPolicyByIDQueries(ctx, req.PolicyID)
	if err != nil {
		return getPolicyByIDResponse{Err: err}, nil
	}
	return getPolicyByIDResponse{Policy: policy}, nil
}

func (svc Service) GetPolicyByIDQueries(ctx context.Context, policyID uint) (*mobius.Policy, error) {
	if err := svc.authz.Authorize(ctx, &mobius.Policy{}, mobius.ActionRead); err != nil {
		return nil, err
	}

	policy, err := svc.ds.Policy(ctx, policyID)
	if err != nil {
		return nil, err
	}
	if err := svc.populatePolicyInstallSoftware(ctx, policy); err != nil {
		return nil, ctxerr.Wrap(ctx, err, "populate install_software")
	}
	if err := svc.populatePolicyRunScript(ctx, policy); err != nil {
		return nil, ctxerr.Wrap(ctx, err, "populate run_script")
	}

	return policy, nil
}

// ///////////////////////////////////////////////////////////////////////////////
// Count
// ///////////////////////////////////////////////////////////////////////////////

type countGlobalPoliciesRequest struct {
	ListOptions mobius.ListOptions `url:"list_options"`
}
type countGlobalPoliciesResponse struct {
	Count int   `json:"count"`
	Err   error `json:"error,omitempty"`
}

func (r countGlobalPoliciesResponse) Error() error { return r.Err }

func countGlobalPoliciesEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*countGlobalPoliciesRequest)
	resp, err := svc.CountGlobalPolicies(ctx, req.ListOptions.MatchQuery)
	if err != nil {
		return countGlobalPoliciesResponse{Err: err}, nil
	}
	return countGlobalPoliciesResponse{Count: resp}, nil
}

func (svc Service) CountGlobalPolicies(ctx context.Context, matchQuery string) (int, error) {
	if err := svc.authz.Authorize(ctx, &mobius.Policy{}, mobius.ActionRead); err != nil {
		return 0, err
	}

	count, err := svc.ds.CountPolicies(ctx, nil, matchQuery)
	if err != nil {
		return 0, err
	}

	return count, nil
}

/////////////////////////////////////////////////////////////////////////////////
// Delete
/////////////////////////////////////////////////////////////////////////////////

type deleteGlobalPoliciesRequest struct {
	IDs []uint `json:"ids"`
}

type deleteGlobalPoliciesResponse struct {
	Deleted []uint `json:"deleted,omitempty"`
	Err     error  `json:"error,omitempty"`
}

func (r deleteGlobalPoliciesResponse) Error() error { return r.Err }

func deleteGlobalPoliciesEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*deleteGlobalPoliciesRequest)
	resp, err := svc.DeleteGlobalPolicies(ctx, req.IDs)
	if err != nil {
		return deleteGlobalPoliciesResponse{Err: err}, nil
	}
	return deleteGlobalPoliciesResponse{Deleted: resp}, nil
}

// DeleteGlobalPolicies deletes the given policies from the database.
// It also deletes the given ids from the failing policies webhook configuration.
func (svc Service) DeleteGlobalPolicies(ctx context.Context, ids []uint) ([]uint, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	policiesByID, err := svc.ds.PoliciesByID(ctx, ids)
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err, "getting policies by ID")
	}
	if err := svc.authz.Authorize(ctx, &mobius.Policy{}, mobius.ActionWrite); err != nil {
		return nil, err
	}
	for _, policy := range policiesByID {
		if policy.PolicyData.TeamID != nil {
			return nil, authz.ForbiddenWithInternal(
				"attempting to delete policy that belongs to team",
				authz.UserFromContext(ctx),
				policy,
				mobius.ActionWrite,
			)
		}
	}
	if err := svc.removeGlobalPoliciesFromWebhookConfig(ctx, ids); err != nil {
		return nil, ctxerr.Wrap(ctx, err, "removing global policies from webhook config")
	}
	deletedIDs, err := svc.ds.DeleteGlobalPolicies(ctx, ids)
	if err != nil {
		return nil, err
	}

	// Note: Issue #4191 proposes that we move to SQL transactions for actions so that we can
	// rollback an action in the event of an error writing the associated activity
	for _, id := range deletedIDs {
		if err := svc.NewActivity(
			ctx,
			authz.UserFromContext(ctx),
			mobius.ActivityTypeDeletedPolicy{
				ID:   id,
				Name: policiesByID[id].Name,
			},
		); err != nil {
			return nil, ctxerr.Wrap(ctx, err, "create activity for policy deletion")
		}
	}
	return ids, nil
}

func (svc Service) removeGlobalPoliciesFromWebhookConfig(ctx context.Context, ids []uint) error {
	ac, err := svc.ds.AppConfig(ctx)
	if err != nil {
		return err
	}
	idSet := make(map[uint]struct{})
	for _, id := range ids {
		idSet[id] = struct{}{}
	}
	n := 0
	policyIDs := ac.WebhookSettings.FailingPoliciesWebhook.PolicyIDs
	origLen := len(policyIDs)
	for i := range policyIDs {
		if _, ok := idSet[policyIDs[i]]; !ok {
			policyIDs[n] = policyIDs[i]
			n++
		}
	}
	if n == origLen {
		return nil
	}
	ac.WebhookSettings.FailingPoliciesWebhook.PolicyIDs = policyIDs[:n]
	if err := svc.ds.SaveAppConfig(ctx, ac); err != nil {
		return err
	}
	return nil
}

/////////////////////////////////////////////////////////////////////////////////
// Modify
/////////////////////////////////////////////////////////////////////////////////

type modifyGlobalPolicyRequest struct {
	PolicyID uint `url:"policy_id"`
	mobius.ModifyPolicyPayload
}

type modifyGlobalPolicyResponse struct {
	Policy *mobius.Policy `json:"policy,omitempty"`
	Err    error         `json:"error,omitempty"`
}

func (r modifyGlobalPolicyResponse) Error() error { return r.Err }

func modifyGlobalPolicyEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*modifyGlobalPolicyRequest)
	resp, err := svc.ModifyGlobalPolicy(ctx, req.PolicyID, req.ModifyPolicyPayload)
	if err != nil {
		return modifyGlobalPolicyResponse{Err: err}, nil
	}
	return modifyGlobalPolicyResponse{Policy: resp}, nil
}

func (svc *Service) ModifyGlobalPolicy(ctx context.Context, id uint, p mobius.ModifyPolicyPayload) (*mobius.Policy, error) {
	return svc.modifyPolicy(ctx, nil, id, p)
}

/////////////////////////////////////////////////////////////////////////////////
// Reset automation
/////////////////////////////////////////////////////////////////////////////////

type resetAutomationRequest struct {
	TeamIDs   []uint `json:"team_ids" premium:"true"`
	PolicyIDs []uint `json:"policy_ids"`
}

type resetAutomationResponse struct {
	Err error `json:"error,omitempty"`
}

func (r resetAutomationResponse) Error() error { return r.Err }

func resetAutomationEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*resetAutomationRequest)
	err := svc.ResetAutomation(ctx, req.TeamIDs, req.PolicyIDs)
	return resetAutomationResponse{Err: err}, nil
}

func (svc *Service) ResetAutomation(ctx context.Context, teamIDs, policyIDs []uint) error {
	ac, err := svc.ds.AppConfig(ctx)
	if err != nil {
		return err
	}
	allAutoPolicies := automationPolicies(ac.WebhookSettings.FailingPoliciesWebhook, ac.Integrations.Jira, ac.Integrations.Zendesk)
	pIDs := make(map[uint]struct{})
	for _, id := range policyIDs {
		pIDs[id] = struct{}{}
	}
	for _, teamID := range teamIDs {
		p1, p2, err := svc.ds.ListTeamPolicies(ctx, teamID, mobius.ListOptions{}, mobius.ListOptions{})
		if err != nil {
			return err
		}
		for _, p := range p1 {
			pIDs[p.ID] = struct{}{}
		}
		for _, p := range p2 {
			pIDs[p.ID] = struct{}{}
		}
	}
	hasGlobal := false
	tIDs := make(map[uint]struct{})
	for id := range pIDs {
		p, err := svc.ds.Policy(ctx, id)
		if err != nil {
			return err
		}
		if p.TeamID == nil {
			hasGlobal = true
		} else {
			tIDs[*p.TeamID] = struct{}{}
		}
	}
	for id := range tIDs {
		if err := svc.authz.Authorize(ctx, &mobius.Team{ID: id}, mobius.ActionWrite); err != nil {
			return err
		}
		t, err := svc.ds.Team(ctx, id)
		if err != nil {
			return err
		}
		for pID := range teamAutomationPolicies(t.Config.WebhookSettings.FailingPoliciesWebhook, t.Config.Integrations.Jira, t.Config.Integrations.Zendesk) {
			allAutoPolicies[pID] = struct{}{}
		}
	}
	if hasGlobal {
		if err := svc.authz.Authorize(ctx, &mobius.AppConfig{}, mobius.ActionWrite); err != nil {
			return err
		}
	}
	if len(tIDs) == 0 && !hasGlobal {
		svc.authz.SkipAuthorization(ctx)
		return nil
	}
	for id := range pIDs {
		if _, ok := allAutoPolicies[id]; !ok {
			continue
		}
		if err := svc.ds.IncreasePolicyAutomationIteration(ctx, id); err != nil {
			return err
		}
	}
	return nil
}

func automationPolicies(wh mobius.FailingPoliciesWebhookSettings, ji []*mobius.JiraIntegration, zi []*mobius.ZendeskIntegration) map[uint]struct{} {
	enabled := wh.Enable
	for _, j := range ji {
		if j.EnableFailingPolicies {
			enabled = true
		}
	}
	for _, z := range zi {
		if z.EnableFailingPolicies {
			enabled = true
		}
	}
	pols := make(map[uint]struct{}, len(wh.PolicyIDs))
	if !enabled {
		return pols
	}
	for _, pid := range wh.PolicyIDs {
		pols[pid] = struct{}{}
	}
	return pols
}

func teamAutomationPolicies(wh mobius.FailingPoliciesWebhookSettings, ji []*mobius.TeamJiraIntegration, zi []*mobius.TeamZendeskIntegration) map[uint]struct{} {
	enabled := wh.Enable
	for _, j := range ji {
		if j.EnableFailingPolicies {
			enabled = true
		}
	}
	for _, z := range zi {
		if z.EnableFailingPolicies {
			enabled = true
		}
	}
	pols := make(map[uint]struct{}, len(wh.PolicyIDs))
	if !enabled {
		return pols
	}
	for _, pid := range wh.PolicyIDs {
		pols[pid] = struct{}{}
	}
	return pols
}

/////////////////////////////////////////////////////////////////////////////////
// Apply Spec
/////////////////////////////////////////////////////////////////////////////////

type applyPolicySpecsRequest struct {
	Specs []*mobius.PolicySpec `json:"specs"`
}

type applyPolicySpecsResponse struct {
	Err error `json:"error,omitempty"`
}

func (r applyPolicySpecsResponse) Error() error { return r.Err }

func applyPolicySpecsEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*applyPolicySpecsRequest)
	err := svc.ApplyPolicySpecs(ctx, req.Specs)
	if err != nil {
		return applyPolicySpecsResponse{Err: err}, nil
	}
	return applyPolicySpecsResponse{}, nil
}

// checkPolicySpecAuthorization verifies that the user is authorized to modify the
// policies defined in the spec.
func (svc *Service) checkPolicySpecAuthorization(ctx context.Context, policies []*mobius.PolicySpec) error {
	checkGlobalPolicyAuth := false
	for _, policy := range policies {
		if policy.Team != "" && policy.Team != "No team" {
			team, err := svc.ds.TeamByName(ctx, policy.Team)
			if err != nil {
				// This is so that the proper HTTP status code is returned
				svc.authz.SkipAuthorization(ctx)
				return ctxerr.Wrap(ctx, err, "getting team by name")
			}
			if err := svc.authz.Authorize(ctx, &mobius.Policy{
				PolicyData: mobius.PolicyData{
					TeamID: &team.ID,
				},
			}, mobius.ActionWrite); err != nil {
				return err
			}
		} else {
			checkGlobalPolicyAuth = true
		}
	}
	if checkGlobalPolicyAuth {
		if err := svc.authz.Authorize(ctx, &mobius.Policy{}, mobius.ActionWrite); err != nil {
			return err
		}
	}
	return nil
}

func (svc *Service) ApplyPolicySpecs(ctx context.Context, policies []*mobius.PolicySpec) error {
	// Check authorization first.
	if err := svc.checkPolicySpecAuthorization(ctx, policies); err != nil {
		return err
	}

	// After the authorization check, check the policy fields.
	for _, policy := range policies {
		if err := policy.Verify(); err != nil {
			return ctxerr.Wrap(ctx, &mobius.BadRequestError{
				Message: fmt.Sprintf("policy spec payload verification: %s", err),
			})
		}

		// Make sure any applied labels exist.
		labels := policy.LabelsIncludeAny
		labels = append(labels, policy.LabelsExcludeAny...)
		if len(labels) > 0 {
			labelsMap, err := svc.ds.LabelsByName(ctx, labels)
			if err != nil {
				return ctxerr.Wrap(ctx, err, "getting labels by name")
			}
			for _, label := range labels {
				if _, ok := labelsMap[label]; !ok {
					return ctxerr.Wrap(ctx, &mobius.BadRequestError{
						Message: fmt.Sprintf("label %q does not exist", label),
					})
				}
			}
		}

	}

	// An empty string indicates there are no duplicate names.
	if name := mobius.FirstDuplicatePolicySpecName(policies); name != "" {
		return ctxerr.Wrap(ctx, &mobius.BadRequestError{
			Message: "duplicate policy names not allowed",
		})
	}

	vc, ok := viewer.FromContext(ctx)
	if !ok {
		return errors.New("user must be authenticated to apply policies")
	}
	if !license.IsPremium(ctx) {
		for i := range policies {
			policies[i].Critical = false
		}
	}

	if err := svc.ds.ApplyPolicySpecs(ctx, vc.UserID(), policies); err != nil {
		return ctxerr.Wrap(ctx, err, "applying policy specs")
	}
	// Note: Issue #4191 proposes that we move to SQL transactions for actions so that we can
	// rollback an action in the event of an error writing the associated activity
	if err := svc.NewActivity(
		ctx,
		authz.UserFromContext(ctx),
		mobius.ActivityTypeAppliedSpecPolicy{
			Policies: policies,
		},
	); err != nil {
		return ctxerr.Wrap(ctx, err, "create activity for policy spec")
	}
	return nil
}

/////////////////////////////////////////////////////////////////////////////////
// Autofill
/////////////////////////////////////////////////////////////////////////////////

type autofillPoliciesRequest struct {
	SQL string `json:"sql"`
}

type autofillPoliciesResponse struct {
	Description string `json:"description"`
	Resolution  string `json:"resolution"`
	Err         error  `json:"error,omitempty"`
}

func (a autofillPoliciesResponse) Error() error {
	return a.Err
}

func autofillPoliciesEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*autofillPoliciesRequest)
	description, resolution, err := svc.AutofillPolicySql(ctx, req.SQL)
	return autofillPoliciesResponse{Description: description, Resolution: resolution, Err: err}, nil
}

// Exposing external URL and timeout for testing purposes
var (
	getHumanInterpretationFromOsquerySqlUrl     = "https://mobiusmdm.com/api/v1/get-human-interpretation-from-osquery-sql"
	getHumanInterpretationFromOsquerySqlTimeout = 30 * time.Second
)

type AutofillError struct {
	Message     string
	InternalErr error
}

// Error implements the error interface.
func (e AutofillError) Error() string {
	return e.Message
}

// StatusCode implements the kithttp.StatusCoder interface.
func (e AutofillError) StatusCode() int {
	return http.StatusUnprocessableEntity
}

func (e AutofillError) Internal() string {
	if e.InternalErr == nil {
		return ""
	}
	return e.InternalErr.Error()
}

func (svc *Service) AutofillPolicySql(ctx context.Context, sql string) (description string, resolution string, err error) {
	vc, ok := viewer.FromContext(ctx)
	if !ok {
		svc.authz.SkipAuthorization(ctx)
		return "", "", mobius.ErrNoContext
	}

	// We expect that only users with policy write permissions will autofill policies.
	if vc.User.GlobalRole != nil || len(vc.User.Teams) == 0 {
		if err = svc.authz.Authorize(ctx, &mobius.Policy{}, mobius.ActionWrite); err != nil {
			return "", "", err
		}
	} else {
		// Check if this user has team policy write permissions.
		teamID := vc.User.Teams[0].Team.ID
		for _, teamUser := range vc.User.Teams {
			if teamUser.Role == mobius.RoleAdmin || teamUser.Role == mobius.RoleMaintainer || teamUser.Role == mobius.RoleGitOps {
				teamID = teamUser.Team.ID
				break
			}
		}
		err = svc.authz.Authorize(
			ctx, &mobius.Policy{PolicyData: mobius.PolicyData{TeamID: &teamID}}, mobius.ActionWrite,
		)
		if err != nil {
			return "", "", err
		}
	}

	appConfig, err := svc.ds.AppConfig(ctx)
	if err != nil {
		return "", "", err
	}
	if appConfig.ServerSettings.AIFeaturesDisabled {
		return "", "", ctxerr.Wrap(
			ctx, &mobius.BadRequestError{
				Message: "AI features are disabled (server_settings.ai_features_disabled)",
			},
		)
	}

	sql = strings.TrimSpace(sql)
	if sql == "" {
		return "", "", ctxerr.Wrap(ctx, &mobius.BadRequestError{Message: "'sql' cannot be empty"})
	}

	// Using a timeout smaller than the Mobius server's WriteTimeout
	client := mobiushttp.NewClient(mobiushttp.WithTimeout(getHumanInterpretationFromOsquerySqlTimeout))
	reqBodyValues := map[string]string{"sql": sql}
	reqBody, err := json.Marshal(reqBodyValues)
	if err != nil {
		return "", "", ctxerr.Wrap(
			ctx, &mobius.BadRequestError{
				Message: fmt.Sprintf("Could not process sql: %s", sql),
			},
		)
	}
	resp, err := client.Post(
		getHumanInterpretationFromOsquerySqlUrl, "application/json", bytes.NewBuffer(reqBody),
	)
	if err != nil {
		return "", "", ctxerr.Wrap(
			ctx, AutofillError{
				Message:     "error sending request to get human interpretation from osquery sql",
				InternalErr: err,
			},
		)
	}
	defer resp.Body.Close()
	if (resp.StatusCode / 100) != 2 {
		return "", "", ctxerr.Wrap(
			ctx, AutofillError{
				Message: "error from human interpretation of osquery sql",
				InternalErr: fmt.Errorf(
					"%s returned %d status code", getHumanInterpretationFromOsquerySqlUrl, resp.StatusCode,
				),
			},
		)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", ctxerr.Wrap(
			ctx, AutofillError{
				Message:     "error reading response body from human interpretation of osquery sql",
				InternalErr: err,
			},
		)
	}

	var result map[string]string
	err = json.Unmarshal(body, &result)
	if err != nil {
		return "", "", ctxerr.Wrap(
			ctx, AutofillError{
				Message:     "error unmarshaling response body from human interpretation of osquery sql",
				InternalErr: err,
			},
		)
	}
	const maxLength = 1<<16 - 1
	descriptionTrimmed := result["risks"]
	if len(descriptionTrimmed) > maxLength {
		descriptionTrimmed = descriptionTrimmed[:maxLength]
	}
	resolutionTrimmed := result["whatWillProbablyHappenDuringMaintenance"]
	if len(resolutionTrimmed) > maxLength {
		resolutionTrimmed = resolutionTrimmed[:maxLength]
	}
	return descriptionTrimmed, resolutionTrimmed, nil
}
