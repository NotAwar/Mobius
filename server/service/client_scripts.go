package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"strings"
	"time"

	mobiuss "github.com/notawar/mobius/server/mobius"
)

const pollWaitTime = 5 * time.Second

func (c *Client) RunHostScriptSync(hostID uint, scriptContents []byte, scriptName string, teamID uint) (*mobiuss.HostScriptResult, error) {
	verb, path := "POST", "/api/latest/mobiuss/scripts/run"
	res, err := c.runHostScript(verb, path, hostID, scriptContents, scriptName, teamID, http.StatusAccepted)
	if err != nil {
		return nil, err
	}

	if res.ExecutionID == "" {
		return nil, errors.New("missing execution id in response")
	}

	return c.pollForResult(res.ExecutionID)
}

func (c *Client) RunHostScriptAsync(hostID uint, scriptContents []byte, scriptName string, teamID uint) (*mobiuss.HostScriptResult, error) {
	verb, path := "POST", "/api/latest/mobiuss/scripts/run"
	return c.runHostScript(verb, path, hostID, scriptContents, scriptName, teamID, http.StatusAccepted)
}

func (c *Client) runHostScript(verb, path string, hostID uint, scriptContents []byte, scriptName string, teamID uint, successStatusCode int) (*mobiuss.HostScriptResult, error) {
	req := mobiuss.HostScriptRequestPayload{
		HostID:     hostID,
		ScriptName: scriptName,
		TeamID:     teamID,
	}
	if len(scriptContents) > 0 {
		req.ScriptContents = string(scriptContents)
	}

	var result mobiuss.HostScriptResult

	res, err := c.AuthenticatedDo(verb, path, "", &req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case successStatusCode:
		b, err := io.ReadAll(res.Body)
		if err != nil {
			return nil, fmt.Errorf("reading %s %s response: %w", verb, path, err)
		}
		if err := json.Unmarshal(b, &result); err != nil {
			return nil, fmt.Errorf("decoding %s %s response: %w, body: %s", verb, path, err, b)
		}
	case http.StatusForbidden:
		errMsg, err := extractServerErrMsg(verb, path, res)
		if err != nil {
			return nil, err
		}
		if strings.Contains(errMsg, mobiuss.RunScriptScriptsDisabledGloballyErrMsg) {
			return nil, errors.New(mobiuss.RunScriptScriptsDisabledGloballyErrMsg)
		}
		return nil, errors.New(mobiuss.RunScriptForbiddenErrMsg)
	// It's possible we get a GatewayTimeout error message from nginx or another
	// proxy server, so we want to return a more helpful error message in that
	// case.
	case http.StatusGatewayTimeout:
		return nil, errors.New(mobiuss.RunScriptGatewayTimeoutErrMsg)
	case http.StatusPaymentRequired:
		if teamID > 0 {
			return nil, errors.New("Team id parameter requires Mobius Premium license.")
		}
		fallthrough // if no team id, fall through to default error message
	default:
		msg, err := extractServerErrMsg(verb, path, res)
		if err != nil {
			return nil, err
		}
		if msg == "" {
			msg = fmt.Sprintf("decoding %d response is missing expected message.", res.StatusCode)
		}
		return nil, errors.New(msg)
	}

	return &result, nil
}

func (c *Client) pollForResult(id string) (*mobiuss.HostScriptResult, error) {
	verb, path := "GET", fmt.Sprintf("/api/latest/mobiuss/scripts/results/%s", id)
	var result *mobiuss.HostScriptResult
	for {
		res, err := c.AuthenticatedDo(verb, path, "", nil)
		if err != nil {
			return nil, fmt.Errorf("polling for result: %w", err)
		}
		defer res.Body.Close()

		if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusNotFound {

			msg, err := extractServerErrMsg(verb, path, res)
			if err != nil {
				return nil, fmt.Errorf("extracting error message: %w", err)
			}
			if msg == "" {
				msg = fmt.Sprintf("decoding %d response is missing expected message.", res.StatusCode)
			}
			return nil, errors.New(msg)
		}

		if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
			return nil, fmt.Errorf("decoding response: %w", err)
		}

		if result.ExitCode != nil {
			break
		}

		time.Sleep(pollWaitTime)

	}

	return result, nil
}

// ApplyNoTeamScripts sends the list of scripts to be applied for the hosts in
// no team.
func (c *Client) ApplyNoTeamScripts(scripts []mobiuss.ScriptPayload, opts mobiuss.ApplySpecOptions) ([]mobiuss.ScriptResponse, error) {
	verb, path := "POST", "/api/latest/mobiuss/scripts/batch"
	var resp batchSetScriptsResponse
	err := c.authenticatedRequestWithQuery(map[string]interface{}{"scripts": scripts}, verb, path, &resp, opts.RawQuery())

	return resp.Scripts, err
}

func (c *Client) validateMacOSSetupScript(fileName string) ([]byte, error) {
	if err := c.CheckAppleMDMEnabled(); err != nil {
		return nil, err
	}

	b, err := os.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func (c *Client) deleteMacOSSetupScript(teamID *uint) error {
	var query string
	if teamID != nil {
		query = fmt.Sprintf("team_id=%d", *teamID)
	}

	verb, path := "DELETE", "/api/latest/mobiuss/setup_experience/script"
	var delResp deleteSetupExperienceScriptResponse
	return c.authenticatedRequestWithQuery(nil, verb, path, &delResp, query)
}

func (c *Client) uploadMacOSSetupScript(filename string, data []byte, teamID *uint) error {
	// there is no "replace setup experience script" endpoint, and none was
	// planned, so to avoid delaying the feature I'm doing DELETE then SET, but
	// that's not ideal (will always re-create the script when apply/gitops is
	// run with the same yaml). Note though that we also redo software installers
	// downloads on each run, so the churn of this one is minor in comparison.
	if err := c.deleteMacOSSetupScript(teamID); err != nil {
		return err
	}

	verb, path := "POST", "/api/latest/mobiuss/setup_experience/script"

	var b bytes.Buffer
	w := multipart.NewWriter(&b)

	fw, err := w.CreateFormFile("script", filename)
	if err != nil {
		return err
	}
	if _, err := io.Copy(fw, bytes.NewBuffer(data)); err != nil {
		return err
	}

	// add the team_id field
	if teamID != nil {
		if err := w.WriteField("team_id", fmt.Sprint(*teamID)); err != nil {
			return err
		}
	}
	w.Close()

	response, err := c.doContextWithBodyAndHeaders(context.Background(), verb, path, "",
		b.Bytes(),
		map[string]string{
			"Content-Type":  w.FormDataContentType(),
			"Accept":        "application/json",
			"Authorization": fmt.Sprintf("Bearer %s", c.token),
		},
	)
	if err != nil {
		return fmt.Errorf("do multipart request: %w", err)
	}
	defer response.Body.Close()

	var resp setSetupExperienceScriptResponse
	if err := c.parseResponse(verb, path, response, &resp); err != nil {
		return fmt.Errorf("parse response: %w", err)
	}

	return nil
}

// ListScripts retrieves the saved scripts.
func (c *Client) ListScripts(query string) ([]*mobiuss.Script, error) {
	verb, path := "GET", "/api/latest/mobiuss/scripts"
	var responseBody listScriptsResponse
	err := c.authenticatedRequestWithQuery(nil, verb, path, &responseBody, query)
	if err != nil {
		return nil, err
	}
	return responseBody.Scripts, nil
}

// Get the contents of a saved script.
func (c *Client) GetScriptContents(scriptID uint) ([]byte, error) {
	verb, path := "GET", "/api/latest/mobiuss/scripts/"+fmt.Sprint(scriptID)
	response, err := c.AuthenticatedDo(verb, path, "alt=media", nil)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", verb, path, err)
	}
	defer response.Body.Close()
	err = c.parseResponse(verb, path, response, nil)
	if err != nil {
		return nil, fmt.Errorf("parsing script response: %w", err)
	}
	if response.StatusCode != http.StatusNoContent {
		b, err := io.ReadAll(response.Body)
		if err != nil {
			return nil, fmt.Errorf("reading response body: %w", err)
		}
		return b, nil
	}
	return nil, nil
}
