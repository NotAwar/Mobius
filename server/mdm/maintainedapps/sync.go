package maintained_apps

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	// ma "github.com/notawar/mobius/ee/maintained-apps" // Removed enterprise dependency
	"github.com/notawar/mobius/pkg/mobiushttp"
	"github.com/notawar/mobius/server/contexts/ctxerr"
	"github.com/notawar/mobius/server/mobius"
	kitlog "github.com/go-kit/log"
)

// Local replacement for enterprise types
type FMAManifestFile struct {
	Versions []FMAVersion          `json:"versions"`
	Refs     map[string]string     `json:"refs"`
}

type FMAVersion struct {
	Version              string   `json:"version"`
	Slug                 string   `json:"slug"`
	InstallerURL         string   `json:"installer_url"`
	SHA256               string   `json:"sha256"`
	InstallScriptRef     string   `json:"install_script_ref"`
	UninstallScriptRef   string   `json:"uninstall_script_ref"`
	DefaultCategories    []string `json:"default_categories"`
	Queries              FMAQueries `json:"queries"`
}

type FMAQueries struct {
	Exists string `json:"exists"`
}

func (v FMAVersion) Platform() string {
	// Stub implementation
	return "darwin"
}

type appListing struct {
	Name             string `json:"name"`
	Slug             string `json:"slug"`
	Platform         string `json:"platform"`
	UniqueIdentifier string `json:"unique_identifier"`
}

type AppsList struct {
	Version uint         `json:"version"`
	Apps    []appListing `json:"apps"`
}

const fmaOutputsBase = "https://raw.githubusercontent.com/mobiusmdm/mobius/refs/heads/main/ee/maintained-apps/outputs"

// Refresh fetches the latest information about maintained apps from FMA's
// apps list on GitHub and updates the Mobius database with the new information.
func Refresh(ctx context.Context, ds mobius.Datastore, logger kitlog.Logger) error {
	httpClient := mobiushttp.NewClient(mobiushttp.WithTimeout(10 * time.Second))
	baseURL := fmaOutputsBase
	if baseFromEnvVar := os.Getenv("MOBIUS_DEV_MAINTAINED_APPS_BASE_URL"); baseFromEnvVar != "" {
		baseURL = baseFromEnvVar
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/apps.json", baseURL), nil)
	if err != nil {
		return ctxerr.Wrap(ctx, err, "create http request")
	}

	res, err := httpClient.Do(req)
	if err != nil {
		return ctxerr.Wrap(ctx, err, "execute http request")
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return ctxerr.Wrap(ctx, err, "read http response body")
	}

	switch res.StatusCode {
	case http.StatusOK:
		// success, go on
	case http.StatusNotFound:
		return ctxerr.New(ctx, "maintained apps list not found")
	default:
		if len(body) > 512 {
			body = body[:512]
		}
		return ctxerr.Errorf(ctx, "apps list returned HTTP status %d: %s", res.StatusCode, string(body))
	}

	var appsList AppsList
	if err := json.Unmarshal(body, &appsList); err != nil {
		return ctxerr.Wrap(ctx, err, "unmarshal apps list")
	}
	if appsList.Version != 2 {
		return ctxerr.New(ctx, "apps list is an incompatible version")
	}

	var gotApps []string

	for _, app := range appsList.Apps {
		gotApps = append(gotApps, app.Slug)

		if app.UniqueIdentifier == "" {
			app.UniqueIdentifier = app.Name
		}

		if _, err = ds.UpsertMaintainedApp(ctx, &mobius.MaintainedApp{
			Name:             app.Name,
			Slug:             app.Slug,
			Platform:         app.Platform,
			UniqueIdentifier: app.UniqueIdentifier,
		}); err != nil {
			return ctxerr.Wrap(ctx, err, "upsert maintained app")
		}
	}

	// remove apps that were removed upstream
	if err := ds.ClearRemovedMobiusMaintainedApps(ctx, gotApps); err != nil {
		return ctxerr.Wrap(ctx, err, "clear removed maintained apps during refresh")
	}

	return nil
}

// Hydrate pulls information from app-level FMA manifests info an FMA skeleton pulled from the database
func Hydrate(ctx context.Context, app *mobius.MaintainedApp) (*mobius.MaintainedApp, error) {
	httpClient := mobiushttp.NewClient(mobiushttp.WithTimeout(10 * time.Second))
	baseURL := fmaOutputsBase
	if baseFromEnvVar := os.Getenv("MOBIUS_DEV_MAINTAINED_APPS_BASE_URL"); baseFromEnvVar != "" {
		baseURL = baseFromEnvVar
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/%s.json", baseURL, app.Slug), nil)
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err, "create http request")
	}

	res, err := httpClient.Do(req)
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err, "execute http request")
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err, "read http response body")
	}

	switch res.StatusCode {
	case http.StatusOK:
		// success, go on
	case http.StatusNotFound:
		return nil, ctxerr.New(ctx, "app not found in Mobius manifests")
	default:
		if len(body) > 512 {
			body = body[:512]
		}
		return nil, ctxerr.Errorf(ctx, "manifest retrieval returned HTTP status %d: %s", res.StatusCode, string(body))
	}

	var manifest FMAManifestFile
	if err := json.Unmarshal(body, &manifest); err != nil {
		return nil, ctxerr.Wrapf(ctx, err, "unmarshal FMA manifest for %s", app.Slug)
	}
	manifest.Versions[0].Slug = app.Slug

	app.Version = manifest.Versions[0].Version
	app.Platform = manifest.Versions[0].Platform()
	app.InstallerURL = manifest.Versions[0].InstallerURL
	app.SHA256 = manifest.Versions[0].SHA256
	app.InstallScript = manifest.Refs[manifest.Versions[0].InstallScriptRef]
	app.UninstallScript = manifest.Refs[manifest.Versions[0].UninstallScriptRef]
	app.AutomaticInstallQuery = manifest.Versions[0].Queries.Exists
	app.Categories = manifest.Versions[0].DefaultCategories

	return app, nil
}
