// pacakge mobiusdbase contains functions to interact with downloads.mobiusmdm.com
package mobiusdaemonbase

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
)

type Metadata struct {
	MSIURL           string `json:"mobiusdaemon_base_msi_url"`
	MSISha256        string `json:"mobiusdaemon_base_msi_sha256"`
	PKGURL           string `json:"mobiusdaemon_base_pkg_url"`
	PKGSha256        string `json:"mobiusdaemon_base_pkg_sha256"`
	ManifestPlistURL string `json:"mobiusdaemon_base_manifest_plist_url"`
	Version          string `json:"version"`
}

func getBaseURL() string {
	devURL := os.Getenv("MOBIUS_DEV_DOWNLOAD_MOBIUSDAEMONM_URL")
	if devURL != "" {
		return devURL
	}
	return "https://download.mobiusmdm.com"
}

func GetMetadata() (*Metadata, error) {
	baseURL := getBaseURL()
	rawURL := fmt.Sprintf("%s/stable/meta.json", baseURL)

	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	resp, err := http.Get(parsedURL.String())
	if err != nil {
		return nil, fmt.Errorf("failed to fetch metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var meta Metadata
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &meta, nil
}

func GetPKGManifestURL() string {
	baseURL := getBaseURL()
	return fmt.Sprintf("%s/stable/mobiusdaemon-base-manifest.plist", baseURL)
}
