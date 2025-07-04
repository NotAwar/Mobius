package maintained_apps

import (
	"context"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/notawar/mobius/server/contexts/ctxerr"
	"github.com/notawar/mobius/server/mobius"
)

// InstallerTimeout is the timeout duration for downloading and adding a maintained app.
const InstallerTimeout = 15 * time.Minute

// DownloadInstaller downloads the maintained app installer located at the given URL.
func DownloadInstaller(ctx context.Context, installerURL string, client *http.Client) (*mobius.TempFileReader, string, error) {
	// validate the URL before doing the request
	_, err := url.ParseRequestURI(installerURL)
	if err != nil {
		return nil, "", mobius.NewInvalidArgumentError(
			"mobius_maintained_app.url",
			fmt.Sprintf("Couldn't download maintained app installer. URL (%q) is invalid", installerURL),
		)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, installerURL, nil)
	if err != nil {
		return nil, "", ctxerr.Wrapf(ctx, err, "creating request for URL %s", installerURL)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, "", ctxerr.Wrapf(ctx, err, "performing request for URL %s", installerURL)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, "", mobius.NewInvalidArgumentError(
			"mobius_maintained_app.url",
			fmt.Sprintf("Couldn't download maintained app installer. URL (%q) doesn't exist. Please make sure that URLs are publicy accessible to the internet.", installerURL),
		)
	}

	// Allow all 2xx and 3xx status codes in this pass.
	if resp.StatusCode > 400 {
		return nil, "", mobius.NewInvalidArgumentError(
			"mobius_maintained_app.url",
			fmt.Sprintf("Couldn't download maintained app installer. URL (%q) received response status code %d.", installerURL, resp.StatusCode),
		)
	}

	tfr, err := mobius.NewTempFileReader(resp.Body, nil)
	if err != nil {
		return nil, "", ctxerr.Wrapf(ctx, err, "reading installer %q contents", installerURL)
	}

	return tfr, FilenameFromResponse(resp), nil
}

func FilenameFromResponse(resp *http.Response) string {
	var filename string
	cdh, ok := resp.Header["Content-Disposition"]
	if ok && len(cdh) > 0 {
		_, params, err := mime.ParseMediaType(cdh[0])
		if err == nil {
			filename = params["filename"]
		} else {
			// fallback for responses that include a filename in their content-disposition header
			// but the header isn't technically RFC compliant
			cdhParts := strings.Split(cdh[0], "filename=")
			if len(cdhParts) > 1 {
				unescapedFilename, err := url.QueryUnescape(cdhParts[1])
				if err == nil {
					filename = unescapedFilename
				}
			}
		}
	}

	// Fall back on extracting the filename from the URL
	// This is OK for the first 20 apps we support, but we should do something more robust once we
	// support more apps.
	if filename == "" && resp.Request.URL.Path != "" {
		filename = path.Base(resp.Request.URL.Path)
	}

	return filename
}
