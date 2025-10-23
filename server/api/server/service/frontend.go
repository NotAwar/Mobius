package service

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/go-kit/log"
	"github.com/notawar/mobius/mobius-server/server/mobius"
	"github.com/notawar/mobius/mobius-server/server/service/middleware/endpoint_utils"
)

func ServeFrontend(urlPrefix string, sandbox bool, logger log.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		endpoint_utils.WriteBrowserSecurityHeaders(w)

		// The following check is to prevent a misconfigured osquery from submitting
		// data to the root endpoint (the osquery remote API uses POST for all its endpoints).
		// See https://github.com/notawar/mobius/issues/16182.
		if r.Method == "POST" {
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}

		serverType := "on-premise"
		if sandbox {
			serverType = "sandbox"
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)

		html := `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Mobius API Server</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 0;
            padding: 40px;
            background-color: #f5f5f5;
            color: #333;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
            background-color: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
        }
        h1 {
            color: #0078d4;
            margin-bottom: 20px;
        }
        .status {
            background-color: #d4edda;
            color: #155724;
            padding: 15px;
            border-radius: 4px;
            margin-bottom: 20px;
            border: 1px solid #c3e6cb;
        }
        .endpoint {
            background-color: #f8f9fa;
            padding: 10px;
            border-radius: 4px;
            margin: 10px 0;
            font-family: monospace;
        }
        .server-type {
            font-weight: bold;
            color: #0078d4;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Mobius API Server</h1>
        
        <div class="status">
            ✅ API Server is running (` + serverType + `)
        </div>
        
        <p>This is a backend-only Mobius installation. The API endpoints are available at:</p>
        
        <div class="endpoint">` + urlPrefix + `/api/v1/mobius/</div>
        
        <h3>Available Endpoints:</h3>
        <ul>
            <li><strong>Health Check:</strong> <code>` + urlPrefix + `/healthz</code></li>
            <li><strong>Version:</strong> <code>` + urlPrefix + `/version</code></li>
            <li><strong>API Documentation:</strong> <code>` + urlPrefix + `/api/v1/mobius/</code></li>
            <li><strong>Device Enrollment:</strong> <code>` + urlPrefix + `/enroll</code></li>
        </ul>
        
        <p>For API documentation and usage information, please refer to the Mobius documentation.</p>
    </div>
</body>
</html>`

		w.Write([]byte(html))
	})
}

func ServeEndUserEnrollOTA(
	svc mobius.Service,
	urlPrefix string,
	ds mobius.Datastore,
	logger log.Logger,
) http.Handler {
	herr := func(w http.ResponseWriter, err string) {
		logger.Log("err", err)
		http.Error(w, err, http.StatusInternalServerError)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		endpoint_utils.WriteBrowserSecurityHeaders(w)
		setupRequired, err := svc.SetupRequired(r.Context())
		if err != nil {
			herr(w, "setup required err: "+err.Error())
			return
		}
		if setupRequired {
			herr(w, "mobius instance not setup")
			return
		}

		appCfg, err := ds.AppConfig(r.Context())
		if err != nil {
			herr(w, "load appconfig err: "+err.Error())
			return
		}

		enrollURL, err := generateEnrollOTAURL(urlPrefix, r.URL.Query().Get("enroll_secret"))
		if err != nil {
			herr(w, "generate enroll ota url: "+err.Error())
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)

		html := `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Device Enrollment - Mobius</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 0;
            padding: 40px;
            background-color: #f5f5f5;
            color: #333;
        }
        .container {
            max-width: 600px;
            margin: 0 auto;
            background-color: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
        }
        h1 {
            color: #0078d4;
            margin-bottom: 20px;
            text-align: center;
        }
        .enroll-section {
            text-align: center;
            padding: 20px;
            background-color: #f8f9fa;
            border-radius: 4px;
            margin: 20px 0;
        }
        .enroll-button {
            background-color: #0078d4;
            color: white;
            border: none;
            padding: 12px 30px;
            font-size: 16px;
            border-radius: 4px;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
            margin: 10px;
        }
        .enroll-button:hover {
            background-color: #106ebe;
        }
        .platform-info {
            background-color: #e3f2fd;
            padding: 15px;
            border-radius: 4px;
            margin: 20px 0;
        }
        .disabled {
            opacity: 0.6;
            cursor: not-allowed;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Device Enrollment</h1>
        
        <p>Enroll your device with Mobius Mobile Device Management.</p>
        
        <div class="enroll-section">
            <h3>Available Enrollment Options:</h3>`

		if appCfg.MDM.EnabledAndConfigured {
			html += `
            <div class="platform-info">
                <h4>macOS Enrollment</h4>
                <p>Enroll your Mac device for management.</p>
                <a href="` + enrollURL + `" class="enroll-button">Enroll macOS Device</a>
            </div>`
		}

		if appCfg.MDM.AndroidEnabledAndConfigured {
			html += `
            <div class="platform-info">
                <h4>Android Enrollment</h4>
                <p>Enroll your Android device for management.</p>
                <a href="` + enrollURL + `" class="enroll-button">Enroll Android Device</a>
            </div>`
		}

		if !appCfg.MDM.EnabledAndConfigured && !appCfg.MDM.AndroidEnabledAndConfigured {
			html += `
            <div class="platform-info">
                <p>No enrollment options are currently available. Please contact your administrator.</p>
            </div>`
		}

		html += `
        </div>
        
        <p><small>If you have questions about enrollment, please contact your IT administrator.</small></p>
    </div>
</body>
</html>`

		w.Write([]byte(html))
	})
}

func generateEnrollOTAURL(mobiusURL string, enrollSecret string) (string, error) {
	path, err := url.JoinPath(mobiusURL, "/api/v1/mobius/enrollment_profiles/ota")
	if err != nil {
		return "", fmt.Errorf("creating path for end user ota enrollment url: %w", err)
	}

	enrollURL, err := url.Parse(path)
	if err != nil {
		return "", fmt.Errorf("parsing end user ota enrollment url: %w", err)
	}

	q := enrollURL.Query()
	q.Set("enroll_secret", enrollSecret)
	enrollURL.RawQuery = q.Encode()
	return enrollURL.String(), nil
}

func ServeStaticAssets(path string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
}
