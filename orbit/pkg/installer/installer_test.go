package installer

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/notawar/mobius/pkg/retry"
	"github.com/notawar/mobius/server/mobius"
	"github.com/notawar/mobius/server/ptr"
	osquery_gen "github.com/osquery/osquery-go/gen/osquery"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type TestOrbitClient struct {
	downloadInstallerFn        func(uint, string) (string, error)
	downloadInstallerFromURLFn func(url string, filename string, downloadDir string) (string, error)
	getInstallerDetailsFn      func(string) (*mobius.SoftwareInstallDetails, error)
	saveInstallerResultFn      func(*mobius.HostSoftwareInstallResultPayload) error
}

func (oc *TestOrbitClient) DownloadSoftwareInstallerFromURL(url string, filename string, downloadDir string, progressFunc func(int)) (string, error) {
	return oc.downloadInstallerFromURLFn(url, filename, downloadDir)
}

func (oc *TestOrbitClient) DownloadSoftwareInstaller(installerID uint, downloadDir string, progressFunc func(int)) (string, error) {
	return oc.downloadInstallerFn(installerID, downloadDir)
}

func (oc *TestOrbitClient) GetInstallerDetails(installId string) (*mobius.SoftwareInstallDetails, error) {
	return oc.getInstallerDetailsFn(installId)
}

func (oc *TestOrbitClient) SaveInstallerResult(payload *mobius.HostSoftwareInstallResultPayload) error {
	return oc.saveInstallerResultFn(payload)
}

type TestQueryClient struct {
	queryFn func(context.Context, string) (*QueryResponse, error)
}

func (qc *TestQueryClient) QueryContext(ctx context.Context, query string) (*QueryResponse, error) {
	return qc.queryFn(ctx, query)
}

func TestRunInstallScript(t *testing.T) {
	oc := &TestOrbitClient{}
	r := Runner{OrbitClient: oc, scriptsEnabled: func() bool { return true }}

	var executedScriptPath string
	var executed bool
	var executedEnv []string
	execCmd := func(ctx context.Context, spath string, env []string) ([]byte, int, error) {
		executed = true
		executedScriptPath = spath
		executedEnv = env
		return []byte("bye"), 2, nil
	}
	r.execCmdFn = execCmd

	installerDir := t.TempDir()
	installerPath := filepath.Join(installerDir, "installer.pkg")

	output, exitCode, err := r.runInstallerScript(context.Background(), "hello", installerPath, "foo")

	require.Equal(t, executedScriptPath, filepath.Join(installerDir, "foo"))
	require.Contains(t, executedScriptPath, installerDir)
	require.True(t, executed)

	require.Nil(t, err)
	require.Equal(t, "bye", output)
	require.Equal(t, 2, exitCode)
	require.Contains(t, executedEnv, "INSTALLER_PATH="+installerPath)
}

func TestPreconditionCheck(t *testing.T) {
	qc := &TestQueryClient{}
	r := &Runner{OsqueryClient: qc, scriptsEnabled: func() bool { return true }}

	qc.queryFn = func(ctx context.Context, s string) (*QueryResponse, error) {
		qr := &QueryResponse{
			Status: &osquery_gen.ExtensionStatus{},
		}

		switch s {
		case "empty":
		case "error":
			return nil, errors.New("something bad")
		case "badstatus":
			qr.Status.Code = 1
			qr.Status.Message = "something bad"
		case "nostatus":
			qr.Status = nil
		case "response":
			row := make(map[string]string)
			row["key"] = "value"
			qr.Response = append(qr.Response, row)
		default:
			t.Error("invalid query test case")
		}

		return qr, nil
	}

	ctx := context.Background()

	// empty query response
	success, output, err := r.preConditionCheck(ctx, "empty")
	require.False(t, success)
	require.Nil(t, err)
	require.Equal(t, "", output)

	success, output, err = r.preConditionCheck(ctx, "response")
	require.True(t, success)
	require.Nil(t, err)
	require.Equal(t, "[{\"key\":\"value\"}]", output)

	success, output, err = r.preConditionCheck(ctx, "error")
	require.False(t, success)
	require.Error(t, err)
	require.Equal(t, "", output)

	success, output, err = r.preConditionCheck(ctx, "badstatus")
	require.False(t, success)
	require.Error(t, err)
	require.Equal(t, "", output)

	success, output, err = r.preConditionCheck(ctx, "nostatus")
	require.False(t, success)
	require.Error(t, err)
	require.Equal(t, "", output)
}

func TestInstallerRun(t *testing.T) {
	oc := &TestOrbitClient{}

	var getInstallerDetailsFnCalled bool
	var installIdRequested string
	installDetails := &mobius.SoftwareInstallDetails{
		ExecutionID:         "exec1",
		InstallerID:         1337,
		PreInstallCondition: "SELECT 1",
		InstallScript:       "script1",
		PostInstallScript:   "script2",
	}
	getInstallerDetailsDefaultFn := func(installID string) (*mobius.SoftwareInstallDetails, error) {
		getInstallerDetailsFnCalled = true
		installIdRequested = installID
		return installDetails, nil
	}
	oc.getInstallerDetailsFn = getInstallerDetailsDefaultFn

	var downloadInstallerFnCalled bool
	downloadInstallerDefaultFn := func(installerID uint, downloadDir string) (string, error) {
		downloadInstallerFnCalled = true
		return filepath.Join(downloadDir, fmt.Sprint(installerID)+".pkg"), nil
	}
	oc.downloadInstallerFn = downloadInstallerDefaultFn

	var savedInstallerResult *mobius.HostSoftwareInstallResultPayload
	oc.saveInstallerResultFn = func(hsirp *mobius.HostSoftwareInstallResultPayload) error {
		savedInstallerResult = hsirp
		return nil
	}

	resetTestOrbitClient := func() {
		getInstallerDetailsFnCalled = false
		installIdRequested = ""
		oc.getInstallerDetailsFn = getInstallerDetailsDefaultFn
		installDetails = &mobius.SoftwareInstallDetails{
			ExecutionID:         "exec1",
			InstallerID:         1337,
			PreInstallCondition: "SELECT 1",
			InstallScript:       "script1",
			PostInstallScript:   "script2",
		}
		downloadInstallerFnCalled = false
		oc.downloadInstallerFn = downloadInstallerDefaultFn
		savedInstallerResult = nil
	}

	q := &TestQueryClient{}

	var queryFnCalled bool
	var queryFnQuery string
	queryFnResMap := make(map[string]string, 0)
	queryFnResMap["col"] = "true"
	queryFnResArr := []map[string]string{queryFnResMap}
	queryFnResStatus := &QueryResponseStatus{}
	queryFnResponse := &QueryResponse{
		Response: queryFnResArr,
		Status:   queryFnResStatus,
	}
	queryDefaultFn := func(ctx context.Context, query string) (*QueryResponse, error) {
		queryFnQuery = query
		queryFnCalled = true
		return queryFnResponse, nil
	}
	q.queryFn = queryDefaultFn

	resetTestQueryClient := func() {
		queryFnCalled = false
		queryFnQuery = ""
		queryFnResMap = make(map[string]string, 0)
		queryFnResMap["col"] = "true"
		queryFnResArr = []map[string]string{queryFnResMap}
		queryFnResStatus = &QueryResponseStatus{}
		queryFnResponse = &QueryResponse{
			Response: queryFnResArr,
			Status:   queryFnResStatus,
		}
		q.queryFn = queryDefaultFn
	}

	r := &Runner{
		OrbitClient:    oc,
		OsqueryClient:  q,
		scriptsEnabled: func() bool { return true },
	}

	var execCalled bool
	var executedScripts []string
	var execEnv []string
	var execErr error
	execOutput := []byte("execOutput")
	execExitCode := 0
	execCmdDefaultFn := func(ctx context.Context, scriptPath string, env []string) ([]byte, int, error) {
		execCalled = true
		execEnv = env
		executedScripts = append(executedScripts, scriptPath)
		return execOutput, execExitCode, execErr
	}
	r.execCmdFn = execCmdDefaultFn

	var tmpDirFnCalled bool
	var tmpDir string
	r.tempDirFn = func(dir, pattern string) (string, error) {
		tmpDirFnCalled = true
		tmpDir = os.TempDir()
		return tmpDir, nil
	}

	var removeAllFnCalled bool
	var removedDir string

	resetRunner := func() {
		execCalled = false
		executedScripts = nil
		execEnv = nil
		execOutput = []byte("execOutput")
		execExitCode = 0
		execErr = nil
		r.execCmdFn = execCmdDefaultFn
		r.removeAllFn = func(s string) error {
			removedDir = s
			removeAllFnCalled = true
			return nil
		}

		tmpDirFnCalled = false
		tmpDir = ""
	}

	var config mobius.OrbitConfig
	config.Notifications.PendingSoftwareInstallerIDs = []string{installDetails.ExecutionID}

	resetConfig := func() {
		config.Notifications.PendingSoftwareInstallerIDs = []string{installDetails.ExecutionID}
	}

	resetAll := func() {
		resetTestOrbitClient()
		resetTestQueryClient()
		resetRunner()
		resetConfig()
	}

	t.Run("everything good", func(t *testing.T) {
		resetAll()

		err := r.run(context.Background(), &config)
		require.NoError(t, err)

		require.True(t, removeAllFnCalled)
		require.Equal(t, tmpDir, removedDir)

		require.True(t, tmpDirFnCalled)

		require.True(t, execCalled)
		scriptExtension := ".sh"
		if runtime.GOOS == "windows" {
			scriptExtension = ".ps1"
		}
		require.Contains(t, executedScripts, filepath.Join(tmpDir, "install-script"+scriptExtension))
		require.Contains(t, executedScripts, filepath.Join(tmpDir, "post-install-script"+scriptExtension))
		require.Contains(t, execEnv, "INSTALLER_PATH="+filepath.Join(tmpDir, fmt.Sprint(installDetails.InstallerID)+".pkg"))

		require.True(t, queryFnCalled)
		require.Equal(t, installDetails.PreInstallCondition, queryFnQuery)

		require.NotNil(t, savedInstallerResult)
		require.Equal(t, execExitCode, *savedInstallerResult.InstallScriptExitCode)
		require.Equal(t, string(execOutput), *savedInstallerResult.InstallScriptOutput)
		require.Equal(t, execExitCode, *savedInstallerResult.PostInstallScriptExitCode)
		require.Equal(t, string(execOutput), *savedInstallerResult.PostInstallScriptOutput)
		require.Equal(t, installDetails.ExecutionID, savedInstallerResult.InstallUUID)

		require.True(t, downloadInstallerFnCalled)

		require.True(t, getInstallerDetailsFnCalled)
		require.Equal(t, installDetails.ExecutionID, installIdRequested)
	})

	t.Run(".tar.gz failed to extract", func(t *testing.T) {
		resetAll()

		oc.downloadInstallerFn = func(installerID uint, downloadDir string) (string, error) {
			downloadInstallerFnCalled = true
			return filepath.Join(downloadDir, fmt.Sprint(installerID)+".tar.gz"), nil
		}

		r.removeAllFn = func(s string) error {
			removedDir = s
			removeAllFnCalled = true
			require.NoError(t, os.Remove(filepath.Join(tmpDir, "extracted")))
			return nil
		}

		// will fail because we're trying to extract a file that doesn't exist (not mocking extract fn)
		err := r.run(context.Background(), &config)
		require.Error(t, err)

		require.True(t, removeAllFnCalled)
		require.True(t, tmpDirFnCalled)
		require.Equal(t, tmpDir, removedDir)

		require.NotNil(t, savedInstallerResult)
		require.NotNil(t, savedInstallerResult.InstallScriptExitCode)
		require.Equal(t, *savedInstallerResult.InstallScriptExitCode, mobius.ExitCodeInstallerDownloadFailed)
		require.NotNil(t, savedInstallerResult.InstallScriptOutput)
		require.Equal(t, *savedInstallerResult.InstallScriptOutput, "Installer extraction failed")
		require.Nil(t, savedInstallerResult.PostInstallScriptExitCode)
		require.Nil(t, savedInstallerResult.PostInstallScriptOutput)
		require.Equal(t, installDetails.ExecutionID, savedInstallerResult.InstallUUID)
	})

	t.Run("everything good for tarball", func(t *testing.T) {
		resetAll()

		oc.downloadInstallerFn = func(installerID uint, downloadDir string) (string, error) {
			downloadInstallerFnCalled = true
			return filepath.Join(downloadDir, fmt.Sprint(installerID)+".tar.gz"), nil
		}

		r.extractTarGzFn = func(path string, destDir string) error {
			return nil
		}

		scriptExtension := ".sh"
		if runtime.GOOS == "windows" {
			scriptExtension = ".ps1"
		}

		r.removeAllFn = func(s string) error {
			removedDir = s
			removeAllFnCalled = true
			require.NoError(t, os.Remove(filepath.Join(tmpDir, "install-script"+scriptExtension)))
			require.NoError(t, os.Remove(filepath.Join(tmpDir, "post-install-script"+scriptExtension)))
			require.NoError(t, os.Remove(filepath.Join(tmpDir, "extracted")))

			return nil
		}

		err := r.run(context.Background(), &config)
		require.NoError(t, err)

		require.True(t, removeAllFnCalled)
		require.Equal(t, tmpDir, removedDir)

		require.True(t, tmpDirFnCalled)

		require.True(t, execCalled)
		require.Contains(t, executedScripts, filepath.Join(tmpDir, "install-script"+scriptExtension))
		require.Contains(t, executedScripts, filepath.Join(tmpDir, "post-install-script"+scriptExtension))
		require.Contains(t, execEnv, "INSTALLER_PATH="+filepath.Join(tmpDir, "extracted"))

		require.True(t, queryFnCalled)
		require.Equal(t, installDetails.PreInstallCondition, queryFnQuery)

		require.NotNil(t, savedInstallerResult)
		require.Equal(t, execExitCode, *savedInstallerResult.InstallScriptExitCode)
		require.Equal(t, string(execOutput), *savedInstallerResult.InstallScriptOutput)
		require.Equal(t, execExitCode, *savedInstallerResult.PostInstallScriptExitCode)
		require.Equal(t, string(execOutput), *savedInstallerResult.PostInstallScriptOutput)
		require.Equal(t, installDetails.ExecutionID, savedInstallerResult.InstallUUID)

		require.True(t, downloadInstallerFnCalled)

		require.True(t, getInstallerDetailsFnCalled)
		require.Equal(t, installDetails.ExecutionID, installIdRequested)
		require.True(t, removeAllFnCalled)
	})

	t.Run("precondition negative", func(t *testing.T) {
		resetAll()

		queryFnResponse.Response = []map[string]string{}

		err := r.run(context.Background(), &config)
		require.NoError(t, err)

		require.False(t, downloadInstallerFnCalled)
		require.False(t, execCalled)
		require.True(t, removeAllFnCalled)
		require.NotNil(t, savedInstallerResult)
		require.Equal(t, installDetails.ExecutionID, savedInstallerResult.InstallUUID)
		require.Nil(t, savedInstallerResult.InstallScriptExitCode)
		require.Nil(t, savedInstallerResult.InstallScriptOutput)
		require.Nil(t, savedInstallerResult.PostInstallScriptExitCode)
		require.Nil(t, savedInstallerResult.PostInstallScriptOutput)
	})

	t.Run("failed install script", func(t *testing.T) {
		resetAll()

		execErr = &exec.ExitError{}
		execExitCode = 2

		err := r.run(context.Background(), &config)
		require.Error(t, err)

		require.True(t, downloadInstallerFnCalled)
		require.True(t, execCalled)
		require.True(t, removeAllFnCalled)
		require.NotNil(t, savedInstallerResult)
		require.Equal(t, installDetails.ExecutionID, savedInstallerResult.InstallUUID)
		require.Equal(t, 2, *savedInstallerResult.InstallScriptExitCode)
		require.Equal(t, string(execOutput), *savedInstallerResult.InstallScriptOutput)
		require.Nil(t, savedInstallerResult.PostInstallScriptExitCode)
		require.Nil(t, savedInstallerResult.PostInstallScriptOutput)
	})

	t.Run("failed post install script", func(t *testing.T) {
		resetAll()

		r.execCmdFn = func(ctx context.Context, scriptPath string, env []string) ([]byte, int, error) {
			execCalled = true
			execEnv = env
			executedScripts = append(executedScripts, scriptPath)
			// bad exit on the post-install script
			if len(executedScripts) == 2 {
				return execOutput, 1, &exec.ExitError{}
			}
			// good exit on rollback uninstall script
			if len(executedScripts) == 3 {
				return []byte("all good"), 0, nil
			}
			return execOutput, execExitCode, execErr
		}

		err := r.run(context.Background(), &config)
		require.NoError(t, err)

		require.True(t, downloadInstallerFnCalled)
		require.True(t, execCalled)
		require.True(t, removeAllFnCalled)
		require.NotNil(t, savedInstallerResult)
		require.Equal(t, installDetails.ExecutionID, savedInstallerResult.InstallUUID)
		require.Equal(t, 0, *savedInstallerResult.InstallScriptExitCode)
		require.Equal(t, string(execOutput), *savedInstallerResult.InstallScriptOutput)
		require.Equal(t, 1, *savedInstallerResult.PostInstallScriptExitCode)
		require.NotNil(t, savedInstallerResult.PostInstallScriptOutput)
		numPostInstallMatches := strings.Count(*savedInstallerResult.PostInstallScriptOutput, string(execOutput))
		assert.Equal(t, 1, numPostInstallMatches, *savedInstallerResult.PostInstallScriptOutput)
	})

	t.Run("failed rollback script", func(t *testing.T) {
		resetAll()

		r.execCmdFn = func(ctx context.Context, scriptPath string, env []string) ([]byte, int, error) {
			execCalled = true
			execEnv = env
			executedScripts = append(executedScripts, scriptPath)
			// bad exit on the post-install and rollback script
			if len(executedScripts) >= 2 {
				return execOutput, 1, &exec.ExitError{}
			}
			return execOutput, execExitCode, execErr
		}

		err := r.run(context.Background(), &config)
		require.Error(t, err)

		require.True(t, downloadInstallerFnCalled)
		require.True(t, execCalled)
		require.True(t, removeAllFnCalled)
		require.NotNil(t, savedInstallerResult)
		require.Equal(t, installDetails.ExecutionID, savedInstallerResult.InstallUUID)
		require.Equal(t, 0, *savedInstallerResult.InstallScriptExitCode)
		require.Equal(t, string(execOutput), *savedInstallerResult.InstallScriptOutput)
		require.Equal(t, 1, *savedInstallerResult.PostInstallScriptExitCode)
		numPostInstallMatches := strings.Count(*savedInstallerResult.PostInstallScriptOutput, string(execOutput))
		assert.Equal(t, 2, numPostInstallMatches)
	})

	t.Run("failed installer download", func(t *testing.T) {
		resetAll()

		oc.downloadInstallerFn = func(installerID uint, downloadDir string) (string, error) {
			return "", errors.New("failed to download installer")
		}

		err := r.run(context.Background(), &config)
		require.Error(t, err)

		require.True(t, removeAllFnCalled)
		require.True(t, tmpDirFnCalled)
		require.Equal(t, tmpDir, removedDir)

		require.NotNil(t, savedInstallerResult)
		require.NotNil(t, savedInstallerResult.InstallScriptExitCode)
		require.Equal(t, *savedInstallerResult.InstallScriptExitCode, mobius.ExitCodeInstallerDownloadFailed)
		require.NotNil(t, savedInstallerResult.InstallScriptOutput)
		require.Equal(t, *savedInstallerResult.InstallScriptOutput, "Installer download failed")
		require.Nil(t, savedInstallerResult.PostInstallScriptExitCode)
		require.Nil(t, savedInstallerResult.PostInstallScriptOutput)
		require.Equal(t, installDetails.ExecutionID, savedInstallerResult.InstallUUID)
	})

	t.Run("failed results upload", func(t *testing.T) {
		var retries int
		// set a shorter interval to speed up tests
		r.retryOpts = []retry.Option{retry.WithInterval(250 * time.Millisecond), retry.WithMaxAttempts(5)}

		testCases := []struct {
			desc                    string
			expectedRetries         int
			expectedErr             string
			saveInstallerResultFunc func(payload *mobius.HostSoftwareInstallResultPayload) error
		}{
			{
				desc:            "multiple retries, eventual success",
				expectedRetries: 4,
				saveInstallerResultFunc: func(payload *mobius.HostSoftwareInstallResultPayload) error {
					retries++
					if retries != 4 {
						return errors.New("save results error")
					}

					return nil
				},
			},

			{
				desc:            "multiple retries, eventual failure",
				expectedRetries: 5,
				saveInstallerResultFunc: func(payload *mobius.HostSoftwareInstallResultPayload) error {
					retries++
					return errors.New("save results error")
				},
				expectedErr: "save results error",
			},
		}
		for _, tc := range testCases {
			t.Run(tc.desc, func(t *testing.T) {
				resetAll()
				t.Cleanup(func() { retries = 0 })
				oc.saveInstallerResultFn = tc.saveInstallerResultFunc
				err := r.run(context.Background(), &config)
				if tc.expectedErr != "" {
					require.ErrorContains(t, err, tc.expectedErr)
				} else {
					require.NoError(t, err)
				}
				require.Equal(t, tc.expectedRetries, retries)
			})
		}
	})
}

func TestInstallerRunWithInstallerFromURL(t *testing.T) {
	oc := &TestOrbitClient{}

	var getInstallerDetailsFnCalled bool
	var installIdRequested string
	installDetails := &mobius.SoftwareInstallDetails{
		ExecutionID:       "exec1",
		InstallerID:       1337,
		InstallScript:     "script1",
		PostInstallScript: "script2",
		SoftwareInstallerURL: &mobius.SoftwareInstallerURL{
			URL:      "https://example.com/ABC",
			Filename: "installer.pkg",
		},
	}
	getInstallerDetailsDefaultFn := func(installID string) (*mobius.SoftwareInstallDetails, error) {
		getInstallerDetailsFnCalled = true
		installIdRequested = installID
		return installDetails, nil
	}
	oc.getInstallerDetailsFn = getInstallerDetailsDefaultFn

	var downloadInstallerFromURLFnCalled bool
	downloadInstallerFromURLDefaultFn := func(url string, filename string, downloadDir string) (string, error) {
		assert.Equal(t, installDetails.SoftwareInstallerURL.URL, url)
		downloadInstallerFromURLFnCalled = true
		return filepath.Join(downloadDir, filename), nil
	}
	oc.downloadInstallerFromURLFn = downloadInstallerFromURLDefaultFn

	var downloadInstallerFnCalled bool
	downloadInstallerDefaultFn := func(installerID uint, downloadDir string) (string, error) {
		downloadInstallerFnCalled = true
		return filepath.Join(downloadDir, fmt.Sprint(installerID)+".pkg"), nil
	}
	oc.downloadInstallerFn = downloadInstallerDefaultFn

	var savedInstallerResult *mobius.HostSoftwareInstallResultPayload
	oc.saveInstallerResultFn = func(hsirp *mobius.HostSoftwareInstallResultPayload) error {
		savedInstallerResult = hsirp
		return nil
	}

	resetTestOrbitClient := func() {
		getInstallerDetailsFnCalled = false
		installIdRequested = ""
		oc.getInstallerDetailsFn = getInstallerDetailsDefaultFn
		installDetails = &mobius.SoftwareInstallDetails{
			ExecutionID:       "exec1",
			InstallerID:       1337,
			InstallScript:     "script1",
			PostInstallScript: "script2",
			SoftwareInstallerURL: &mobius.SoftwareInstallerURL{
				URL:      "https://example.com/ABC",
				Filename: "installer.pkg",
			},
		}
		downloadInstallerFnCalled = false
		downloadInstallerFromURLFnCalled = false
		oc.downloadInstallerFromURLFn = downloadInstallerFromURLDefaultFn
		savedInstallerResult = nil
	}

	r := &Runner{
		OrbitClient:    oc,
		scriptsEnabled: func() bool { return true },
	}

	var execCalled bool
	var executedScripts []string
	var execEnv []string
	var execErr error
	execOutput := []byte("execOutput")
	execExitCode := 0
	execCmdDefaultFn := func(ctx context.Context, scriptPath string, env []string) ([]byte, int, error) {
		execCalled = true
		execEnv = env
		executedScripts = append(executedScripts, scriptPath)
		return execOutput, execExitCode, execErr
	}
	r.execCmdFn = execCmdDefaultFn

	var tmpDirFnCalled bool
	var tmpDir string
	r.tempDirFn = func(dir, pattern string) (string, error) {
		tmpDirFnCalled = true
		tmpDir = os.TempDir()
		return tmpDir, nil
	}

	var removeAllFnCalled bool
	var removedDir string
	r.removeAllFn = func(s string) error {
		removedDir = s
		removeAllFnCalled = true
		return nil
	}

	resetRunner := func() {
		execCalled = false
		executedScripts = nil
		execEnv = nil
		execOutput = []byte("execOutput")
		execExitCode = 0
		execErr = nil
		r.execCmdFn = execCmdDefaultFn

		tmpDirFnCalled = false
		tmpDir = ""
	}

	var config mobius.OrbitConfig
	config.Notifications.PendingSoftwareInstallerIDs = []string{installDetails.ExecutionID}

	resetConfig := func() {
		config.Notifications.PendingSoftwareInstallerIDs = []string{installDetails.ExecutionID}
	}

	resetAll := func() {
		resetTestOrbitClient()
		resetRunner()
		resetConfig()
	}

	t.Run("everything good", func(t *testing.T) {
		resetAll()

		err := r.run(context.Background(), &config)
		require.NoError(t, err)

		assert.True(t, removeAllFnCalled)
		assert.Equal(t, tmpDir, removedDir)

		assert.True(t, tmpDirFnCalled)

		assert.True(t, execCalled)
		scriptExtension := ".sh"
		if runtime.GOOS == "windows" {
			scriptExtension = ".ps1"
		}
		assert.Contains(t, executedScripts, filepath.Join(tmpDir, "install-script"+scriptExtension))
		assert.Contains(t, executedScripts, filepath.Join(tmpDir, "post-install-script"+scriptExtension))
		assert.Contains(t, execEnv, "INSTALLER_PATH="+filepath.Join(tmpDir, installDetails.SoftwareInstallerURL.Filename))

		assert.NotNil(t, savedInstallerResult)
		assert.Equal(t, execExitCode, *savedInstallerResult.InstallScriptExitCode)
		assert.Equal(t, string(execOutput), *savedInstallerResult.InstallScriptOutput)
		assert.Equal(t, execExitCode, *savedInstallerResult.PostInstallScriptExitCode)
		assert.Equal(t, string(execOutput), *savedInstallerResult.PostInstallScriptOutput)
		assert.Equal(t, installDetails.ExecutionID, savedInstallerResult.InstallUUID)

		assert.True(t, downloadInstallerFromURLFnCalled)
		assert.False(t, downloadInstallerFnCalled)

		assert.True(t, getInstallerDetailsFnCalled)
		assert.Equal(t, installDetails.ExecutionID, installIdRequested)
	})

	t.Run("CDN fails and we fall back to Mobius download", func(t *testing.T) {
		resetAll()

		oc.downloadInstallerFromURLFn = func(url string, filename string, downloadDir string) (string, error) {
			assert.Equal(t, installDetails.SoftwareInstallerURL.URL, url)
			downloadInstallerFromURLFnCalled = true
			return "bozo", errors.New("test error")
		}

		err := r.run(context.Background(), &config)
		require.NoError(t, err)

		assert.True(t, removeAllFnCalled)
		assert.Equal(t, tmpDir, removedDir)

		assert.True(t, tmpDirFnCalled)

		assert.True(t, execCalled)
		scriptExtension := ".sh"
		if runtime.GOOS == "windows" {
			scriptExtension = ".ps1"
		}
		assert.Contains(t, executedScripts, filepath.Join(tmpDir, "install-script"+scriptExtension))
		assert.Contains(t, executedScripts, filepath.Join(tmpDir, "post-install-script"+scriptExtension))
		require.Contains(t, execEnv, "INSTALLER_PATH="+filepath.Join(tmpDir, fmt.Sprint(installDetails.InstallerID)+".pkg"))

		assert.NotNil(t, savedInstallerResult)
		assert.Equal(t, execExitCode, *savedInstallerResult.InstallScriptExitCode)
		assert.Equal(t, string(execOutput), *savedInstallerResult.InstallScriptOutput)
		assert.Equal(t, execExitCode, *savedInstallerResult.PostInstallScriptExitCode)
		assert.Equal(t, string(execOutput), *savedInstallerResult.PostInstallScriptOutput)
		assert.Equal(t, installDetails.ExecutionID, savedInstallerResult.InstallUUID)

		assert.True(t, downloadInstallerFromURLFnCalled)
		assert.True(t, downloadInstallerFnCalled)

		assert.True(t, getInstallerDetailsFnCalled)
		assert.Equal(t, installDetails.ExecutionID, installIdRequested)
	})
}

func TestScriptsDisabled(t *testing.T) {
	oc := &TestOrbitClient{}
	qc := &TestQueryClient{}
	r := &Runner{
		OrbitClient:    oc,
		OsqueryClient:  qc,
		scriptsEnabled: func() bool { return false },
	}

	qc.queryFn = func(ctx context.Context, s string) (*QueryResponse, error) {
		queryFnResMap := make(map[string]string, 0)
		queryFnResMap["col"] = "true"
		queryFnResArr := []map[string]string{queryFnResMap}
		queryFnResStatus := &QueryResponseStatus{}
		return &QueryResponse{
			Response: queryFnResArr,
			Status:   queryFnResStatus,
		}, nil
	}

	var getInstallerDetailsFnCalled bool
	var installIdRequested string
	installDetails := &mobius.SoftwareInstallDetails{
		ExecutionID:         "exec1",
		InstallerID:         1337,
		PreInstallCondition: "SELECT 1",
		InstallScript:       "script1",
		PostInstallScript:   "script2",
	}
	getInstallerDetailsDefaultFn := func(installID string) (*mobius.SoftwareInstallDetails, error) {
		getInstallerDetailsFnCalled = true
		installIdRequested = installID
		return installDetails, nil
	}
	oc.getInstallerDetailsFn = getInstallerDetailsDefaultFn

	out, err := r.installSoftware(context.Background(), "1", log.With().Logger())
	require.NoError(t, err)
	require.EqualValues(t, &mobius.HostSoftwareInstallResultPayload{
		InstallUUID:               "1",
		InstallScriptExitCode:     ptr.Int(-2),
		InstallScriptOutput:       ptr.String("Scripts are disabled"),
		PreInstallConditionOutput: ptr.String(`[{"col":"true"}]`),
	}, out)
	require.True(t, getInstallerDetailsFnCalled)
	require.Equal(t, "1", installIdRequested)
}
