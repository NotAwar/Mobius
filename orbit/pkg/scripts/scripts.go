// Package scripts implements support to execute scripts on the host when
// requested by the Mobius server.
package scripts

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"
	"unicode/utf8"

	"github.com/notawar/mobius/orbit/pkg/constant"
	"github.com/notawar/mobius/server/mobius"
	"github.com/rs/zerolog/log"
)

// Client defines the methods required for the API requests to the server. The
// mobius.OrbitClient type satisfies this interface.
type Client interface {
	GetHostScript(execID string) (*mobius.HostScriptResult, error)
	SaveHostScriptResult(result *mobius.HostScriptResultPayload) error
}

// Runner is the type that processes scripts to execute, taking care of
// retrieving each script, saving it in a temporary directory, executing it and
// saving the results.
type Runner struct {
	Client                 Client
	ScriptExecutionEnabled bool
	ScriptExecutionTimeout time.Duration

	// tempDirFn is the function to call to get the temporary directory to use,
	// inside of which the script-specific subdirectories will be created. If nil,
	// the user's temp dir will be used (can be set to t.TempDir in tests).
	tempDirFn func() string

	// execCmdFn can be set for tests to mock actual execution of the script. If
	// nil, execCmd will be used, which has a different implementation on Windows
	// and non-Windows platforms.
	execCmdFn func(ctx context.Context, scriptPath string, env []string) ([]byte, int, error)

	// can be set for tests to replace os.RemoveAll, which is called to remove
	// the script's temporary directory after execution.
	removeAllFn func(string) error
}

// Run processes all scripts identified by the execution IDs.
func (r *Runner) Run(execIDs []string) error {
	var errs []error

	for _, execID := range execIDs {
		log.Info().Msgf("processing script %v", execID)
		if !r.ScriptExecutionEnabled {
			if err := r.runOneDisabled(execID); err != nil {
				errs = append(errs, err)
			}
			continue
		}

		log.Info().Msgf("getting script %v", execID)
		script, err := r.Client.GetHostScript(execID)
		if err != nil {
			errs = append(errs, fmt.Errorf("get host script: %w", err))
			// Stop here since we want to preserve the order in which scripts are queued.
			break
		}

		log.Info().Msgf("proceeding to execution of script %v", execID)
		if err := r.runOne(script); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

func (r *Runner) runOne(script *mobius.HostScriptResult) (finalErr error) {
	const maxOutputRuneLen = 10000

	if script.ExitCode != nil {
		// already a result stored for this execution, skip, it shouldn't be sent
		// again by Mobius.
		return nil
	}

	runDir, err := r.createRunDir(script.ExecutionID)
	if err != nil {
		return fmt.Errorf("create run directory: %w", err)
	}
	// prevent destruction of dir if this env var is set
	if os.Getenv("MOBIUS_PREVENT_SCRIPT_TEMPDIR_DELETION") == "" {
		defer func() {
			fn := os.RemoveAll
			if r.removeAllFn != nil {
				fn = r.removeAllFn
			}
			err := fn(runDir)
			if finalErr == nil && err != nil {
				finalErr = fmt.Errorf("remove temp dir: %w", err)
			}
		}()
	}

	var ext string
	if runtime.GOOS == "windows" {
		ext = ".ps1"
	}
	scriptFile := filepath.Join(runDir, "script"+ext)
	if err := os.WriteFile(scriptFile, []byte(script.ScriptContents), constant.DefaultFileMode); err != nil {
		return fmt.Errorf("write script file: %w", err)
	}

	log.Info().Msgf("ready to execute script %v", script.ExecutionID)

	ctx, cancel := context.WithTimeout(context.Background(), r.ScriptExecutionTimeout)
	defer cancel()

	execCmdFn := r.execCmdFn
	if execCmdFn == nil {
		execCmdFn = ExecCmd
	}
	start := time.Now()
	log.Debug().Msgf("starting script execution of %v with timeout of %v", script.ExecutionID, r.ScriptExecutionTimeout)
	output, exitCode, execErr := execCmdFn(ctx, scriptFile, nil)
	log.Debug().Msgf("after script execution of %v", script.ExecutionID)
	duration := time.Since(start)

	// report the output or the error
	if execErr != nil {
		output = append(output, []byte(fmt.Sprintf("\nscript execution error: %v", execErr))...)
	}

	// sanity-check the size of the output sent to the server, the actual
	// trimming to 10K chars is done by the API endpoint, we just make sure not
	// to send a ridiculously big payload that is sure to be over 10K chars.
	if len(output) > (utf8.UTFMax * maxOutputRuneLen) {
		output = output[len(output)-(utf8.UTFMax*maxOutputRuneLen):]
	}

	log.Info().Msgf("saving script result %v with exit code %d", script.ExecutionID, exitCode)
	err = r.Client.SaveHostScriptResult(&mobius.HostScriptResultPayload{
		ExecutionID: script.ExecutionID,
		Output:      string(output),
		Runtime:     int(duration.Seconds()),
		ExitCode:    exitCode,
		Timeout:     int(r.ScriptExecutionTimeout.Seconds()),
	})
	if err != nil {
		return fmt.Errorf("save script result: %w", err)
	}
	return nil
}

func (r *Runner) createRunDir(execID string) (string, error) {
	var tempDir string // empty tempDir means use system default
	if r.tempDirFn != nil {
		tempDir = r.tempDirFn()
	}
	// MkdirTemp will only allow read/write by current user (root), which is what
	// we want.
	return os.MkdirTemp(tempDir, "mobius-"+execID+"-*")
}

func (r *Runner) runOneDisabled(execID string) error {
	err := r.Client.SaveHostScriptResult(&mobius.HostScriptResultPayload{
		ExecutionID: execID,
		Output:      "Scripts are disabled",
		ExitCode:    -2, // mobiuscli knows that -2 means script was disabled on host
	})
	if err != nil {
		return fmt.Errorf("save script result: %w", err)
	}
	return nil
}
