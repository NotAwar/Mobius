package mobiuscli

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/notawar/mobius/cmd/mobiuscli/mobiuscli/testing_utils"
	"github.com/notawar/mobius/server/mobius"
	"github.com/notawar/mobius/server/service"
	"github.com/notawar/mobius/server/service/schedule"
	kitlog "github.com/go-kit/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTrigger(t *testing.T) {
	const (
		name       = "test_sched"
		instanceID = "test_instance"
		interval   = 5 * time.Minute
	)

	testCases := []struct {
		args     []string
		delay    time.Duration
		expected string
	}{
		{
			args:     []string{"trigger"},
			expected: fmt.Sprintf("[!] Name must be specified; supported trigger name is %s", name),
		},
		{
			args:     []string{"trigger", "--name", name},
			expected: fmt.Sprintf("[+] Sent request to trigger %s schedule", name),
		},
		{
			args:     []string{"trigger", "--name", name},
			delay:    10 * time.Millisecond,
			expected: fmt.Sprintf("[!] Conflicts with current status of %s schedule: triggered run started", name),
		},
		{
			args:     []string{"trigger", "--name", "foo"},
			expected: fmt.Sprintf("[!] Invalid name; supported trigger name is %s", name),
		},
	}

	r, w, _ := os.Pipe()
	oldStdout := os.Stdout
	os.Stdout = w

	_, _ = testing_utils.RunServerWithMockedDS(t, &service.TestServerOpts{
		Logger: kitlog.NewNopLogger(),
		StartCronSchedules: []service.TestNewScheduleFunc{
			func(ctx context.Context, ds mobius.Datastore) mobius.NewCronScheduleFunc {
				return func() (mobius.CronSchedule, error) {
					s := schedule.New(ctx, name, instanceID, interval,
						schedule.SetupMockLocker(name, instanceID, time.Now().Add(-1*time.Hour)),
						schedule.SetUpMockStatsStore(name),
						schedule.WithJob("test_job",
							func(context.Context) error {
								time.Sleep(100 * time.Millisecond)
								return nil
							}))
					return s, nil
				}
			},
		},
	})

	for _, c := range testCases {
		if c.delay != 0 {
			time.Sleep(c.delay)
		}
		assert.Equal(t, "", RunAppForTest(t, c.args))
	}

	os.Stdout = oldStdout
	w.Close()
	out, _ := io.ReadAll(r)
	outlines := strings.Split(string(out), "\n")
	require.Len(t, outlines, len(testCases)+1)

	for i, c := range testCases {
		require.True(t, strings.HasPrefix(outlines[i], c.expected))
	}
}
