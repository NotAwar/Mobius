package service

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/notawar/mobius/server/contexts/viewer"
	"github.com/notawar/mobius/server/mobius"
	"github.com/notawar/mobius/server/mock"
	"github.com/notawar/mobius/server/ptr"
	"github.com/stretchr/testify/require"
)

func TestSetupExperienceAuth(t *testing.T) {
	ds := new(mock.Store)
	license := &mobius.LicenseInfo{Tier: mobius.TierPremium, Expiration: time.Now().Add(24 * time.Hour)}
	svc, ctx := newTestService(t, ds, nil, nil, &TestServerOpts{License: license, SkipCreateTestUsers: true})

	teamID := uint(1)
	teamScriptID := uint(1)
	noTeamScriptID := uint(2)

	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		return &mobius.AppConfig{}, nil
	}
	ds.SetSetupExperienceScriptFunc = func(ctx context.Context, script *mobius.Script) error {
		return nil
	}

	ds.GetSetupExperienceScriptFunc = func(ctx context.Context, teamID *uint) (*mobius.Script, error) {
		if teamID == nil {
			return &mobius.Script{ID: noTeamScriptID}, nil
		}
		switch *teamID {
		case uint(1):
			return &mobius.Script{ID: teamScriptID, TeamID: teamID}, nil
		default:
			return nil, newNotFoundError()
		}
	}
	ds.GetAnyScriptContentsFunc = func(ctx context.Context, id uint) ([]byte, error) {
		return []byte("echo"), nil
	}
	ds.DeleteSetupExperienceScriptFunc = func(ctx context.Context, teamID *uint) error {
		if teamID == nil {
			return nil
		}
		switch *teamID {
		case uint(1):
			return nil
		default:
			return newNotFoundError() // TODO: confirm if we want to return not found on deletes
		}
	}
	ds.TeamFunc = func(ctx context.Context, id uint) (*mobius.Team, error) {
		return &mobius.Team{ID: id}, nil
	}
	ds.ValidateEmbeddedSecretsFunc = func(ctx context.Context, documents []string) error {
		return nil
	}
	ds.ExpandEmbeddedSecretsFunc = func(ctx context.Context, document string) (string, error) {
		return document, nil
	}

	testCases := []struct {
		name                  string
		user                  *mobius.User
		shouldFailTeamWrite   bool
		shouldFailGlobalWrite bool
		shouldFailTeamRead    bool
		shouldFailGlobalRead  bool
	}{
		{
			name:                  "global admin",
			user:                  &mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)},
			shouldFailTeamWrite:   false,
			shouldFailGlobalWrite: false,
			shouldFailTeamRead:    false,
			shouldFailGlobalRead:  false,
		},
		{
			name:                  "global maintainer",
			user:                  &mobius.User{GlobalRole: ptr.String(mobius.RoleMaintainer)},
			shouldFailTeamWrite:   false,
			shouldFailGlobalWrite: false,
			shouldFailTeamRead:    false,
			shouldFailGlobalRead:  false,
		},
		{
			name:                  "global observer",
			user:                  &mobius.User{GlobalRole: ptr.String(mobius.RoleObserver)},
			shouldFailTeamWrite:   true,
			shouldFailGlobalWrite: true,
			shouldFailTeamRead:    false,
			shouldFailGlobalRead:  false,
		},
		{
			name:                  "global observer+",
			user:                  &mobius.User{GlobalRole: ptr.String(mobius.RoleObserverPlus)},
			shouldFailTeamWrite:   true,
			shouldFailGlobalWrite: true,
			shouldFailTeamRead:    false,
			shouldFailGlobalRead:  false,
		},
		{
			name:                  "global gitops",
			user:                  &mobius.User{GlobalRole: ptr.String(mobius.RoleGitOps)},
			shouldFailTeamWrite:   false,
			shouldFailGlobalWrite: false,
			shouldFailTeamRead:    true,
			shouldFailGlobalRead:  true,
		},
		{
			name:                  "team admin, belongs to team",
			user:                  &mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleAdmin}}},
			shouldFailTeamWrite:   false,
			shouldFailGlobalWrite: true,
			shouldFailTeamRead:    false,
			shouldFailGlobalRead:  true,
		},
		{
			name:                  "team maintainer, belongs to team",
			user:                  &mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleMaintainer}}},
			shouldFailTeamWrite:   false,
			shouldFailGlobalWrite: true,
			shouldFailTeamRead:    false,
			shouldFailGlobalRead:  true,
		},
		{
			name:                  "team observer, belongs to team",
			user:                  &mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleObserver}}},
			shouldFailTeamWrite:   true,
			shouldFailGlobalWrite: true,
			shouldFailTeamRead:    false,
			shouldFailGlobalRead:  true,
		},
		{
			name:                  "team observer+, belongs to team",
			user:                  &mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleObserverPlus}}},
			shouldFailTeamWrite:   true,
			shouldFailGlobalWrite: true,
			shouldFailTeamRead:    false,
			shouldFailGlobalRead:  true,
		},
		{
			name:                  "team gitops, belongs to team",
			user:                  &mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleGitOps}}},
			shouldFailTeamWrite:   false,
			shouldFailGlobalWrite: true,
			shouldFailTeamRead:    true,
			shouldFailGlobalRead:  true,
		},
		{
			name:                  "team admin, DOES NOT belong to team",
			user:                  &mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 2}, Role: mobius.RoleAdmin}}},
			shouldFailTeamWrite:   true,
			shouldFailGlobalWrite: true,
			shouldFailTeamRead:    true,
			shouldFailGlobalRead:  true,
		},
		{
			name:                  "team maintainer, DOES NOT belong to team",
			user:                  &mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 2}, Role: mobius.RoleMaintainer}}},
			shouldFailTeamWrite:   true,
			shouldFailGlobalWrite: true,
			shouldFailTeamRead:    true,
			shouldFailGlobalRead:  true,
		},
		{
			name:                  "team observer, DOES NOT belong to team",
			user:                  &mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 2}, Role: mobius.RoleObserver}}},
			shouldFailTeamWrite:   true,
			shouldFailGlobalWrite: true,
			shouldFailTeamRead:    true,
			shouldFailGlobalRead:  true,
		},
		{
			name:                  "team observer+, DOES NOT belong to team",
			user:                  &mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 2}, Role: mobius.RoleObserverPlus}}},
			shouldFailTeamWrite:   true,
			shouldFailGlobalWrite: true,
			shouldFailTeamRead:    true,
			shouldFailGlobalRead:  true,
		},
		{
			name:                  "team gitops, DOES NOT belong to team",
			user:                  &mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 2}, Role: mobius.RoleGitOps}}},
			shouldFailTeamWrite:   true,
			shouldFailGlobalWrite: true,
			shouldFailTeamRead:    true,
			shouldFailGlobalRead:  true,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			ctx = viewer.NewContext(ctx, viewer.Viewer{User: tt.user})

			t.Run("setup experience script", func(t *testing.T) {
				err := svc.SetSetupExperienceScript(ctx, nil, "test.sh", strings.NewReader("echo"))
				checkAuthErr(t, tt.shouldFailGlobalWrite, err)
				err = svc.DeleteSetupExperienceScript(ctx, nil)
				checkAuthErr(t, tt.shouldFailGlobalWrite, err)
				_, _, err = svc.GetSetupExperienceScript(ctx, nil, false)
				checkAuthErr(t, tt.shouldFailGlobalRead, err)
				_, _, err = svc.GetSetupExperienceScript(ctx, nil, true)
				checkAuthErr(t, tt.shouldFailGlobalRead, err)

				err = svc.SetSetupExperienceScript(ctx, &teamID, "test.sh", strings.NewReader("echo"))
				checkAuthErr(t, tt.shouldFailTeamWrite, err)
				err = svc.DeleteSetupExperienceScript(ctx, &teamID)
				checkAuthErr(t, tt.shouldFailTeamWrite, err)
				_, _, err = svc.GetSetupExperienceScript(ctx, &teamID, false)
				checkAuthErr(t, tt.shouldFailTeamRead, err)
				_, _, err = svc.GetSetupExperienceScript(ctx, &teamID, true)
				checkAuthErr(t, tt.shouldFailTeamRead, err)
			})
		})
	}
}

func TestMaybeUpdateSetupExperience(t *testing.T) {
	ds := new(mock.Store)
	// _, ctx := newTestService(t, ds, nil, nil, nil)
	ctx := context.Background()

	hostUUID := "host-uuid"
	scriptUUID := "script-uuid"
	softwareUUID := "software-uuid"
	vppUUID := "vpp-uuid"

	t.Run("unsupported result type", func(t *testing.T) {
		_, err := maybeUpdateSetupExperienceStatus(ctx, ds, map[string]interface{}{"key": "value"}, true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported result type")
	})

	t.Run("script results", func(t *testing.T) {
		testCases := []struct {
			name          string
			exitCode      int
			expected      mobius.SetupExperienceStatusResultStatus
			alwaysUpdated bool
		}{
			{
				name:          "success",
				exitCode:      0,
				expected:      mobius.SetupExperienceStatusSuccess,
				alwaysUpdated: true,
			},
			{
				name:          "failure",
				exitCode:      1,
				expected:      mobius.SetupExperienceStatusFailure,
				alwaysUpdated: true,
			},
		}

		for _, tt := range testCases {
			t.Run(tt.name, func(t *testing.T) {
				ds.MaybeUpdateSetupExperienceScriptStatusFunc = func(ctx context.Context, hostUUID string, executionID string, status mobius.SetupExperienceStatusResultStatus) (bool, error) {
					require.Equal(t, hostUUID, hostUUID)
					require.Equal(t, executionID, scriptUUID)
					require.Equal(t, tt.expected, status)
					require.True(t, status.IsValid())
					return true, nil
				}
				ds.MaybeUpdateSetupExperienceScriptStatusFuncInvoked = false

				result := mobius.SetupExperienceScriptResult{
					HostUUID:    hostUUID,
					ExecutionID: scriptUUID,
					ExitCode:    tt.exitCode,
				}
				updated, err := maybeUpdateSetupExperienceStatus(ctx, ds, result, true)
				require.NoError(t, err)
				require.Equal(t, tt.alwaysUpdated, updated)
				require.Equal(t, tt.alwaysUpdated, ds.MaybeUpdateSetupExperienceScriptStatusFuncInvoked)
			})
		}
	})

	t.Run("software install results", func(t *testing.T) {
		testCases := []struct {
			name          string
			status        mobius.SoftwareInstallerStatus
			expectStatus  mobius.SetupExperienceStatusResultStatus
			alwaysUpdated bool
		}{
			{
				name:          "success",
				status:        mobius.SoftwareInstalled,
				expectStatus:  mobius.SetupExperienceStatusSuccess,
				alwaysUpdated: true,
			},
			{
				name:          "failure",
				status:        mobius.SoftwareInstallFailed,
				expectStatus:  mobius.SetupExperienceStatusFailure,
				alwaysUpdated: true,
			},
			{
				name:          "pending",
				status:        mobius.SoftwareInstallPending,
				expectStatus:  mobius.SetupExperienceStatusPending,
				alwaysUpdated: false,
			},
		}

		for _, tt := range testCases {
			t.Run(tt.name, func(t *testing.T) {
				requireTerminalStatus := true // when this flag is true, we don't expect pending status to update

				ds.MaybeUpdateSetupExperienceSoftwareInstallStatusFunc = func(ctx context.Context, hostUUID string, executionID string, status mobius.SetupExperienceStatusResultStatus) (bool, error) {
					require.Equal(t, hostUUID, hostUUID)
					require.Equal(t, executionID, softwareUUID)
					require.Equal(t, tt.expectStatus, status)
					require.True(t, status.IsValid())
					require.True(t, status.IsTerminalStatus())
					return true, nil
				}
				ds.MaybeUpdateSetupExperienceSoftwareInstallStatusFuncInvoked = false

				result := mobius.SetupExperienceSoftwareInstallResult{
					HostUUID:        hostUUID,
					ExecutionID:     softwareUUID,
					InstallerStatus: tt.status,
				}
				updated, err := maybeUpdateSetupExperienceStatus(ctx, ds, result, requireTerminalStatus)
				require.NoError(t, err)
				require.Equal(t, tt.alwaysUpdated, updated)
				require.Equal(t, tt.alwaysUpdated, ds.MaybeUpdateSetupExperienceSoftwareInstallStatusFuncInvoked)

				requireTerminalStatus = false // when this flag is false, we do expect pending status to update

				ds.MaybeUpdateSetupExperienceSoftwareInstallStatusFunc = func(ctx context.Context, hostUUID string, executionID string, status mobius.SetupExperienceStatusResultStatus) (bool, error) {
					require.Equal(t, hostUUID, hostUUID)
					require.Equal(t, executionID, softwareUUID)
					require.Equal(t, tt.expectStatus, status)
					require.True(t, status.IsValid())
					if status.IsTerminalStatus() {
						require.True(t, status == mobius.SetupExperienceStatusSuccess || status == mobius.SetupExperienceStatusFailure)
					} else {
						require.True(t, status == mobius.SetupExperienceStatusPending || status == mobius.SetupExperienceStatusRunning)
					}
					return true, nil
				}
				ds.MaybeUpdateSetupExperienceSoftwareInstallStatusFuncInvoked = false
				updated, err = maybeUpdateSetupExperienceStatus(ctx, ds, result, requireTerminalStatus)
				require.NoError(t, err)
				shouldUpdate := tt.alwaysUpdated
				if tt.expectStatus == mobius.SetupExperienceStatusPending || tt.expectStatus == mobius.SetupExperienceStatusRunning {
					shouldUpdate = true
				}
				require.Equal(t, shouldUpdate, updated)
				require.Equal(t, shouldUpdate, ds.MaybeUpdateSetupExperienceSoftwareInstallStatusFuncInvoked)
			})
		}
	})

	t.Run("vpp install results", func(t *testing.T) {
		testCases := []struct {
			name          string
			status        string
			expected      mobius.SetupExperienceStatusResultStatus
			alwaysUpdated bool
		}{
			{
				name:          "success",
				status:        mobius.MDMAppleStatusAcknowledged,
				expected:      mobius.SetupExperienceStatusSuccess,
				alwaysUpdated: true,
			},
			{
				name:          "failure",
				status:        mobius.MDMAppleStatusError,
				expected:      mobius.SetupExperienceStatusFailure,
				alwaysUpdated: true,
			},
			{
				name:          "format error",
				status:        mobius.MDMAppleStatusCommandFormatError,
				expected:      mobius.SetupExperienceStatusFailure,
				alwaysUpdated: true,
			},
			{
				name:          "pending",
				status:        mobius.MDMAppleStatusNotNow,
				expected:      mobius.SetupExperienceStatusPending,
				alwaysUpdated: false,
			},
		}

		for _, tt := range testCases {
			t.Run(tt.name, func(t *testing.T) {
				requireTerminalStatus := true // when this flag is true, we don't expect pending status to update

				ds.MaybeUpdateSetupExperienceVPPStatusFunc = func(ctx context.Context, hostUUID string, cmdUUID string, status mobius.SetupExperienceStatusResultStatus) (bool, error) {
					require.Equal(t, hostUUID, hostUUID)
					require.Equal(t, cmdUUID, vppUUID)
					require.Equal(t, tt.expected, status)
					require.True(t, status.IsValid())
					return true, nil
				}
				ds.MaybeUpdateSetupExperienceVPPStatusFuncInvoked = false

				result := mobius.SetupExperienceVPPInstallResult{
					HostUUID:      hostUUID,
					CommandUUID:   vppUUID,
					CommandStatus: tt.status,
				}
				updated, err := maybeUpdateSetupExperienceStatus(ctx, ds, result, requireTerminalStatus)
				require.NoError(t, err)
				require.Equal(t, tt.alwaysUpdated, updated)
				require.Equal(t, tt.alwaysUpdated, ds.MaybeUpdateSetupExperienceVPPStatusFuncInvoked)

				requireTerminalStatus = false // when this flag is false, we do expect pending status to update

				ds.MaybeUpdateSetupExperienceVPPStatusFunc = func(ctx context.Context, hostUUID string, cmdUUID string, status mobius.SetupExperienceStatusResultStatus) (bool, error) {
					require.Equal(t, hostUUID, hostUUID)
					require.Equal(t, cmdUUID, vppUUID)
					require.Equal(t, tt.expected, status)
					require.True(t, status.IsValid())
					if status.IsTerminalStatus() {
						require.True(t, status == mobius.SetupExperienceStatusSuccess || status == mobius.SetupExperienceStatusFailure)
					} else {
						require.True(t, status == mobius.SetupExperienceStatusPending || status == mobius.SetupExperienceStatusRunning)
					}
					return true, nil
				}
				ds.MaybeUpdateSetupExperienceVPPStatusFuncInvoked = false

				updated, err = maybeUpdateSetupExperienceStatus(ctx, ds, result, requireTerminalStatus)
				require.NoError(t, err)
				shouldUpdate := tt.alwaysUpdated
				if tt.expected == mobius.SetupExperienceStatusPending || tt.expected == mobius.SetupExperienceStatusRunning {
					shouldUpdate = true
				}
				require.Equal(t, shouldUpdate, updated)
				require.Equal(t, shouldUpdate, ds.MaybeUpdateSetupExperienceVPPStatusFuncInvoked)
			})
		}
	})
}
