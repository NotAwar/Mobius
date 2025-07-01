package service

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/notawar/mobius/v4/server/authz"
	"github.com/notawar/mobius/v4/server/contexts/viewer"
	"github.com/notawar/mobius/v4/server/mobius"
	"github.com/notawar/mobius/v4/server/mock"
	"github.com/notawar/mobius/v4/server/ptr"
	"github.com/notawar/mobius/v4/server/test"
	"github.com/stretchr/testify/require"
)

func TestHostRunScript(t *testing.T) {
	ds := new(mock.Store)
	license := &mobius.LicenseInfo{Tier: mobius.TierPremium, Expiration: time.Now().Add(24 * time.Hour)}
	svc, ctx := newTestService(t, ds, nil, nil, &TestServerOpts{License: license, SkipCreateTestUsers: true})

	// use a custom implementation of checkAuthErr as the service call will fail
	// with a not found error for unknown host in case of authorization success,
	// and the package-wide checkAuthErr requires no error.
	checkAuthErr := func(t *testing.T, shouldFail bool, err error) {
		if shouldFail {
			require.Error(t, err)
			require.Equal(t, (&authz.Forbidden{}).Error(), err.Error())
		} else if err != nil {
			require.NotEqual(t, (&authz.Forbidden{}).Error(), err.Error())
		}
	}

	teamHost := &mobius.Host{ID: 1, Hostname: "host-team", TeamID: ptr.Uint(1), SeenTime: time.Now(), OrbitNodeKey: ptr.String("abc")}
	noTeamHost := &mobius.Host{ID: 2, Hostname: "host-no-team", TeamID: nil, SeenTime: time.Now(), OrbitNodeKey: ptr.String("def")}
	nonExistingHost := &mobius.Host{ID: 3, Hostname: "no-such-host", TeamID: nil}
	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		return &mobius.AppConfig{}, nil
	}
	ds.HostFunc = func(ctx context.Context, hostID uint) (*mobius.Host, error) {
		if hostID == 1 {
			return teamHost, nil
		}
		if hostID == 2 {
			return noTeamHost, nil
		}
		return nil, newNotFoundError()
	}
	ds.NewHostScriptExecutionRequestFunc = func(ctx context.Context, request *mobius.HostScriptRequestPayload) (*mobius.HostScriptResult, error) {
		return &mobius.HostScriptResult{HostID: request.HostID, ScriptContents: request.ScriptContents, ExecutionID: "abc"}, nil
	}
	ds.ListPendingHostScriptExecutionsFunc = func(ctx context.Context, hostID uint, onlyShowInternal bool) ([]*mobius.HostScriptResult, error) {
		return nil, nil
	}
	ds.ScriptFunc = func(ctx context.Context, id uint) (*mobius.Script, error) {
		return &mobius.Script{ID: id}, nil
	}
	ds.GetScriptContentsFunc = func(ctx context.Context, id uint) ([]byte, error) {
		return []byte("echo"), nil
	}
	ds.IsExecutionPendingForHostFunc = func(ctx context.Context, hostID, scriptID uint) (bool, error) { return false, nil }
	ds.ValidateEmbeddedSecretsFunc = func(ctx context.Context, documents []string) error {
		return nil
	}

	t.Run("authorization checks", func(t *testing.T) {
		testCases := []struct {
			name                  string
			user                  *mobius.User
			scriptID              *uint
			shouldFailTeamWrite   bool
			shouldFailGlobalWrite bool
		}{
			{
				name:                  "global admin",
				user:                  &mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)},
				shouldFailTeamWrite:   false,
				shouldFailGlobalWrite: false,
			},
			{
				name:                  "global admin saved",
				user:                  &mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)},
				scriptID:              ptr.Uint(1),
				shouldFailTeamWrite:   false,
				shouldFailGlobalWrite: false,
			},
			{
				name:                  "global maintainer",
				user:                  &mobius.User{GlobalRole: ptr.String(mobius.RoleMaintainer)},
				shouldFailTeamWrite:   false,
				shouldFailGlobalWrite: false,
			},
			{
				name:                  "global maintainer saved",
				user:                  &mobius.User{GlobalRole: ptr.String(mobius.RoleMaintainer)},
				scriptID:              ptr.Uint(1),
				shouldFailTeamWrite:   false,
				shouldFailGlobalWrite: false,
			},
			{
				name:                  "global observer",
				user:                  &mobius.User{GlobalRole: ptr.String(mobius.RoleObserver)},
				shouldFailTeamWrite:   true,
				shouldFailGlobalWrite: true,
			},
			{
				name:                  "global observer saved",
				user:                  &mobius.User{GlobalRole: ptr.String(mobius.RoleObserver)},
				scriptID:              ptr.Uint(1),
				shouldFailTeamWrite:   true,
				shouldFailGlobalWrite: true,
			},
			{
				name:                  "global observer+",
				user:                  &mobius.User{GlobalRole: ptr.String(mobius.RoleObserverPlus)},
				shouldFailTeamWrite:   true,
				shouldFailGlobalWrite: true,
			},
			{
				name:                  "global observer+ saved",
				user:                  &mobius.User{GlobalRole: ptr.String(mobius.RoleObserverPlus)},
				scriptID:              ptr.Uint(1),
				shouldFailTeamWrite:   true,
				shouldFailGlobalWrite: true,
			},
			{
				name:                  "global gitops",
				user:                  &mobius.User{GlobalRole: ptr.String(mobius.RoleGitOps)},
				shouldFailTeamWrite:   true,
				shouldFailGlobalWrite: true,
			},
			{
				name:                  "global gitops saved",
				user:                  &mobius.User{GlobalRole: ptr.String(mobius.RoleGitOps)},
				scriptID:              ptr.Uint(1),
				shouldFailTeamWrite:   true,
				shouldFailGlobalWrite: true,
			},
			{
				name:                  "team admin, belongs to team",
				user:                  &mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleAdmin}}},
				shouldFailTeamWrite:   false,
				shouldFailGlobalWrite: true,
			},
			{
				name:                  "team admin, belongs to team, saved",
				user:                  &mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleAdmin}}},
				scriptID:              ptr.Uint(1),
				shouldFailTeamWrite:   false,
				shouldFailGlobalWrite: true,
			},
			{
				name:                  "team maintainer, belongs to team",
				user:                  &mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleMaintainer}}},
				shouldFailTeamWrite:   false,
				shouldFailGlobalWrite: true,
			},
			{
				name:                  "team maintainer, belongs to team, saved",
				user:                  &mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleMaintainer}}},
				scriptID:              ptr.Uint(1),
				shouldFailTeamWrite:   false,
				shouldFailGlobalWrite: true,
			},
			{
				name:                  "team observer, belongs to team",
				user:                  &mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleObserver}}},
				shouldFailTeamWrite:   true,
				shouldFailGlobalWrite: true,
			},
			{
				name:                  "team observer, belongs to team, saved",
				user:                  &mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleObserver}}},
				scriptID:              ptr.Uint(1),
				shouldFailTeamWrite:   true,
				shouldFailGlobalWrite: true,
			},
			{
				name:                  "team observer+, belongs to team",
				user:                  &mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleObserverPlus}}},
				shouldFailTeamWrite:   true,
				shouldFailGlobalWrite: true,
			},
			{
				name:                  "team observer+, belongs to team, saved",
				user:                  &mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleObserverPlus}}},
				scriptID:              ptr.Uint(1),
				shouldFailTeamWrite:   true,
				shouldFailGlobalWrite: true,
			},
			{
				name:                  "team gitops, belongs to team",
				user:                  &mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleGitOps}}},
				shouldFailTeamWrite:   true,
				shouldFailGlobalWrite: true,
			},
			{
				name:                  "team gitops, belongs to team, saved",
				user:                  &mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleGitOps}}},
				scriptID:              ptr.Uint(1),
				shouldFailTeamWrite:   true,
				shouldFailGlobalWrite: true,
			},
			{
				name:                  "team admin, DOES NOT belong to team",
				user:                  &mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 2}, Role: mobius.RoleAdmin}}},
				shouldFailTeamWrite:   true,
				shouldFailGlobalWrite: true,
			},
			{
				name:                  "team admin, DOES NOT belong to team, saved",
				user:                  &mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 2}, Role: mobius.RoleAdmin}}},
				scriptID:              ptr.Uint(1),
				shouldFailTeamWrite:   true,
				shouldFailGlobalWrite: true,
			},
			{
				name:                  "team maintainer, DOES NOT belong to team",
				user:                  &mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 2}, Role: mobius.RoleMaintainer}}},
				shouldFailTeamWrite:   true,
				shouldFailGlobalWrite: true,
			},
			{
				name:                  "team maintainer, DOES NOT belong to team, saved",
				user:                  &mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 2}, Role: mobius.RoleMaintainer}}},
				scriptID:              ptr.Uint(1),
				shouldFailTeamWrite:   true,
				shouldFailGlobalWrite: true,
			},
			{
				name:                  "team observer, DOES NOT belong to team",
				user:                  &mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 2}, Role: mobius.RoleObserver}}},
				shouldFailTeamWrite:   true,
				shouldFailGlobalWrite: true,
			},
			{
				name:                  "team observer, DOES NOT belong to team, saved",
				user:                  &mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 2}, Role: mobius.RoleObserver}}},
				scriptID:              ptr.Uint(1),
				shouldFailTeamWrite:   true,
				shouldFailGlobalWrite: true,
			},
			{
				name:                  "team observer+, DOES NOT belong to team",
				user:                  &mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 2}, Role: mobius.RoleObserverPlus}}},
				shouldFailTeamWrite:   true,
				shouldFailGlobalWrite: true,
			},
			{
				name:                  "team observer+, DOES NOT belong to team, saved",
				user:                  &mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 2}, Role: mobius.RoleObserverPlus}}},
				scriptID:              ptr.Uint(1),
				shouldFailTeamWrite:   true,
				shouldFailGlobalWrite: true,
			},
			{
				name:                  "team gitops, DOES NOT belong to team",
				user:                  &mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 2}, Role: mobius.RoleGitOps}}},
				shouldFailTeamWrite:   true,
				shouldFailGlobalWrite: true,
			},
			{
				name:                  "team gitops, DOES NOT belong to team, saved",
				user:                  &mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 2}, Role: mobius.RoleGitOps}}},
				scriptID:              ptr.Uint(1),
				shouldFailTeamWrite:   true,
				shouldFailGlobalWrite: true,
			},
		}
		for _, tt := range testCases {
			t.Run(tt.name, func(t *testing.T) {
				ctx = viewer.NewContext(ctx, viewer.Viewer{User: tt.user})

				contents := "abc"
				if tt.scriptID != nil {
					contents = ""
				}
				_, err := svc.RunHostScript(ctx, &mobius.HostScriptRequestPayload{HostID: noTeamHost.ID, ScriptContents: contents, ScriptID: tt.scriptID}, 0)
				checkAuthErr(t, tt.shouldFailGlobalWrite, err)
				_, err = svc.RunHostScript(ctx, &mobius.HostScriptRequestPayload{HostID: teamHost.ID, ScriptContents: contents, ScriptID: tt.scriptID}, 0)
				checkAuthErr(t, tt.shouldFailTeamWrite, err)

				if tt.scriptID == nil {
					// a non-existing host is authorized as for global write (because we can't know what team it belongs to)
					_, err = svc.RunHostScript(ctx, &mobius.HostScriptRequestPayload{HostID: nonExistingHost.ID, ScriptContents: "abc"}, 0)
					checkAuthErr(t, tt.shouldFailGlobalWrite, err)
				}

				// test auth for run sync saved script by name
				if tt.scriptID != nil {
					ds.GetScriptIDByNameFunc = func(ctx context.Context, name string, teamID *uint) (uint, error) {
						return *tt.scriptID, nil
					}
					_, err = svc.RunHostScript(ctx, &mobius.HostScriptRequestPayload{HostID: noTeamHost.ID, ScriptContents: "", ScriptID: nil, ScriptName: "Foo", TeamID: 1}, 1)
					checkAuthErr(t, tt.shouldFailGlobalWrite, err)
					_, err = svc.RunHostScript(ctx, &mobius.HostScriptRequestPayload{HostID: teamHost.ID, ScriptContents: "", ScriptID: nil, ScriptName: "Foo", TeamID: 1}, 1)
					checkAuthErr(t, tt.shouldFailTeamWrite, err)
				}
			})
		}
	})

	t.Run("script contents validation", func(t *testing.T) {
		testCases := []struct {
			name    string
			script  string
			wantErr string
		}{
			{"empty script", "", "One of 'script_id', 'script_contents', or 'script_name' is required."},
			{"overly long script", strings.Repeat("a", mobius.UnsavedScriptMaxRuneLen+1), "Script is too large."},
			{"large script", strings.Repeat("a", mobius.UnsavedScriptMaxRuneLen), ""},
			{"invalid utf8", "\xff\xfa", "Wrong data format."},
			{"valid without hashbang", "echo 'a'", ""},
			{"valid with posix hashbang", "#!/bin/sh\necho 'a'", ""},
			{"valid with usr bash hashbang", "#!/usr/bin/bash\necho 'a'", ""},
			{"valid with bash hashbang", "#!/bin/bash\necho 'a'", ""},
			{"valid with bash hashbang and arguments", "#!/bin/bash -x\necho 'a'", ""},
			{"valid with usr zsh hashbang", "#!/usr/bin/zsh\necho 'a'", ""},
			{"valid with zsh hashbang", "#!/bin/zsh\necho 'a'", ""},
			{"valid with zsh hashbang and arguments", "#!/bin/zsh -x\necho 'a'", ""},
			{"valid with hashbang and spacing", "#! /bin/sh  \necho 'a'", ""},
			{"valid with hashbang and Windows newline", "#! /bin/sh  \r\necho 'a'", ""},
			{"invalid hashbang", "#!/bin/ksh\necho 'a'", "Interpreter not supported."},
		}

		ctx = viewer.NewContext(ctx, viewer.Viewer{User: test.UserAdmin})
		for _, tt := range testCases {
			t.Run(tt.name, func(t *testing.T) {
				_, err := svc.RunHostScript(ctx, &mobius.HostScriptRequestPayload{HostID: noTeamHost.ID, ScriptContents: tt.script}, 0)
				if tt.wantErr != "" {
					require.ErrorContains(t, err, tt.wantErr)
				} else {
					require.NoError(t, err)
				}
			})
		}
	})
}

func TestGetScriptResult(t *testing.T) {
	ds := new(mock.Store)
	license := &mobius.LicenseInfo{Tier: mobius.TierPremium, Expiration: time.Now().Add(24 * time.Hour)}
	svc, ctx := newTestService(t, ds, nil, nil, &TestServerOpts{License: license, SkipCreateTestUsers: true})

	const (
		noTeamHostExecID      = "no-team-host"
		teamHostExecID        = "team-host"
		nonExistingHostExecID = "non-existing-host"
	)

	checkAuthErr := func(t *testing.T, shouldFail bool, err error) {
		if shouldFail {
			require.Error(t, err)
			require.Equal(t, (&authz.Forbidden{}).Error(), err.Error())
		} else if err != nil {
			require.NotEqual(t, (&authz.Forbidden{}).Error(), err.Error())
		}
	}

	teamHost := &mobius.Host{ID: 1, Hostname: "host-team", TeamID: ptr.Uint(1), SeenTime: time.Now()}
	noTeamHost := &mobius.Host{ID: 2, Hostname: "host-no-team", TeamID: nil, SeenTime: time.Now()}
	nonExistingHost := &mobius.Host{ID: 3, Hostname: "no-such-host", TeamID: nil}
	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		return &mobius.AppConfig{}, nil
	}
	ds.GetHostScriptExecutionResultFunc = func(ctx context.Context, executionID string) (*mobius.HostScriptResult, error) {
		switch executionID {
		case noTeamHostExecID:
			return &mobius.HostScriptResult{HostID: noTeamHost.ID, ScriptContents: "abc", ExecutionID: executionID}, nil
		case teamHostExecID:
			return &mobius.HostScriptResult{HostID: teamHost.ID, ScriptContents: "abc", ExecutionID: executionID}, nil
		case nonExistingHostExecID:
			return &mobius.HostScriptResult{HostID: nonExistingHost.ID, ScriptContents: "abc", ExecutionID: executionID}, nil
		default:
			return nil, newNotFoundError()
		}
	}
	ds.HostLiteFunc = func(ctx context.Context, hostID uint) (*mobius.Host, error) {
		if hostID == 1 {
			return teamHost, nil
		}
		if hostID == 2 {
			return noTeamHost, nil
		}
		return nil, newNotFoundError()
	}

	testCases := []struct {
		name                 string
		user                 *mobius.User
		shouldFailTeamRead   bool
		shouldFailGlobalRead bool
	}{
		{
			name:                 "global admin",
			user:                 &mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)},
			shouldFailTeamRead:   false,
			shouldFailGlobalRead: false,
		},
		{
			name:                 "global maintainer",
			user:                 &mobius.User{GlobalRole: ptr.String(mobius.RoleMaintainer)},
			shouldFailTeamRead:   false,
			shouldFailGlobalRead: false,
		},
		{
			name:                 "global observer",
			user:                 &mobius.User{GlobalRole: ptr.String(mobius.RoleObserver)},
			shouldFailTeamRead:   false,
			shouldFailGlobalRead: false,
		},
		{
			name:                 "global observer+",
			user:                 &mobius.User{GlobalRole: ptr.String(mobius.RoleObserverPlus)},
			shouldFailTeamRead:   false,
			shouldFailGlobalRead: false,
		},
		{
			name:                 "global gitops",
			user:                 &mobius.User{GlobalRole: ptr.String(mobius.RoleGitOps)},
			shouldFailTeamRead:   true,
			shouldFailGlobalRead: true,
		},
		{
			name:                 "team admin, belongs to team",
			user:                 &mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleAdmin}}},
			shouldFailTeamRead:   false,
			shouldFailGlobalRead: true,
		},
		{
			name:                 "team maintainer, belongs to team",
			user:                 &mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleMaintainer}}},
			shouldFailTeamRead:   false,
			shouldFailGlobalRead: true,
		},
		{
			name:                 "team observer, belongs to team",
			user:                 &mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleObserver}}},
			shouldFailTeamRead:   false,
			shouldFailGlobalRead: true,
		},
		{
			name:                 "team observer+, belongs to team",
			user:                 &mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleObserverPlus}}},
			shouldFailTeamRead:   false,
			shouldFailGlobalRead: true,
		},
		{
			name:                 "team gitops, belongs to team",
			user:                 &mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleGitOps}}},
			shouldFailTeamRead:   true,
			shouldFailGlobalRead: true,
		},
		{
			name:                 "team admin, DOES NOT belong to team",
			user:                 &mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 2}, Role: mobius.RoleAdmin}}},
			shouldFailTeamRead:   true,
			shouldFailGlobalRead: true,
		},
		{
			name:                 "team maintainer, DOES NOT belong to team",
			user:                 &mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 2}, Role: mobius.RoleMaintainer}}},
			shouldFailTeamRead:   true,
			shouldFailGlobalRead: true,
		},
		{
			name:                 "team observer, DOES NOT belong to team",
			user:                 &mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 2}, Role: mobius.RoleObserver}}},
			shouldFailTeamRead:   true,
			shouldFailGlobalRead: true,
		},
		{
			name:                 "team observer+, DOES NOT belong to team",
			user:                 &mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 2}, Role: mobius.RoleObserverPlus}}},
			shouldFailTeamRead:   true,
			shouldFailGlobalRead: true,
		},
		{
			name:                 "team gitops, DOES NOT belong to team",
			user:                 &mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 2}, Role: mobius.RoleGitOps}}},
			shouldFailTeamRead:   true,
			shouldFailGlobalRead: true,
		},
	}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			ctx = viewer.NewContext(ctx, viewer.Viewer{User: tt.user})

			_, err := svc.GetScriptResult(ctx, noTeamHostExecID)
			checkAuthErr(t, tt.shouldFailGlobalRead, err)
			_, err = svc.GetScriptResult(ctx, teamHostExecID)
			checkAuthErr(t, tt.shouldFailTeamRead, err)

			// a non-existing host is authorized as for global write (because we can't know what team it belongs to)
			_, err = svc.GetScriptResult(ctx, nonExistingHostExecID)
			checkAuthErr(t, tt.shouldFailGlobalRead, err)
		})
	}
}

func TestSavedScripts(t *testing.T) {
	ds := new(mock.Store)
	license := &mobius.LicenseInfo{Tier: mobius.TierPremium, Expiration: time.Now().Add(24 * time.Hour)}
	svc, ctx := newTestService(t, ds, nil, nil, &TestServerOpts{License: license, SkipCreateTestUsers: true})

	withLFContents := "echo\necho"
	withCRLFContents := "echo\r\necho"

	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		return &mobius.AppConfig{}, nil
	}
	ds.NewScriptFunc = func(ctx context.Context, script *mobius.Script) (*mobius.Script, error) {
		require.Equal(t, withLFContents, script.ScriptContents)
		newScript := *script
		newScript.ID = 1
		return &newScript, nil
	}
	const (
		team1ScriptID  = 1
		noTeamScriptID = 2
	)
	ds.ScriptFunc = func(ctx context.Context, id uint) (*mobius.Script, error) {
		switch id {
		case team1ScriptID:
			return &mobius.Script{ID: id, TeamID: ptr.Uint(1)}, nil
		default:
			return &mobius.Script{ID: id}, nil
		}
	}
	ds.GetScriptContentsFunc = func(ctx context.Context, id uint) ([]byte, error) {
		return []byte("echo"), nil
	}
	ds.DeleteScriptFunc = func(ctx context.Context, id uint) error {
		return nil
	}
	ds.ListScriptsFunc = func(ctx context.Context, teamID *uint, opt mobius.ListOptions) ([]*mobius.Script, *mobius.PaginationMetadata, error) {
		return nil, &mobius.PaginationMetadata{}, nil
	}
	ds.NewActivityFunc = func(
		ctx context.Context, user *mobius.User, activity mobius.ActivityDetails, details []byte, createdAt time.Time,
	) error {
		return nil
	}
	ds.TeamFunc = func(ctx context.Context, id uint) (*mobius.Team, error) {
		return &mobius.Team{ID: 0}, nil
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

			_, err := svc.NewScript(ctx, nil, "test.ps1", strings.NewReader(withCRLFContents))
			checkAuthErr(t, tt.shouldFailGlobalWrite, err)
			err = svc.DeleteScript(ctx, noTeamScriptID)
			checkAuthErr(t, tt.shouldFailGlobalWrite, err)
			_, _, err = svc.ListScripts(ctx, nil, mobius.ListOptions{})
			checkAuthErr(t, tt.shouldFailGlobalRead, err)
			_, _, err = svc.GetScript(ctx, noTeamScriptID, false)
			checkAuthErr(t, tt.shouldFailGlobalRead, err)
			_, _, err = svc.GetScript(ctx, noTeamScriptID, true)
			checkAuthErr(t, tt.shouldFailGlobalRead, err)

			_, err = svc.NewScript(ctx, ptr.Uint(1), "test.sh", strings.NewReader(withLFContents))
			checkAuthErr(t, tt.shouldFailTeamWrite, err)
			err = svc.DeleteScript(ctx, team1ScriptID)
			checkAuthErr(t, tt.shouldFailTeamWrite, err)
			_, _, err = svc.ListScripts(ctx, ptr.Uint(1), mobius.ListOptions{})
			checkAuthErr(t, tt.shouldFailTeamRead, err)
			_, _, err = svc.GetScript(ctx, team1ScriptID, false)
			checkAuthErr(t, tt.shouldFailTeamRead, err)
			_, _, err = svc.GetScript(ctx, team1ScriptID, true)
			checkAuthErr(t, tt.shouldFailTeamRead, err)
		})
	}
}

func TestHostScriptDetailsAuth(t *testing.T) {
	ds := new(mock.Store)
	license := &mobius.LicenseInfo{Tier: mobius.TierPremium, Expiration: time.Now().Add(24 * time.Hour)}
	svc, ctx := newTestService(t, ds, nil, nil, &TestServerOpts{License: license, SkipCreateTestUsers: true})

	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		return &mobius.AppConfig{}, nil
	}

	testCases := []struct {
		name                 string
		user                 *mobius.User
		shouldFailTeamRead   bool
		shouldFailGlobalRead bool
	}{
		{
			name:                 "global admin",
			user:                 &mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)},
			shouldFailTeamRead:   false,
			shouldFailGlobalRead: false,
		},
		{
			name:                 "global maintainer",
			user:                 &mobius.User{GlobalRole: ptr.String(mobius.RoleMaintainer)},
			shouldFailTeamRead:   false,
			shouldFailGlobalRead: false,
		},
		{
			name:                 "global observer",
			user:                 &mobius.User{GlobalRole: ptr.String(mobius.RoleObserver)},
			shouldFailTeamRead:   false,
			shouldFailGlobalRead: false,
		},
		{
			name:                 "global observer+",
			user:                 &mobius.User{GlobalRole: ptr.String(mobius.RoleObserverPlus)},
			shouldFailTeamRead:   false,
			shouldFailGlobalRead: false,
		},
		{
			name:                 "global gitops",
			user:                 &mobius.User{GlobalRole: ptr.String(mobius.RoleGitOps)},
			shouldFailTeamRead:   true,
			shouldFailGlobalRead: true,
		},
		{
			name:                 "team admin, belongs to team",
			user:                 &mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleAdmin}}},
			shouldFailTeamRead:   false,
			shouldFailGlobalRead: true,
		},
		{
			name:                 "team maintainer, belongs to team",
			user:                 &mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleMaintainer}}},
			shouldFailTeamRead:   false,
			shouldFailGlobalRead: true,
		},
		{
			name:                 "team observer, belongs to team",
			user:                 &mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleObserver}}},
			shouldFailTeamRead:   false,
			shouldFailGlobalRead: true,
		},
		{
			name:                 "team observer+, belongs to team",
			user:                 &mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleObserverPlus}}},
			shouldFailTeamRead:   false,
			shouldFailGlobalRead: true,
		},
		{
			name:                 "team gitops, belongs to team",
			user:                 &mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleGitOps}}},
			shouldFailTeamRead:   true,
			shouldFailGlobalRead: true,
		},
		{
			name:                 "team admin, DOES NOT belong to team",
			user:                 &mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 2}, Role: mobius.RoleAdmin}}},
			shouldFailTeamRead:   true,
			shouldFailGlobalRead: true,
		},
		{
			name:                 "team maintainer, DOES NOT belong to team",
			user:                 &mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 2}, Role: mobius.RoleMaintainer}}},
			shouldFailTeamRead:   true,
			shouldFailGlobalRead: true,
		},
		{
			name:                 "team observer, DOES NOT belong to team",
			user:                 &mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 2}, Role: mobius.RoleObserver}}},
			shouldFailTeamRead:   true,
			shouldFailGlobalRead: true,
		},
		{
			name:                 "team observer+, DOES NOT belong to team",
			user:                 &mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 2}, Role: mobius.RoleObserverPlus}}},
			shouldFailTeamRead:   true,
			shouldFailGlobalRead: true,
		},
		{
			name:                 "team gitops, DOES NOT belong to team",
			user:                 &mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 2}, Role: mobius.RoleGitOps}}},
			shouldFailTeamRead:   true,
			shouldFailGlobalRead: true,
		},
	}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			ctx = viewer.NewContext(ctx, viewer.Viewer{User: tt.user})

			t.Run("no team host script details", func(t *testing.T) {
				ds.HostLiteFunc = func(ctx context.Context, hostID uint) (*mobius.Host, error) {
					require.Equal(t, uint(42), hostID)
					return &mobius.Host{ID: hostID}, nil
				}
				ds.GetHostScriptDetailsFunc = func(ctx context.Context, hostID uint, teamID *uint, opts mobius.ListOptions, hostPlatform string) ([]*mobius.HostScriptDetail, *mobius.PaginationMetadata, error) {
					require.Nil(t, teamID)
					return []*mobius.HostScriptDetail{}, nil, nil
				}
				_, _, err := svc.GetHostScriptDetails(ctx, 42, mobius.ListOptions{})
				checkAuthErr(t, tt.shouldFailGlobalRead, err)
			})

			t.Run("team host script details", func(t *testing.T) {
				ds.HostLiteFunc = func(ctx context.Context, hostID uint) (*mobius.Host, error) {
					require.Equal(t, uint(42), hostID)
					return &mobius.Host{ID: hostID, TeamID: ptr.Uint(1)}, nil
				}
				ds.GetHostScriptDetailsFunc = func(ctx context.Context, hostID uint, teamID *uint, opts mobius.ListOptions, hostPlatform string) ([]*mobius.HostScriptDetail, *mobius.PaginationMetadata, error) {
					require.NotNil(t, teamID)
					require.Equal(t, uint(1), *teamID)
					return []*mobius.HostScriptDetail{}, nil, nil
				}
				_, _, err := svc.GetHostScriptDetails(ctx, 42, mobius.ListOptions{})
				checkAuthErr(t, tt.shouldFailTeamRead, err)
			})

			t.Run("host not found", func(t *testing.T) {
				ds.HostLiteFunc = func(ctx context.Context, hostID uint) (*mobius.Host, error) {
					require.Equal(t, uint(43), hostID)
					return nil, &notFoundError{}
				}
				_, _, err := svc.GetHostScriptDetails(ctx, 43, mobius.ListOptions{})
				if tt.shouldFailGlobalRead {
					checkAuthErr(t, tt.shouldFailGlobalRead, err)
				} else {
					require.True(t, mobius.IsNotFound(err))
				}
			})
		})
	}
}

func TestBatchScriptExecute(t *testing.T) {
	ds := new(mock.Store)
	license := &mobius.LicenseInfo{Tier: mobius.TierPremium, Expiration: time.Now().Add(24 * time.Hour)}
	svc, ctx := newTestService(t, ds, nil, nil, &TestServerOpts{License: license, SkipCreateTestUsers: true})

	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		return &mobius.AppConfig{}, nil
	}

	t.Run("error if hosts do not all belong to the same team as script", func(t *testing.T) {
		ds.ListHostsLiteByIDsFunc = func(ctx context.Context, ids []uint) ([]*mobius.Host, error) {
			return []*mobius.Host{
				{ID: 1, TeamID: ptr.Uint(1)},
				{ID: 2, TeamID: ptr.Uint(1)},
				{ID: 3, TeamID: ptr.Uint(2)},
			}, nil
		}
		ds.ScriptFunc = func(ctx context.Context, id uint) (*mobius.Script, error) {
			if id == 1 {
				return &mobius.Script{ID: id, TeamID: ptr.Uint(1)}, nil
			}
			return &mobius.Script{ID: id}, nil
		}
		ctx = viewer.NewContext(ctx, viewer.Viewer{User: &mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)}})
		_, err := svc.BatchScriptExecute(ctx, 1, []uint{1, 2, 3}, nil)
		require.Error(t, err)
		require.ErrorContains(t, err, "all hosts must be on the same team as the script")
	})

	t.Run("error if both host_ids and filters are specified", func(t *testing.T) {
		ctx = viewer.NewContext(ctx, viewer.Viewer{User: &mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)}})
		_, err := svc.BatchScriptExecute(ctx, 1, []uint{1, 2, 3}, &map[string]interface{}{"foo": "bar"})
		require.Error(t, err)
		require.ErrorContains(t, err, "cannot specify both host_ids and filters")
	})

	t.Run("error if filters are specified but no team_id", func(t *testing.T) {
		ctx = viewer.NewContext(ctx, viewer.Viewer{User: &mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)}})
		_, err := svc.BatchScriptExecute(ctx, 1, nil, &map[string]interface{}{"label_id": float64(123)})
		require.Error(t, err)
		require.ErrorContains(t, err, "filters must include a team filter")
	})

	t.Run("error if filters match too many hosts", func(t *testing.T) {
		hosts := make([]*mobius.Host, 5001)
		for i := 0; i < 5001; i++ {
			hosts[i] = &mobius.Host{ID: uint(i + 1), TeamID: ptr.Uint(1)} // nolint:gosec // ignore G115
		}
		ds.ListHostsFunc = func(ctx context.Context, filter mobius.TeamFilter, opt mobius.HostListOptions) ([]*mobius.Host, error) {
			return hosts, nil
		}
		ds.ListHostsLiteByIDsFunc = func(ctx context.Context, ids []uint) ([]*mobius.Host, error) {
			return hosts, nil
		}
		ds.ScriptFunc = func(ctx context.Context, id uint) (*mobius.Script, error) {
			if id == 1 {
				return &mobius.Script{ID: id, TeamID: ptr.Uint(1)}, nil
			}
			return &mobius.Script{ID: id}, nil
		}
		ctx = viewer.NewContext(ctx, viewer.Viewer{User: &mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)}})
		_, err := svc.BatchScriptExecute(ctx, 1, nil, &map[string]interface{}{"team_id": float64(1)})
		require.Error(t, err)
		require.ErrorContains(t, err, "too_many_hosts")
	})

	t.Run("happy path", func(t *testing.T) {
		var requestedHostIds []uint
		ds.BatchExecuteScriptFunc = func(ctx context.Context, userID *uint, scriptID uint, hostIDs []uint) (string, error) {
			requestedHostIds = hostIDs
			return "", errors.New("ok")
		}
		ds.ListHostsLiteByIDsFunc = func(ctx context.Context, ids []uint) ([]*mobius.Host, error) {
			return []*mobius.Host{
				{ID: 1, TeamID: ptr.Uint(1)},
				{ID: 2, TeamID: ptr.Uint(1)},
			}, nil
		}
		ds.ScriptFunc = func(ctx context.Context, id uint) (*mobius.Script, error) {
			if id == 1 {
				return &mobius.Script{ID: id, TeamID: ptr.Uint(1)}, nil
			}
			return &mobius.Script{ID: id}, nil
		}
		ds.ListHostsFunc = func(ctx context.Context, filter mobius.TeamFilter, opt mobius.HostListOptions) ([]*mobius.Host, error) {
			return []*mobius.Host{
				{ID: 3, TeamID: ptr.Uint(1)},
				{ID: 4, TeamID: ptr.Uint(1)},
			}, nil
		}

		ctx = viewer.NewContext(ctx, viewer.Viewer{User: &mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)}})
		_, err := svc.BatchScriptExecute(ctx, 1, []uint{1, 2}, nil)
		require.Error(t, err)
		require.ErrorContains(t, err, "ok")
		require.Equal(t, []uint{1, 2}, requestedHostIds)

		ctx = viewer.NewContext(ctx, viewer.Viewer{User: &mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)}})
		_, err = svc.BatchScriptExecute(ctx, 1, nil, &map[string]interface{}{"team_id": float64(1)})
		require.Error(t, err)
		require.ErrorContains(t, err, "ok")
		require.Equal(t, []uint{3, 4}, requestedHostIds)
	})
}

func TestWipeHostRequestDecodeBody(t *testing.T) {
	ctx := context.Background()

	testCases := []struct {
		name          string
		body          io.Reader
		expectedError string
		expectation   func(t *testing.T, req *wipeHostRequest)
	}{
		{
			name: "empty body",
			body: strings.NewReader(""),
			expectation: func(t *testing.T, req *wipeHostRequest) {
				require.Nil(t, req.Metadata)
			},
		},
		{
			name: "doWipe",
			body: strings.NewReader(`{"windows": {"wipe_type": "doWipe"}}`),
			expectation: func(t *testing.T, req *wipeHostRequest) {
				require.NotNil(t, req.Metadata)
				require.NotNil(t, req.Metadata.Windows)
				require.Equal(t, mobius.MDMWindowsWipeTypeDoWipe, req.Metadata.Windows.WipeType)
			},
		},
		{
			name: "doWipeProtected",
			body: strings.NewReader(`{"windows": {"wipe_type": "doWipeProtected"}}`),
			expectation: func(t *testing.T, req *wipeHostRequest) {
				require.NotNil(t, req.Metadata)
				require.NotNil(t, req.Metadata.Windows)
				require.Equal(t, mobius.MDMWindowsWipeTypeDoWipeProtected, req.Metadata.Windows.WipeType)
			},
		},
		{
			name:          "invalid wipe type",
			body:          strings.NewReader(`{"windows": {"wipe_type": "doWipeProtectedII"}}`),
			expectedError: "failed to unmarshal request body",
		},
		{
			name: "empty payload",
			body: strings.NewReader(`{}`),
			expectation: func(t *testing.T, req *wipeHostRequest) {
				require.NotNil(t, req.Metadata)
				require.Nil(t, req.Metadata.Windows)
			},
		},
		{
			name: "windows field is null",
			body: strings.NewReader(`{"windows": null}`),
			expectation: func(t *testing.T, req *wipeHostRequest) {
				require.NotNil(t, req.Metadata)
				require.Nil(t, req.Metadata.Windows)
			},
		},
		{
			name:          "empty wipe type",
			body:          strings.NewReader(`{"windows": {"wipe_type": null}}`),
			expectedError: "failed to unmarshal request body",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			sut := wipeHostRequest{}
			err := sut.DecodeBody(ctx, tc.body, nil, nil)

			if tc.expectedError != "" {
				require.ErrorContains(t, err, tc.expectedError)
			} else {
				require.NoError(t, err)
				tc.expectation(t, &sut)
			}
		})
	}
}
