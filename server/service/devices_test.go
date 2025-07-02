package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/notawar/mobius/pkg/optjson"
	"github.com/notawar/mobius/server/mobius"
	"github.com/notawar/mobius/server/mock"
	"github.com/notawar/mobius/server/ptr"
	"github.com/notawar/mobius/server/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetMobiusDesktopSummary(t *testing.T) {
	t.Run("free implementation", func(t *testing.T) {
		ds := new(mock.Store)
		svc, ctx := newTestService(t, ds, nil, nil)
		sum, err := svc.GetMobiusDesktopSummary(ctx)
		require.ErrorIs(t, err, mobius.ErrMissingLicense)
		require.Empty(t, sum)
	})

	t.Run("different app config values for managed host", func(t *testing.T) {
		ds := new(mock.Store)
		license := &mobius.LicenseInfo{Tier: mobius.TierPremium, Expiration: time.Now().Add(24 * time.Hour)}
		svc, ctx := newTestService(t, ds, nil, nil, &TestServerOpts{License: license, SkipCreateTestUsers: true})
		ds.FailingPoliciesCountFunc = func(ctx context.Context, host *mobius.Host) (uint, error) {
			return uint(1), nil
		}
		const expectedPlatform = "darwin"
		ds.HasSelfServiceSoftwareInstallersFunc = func(ctx context.Context, platform string, teamID *uint) (bool, error) {
			assert.Equal(t, expectedPlatform, platform)
			return true, nil
		}

		cases := []struct {
			mdm         mobius.MDM
			depAssigned bool
			out         mobius.DesktopNotifications
		}{
			{
				mdm: mobius.MDM{
					EnabledAndConfigured: true,
					MacOSMigration: mobius.MacOSMigration{
						Enable: true,
					},
				},
				depAssigned: true,
				out: mobius.DesktopNotifications{
					NeedsMDMMigration:      true,
					RenewEnrollmentProfile: false,
				},
			},
			{
				mdm: mobius.MDM{
					EnabledAndConfigured: true,
					MacOSMigration: mobius.MacOSMigration{
						Enable: true,
					},
				},
				depAssigned: false,
				out: mobius.DesktopNotifications{
					NeedsMDMMigration:      false,
					RenewEnrollmentProfile: false,
				},
			},
			{
				mdm: mobius.MDM{
					EnabledAndConfigured: false,
					MacOSMigration: mobius.MacOSMigration{
						Enable: true,
					},
				},
				depAssigned: true,
				out: mobius.DesktopNotifications{
					NeedsMDMMigration:      false,
					RenewEnrollmentProfile: false,
				},
			},
			{
				mdm: mobius.MDM{
					EnabledAndConfigured: true,
					MacOSMigration: mobius.MacOSMigration{
						Enable: false,
					},
				},
				depAssigned: true,
				out: mobius.DesktopNotifications{
					NeedsMDMMigration:      false,
					RenewEnrollmentProfile: false,
				},
			},
			{
				mdm: mobius.MDM{
					EnabledAndConfigured: false,
					MacOSMigration: mobius.MacOSMigration{
						Enable: false,
					},
				},
				depAssigned: true,
				out: mobius.DesktopNotifications{
					NeedsMDMMigration:      false,
					RenewEnrollmentProfile: false,
				},
			},
		}

		for _, c := range cases {
			c := c
			ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
				appCfg := mobius.AppConfig{}
				appCfg.MDM = c.mdm
				return &appCfg, nil
			}

			ds.IsHostConnectedToMobiusMDMFunc = func(ctx context.Context, host *mobius.Host) (bool, error) {
				return false, nil
			}
			ds.GetHostMDMFunc = func(ctx context.Context, hostID uint) (*mobius.HostMDM, error) {
				return &mobius.HostMDM{
					IsServer:               false,
					InstalledFromDep:       true,
					Enrolled:               true,
					Name:                   mobius.WellKnownMDMIntune,
					DEPProfileAssignStatus: ptr.String(string(mobius.DEPAssignProfileResponseSuccess)),
				}, nil
			}

			ctx := test.HostContext(ctx, &mobius.Host{
				OsqueryHostID:      ptr.String("test"),
				DEPAssignedToMobius: &c.depAssigned,
				Platform:           expectedPlatform,
			})
			sum, err := svc.GetMobiusDesktopSummary(ctx)
			require.NoError(t, err)
			require.Equal(t, c.out, sum.Notifications, fmt.Sprintf("enabled_and_configured: %t | macos_migration.enable: %t", c.mdm.EnabledAndConfigured, c.mdm.MacOSMigration.Enable))
			require.EqualValues(t, 1, *sum.FailingPolicies)
			assert.Equal(t, ptr.Bool(true), sum.SelfService)
		}
	})

	t.Run("different app config values for unmanaged host", func(t *testing.T) {
		ds := new(mock.Store)
		license := &mobius.LicenseInfo{Tier: mobius.TierPremium, Expiration: time.Now().Add(24 * time.Hour)}
		svc, ctx := newTestService(t, ds, nil, nil, &TestServerOpts{License: license, SkipCreateTestUsers: true})
		ds.FailingPoliciesCountFunc = func(ctx context.Context, host *mobius.Host) (uint, error) {
			return uint(1), nil
		}
		ds.HasSelfServiceSoftwareInstallersFunc = func(ctx context.Context, platform string, teamID *uint) (bool, error) {
			return true, nil
		}
		cases := []struct {
			mdm         mobius.MDM
			depAssigned bool
			out         mobius.DesktopNotifications
		}{
			{
				mdm: mobius.MDM{
					EnabledAndConfigured: true,
					MacOSMigration: mobius.MacOSMigration{
						Enable: true,
					},
				},
				depAssigned: true,
				out: mobius.DesktopNotifications{
					NeedsMDMMigration:      false,
					RenewEnrollmentProfile: true,
				},
			},
			{
				mdm: mobius.MDM{
					EnabledAndConfigured: false,
					MacOSMigration: mobius.MacOSMigration{
						Enable: true,
					},
				},
				depAssigned: true,
				out: mobius.DesktopNotifications{
					NeedsMDMMigration:      false,
					RenewEnrollmentProfile: false,
				},
			},
			{
				mdm: mobius.MDM{
					EnabledAndConfigured: true,
					MacOSMigration: mobius.MacOSMigration{
						Enable: false,
					},
				},
				depAssigned: true,
				out: mobius.DesktopNotifications{
					NeedsMDMMigration:      false,
					RenewEnrollmentProfile: false,
				},
			},
			{
				mdm: mobius.MDM{
					EnabledAndConfigured: false,
					MacOSMigration: mobius.MacOSMigration{
						Enable: false,
					},
				},
				depAssigned: true,
				out: mobius.DesktopNotifications{
					NeedsMDMMigration:      false,
					RenewEnrollmentProfile: false,
				},
			},
		}

		mdmInfo := &mobius.HostMDM{
			IsServer:               false,
			InstalledFromDep:       true,
			Enrolled:               false,
			Name:                   mobius.WellKnownMDMMobius,
			DEPProfileAssignStatus: ptr.String(string(mobius.DEPAssignProfileResponseSuccess)),
		}

		for _, c := range cases {
			c := c
			ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
				appCfg := mobius.AppConfig{}
				appCfg.MDM = c.mdm
				return &appCfg, nil
			}
			ds.IsHostConnectedToMobiusMDMFunc = func(ctx context.Context, host *mobius.Host) (bool, error) {
				return false, nil
			}

			ds.GetHostMDMFunc = func(ctx context.Context, hostID uint) (*mobius.HostMDM, error) {
				return mdmInfo, nil
			}

			ctx = test.HostContext(ctx, &mobius.Host{
				OsqueryHostID:      ptr.String("test"),
				DEPAssignedToMobius: &c.depAssigned,
			})
			sum, err := svc.GetMobiusDesktopSummary(ctx)
			require.NoError(t, err)
			require.Equal(t, c.out, sum.Notifications, fmt.Sprintf("enabled_and_configured: %t | macos_migration.enable: %t", c.mdm.EnabledAndConfigured, c.mdm.MacOSMigration.Enable))
			require.EqualValues(t, 1, *sum.FailingPolicies)
		}
	})

	t.Run("different host attributes", func(t *testing.T) {
		ds := new(mock.Store)
		license := &mobius.LicenseInfo{Tier: mobius.TierPremium, Expiration: time.Now().Add(24 * time.Hour)}
		svc, ctx := newTestService(t, ds, nil, nil, &TestServerOpts{License: license, SkipCreateTestUsers: true})

		// context without a host
		sum, err := svc.GetMobiusDesktopSummary(ctx)
		require.Empty(t, sum)
		var authErr *mobius.AuthRequiredError
		require.ErrorAs(t, err, &authErr)

		ds.FailingPoliciesCountFunc = func(ctx context.Context, host *mobius.Host) (uint, error) {
			return uint(1), nil
		}

		ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
			appCfg := mobius.AppConfig{}
			appCfg.MDM.EnabledAndConfigured = true
			appCfg.MDM.MacOSMigration.Enable = true
			return &appCfg, nil
		}

		ds.HasSelfServiceSoftwareInstallersFunc = func(ctx context.Context, platform string, teamID *uint) (bool, error) {
			return false, nil
		}

		cases := []struct {
			name    string
			host    *mobius.Host
			hostMDM *mobius.HostMDM
			err     error
			out     mobius.DesktopNotifications
		}{
			{
				name: "not enrolled into osquery",
				host: &mobius.Host{OsqueryHostID: nil},
				err:  nil,
				out: mobius.DesktopNotifications{
					NeedsMDMMigration:      false,
					RenewEnrollmentProfile: false,
				},
			},
			{
				name: "manually enrolled into another MDM",
				host: &mobius.Host{
					OsqueryHostID:      ptr.String("test"),
					DEPAssignedToMobius: ptr.Bool(false),
				},
				hostMDM: &mobius.HostMDM{
					IsServer:               false,
					InstalledFromDep:       false,
					Enrolled:               true,
					Name:                   mobius.WellKnownMDMIntune,
					DEPProfileAssignStatus: ptr.String(string(mobius.DEPAssignProfileResponseSuccess)),
				},
				err: nil,
				out: mobius.DesktopNotifications{
					NeedsMDMMigration:      false,
					RenewEnrollmentProfile: false,
				},
			},
			{
				name: "DEP capable, but already unenrolled",
				host: &mobius.Host{
					DEPAssignedToMobius: ptr.Bool(true),
					OsqueryHostID:      ptr.String("test"),
				},
				hostMDM: &mobius.HostMDM{
					IsServer:               false,
					InstalledFromDep:       true,
					Enrolled:               false,
					Name:                   mobius.WellKnownMDMMobius,
					DEPProfileAssignStatus: ptr.String(string(mobius.DEPAssignProfileResponseSuccess)),
				},
				err: nil,
				out: mobius.DesktopNotifications{
					NeedsMDMMigration:      false,
					RenewEnrollmentProfile: true,
				},
			},
			{
				name: "DEP capable, but enrolled into Mobius",
				host: &mobius.Host{
					DEPAssignedToMobius: ptr.Bool(true),
					OsqueryHostID:      ptr.String("test"),
				},
				hostMDM: &mobius.HostMDM{
					IsServer:               false,
					InstalledFromDep:       true,
					Enrolled:               true,
					Name:                   mobius.WellKnownMDMMobius,
					DEPProfileAssignStatus: ptr.String(string(mobius.DEPAssignProfileResponseSuccess)),
				},
				err: nil,
				out: mobius.DesktopNotifications{
					NeedsMDMMigration:      false,
					RenewEnrollmentProfile: false,
				},
			},
			{
				name: "failed ADE assignment status",
				host: &mobius.Host{
					DEPAssignedToMobius: ptr.Bool(true),
					OsqueryHostID:      ptr.String("test"),
				},
				hostMDM: &mobius.HostMDM{
					IsServer:               false,
					InstalledFromDep:       true,
					Enrolled:               true,
					Name:                   mobius.WellKnownMDMIntune,
					DEPProfileAssignStatus: ptr.String(string(mobius.DEPAssignProfileResponseFailed)),
				},
				err: nil,
				out: mobius.DesktopNotifications{
					NeedsMDMMigration:      false,
					RenewEnrollmentProfile: false,
				},
			},
			{
				name: "not accessible ADE assignment status",
				host: &mobius.Host{
					DEPAssignedToMobius: ptr.Bool(true),
					OsqueryHostID:      ptr.String("test"),
				},
				hostMDM: &mobius.HostMDM{
					IsServer:               false,
					InstalledFromDep:       true,
					Enrolled:               true,
					Name:                   mobius.WellKnownMDMIntune,
					DEPProfileAssignStatus: ptr.String(string(mobius.DEPAssignProfileResponseNotAccessible)),
				},
				err: nil,
				out: mobius.DesktopNotifications{
					NeedsMDMMigration:      false,
					RenewEnrollmentProfile: false,
				},
			},
			{
				name: "empty ADE assignment status",
				host: &mobius.Host{
					DEPAssignedToMobius: ptr.Bool(true),
					OsqueryHostID:      ptr.String("test"),
				},
				hostMDM: &mobius.HostMDM{
					IsServer:               false,
					InstalledFromDep:       true,
					Enrolled:               true,
					Name:                   mobius.WellKnownMDMIntune,
					DEPProfileAssignStatus: ptr.String(""),
				},
				err: nil,
				out: mobius.DesktopNotifications{
					NeedsMDMMigration:      false,
					RenewEnrollmentProfile: false,
				},
			},
			{
				name: "nil ADE assignment status",
				host: &mobius.Host{
					DEPAssignedToMobius: ptr.Bool(true),
					OsqueryHostID:      ptr.String("test"),
				},
				hostMDM: &mobius.HostMDM{
					IsServer:               false,
					InstalledFromDep:       true,
					Enrolled:               true,
					Name:                   mobius.WellKnownMDMIntune,
					DEPProfileAssignStatus: nil,
				},
				err: nil,
				out: mobius.DesktopNotifications{
					NeedsMDMMigration:      false,
					RenewEnrollmentProfile: false,
				},
			},
			{
				name: "all conditions met",
				host: &mobius.Host{
					DEPAssignedToMobius: ptr.Bool(true),
					OsqueryHostID:      ptr.String("test"),
				},
				hostMDM: &mobius.HostMDM{
					IsServer:               false,
					InstalledFromDep:       true,
					Enrolled:               true,
					Name:                   mobius.WellKnownMDMIntune,
					DEPProfileAssignStatus: ptr.String(string(mobius.DEPAssignProfileResponseSuccess)),
				},
				err: nil,
				out: mobius.DesktopNotifications{
					NeedsMDMMigration:      true,
					RenewEnrollmentProfile: false,
				},
			},
		}

		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				ctx = test.HostContext(ctx, c.host)

				ds.GetHostMDMFunc = func(ctx context.Context, hostID uint) (*mobius.HostMDM, error) {
					if c.hostMDM == nil {
						return nil, sql.ErrNoRows
					}
					return c.hostMDM, nil
				}

				ds.IsHostConnectedToMobiusMDMFunc = func(ctx context.Context, host *mobius.Host) (bool, error) {
					return c.hostMDM != nil && c.hostMDM.Enrolled == true && c.hostMDM.Name == mobius.WellKnownMDMMobius, nil
				}

				sum, err := svc.GetMobiusDesktopSummary(ctx)

				if c.err != nil {
					require.ErrorIs(t, err, c.err)
					require.Empty(t, sum)
				} else {

					require.NoError(t, err)
					require.Equal(t, c.out, sum.Notifications)
					require.EqualValues(t, 1, *sum.FailingPolicies)
				}
			})
		}
	})
}

func TestTriggerLinuxDiskEncryptionEscrow(t *testing.T) {
	t.Run("unavailable in Mobius Free", func(t *testing.T) {
		ds := new(mock.Store)
		svc, ctx := newTestService(t, ds, nil, nil, &TestServerOpts{SkipCreateTestUsers: true})
		err := svc.TriggerLinuxDiskEncryptionEscrow(ctx, &mobius.Host{ID: 1})
		require.ErrorIs(t, err, mobius.ErrMissingLicense)
	})

	t.Run("no-op on already pending", func(t *testing.T) {
		ds := new(mock.Store)
		svc, ctx := newTestService(t, ds, nil, nil, &TestServerOpts{License: &mobius.LicenseInfo{Tier: mobius.TierPremium}, SkipCreateTestUsers: true})
		ds.IsHostPendingEscrowFunc = func(ctx context.Context, hostID uint) bool {
			return true
		}

		err := svc.TriggerLinuxDiskEncryptionEscrow(ctx, &mobius.Host{ID: 1})
		require.NoError(t, err)
		require.True(t, ds.IsHostPendingEscrowFuncInvoked)
	})

	t.Run("validation failures", func(t *testing.T) {
		ds := new(mock.Store)
		svc, ctx := newTestService(t, ds, nil, nil, &TestServerOpts{License: &mobius.LicenseInfo{Tier: mobius.TierPremium}, SkipCreateTestUsers: true})
		ds.IsHostPendingEscrowFunc = func(ctx context.Context, hostID uint) bool {
			return false
		}
		var reportedErrors []string
		host := &mobius.Host{ID: 1, Platform: "rhel", OSVersion: "Red Hat Enterprise Linux 9.0.0"}
		ds.ReportEscrowErrorFunc = func(ctx context.Context, hostID uint, err string) error {
			require.Equal(t, hostID, host.ID)
			reportedErrors = append(reportedErrors, err)
			return nil
		}

		// invalid platform
		err := svc.TriggerLinuxDiskEncryptionEscrow(ctx, host)
		require.ErrorContains(t, err, "Mobius does not yet support creating LUKS disk encryption keys on this platform.")
		require.True(t, ds.IsHostPendingEscrowFuncInvoked)

		// valid platform, no-team, encryption not enabled
		host.OSVersion = "Fedora 32.0.0"
		appConfig := &mobius.AppConfig{MDM: mobius.MDM{EnableDiskEncryption: optjson.SetBool(false)}}
		ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
			return appConfig, nil
		}
		err = svc.TriggerLinuxDiskEncryptionEscrow(ctx, host)
		require.ErrorContains(t, err, "Disk encryption is not enabled for hosts not assigned to a team.")

		// valid platform, team, encryption not enabled
		host.TeamID = ptr.Uint(1)
		teamConfig := &mobius.TeamMDM{}
		ds.TeamMDMConfigFunc = func(ctx context.Context, teamID uint) (*mobius.TeamMDM, error) {
			require.Equal(t, uint(1), teamID)
			return teamConfig, nil
		}
		err = svc.TriggerLinuxDiskEncryptionEscrow(ctx, host)
		require.ErrorContains(t, err, "Disk encryption is not enabled for this host's team.")

		// valid platform, team, host disk is not encrypted or unknown encryption state
		teamConfig = &mobius.TeamMDM{EnableDiskEncryption: true}
		err = svc.TriggerLinuxDiskEncryptionEscrow(ctx, host)
		require.ErrorContains(t, err, "Host's disk is not encrypted. Please encrypt your disk first.")
		host.DiskEncryptionEnabled = ptr.Bool(false)
		err = svc.TriggerLinuxDiskEncryptionEscrow(ctx, host)
		require.ErrorContains(t, err, "Host's disk is not encrypted. Please encrypt your disk first.")

		// No Mobius Desktop
		host.DiskEncryptionEnabled = ptr.Bool(true)
		orbitInfo := &mobius.HostOrbitInfo{Version: "1.35.1"}
		ds.GetHostOrbitInfoFunc = func(ctx context.Context, id uint) (*mobius.HostOrbitInfo, error) {
			return orbitInfo, nil
		}
		err = svc.TriggerLinuxDiskEncryptionEscrow(ctx, host)
		require.ErrorContains(t, err, "Your version of mobiusdaemon does not support creating disk encryption keys on Linux. Please upgrade mobiusdaemon, then click Refetch, then try again.")

		// Encryption key is already escrowed
		orbitInfo.Version = mobius.MinOrbitLUKSVersion
		ds.AssertHasNoEncryptionKeyStoredFunc = func(ctx context.Context, hostID uint) error {
			return errors.New("encryption key is already escrowed")
		}
		err = svc.TriggerLinuxDiskEncryptionEscrow(ctx, host)
		require.ErrorContains(t, err, "encryption key is already escrowed")

		require.Len(t, reportedErrors, 7)
	})

	t.Run("validation success", func(t *testing.T) {
		ds := new(mock.Store)
		svc, ctx := newTestService(t, ds, nil, nil, &TestServerOpts{License: &mobius.LicenseInfo{Tier: mobius.TierPremium}, SkipCreateTestUsers: true})
		ds.IsHostPendingEscrowFunc = func(ctx context.Context, hostID uint) bool {
			return false
		}
		ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
			return &mobius.AppConfig{MDM: mobius.MDM{EnableDiskEncryption: optjson.SetBool(true)}}, nil
		}
		ds.GetHostOrbitInfoFunc = func(ctx context.Context, id uint) (*mobius.HostOrbitInfo, error) {
			return &mobius.HostOrbitInfo{Version: "1.36.0", DesktopVersion: ptr.String("42")}, nil
		}
		ds.AssertHasNoEncryptionKeyStoredFunc = func(ctx context.Context, hostID uint) error {
			return nil
		}
		host := &mobius.Host{ID: 1, Platform: "ubuntu", DiskEncryptionEnabled: ptr.Bool(true), OrbitVersion: ptr.String(mobius.MinOrbitLUKSVersion)}
		ds.QueueEscrowFunc = func(ctx context.Context, hostID uint) error {
			require.Equal(t, uint(1), hostID)
			return nil
		}

		err := svc.TriggerLinuxDiskEncryptionEscrow(ctx, host)
		require.NoError(t, err)
		require.True(t, ds.QueueEscrowFuncInvoked)
	})
}
