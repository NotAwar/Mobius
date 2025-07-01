package service

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/WatchBeam/clock"
	"github.com/notawar/mobius/v4/server/authz"
	"github.com/notawar/mobius/v4/server/config"
	"github.com/notawar/mobius/v4/server/contexts/capabilities"
	"github.com/notawar/mobius/v4/server/contexts/license"
	"github.com/notawar/mobius/v4/server/contexts/viewer"
	"github.com/notawar/mobius/v4/server/datastore/mysql"
	"github.com/notawar/mobius/v4/server/mdm"
	apple_mdm "github.com/notawar/mobius/v4/server/mdm/apple"
	"github.com/notawar/mobius/v4/server/mdm/apple/mobileconfig"
	"github.com/notawar/mobius/v4/server/mdm/nanodep/tokenpki"
	"github.com/notawar/mobius/v4/server/mobius"
	"github.com/notawar/mobius/v4/server/mock"
	"github.com/notawar/mobius/v4/server/ptr"
	"github.com/notawar/mobius/v4/server/test"
	kitlog "github.com/go-kit/log"
	"github.com/jmoiron/sqlx"
	"github.com/smallstep/pkcs7"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Fragile test: This test is fragile because of the large reliance on Datastore mocks. Consider refactoring test/logic or removing the test. It may be slowing us down more than helping us.
func TestHostDetails(t *testing.T) {
	ds := new(mock.Store)
	svc := &Service{ds: ds}

	host := &mobius.Host{ID: 3}
	expectedLabels := []*mobius.Label{
		{
			Name:        "foobar",
			Description: "the foobar label",
		},
	}
	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		return &mobius.AppConfig{}, nil
	}
	ds.ListLabelsForHostFunc = func(ctx context.Context, hid uint) ([]*mobius.Label, error) {
		return expectedLabels, nil
	}
	expectedPacks := []*mobius.Pack{
		{
			Name: "pack1",
		},
		{
			Name: "pack2",
		},
	}
	ds.ListPacksForHostFunc = func(ctx context.Context, hid uint) ([]*mobius.Pack, error) {
		return expectedPacks, nil
	}
	ds.LoadHostSoftwareFunc = func(ctx context.Context, host *mobius.Host, includeCVEScores bool) error {
		return nil
	}
	ds.ListPoliciesForHostFunc = func(ctx context.Context, host *mobius.Host) ([]*mobius.HostPolicy, error) {
		return nil, nil
	}
	dsBats := []*mobius.HostBattery{{HostID: host.ID, SerialNumber: "a", CycleCount: 999, Health: "Normal"}, {HostID: host.ID, SerialNumber: "b", CycleCount: 1001, Health: "Service recommended"}}
	ds.ListHostBatteriesFunc = func(ctx context.Context, hostID uint) ([]*mobius.HostBattery, error) {
		return dsBats, nil
	}
	ds.ListUpcomingHostMaintenanceWindowsFunc = func(ctx context.Context, hid uint) ([]*mobius.HostMaintenanceWindow, error) {
		return nil, nil
	}
	ds.GetHostLockWipeStatusFunc = func(ctx context.Context, host *mobius.Host) (*mobius.HostLockWipeStatus, error) {
		return &mobius.HostLockWipeStatus{}, nil
	}
	ds.ScimUserByHostIDFunc = func(ctx context.Context, hostID uint) (*mobius.ScimUser, error) {
		return nil, nil
	}
	ds.ListHostDeviceMappingFunc = func(ctx context.Context, id uint) ([]*mobius.HostDeviceMapping, error) {
		return nil, nil
	}

	opts := mobius.HostDetailOptions{
		IncludeCVEScores: false,
		IncludePolicies:  false,
	}
	hostDetail, err := svc.getHostDetails(test.UserContext(context.Background(), test.UserAdmin), host, opts)
	require.NoError(t, err)
	assert.Equal(t, expectedLabels, hostDetail.Labels)
	assert.Equal(t, expectedPacks, hostDetail.Packs)
	require.NotNil(t, hostDetail.Batteries)
	assert.Equal(t, dsBats, *hostDetail.Batteries)
	require.Nil(t, hostDetail.MDM.MacOSSettings)
}

// Fragile test: This test is fragile because of the large reliance on Datastore mocks. Consider refactoring test/logic or removing the test. It may be slowing us down more than helping us.
func TestHostDetailsMDMAppleDiskEncryption(t *testing.T) {
	ds := new(mock.Store)
	svc := &Service{ds: ds}

	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		return &mobius.AppConfig{MDM: mobius.MDM{EnabledAndConfigured: true}}, nil
	}
	ds.ListLabelsForHostFunc = func(ctx context.Context, hid uint) ([]*mobius.Label, error) {
		return nil, nil
	}
	ds.ListPacksForHostFunc = func(ctx context.Context, hid uint) ([]*mobius.Pack, error) {
		return nil, nil
	}
	ds.LoadHostSoftwareFunc = func(ctx context.Context, host *mobius.Host, includeCVEScores bool) error {
		return nil
	}
	ds.ListPoliciesForHostFunc = func(ctx context.Context, host *mobius.Host) ([]*mobius.HostPolicy, error) {
		return nil, nil
	}
	ds.ListHostBatteriesFunc = func(ctx context.Context, hostID uint) ([]*mobius.HostBattery, error) {
		return nil, nil
	}
	ds.ListUpcomingHostMaintenanceWindowsFunc = func(ctx context.Context, hid uint) ([]*mobius.HostMaintenanceWindow, error) {
		return nil, nil
	}
	ds.GetHostLockWipeStatusFunc = func(ctx context.Context, host *mobius.Host) (*mobius.HostLockWipeStatus, error) {
		return &mobius.HostLockWipeStatus{}, nil
	}
	ds.ScimUserByHostIDFunc = func(ctx context.Context, hostID uint) (*mobius.ScimUser, error) {
		return nil, nil
	}
	ds.ListHostDeviceMappingFunc = func(ctx context.Context, id uint) ([]*mobius.HostDeviceMapping, error) {
		return nil, nil
	}
	ds.GetNanoMDMEnrollmentTimesFunc = func(ctx context.Context, hostUUID string) (*time.Time, *time.Time, error) {
		return nil, nil, nil
	}

	cases := []struct {
		name       string
		rawDecrypt *int
		fvProf     *mobius.HostMDMAppleProfile
		wantState  mobius.DiskEncryptionStatus
		wantAction mobius.ActionRequiredState
		wantStatus *mobius.MDMDeliveryStatus
	}{
		{"no profile", ptr.Int(-1), nil, "", "", nil},

		{
			"installed profile, no key",
			ptr.Int(-1),
			&mobius.HostMDMAppleProfile{
				HostUUID:      "abc",
				Identifier:    mobileconfig.MobiusFileVaultPayloadIdentifier,
				Status:        &mobius.MDMDeliveryVerifying,
				OperationType: mobius.MDMOperationTypeInstall,
			},
			mobius.DiskEncryptionActionRequired,
			mobius.ActionRequiredRotateKey,
			&mobius.MDMDeliveryPending,
		},
		{
			"installed profile, unknown decryptable",
			nil,
			&mobius.HostMDMAppleProfile{
				HostUUID:      "abc",
				Identifier:    mobileconfig.MobiusFileVaultPayloadIdentifier,
				Status:        &mobius.MDMDeliveryVerifying,
				OperationType: mobius.MDMOperationTypeInstall,
			},
			mobius.DiskEncryptionVerifying,
			"",
			&mobius.MDMDeliveryVerifying,
		},
		{
			"installed profile, not decryptable",
			ptr.Int(0),
			&mobius.HostMDMAppleProfile{
				HostUUID:      "abc",
				Identifier:    mobileconfig.MobiusFileVaultPayloadIdentifier,
				Status:        &mobius.MDMDeliveryVerifying,
				OperationType: mobius.MDMOperationTypeInstall,
			},
			mobius.DiskEncryptionActionRequired,
			mobius.ActionRequiredRotateKey,
			&mobius.MDMDeliveryPending,
		},
		{
			"installed profile, decryptable",
			ptr.Int(1),
			&mobius.HostMDMAppleProfile{
				HostUUID:      "abc",
				Identifier:    mobileconfig.MobiusFileVaultPayloadIdentifier,
				Status:        &mobius.MDMDeliveryVerifying,
				OperationType: mobius.MDMOperationTypeInstall,
			},
			mobius.DiskEncryptionVerifying,
			"",
			&mobius.MDMDeliveryVerifying,
		},
		{
			"installed profile, decryptable, verified",
			ptr.Int(1),
			&mobius.HostMDMAppleProfile{
				HostUUID:      "abc",
				Identifier:    mobileconfig.MobiusFileVaultPayloadIdentifier,
				Status:        &mobius.MDMDeliveryVerified,
				OperationType: mobius.MDMOperationTypeInstall,
			},
			mobius.DiskEncryptionVerified,
			"",
			&mobius.MDMDeliveryVerified,
		},
		{
			"pending install, decryptable",
			ptr.Int(1),
			&mobius.HostMDMAppleProfile{
				HostUUID:      "abc",
				Identifier:    mobileconfig.MobiusFileVaultPayloadIdentifier,
				Status:        &mobius.MDMDeliveryPending,
				OperationType: mobius.MDMOperationTypeInstall,
			},
			mobius.DiskEncryptionEnforcing,
			"",
			&mobius.MDMDeliveryPending,
		},
		{
			"pending install, unknown decryptable",
			nil,
			&mobius.HostMDMAppleProfile{
				HostUUID:      "abc",
				Identifier:    mobileconfig.MobiusFileVaultPayloadIdentifier,
				Status:        &mobius.MDMDeliveryPending,
				OperationType: mobius.MDMOperationTypeInstall,
			},
			mobius.DiskEncryptionEnforcing,
			"",
			&mobius.MDMDeliveryPending,
		},
		{
			"pending install, no key",
			ptr.Int(-1),
			&mobius.HostMDMAppleProfile{
				HostUUID:      "abc",
				Identifier:    mobileconfig.MobiusFileVaultPayloadIdentifier,
				Status:        &mobius.MDMDeliveryPending,
				OperationType: mobius.MDMOperationTypeInstall,
			},
			mobius.DiskEncryptionEnforcing,
			"",
			&mobius.MDMDeliveryPending,
		},
		{
			"failed install, no key",
			ptr.Int(-1),
			&mobius.HostMDMAppleProfile{
				HostUUID:      "abc",
				Identifier:    mobileconfig.MobiusFileVaultPayloadIdentifier,
				Status:        &mobius.MDMDeliveryFailed,
				OperationType: mobius.MDMOperationTypeInstall,
				Detail:        "some mdm profile install error",
			},
			mobius.DiskEncryptionFailed,
			"",
			&mobius.MDMDeliveryFailed,
		},
		{
			"failed install, not decryptable",
			ptr.Int(0),
			&mobius.HostMDMAppleProfile{
				HostUUID:      "abc",
				Identifier:    mobileconfig.MobiusFileVaultPayloadIdentifier,
				Status:        &mobius.MDMDeliveryFailed,
				OperationType: mobius.MDMOperationTypeInstall,
			},
			mobius.DiskEncryptionFailed,
			"",
			&mobius.MDMDeliveryFailed,
		},
		{
			"pending remove, decryptable",
			ptr.Int(1),
			&mobius.HostMDMAppleProfile{
				HostUUID:      "abc",
				Identifier:    mobileconfig.MobiusFileVaultPayloadIdentifier,
				Status:        &mobius.MDMDeliveryPending,
				OperationType: mobius.MDMOperationTypeRemove,
			},
			mobius.DiskEncryptionRemovingEnforcement,
			"",
			&mobius.MDMDeliveryPending,
		},
		{
			"pending remove, no key",
			ptr.Int(-1),
			&mobius.HostMDMAppleProfile{
				HostUUID:      "abc",
				Identifier:    mobileconfig.MobiusFileVaultPayloadIdentifier,
				Status:        &mobius.MDMDeliveryPending,
				OperationType: mobius.MDMOperationTypeRemove,
			},
			mobius.DiskEncryptionRemovingEnforcement,
			"",
			&mobius.MDMDeliveryPending,
		},
		{
			"failed remove, unknown decryptable",
			nil,
			&mobius.HostMDMAppleProfile{
				HostUUID:      "abc",
				Identifier:    mobileconfig.MobiusFileVaultPayloadIdentifier,
				Status:        &mobius.MDMDeliveryFailed,
				OperationType: mobius.MDMOperationTypeRemove,
				Detail:        "some mdm profile removal error",
			},
			mobius.DiskEncryptionFailed,
			"",
			&mobius.MDMDeliveryFailed,
		},
		{
			"removed profile, not decryptable",
			ptr.Int(0),
			&mobius.HostMDMAppleProfile{
				HostUUID:      "abc",
				Identifier:    mobileconfig.MobiusFileVaultPayloadIdentifier,
				Status:        &mobius.MDMDeliveryVerifying,
				OperationType: mobius.MDMOperationTypeRemove,
			},
			"",
			"",
			&mobius.MDMDeliveryVerifying,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var mdmData mobius.MDMHostData
			rawDecrypt := "null"
			if c.rawDecrypt != nil {
				rawDecrypt = strconv.Itoa(*c.rawDecrypt)
			}
			require.NoError(t, mdmData.Scan([]byte(fmt.Sprintf(`{"raw_decryptable": %s}`, rawDecrypt))))

			host := &mobius.Host{ID: 3, MDM: mdmData, UUID: "abc", Platform: "darwin"}
			opts := mobius.HostDetailOptions{
				IncludeCVEScores: false,
				IncludePolicies:  false,
			}

			ds.GetHostMDMAppleProfilesFunc = func(ctx context.Context, uuid string) ([]mobius.HostMDMAppleProfile, error) {
				if c.fvProf == nil {
					return nil, nil
				}
				return []mobius.HostMDMAppleProfile{*c.fvProf}, nil
			}
			hostDetail, err := svc.getHostDetails(test.UserContext(context.Background(), test.UserAdmin), host, opts)
			require.NoError(t, err)
			require.NotNil(t, hostDetail.MDM.MacOSSettings)

			if c.wantState == "" {
				require.Nil(t, hostDetail.MDM.MacOSSettings.DiskEncryption)
				require.Nil(t, hostDetail.MDM.OSSettings.DiskEncryption.Status)
				require.Empty(t, hostDetail.MDM.OSSettings.DiskEncryption.Detail)
			} else {
				require.NotNil(t, hostDetail.MDM.MacOSSettings.DiskEncryption)
				require.Equal(t, c.wantState, *hostDetail.MDM.MacOSSettings.DiskEncryption)
				require.NotNil(t, hostDetail.MDM.OSSettings.DiskEncryption.Status)
				require.Equal(t, c.wantState, *hostDetail.MDM.OSSettings.DiskEncryption.Status)
				require.Equal(t, c.fvProf.Detail, hostDetail.MDM.OSSettings.DiskEncryption.Detail)
			}
			if c.wantAction == "" {
				require.Nil(t, hostDetail.MDM.MacOSSettings.ActionRequired)
			} else {
				require.NotNil(t, hostDetail.MDM.MacOSSettings.ActionRequired)
				require.Equal(t, c.wantAction, *hostDetail.MDM.MacOSSettings.ActionRequired)
			}
			if c.wantStatus != nil {
				require.NotNil(t, hostDetail.MDM.Profiles)
				profs := *hostDetail.MDM.Profiles
				require.Equal(t, c.wantStatus, profs[0].Status)
				require.Equal(t, c.fvProf.Detail, profs[0].Detail)
			} else {
				require.Nil(t, *hostDetail.MDM.Profiles)
			}
		})
	}
}

func TestHostDetailsMDMTimestamps(t *testing.T) {
	ds := new(mock.Store)
	svc := &Service{ds: ds}
	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		return &mobius.AppConfig{MDM: mobius.MDM{EnabledAndConfigured: true, WindowsEnabledAndConfigured: true}}, nil
	}
	ds.ListLabelsForHostFunc = func(ctx context.Context, hid uint) ([]*mobius.Label, error) {
		return nil, nil
	}
	ds.ListPacksForHostFunc = func(ctx context.Context, hid uint) ([]*mobius.Pack, error) {
		return nil, nil
	}
	ds.LoadHostSoftwareFunc = func(ctx context.Context, host *mobius.Host, includeCVEScores bool) error {
		return nil
	}
	ds.ListPoliciesForHostFunc = func(ctx context.Context, host *mobius.Host) ([]*mobius.HostPolicy, error) {
		return nil, nil
	}
	ds.ListHostBatteriesFunc = func(ctx context.Context, hostID uint) ([]*mobius.HostBattery, error) {
		return nil, nil
	}
	ds.ListUpcomingHostMaintenanceWindowsFunc = func(ctx context.Context, hid uint) ([]*mobius.HostMaintenanceWindow, error) {
		return nil, nil
	}
	ds.GetHostLockWipeStatusFunc = func(ctx context.Context, host *mobius.Host) (*mobius.HostLockWipeStatus, error) {
		return &mobius.HostLockWipeStatus{}, nil
	}
	ds.ScimUserByHostIDFunc = func(ctx context.Context, hostID uint) (*mobius.ScimUser, error) {
		return nil, nil
	}
	ds.ListHostDeviceMappingFunc = func(ctx context.Context, id uint) ([]*mobius.HostDeviceMapping, error) {
		return nil, nil
	}
	ds.GetHostMDMAppleProfilesFunc = func(ctx context.Context, uuid string) ([]mobius.HostMDMAppleProfile, error) {
		return nil, nil
	}
	ds.GetHostMDMWindowsProfilesFunc = func(ctx context.Context, uuid string) ([]mobius.HostMDMWindowsProfile, error) {
		return nil, nil
	}
	ds.GetConfigEnableDiskEncryptionFunc = func(ctx context.Context, teamID *uint) (bool, error) {
		return false, nil
	}

	ts1 := time.Now().Add(-1 * time.Hour).UTC()
	ts2 := time.Now().Add(-2 * time.Hour).UTC()
	ds.GetNanoMDMEnrollmentTimesFunc = func(ctx context.Context, hostUUID string) (*time.Time, *time.Time, error) {
		return &ts1, &ts2, nil
	}

	cases := []struct {
		platform        string
		platformIsApple bool
	}{
		{"darwin", true},
		{"ios", true},
		{"ipados", true},
		{"windows", false},
		{"ubuntu", false},
		{"centos", false},
		{"rhel", false},
		{"debian", false},
	}
	for _, testcase := range cases {
		t.Run("test MDM timestamps on platform "+testcase.platform, func(t *testing.T) {
			ds.GetNanoMDMEnrollmentTimesFuncInvoked = false
			host := &mobius.Host{ID: 3, MDM: mobius.MDMHostData{}, Platform: testcase.platform, UUID: "abc123"}
			opts := mobius.HostDetailOptions{
				IncludeCVEScores:                    false,
				IncludePolicies:                     false,
				ExcludeSoftware:                     true,
				IncludeCriticalVulnerabilitiesCount: false,
			}
			hostDetail, err := svc.getHostDetails(test.UserContext(context.Background(), test.UserAdmin), host, opts)
			require.NoError(t, err)
			if testcase.platformIsApple {
				assert.True(t, ds.GetNanoMDMEnrollmentTimesFuncInvoked)
				require.NotNil(t, hostDetail.LastMDMEnrolledAt)
				assert.Equal(t, *hostDetail.LastMDMEnrolledAt, ts1)
				require.NotNil(t, hostDetail.LastMDMCheckedInAt)
				assert.Equal(t, *hostDetail.LastMDMCheckedInAt, ts2)
			} else {
				assert.False(t, ds.GetNanoMDMEnrollmentTimesFuncInvoked)
				assert.Nil(t, hostDetail.LastMDMEnrolledAt)
				assert.Nil(t, hostDetail.LastMDMCheckedInAt)
			}
		})
	}
}

// Fragile test: This test is fragile because of the large reliance on Datastore mocks. Consider refactoring test/logic or removing the test. It may be slowing us down more than helping us.
func TestHostDetailsOSSettings(t *testing.T) {
	ds := new(mock.Store)
	svc := &Service{ds: ds}

	ctx := context.Background()

	ds.ListLabelsForHostFunc = func(ctx context.Context, hid uint) ([]*mobius.Label, error) {
		return nil, nil
	}
	ds.ListPacksForHostFunc = func(ctx context.Context, hid uint) ([]*mobius.Pack, error) {
		return nil, nil
	}
	ds.LoadHostSoftwareFunc = func(ctx context.Context, host *mobius.Host, includeCVEScores bool) error {
		return nil
	}
	ds.ListPoliciesForHostFunc = func(ctx context.Context, host *mobius.Host) ([]*mobius.HostPolicy, error) {
		return nil, nil
	}
	ds.ListHostBatteriesFunc = func(ctx context.Context, hostID uint) ([]*mobius.HostBattery, error) {
		return nil, nil
	}
	ds.ListUpcomingHostMaintenanceWindowsFunc = func(ctx context.Context, hid uint) ([]*mobius.HostMaintenanceWindow, error) {
		return nil, nil
	}
	ds.GetHostMDMMacOSSetupFunc = func(ctx context.Context, hid uint) (*mobius.HostMDMMacOSSetup, error) {
		return nil, nil
	}
	ds.GetHostLockWipeStatusFunc = func(ctx context.Context, host *mobius.Host) (*mobius.HostLockWipeStatus, error) {
		return &mobius.HostLockWipeStatus{}, nil
	}

	ds.GetHostDiskEncryptionKeyFunc = func(ctx context.Context, hostID uint) (*mobius.HostDiskEncryptionKey, error) {
		return &mobius.HostDiskEncryptionKey{}, nil
	}
	ds.ScimUserByHostIDFunc = func(ctx context.Context, hostID uint) (*mobius.ScimUser, error) {
		return nil, nil
	}
	ds.ListHostDeviceMappingFunc = func(ctx context.Context, id uint) ([]*mobius.HostDeviceMapping, error) {
		return nil, nil
	}
	ds.GetNanoMDMEnrollmentTimesFunc = func(ctx context.Context, hostUUID string) (*time.Time, *time.Time, error) {
		return nil, nil, nil
	}

	type testCase struct {
		name        string
		host        *mobius.Host
		licenseTier string
		wantStatus  mobius.DiskEncryptionStatus
	}
	cases := []testCase{
		{"windows", &mobius.Host{ID: 42, Platform: "windows"}, mobius.TierPremium, mobius.DiskEncryptionEnforcing},
		{"darwin", &mobius.Host{ID: 42, Platform: "darwin"}, mobius.TierPremium, ""},
		// TeamID necessary to check whether disk encryption is enabled for Linux hosts, in lieu of
		// MDM-related logic which doesn't apply to Linux hosts
		{"ubuntu", &mobius.Host{ID: 42, Platform: "ubuntu", TeamID: ptr.Uint(1)}, mobius.TierPremium, ""},
		{"not premium", &mobius.Host{ID: 42, Platform: "windows"}, mobius.TierFree, ""},
	}

	setupDS := func(c testCase) {
		ds.AppConfigFuncInvoked = false
		ds.GetMDMWindowsBitLockerStatusFuncInvoked = false
		ds.GetHostMDMAppleProfilesFuncInvoked = false
		ds.GetHostMDMWindowsProfilesFuncInvoked = false
		ds.GetHostMDMFuncInvoked = false
		ds.GetConfigEnableDiskEncryptionFuncInvoked = false

		ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
			return &mobius.AppConfig{MDM: mobius.MDM{EnabledAndConfigured: true, WindowsEnabledAndConfigured: true}}, nil
		}
		ds.GetMDMWindowsBitLockerStatusFunc = func(ctx context.Context, host *mobius.Host) (*mobius.HostMDMDiskEncryption, error) {
			if c.wantStatus == "" {
				return nil, nil
			}
			return &mobius.HostMDMDiskEncryption{Status: &c.wantStatus, Detail: ""}, nil
		}
		ds.GetHostMDMAppleProfilesFunc = func(ctx context.Context, uuid string) ([]mobius.HostMDMAppleProfile, error) {
			return nil, nil
		}
		ds.GetHostMDMWindowsProfilesFunc = func(ctx context.Context, uuid string) ([]mobius.HostMDMWindowsProfile, error) {
			return nil, nil
		}
		ds.GetHostMDMFunc = func(ctx context.Context, hostID uint) (*mobius.HostMDM, error) {
			hmdm := mobius.HostMDM{Enrolled: true, IsServer: false}
			return &hmdm, nil
		}
		ds.GetConfigEnableDiskEncryptionFunc = func(ctx context.Context, teamID *uint) (bool, error) {
			// testing API response when not enabled
			return false, nil
		}
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			setupDS(c)

			ctx = license.NewContext(ctx, &mobius.LicenseInfo{Tier: c.licenseTier})

			hostDetail, err := svc.getHostDetails(test.UserContext(ctx, test.UserAdmin), c.host, mobius.HostDetailOptions{
				IncludeCVEScores: false,
				IncludePolicies:  false,
			})
			require.NoError(t, err)
			require.NotNil(t, hostDetail)
			require.True(t, ds.AppConfigFuncInvoked)

			switch c.host.Platform {
			case "windows":
				require.False(t, ds.GetHostMDMAppleProfilesFuncInvoked)
				if c.licenseTier == mobius.TierPremium {
					require.True(t, ds.GetHostMDMFuncInvoked)
				} else {
					require.False(t, ds.GetHostMDMFuncInvoked)
				}
				if c.wantStatus != "" {
					require.True(t, ds.GetMDMWindowsBitLockerStatusFuncInvoked)
					require.NotNil(t, hostDetail.MDM.OSSettings.DiskEncryption.Status)
					require.Equal(t, c.wantStatus, *hostDetail.MDM.OSSettings.DiskEncryption.Status)
				} else {
					require.False(t, ds.GetMDMWindowsBitLockerStatusFuncInvoked)
					require.Nil(t, hostDetail.MDM.OSSettings.DiskEncryption.Status)
				}
			case "ubuntu":
				require.False(t, ds.GetHostMDMAppleProfilesFuncInvoked)
				require.False(t, ds.GetMDMWindowsBitLockerStatusFuncInvoked)
				// service should call this function to check whether disk encryption is enabled for a Linux host
				require.True(t, ds.GetConfigEnableDiskEncryptionFuncInvoked)

				// `hostDetail.MDM.OSSettings` and `hostDetail.MDM.OSSettings.DiskEncryption` will actually not
				// be `nil` here due to the way those fields are initialized by `svc.ds.Host`, so we can't
				// expect them to be `nil` in these tests. However, since the relevant struct tags are set to
				// `omitempty`, the resulting API response WILL omit these fields/subfields when empty,
				// which is confirmed at the integration layer.
				require.Nil(t, hostDetail.MDM.OSSettings.DiskEncryption.Status)

			case "darwin":
				require.True(t, ds.GetHostMDMAppleProfilesFuncInvoked)
				require.False(t, ds.GetMDMWindowsBitLockerStatusFuncInvoked)
				require.Nil(t, hostDetail.MDM.OSSettings.DiskEncryption.Status)
			default:
				require.False(t, ds.GetHostMDMAppleProfilesFuncInvoked)
				require.False(t, ds.GetMDMWindowsBitLockerStatusFuncInvoked)
			}
		})
	}
}

// Fragile test: This test is fragile because of the large reliance on Datastore mocks. Consider refactoring test/logic or removing the test. It may be slowing us down more than helping us.
func TestHostDetailsOSSettingsWindowsOnly(t *testing.T) {
	ds := new(mock.Store)
	svc := &Service{ds: ds}

	ds.ListLabelsForHostFunc = func(ctx context.Context, hid uint) ([]*mobius.Label, error) {
		return nil, nil
	}
	ds.ListPacksForHostFunc = func(ctx context.Context, hid uint) ([]*mobius.Pack, error) {
		return nil, nil
	}
	ds.LoadHostSoftwareFunc = func(ctx context.Context, host *mobius.Host, includeCVEScores bool) error {
		return nil
	}
	ds.ListPoliciesForHostFunc = func(ctx context.Context, host *mobius.Host) ([]*mobius.HostPolicy, error) {
		return nil, nil
	}
	ds.ListHostBatteriesFunc = func(ctx context.Context, hostID uint) ([]*mobius.HostBattery, error) {
		return nil, nil
	}
	ds.ListUpcomingHostMaintenanceWindowsFunc = func(ctx context.Context, hid uint) ([]*mobius.HostMaintenanceWindow, error) {
		return nil, nil
	}
	ds.GetHostMDMMacOSSetupFunc = func(ctx context.Context, hid uint) (*mobius.HostMDMMacOSSetup, error) {
		return nil, nil
	}
	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		return &mobius.AppConfig{MDM: mobius.MDM{WindowsEnabledAndConfigured: true}}, nil
	}
	ds.GetMDMWindowsBitLockerStatusFunc = func(ctx context.Context, host *mobius.Host) (*mobius.HostMDMDiskEncryption, error) {
		verified := mobius.DiskEncryptionVerified
		return &mobius.HostMDMDiskEncryption{Status: &verified, Detail: ""}, nil
	}
	ds.GetHostMDMAppleProfilesFunc = func(ctx context.Context, uuid string) ([]mobius.HostMDMAppleProfile, error) {
		return nil, nil
	}
	ds.GetHostMDMWindowsProfilesFunc = func(ctx context.Context, uuid string) ([]mobius.HostMDMWindowsProfile, error) {
		return nil, nil
	}
	ds.GetHostLockWipeStatusFunc = func(ctx context.Context, host *mobius.Host) (*mobius.HostLockWipeStatus, error) {
		return &mobius.HostLockWipeStatus{}, nil
	}
	ds.GetHostMDMFunc = func(ctx context.Context, hostID uint) (*mobius.HostMDM, error) {
		hmdm := mobius.HostMDM{Enrolled: true, IsServer: false}
		return &hmdm, nil
	}
	ds.ScimUserByHostIDFunc = func(ctx context.Context, hostID uint) (*mobius.ScimUser, error) {
		return nil, nil
	}
	ds.ListHostDeviceMappingFunc = func(ctx context.Context, id uint) ([]*mobius.HostDeviceMapping, error) {
		return nil, nil
	}

	ctx := license.NewContext(context.Background(), &mobius.LicenseInfo{Tier: mobius.TierPremium})
	hostDetail, err := svc.getHostDetails(test.UserContext(ctx, test.UserAdmin), &mobius.Host{ID: 42, Platform: "windows"}, mobius.HostDetailOptions{
		IncludeCVEScores: false,
		IncludePolicies:  false,
	})
	require.NoError(t, err)
	require.NotNil(t, hostDetail)
	require.True(t, ds.AppConfigFuncInvoked)
	require.False(t, ds.GetHostMDMAppleProfilesFuncInvoked)
	require.True(t, ds.GetMDMWindowsBitLockerStatusFuncInvoked)
	require.NotNil(t, hostDetail.MDM.OSSettings.DiskEncryption.Status)
	require.Equal(t, mobius.DiskEncryptionVerified, *hostDetail.MDM.OSSettings.DiskEncryption.Status)
}

// Fragile test: This test is fragile because of the large reliance on Datastore mocks. Consider refactoring test/logic or removing the test. It may be slowing us down more than helping us.
func TestHostAuth(t *testing.T) {
	ds := new(mock.Store)
	svc, ctx := newTestService(t, ds, nil, nil)

	teamHost := &mobius.Host{TeamID: ptr.Uint(1)}
	globalHost := &mobius.Host{}

	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		return &mobius.AppConfig{}, nil
	}

	ds.DeleteHostFunc = func(ctx context.Context, hid uint) error {
		return nil
	}
	ds.HostLiteFunc = func(ctx context.Context, id uint) (*mobius.Host, error) {
		if id == 1 {
			return teamHost, nil
		}
		return globalHost, nil
	}
	ds.HostFunc = func(ctx context.Context, id uint) (*mobius.Host, error) {
		if id == 1 {
			return teamHost, nil
		}
		return globalHost, nil
	}
	ds.HostByIdentifierFunc = func(ctx context.Context, identifier string) (*mobius.Host, error) {
		if identifier == "1" {
			return teamHost, nil
		}
		return globalHost, nil
	}
	ds.ListHostsFunc = func(ctx context.Context, filter mobius.TeamFilter, opt mobius.HostListOptions) ([]*mobius.Host, error) {
		return nil, nil
	}
	ds.LoadHostSoftwareFunc = func(ctx context.Context, host *mobius.Host, includeCVEScores bool) error {
		return nil
	}
	ds.ListLabelsForHostFunc = func(ctx context.Context, hid uint) ([]*mobius.Label, error) {
		return nil, nil
	}
	ds.ListPacksForHostFunc = func(ctx context.Context, hid uint) (packs []*mobius.Pack, err error) {
		return nil, nil
	}
	ds.AddHostsToTeamFunc = func(ctx context.Context, teamID *uint, hostIDs []uint) error {
		return nil
	}
	ds.ListPoliciesForHostFunc = func(ctx context.Context, host *mobius.Host) ([]*mobius.HostPolicy, error) {
		return nil, nil
	}
	ds.ListHostBatteriesFunc = func(ctx context.Context, hostID uint) ([]*mobius.HostBattery, error) {
		return nil, nil
	}
	ds.ListUpcomingHostMaintenanceWindowsFunc = func(ctx context.Context, hid uint) ([]*mobius.HostMaintenanceWindow, error) {
		return nil, nil
	}
	ds.DeleteHostsFunc = func(ctx context.Context, ids []uint) error {
		return nil
	}
	ds.UpdateHostRefetchRequestedFunc = func(ctx context.Context, id uint, value bool) error {
		if id == 1 {
			teamHost.RefetchRequested = true
		} else {
			globalHost.RefetchRequested = true
		}
		return nil
	}
	ds.BulkSetPendingMDMHostProfilesFunc = func(ctx context.Context, hids, tids []uint, puuids, uuids []string,
	) (updates mobius.MDMProfilesUpdates, err error) {
		return mobius.MDMProfilesUpdates{}, nil
	}
	ds.ListMDMAppleDEPSerialsInHostIDsFunc = func(ctx context.Context, hids []uint) ([]string, error) {
		return nil, nil
	}
	ds.TeamFunc = func(ctx context.Context, id uint) (*mobius.Team, error) {
		return &mobius.Team{ID: id}, nil
	}
	ds.NewActivityFunc = func(ctx context.Context, u *mobius.User, a mobius.ActivityDetails, details []byte, createdAt time.Time) error {
		return nil
	}
	ds.ListHostsLiteByIDsFunc = func(ctx context.Context, ids []uint) ([]*mobius.Host, error) {
		return nil, nil
	}
	ds.SetOrUpdateCustomHostDeviceMappingFunc = func(ctx context.Context, hostID uint, email, source string) ([]*mobius.HostDeviceMapping, error) {
		return nil, nil
	}
	ds.ListHostUpcomingActivitiesFunc = func(ctx context.Context, hostID uint, opt mobius.ListOptions) ([]*mobius.UpcomingActivity, *mobius.PaginationMetadata, error) {
		return nil, nil, nil
	}
	ds.GetHostLockWipeStatusFunc = func(ctx context.Context, host *mobius.Host) (*mobius.HostLockWipeStatus, error) {
		return &mobius.HostLockWipeStatus{}, nil
	}
	ds.ListHostSoftwareFunc = func(ctx context.Context, host *mobius.Host, opts mobius.HostSoftwareTitleListOptions) ([]*mobius.HostSoftwareWithInstaller, *mobius.PaginationMetadata, error) {
		return nil, nil, nil
	}
	ds.IsHostConnectedToMobiusMDMFunc = func(ctx context.Context, host *mobius.Host) (bool, error) {
		return true, nil
	}
	ds.ListHostCertificatesFunc = func(ctx context.Context, hostID uint, opts mobius.ListOptions) ([]*mobius.HostCertificateRecord, *mobius.PaginationMetadata, error) {
		return nil, nil, nil
	}
	ds.ScimUserByHostIDFunc = func(ctx context.Context, hostID uint) (*mobius.ScimUser, error) {
		return nil, nil
	}
	ds.ListHostDeviceMappingFunc = func(ctx context.Context, id uint) ([]*mobius.HostDeviceMapping, error) {
		return nil, nil
	}

	ds.GetCategoriesForSoftwareTitlesFunc = func(ctx context.Context, softwareTitleIDs []uint, team_id *uint) (map[uint][]string, error) {
		return map[uint][]string{}, nil
	}
	ds.UpdateHostIssuesFailingPoliciesFunc = func(ctx context.Context, hostIDs []uint) error {
		return nil
	}
	ds.GetHostIssuesLastUpdatedFunc = func(ctx context.Context, hostId uint) (time.Time, error) {
		return time.Time{}, nil
	}

	testCases := []struct {
		name                  string
		user                  *mobius.User
		shouldFailGlobalWrite bool
		shouldFailGlobalRead  bool
		shouldFailTeamWrite   bool
		shouldFailTeamRead    bool
	}{
		{
			"global admin",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)},
			false,
			false,
			false,
			false,
		},
		{
			"global maintainer",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleMaintainer)},
			false,
			false,
			false,
			false,
		},
		{
			"global observer",
			&mobius.User{GlobalRole: ptr.String(mobius.RoleObserver)},
			true,
			false,
			true,
			false,
		},
		{
			"team admin, belongs to team",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleAdmin}}},
			true,
			true,
			false,
			false,
		},
		{
			"team maintainer, belongs to team",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleMaintainer}}},
			true,
			true,
			false,
			false,
		},
		{
			"team observer, belongs to team",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleObserver}}},
			true,
			true,
			true,
			false,
		},
		{
			"team admin, DOES NOT belong to team",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 2}, Role: mobius.RoleAdmin}}},
			true,
			true,
			true,
			true,
		},
		{
			"team maintainer, DOES NOT belong to team",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 2}, Role: mobius.RoleMaintainer}}},
			true,
			true,
			true,
			true,
		},
		{
			"team observer, DOES NOT belong to team",
			&mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 2}, Role: mobius.RoleObserver}}},
			true,
			true,
			true,
			true,
		},
	}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			ctx := viewer.NewContext(ctx, viewer.Viewer{User: tt.user})
			opts := mobius.HostDetailOptions{
				IncludeCVEScores: false,
				IncludePolicies:  false,
			}

			_, err := svc.GetHost(ctx, 1, opts)
			checkAuthErr(t, tt.shouldFailTeamRead, err)

			_, err = svc.GetHostLite(ctx, 1)
			checkAuthErr(t, tt.shouldFailTeamRead, err)

			_, err = svc.HostByIdentifier(ctx, "1", opts)
			checkAuthErr(t, tt.shouldFailTeamRead, err)

			_, _, err = svc.ListHostUpcomingActivities(ctx, 1, mobius.ListOptions{})
			checkAuthErr(t, tt.shouldFailTeamRead, err)

			_, err = svc.GetHost(ctx, 2, opts)
			checkAuthErr(t, tt.shouldFailGlobalRead, err)

			_, err = svc.GetHostLite(ctx, 2)
			checkAuthErr(t, tt.shouldFailGlobalRead, err)

			_, err = svc.HostByIdentifier(ctx, "2", opts)
			checkAuthErr(t, tt.shouldFailGlobalRead, err)

			_, _, err = svc.ListHostUpcomingActivities(ctx, 2, mobius.ListOptions{})
			checkAuthErr(t, tt.shouldFailGlobalRead, err)

			err = svc.DeleteHost(ctx, 1)
			checkAuthErr(t, tt.shouldFailTeamWrite, err)

			err = svc.DeleteHost(ctx, 2)
			checkAuthErr(t, tt.shouldFailGlobalWrite, err)

			err = svc.DeleteHosts(ctx, []uint{1}, nil)
			checkAuthErr(t, tt.shouldFailTeamWrite, err)

			err = svc.DeleteHosts(ctx, []uint{2}, nil)
			checkAuthErr(t, tt.shouldFailGlobalWrite, err)

			err = svc.AddHostsToTeam(ctx, ptr.Uint(1), []uint{1}, false)
			checkAuthErr(t, tt.shouldFailTeamWrite, err)

			emptyFilter := make(map[string]interface{})
			err = svc.AddHostsToTeamByFilter(ctx, ptr.Uint(1), &emptyFilter)
			checkAuthErr(t, tt.shouldFailTeamWrite, err)

			err = svc.RefetchHost(ctx, 1)
			checkAuthErr(t, tt.shouldFailTeamRead, err)

			_, err = svc.SetCustomHostDeviceMapping(ctx, 1, "a@b.c")
			checkAuthErr(t, tt.shouldFailTeamWrite, err)

			_, err = svc.SetCustomHostDeviceMapping(ctx, 2, "a@b.c")
			checkAuthErr(t, tt.shouldFailGlobalWrite, err)

			_, _, err = svc.ListHostSoftware(ctx, 1, mobius.HostSoftwareTitleListOptions{})
			checkAuthErr(t, tt.shouldFailTeamRead, err)

			_, _, err = svc.ListHostSoftware(ctx, 2, mobius.HostSoftwareTitleListOptions{})
			checkAuthErr(t, tt.shouldFailGlobalRead, err)

			_, _, err = svc.ListHostCertificates(ctx, 1, mobius.ListOptions{})
			checkAuthErr(t, tt.shouldFailTeamRead, err)
			_, _, err = svc.ListHostCertificates(ctx, 2, mobius.ListOptions{})
			checkAuthErr(t, tt.shouldFailGlobalRead, err)
		})
	}

	// List, GetHostSummary work for all
}

func TestListHosts(t *testing.T) {
	ds := new(mock.Store)
	svc, ctx := newTestService(t, ds, nil, nil)

	ds.ListHostsFunc = func(ctx context.Context, filter mobius.TeamFilter, opt mobius.HostListOptions) ([]*mobius.Host, error) {
		return []*mobius.Host{
			{ID: 1},
		}, nil
	}

	userContext := test.UserContext(ctx, test.UserAdmin)
	hosts, err := svc.ListHosts(userContext, mobius.HostListOptions{})
	require.NoError(t, err)
	require.Len(t, hosts, 1)

	// a user is required
	_, err = svc.ListHosts(ctx, mobius.HostListOptions{})
	require.Error(t, err)
	require.Contains(t, err.Error(), authz.ForbiddenErrorMessage)

	var shouldIncludeCVEScores bool
	ds.LoadHostSoftwareFunc = func(ctx context.Context, host *mobius.Host, includeCVEScores bool) error {
		require.Equal(t, shouldIncludeCVEScores, includeCVEScores)
		return nil
	}

	// free license disallows getting vuln details
	hosts, err = svc.ListHosts(userContext, mobius.HostListOptions{PopulateSoftware: true, PopulateSoftwareVulnerabilityDetails: true})
	require.NoError(t, err)
	require.Len(t, hosts, 1)
	require.True(t, ds.LoadHostSoftwareFuncInvoked)
	ds.LoadHostSoftwareFuncInvoked = false

	// you're allowed to skip vuln details on Premium
	userContext = license.NewContext(userContext, &mobius.LicenseInfo{Tier: mobius.TierPremium})
	hosts, err = svc.ListHosts(userContext, mobius.HostListOptions{PopulateSoftware: true, PopulateSoftwareVulnerabilityDetails: false})
	require.NoError(t, err)
	require.Len(t, hosts, 1)
	require.True(t, ds.LoadHostSoftwareFuncInvoked)
	ds.LoadHostSoftwareFuncInvoked = false

	// you're allowed to retrieve vuln details on Premium
	shouldIncludeCVEScores = true
	hosts, err = svc.ListHosts(userContext, mobius.HostListOptions{PopulateSoftware: true, PopulateSoftwareVulnerabilityDetails: true})
	require.NoError(t, err)
	require.Len(t, hosts, 1)
	require.True(t, ds.LoadHostSoftwareFuncInvoked)
}

func TestGetHostSummary(t *testing.T) {
	ds := new(mock.Store)
	svc, ctx := newTestService(t, ds, nil, nil)

	ds.GenerateHostStatusStatisticsFunc = func(ctx context.Context, filter mobius.TeamFilter, now time.Time, platform *string, lowDiskSpace *int) (*mobius.HostSummary, error) {
		return &mobius.HostSummary{
			OnlineCount:      1,
			OfflineCount:     5, // offline hosts also includes mia hosts as of Mobius 4.15
			MIACount:         3,
			NewCount:         4,
			TotalsHostsCount: 5,
			Platforms:        []*mobius.HostSummaryPlatform{{Platform: "darwin", HostsCount: 1}, {Platform: "debian", HostsCount: 2}, {Platform: "centos", HostsCount: 3}, {Platform: "ubuntu", HostsCount: 4}},
		}, nil
	}
	ds.LabelsSummaryFunc = func(ctx context.Context) ([]*mobius.LabelSummary, error) {
		return []*mobius.LabelSummary{{ID: 1, Name: "All hosts", Description: "All hosts enrolled in Mobius", LabelType: mobius.LabelTypeBuiltIn}, {ID: 10, Name: "Other label", Description: "Not a builtin label", LabelType: mobius.LabelTypeRegular}}, nil
	}

	summary, err := svc.GetHostSummary(test.UserContext(ctx, test.UserAdmin), nil, nil, nil)
	require.NoError(t, err)
	require.Nil(t, summary.TeamID)
	require.Equal(t, uint(1), summary.OnlineCount)
	require.Equal(t, uint(5), summary.OfflineCount)
	require.Equal(t, uint(3), summary.MIACount)
	require.Equal(t, uint(4), summary.NewCount)
	require.Equal(t, uint(5), summary.TotalsHostsCount)
	require.Len(t, summary.Platforms, 4)
	require.Equal(t, uint(9), summary.AllLinuxCount)
	require.Nil(t, summary.LowDiskSpaceCount)
	require.Len(t, summary.BuiltinLabels, 1)
	require.Equal(t, "All hosts", summary.BuiltinLabels[0].Name)

	// a user is required
	_, err = svc.GetHostSummary(ctx, nil, nil, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), authz.ForbiddenErrorMessage)
}

func TestDeleteHost(t *testing.T) {
	ds := mysql.CreateMySQLDS(t)
	defer ds.Close()

	svc, ctx := newTestService(t, ds, nil, nil)

	mockClock := clock.NewMockClock()
	host := test.NewHost(t, ds, "foo", "192.168.1.10", "1", "1", mockClock.Now())
	assert.NotZero(t, host.ID)

	err := svc.DeleteHost(test.UserContext(ctx, test.UserAdmin), host.ID)
	assert.Nil(t, err)

	filter := mobius.TeamFilter{User: test.UserAdmin}
	hosts, err := ds.ListHosts(ctx, filter, mobius.HostListOptions{})
	assert.Nil(t, err)
	assert.Len(t, hosts, 0)
}

func TestAddHostsToTeamByFilter(t *testing.T) {
	ds := new(mock.Store)
	svc, ctx := newTestService(t, ds, nil, nil)

	expectedHostIDs := []uint{1, 2, 4}
	expectedTeam := (*uint)(nil)

	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		return &mobius.AppConfig{}, nil
	}
	ds.ListHostsFunc = func(ctx context.Context, filter mobius.TeamFilter, opt mobius.HostListOptions) ([]*mobius.Host, error) {
		var hosts []*mobius.Host
		for _, id := range expectedHostIDs {
			hosts = append(hosts, &mobius.Host{ID: id})
		}
		return hosts, nil
	}
	ds.AddHostsToTeamFunc = func(ctx context.Context, teamID *uint, hostIDs []uint) error {
		assert.Equal(t, expectedTeam, teamID)
		assert.Equal(t, expectedHostIDs, hostIDs)
		return nil
	}
	ds.BulkSetPendingMDMHostProfilesFunc = func(ctx context.Context, hids, tids []uint, puuids, uuids []string,
	) (updates mobius.MDMProfilesUpdates, err error) {
		return mobius.MDMProfilesUpdates{}, nil
	}
	ds.ListMDMAppleDEPSerialsInHostIDsFunc = func(ctx context.Context, hids []uint) ([]string, error) {
		return nil, nil
	}
	ds.NewActivityFunc = func(
		ctx context.Context, user *mobius.User, activity mobius.ActivityDetails, details []byte, createdAt time.Time,
	) error {
		return nil
	}

	emptyRequest := &map[string]interface{}{}

	require.NoError(t, svc.AddHostsToTeamByFilter(test.UserContext(ctx, test.UserAdmin), expectedTeam, emptyRequest))
	assert.True(t, ds.ListHostsFuncInvoked)
	assert.True(t, ds.AddHostsToTeamFuncInvoked)
}

func TestAddHostsToTeamByFilterLabel(t *testing.T) {
	ds := new(mock.Store)
	svc, ctx := newTestService(t, ds, nil, nil)

	expectedHostIDs := []uint{6}
	expectedTeam := ptr.Uint(1)
	expectedLabel := float64(2)

	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		return &mobius.AppConfig{}, nil
	}
	ds.ListHostsInLabelFunc = func(ctx context.Context, filter mobius.TeamFilter, lid uint, opt mobius.HostListOptions) ([]*mobius.Host, error) {
		assert.Equal(t, uint(expectedLabel), lid)
		var hosts []*mobius.Host
		for _, id := range expectedHostIDs {
			hosts = append(hosts, &mobius.Host{ID: id})
		}
		return hosts, nil
	}
	ds.AddHostsToTeamFunc = func(ctx context.Context, teamID *uint, hostIDs []uint) error {
		assert.Equal(t, expectedHostIDs, hostIDs)
		return nil
	}
	ds.BulkSetPendingMDMHostProfilesFunc = func(ctx context.Context, hids, tids []uint, puuids, uuids []string,
	) (updates mobius.MDMProfilesUpdates, err error) {
		return mobius.MDMProfilesUpdates{}, nil
	}
	ds.ListMDMAppleDEPSerialsInHostIDsFunc = func(ctx context.Context, hids []uint) ([]string, error) {
		return nil, nil
	}
	ds.TeamFunc = func(ctx context.Context, id uint) (*mobius.Team, error) {
		return &mobius.Team{ID: id}, nil
	}
	ds.NewActivityFunc = func(
		ctx context.Context, user *mobius.User, activity mobius.ActivityDetails, details []byte, createdAt time.Time,
	) error {
		return nil
	}

	filter := &map[string]interface{}{"label_id": expectedLabel}

	require.NoError(t, svc.AddHostsToTeamByFilter(test.UserContext(ctx, test.UserAdmin), expectedTeam, filter))
	assert.True(t, ds.ListHostsInLabelFuncInvoked)
	assert.True(t, ds.AddHostsToTeamFuncInvoked)
}

func TestAddHostsToTeamByFilterEmptyHosts(t *testing.T) {
	ds := new(mock.Store)
	svc, ctx := newTestService(t, ds, nil, nil)

	ds.ListHostsFunc = func(ctx context.Context, filter mobius.TeamFilter, opt mobius.HostListOptions) ([]*mobius.Host, error) {
		return []*mobius.Host{}, nil
	}
	ds.AddHostsToTeamFunc = func(ctx context.Context, teamID *uint, hostIDs []uint) error {
		return nil
	}
	ds.BulkSetPendingMDMHostProfilesFunc = func(ctx context.Context, hids, tids []uint, puuids, uuids []string,
	) (updates mobius.MDMProfilesUpdates, err error) {
		return mobius.MDMProfilesUpdates{}, nil
	}

	emptyFilter := &map[string]interface{}{}

	require.NoError(t, svc.AddHostsToTeamByFilter(test.UserContext(ctx, test.UserAdmin), nil, emptyFilter))
	assert.True(t, ds.ListHostsFuncInvoked)
	assert.False(t, ds.AddHostsToTeamFuncInvoked)
}

func TestRefetchHost(t *testing.T) {
	ds := new(mock.Store)
	svc, ctx := newTestService(t, ds, nil, nil)

	host := &mobius.Host{ID: 3}

	ds.HostLiteFunc = func(ctx context.Context, id uint) (*mobius.Host, error) {
		return host, nil
	}
	ds.UpdateHostRefetchRequestedFunc = func(ctx context.Context, id uint, value bool) error {
		assert.Equal(t, host.ID, id)
		assert.True(t, value)
		return nil
	}

	require.NoError(t, svc.RefetchHost(test.UserContext(ctx, test.UserAdmin), host.ID))
	require.NoError(t, svc.RefetchHost(test.UserContext(ctx, test.UserObserver), host.ID))
	require.NoError(t, svc.RefetchHost(test.UserContext(ctx, test.UserObserverPlus), host.ID))
	require.NoError(t, svc.RefetchHost(test.UserContext(ctx, test.UserMaintainer), host.ID))
	assert.True(t, ds.HostLiteFuncInvoked)
	assert.True(t, ds.UpdateHostRefetchRequestedFuncInvoked)
}

func TestRefetchHostUserInTeams(t *testing.T) {
	ds := new(mock.Store)
	svc, ctx := newTestService(t, ds, nil, nil)

	host := &mobius.Host{ID: 3, TeamID: ptr.Uint(4)}

	ds.HostLiteFunc = func(ctx context.Context, id uint) (*mobius.Host, error) {
		return host, nil
	}
	ds.UpdateHostRefetchRequestedFunc = func(ctx context.Context, id uint, value bool) error {
		assert.Equal(t, host.ID, id)
		assert.True(t, value)
		return nil
	}

	maintainer := &mobius.User{
		Teams: []mobius.UserTeam{
			{
				Team: mobius.Team{ID: 4},
				Role: mobius.RoleMaintainer,
			},
		},
	}
	require.NoError(t, svc.RefetchHost(test.UserContext(ctx, maintainer), host.ID))
	assert.True(t, ds.HostLiteFuncInvoked)
	assert.True(t, ds.UpdateHostRefetchRequestedFuncInvoked)
	ds.HostLiteFuncInvoked, ds.UpdateHostRefetchRequestedFuncInvoked = false, false

	observer := &mobius.User{
		Teams: []mobius.UserTeam{
			{
				Team: mobius.Team{ID: 4},
				Role: mobius.RoleObserver,
			},
		},
	}
	require.NoError(t, svc.RefetchHost(test.UserContext(ctx, observer), host.ID))
	assert.True(t, ds.HostLiteFuncInvoked)
	assert.True(t, ds.UpdateHostRefetchRequestedFuncInvoked)
}

func TestEmptyTeamOSVersions(t *testing.T) {
	ds := new(mock.Store)
	svc, ctx := newTestService(t, ds, nil, nil)

	testVersions := []mobius.OSVersion{{HostsCount: 1, Name: "macOS 12.1", Platform: "darwin"}}

	ds.TeamExistsFunc = func(ctx context.Context, teamID uint) (bool, error) {
		if teamID == 3 {
			return false, nil
		}
		return true, nil
	}
	ds.OSVersionsFunc = func(
		ctx context.Context, teamFilter *mobius.TeamFilter, platform *string, name *string, version *string,
	) (*mobius.OSVersions, error) {
		if *teamFilter.TeamID == 1 {
			return &mobius.OSVersions{CountsUpdatedAt: time.Now(), OSVersions: testVersions}, nil
		}
		if *teamFilter.TeamID == 4 {
			return nil, errors.New("some unknown error")
		}

		return nil, newNotFoundError()
	}

	ds.ListVulnsByOsNameAndVersionFunc = func(ctx context.Context, name, version string, includeCVSS bool) (mobius.Vulnerabilities, error) {
		return mobius.Vulnerabilities{}, nil
	}

	// team exists with stats
	vers, _, _, err := svc.OSVersions(test.UserContext(ctx, test.UserAdmin), ptr.Uint(1), ptr.String("darwin"), nil, nil, mobius.ListOptions{}, false)
	require.NoError(t, err)
	assert.Len(t, vers.OSVersions, 1)

	// team exists but no stats
	vers, _, _, err = svc.OSVersions(test.UserContext(ctx, test.UserAdmin), ptr.Uint(2), ptr.String("darwin"), nil, nil, mobius.ListOptions{}, false)
	require.NoError(t, err)
	assert.Empty(t, vers.OSVersions)

	// team does not exist
	_, _, _, err = svc.OSVersions(test.UserContext(ctx, test.UserAdmin), ptr.Uint(3), ptr.String("darwin"), nil, nil, mobius.ListOptions{}, false)
	require.Error(t, err)
	require.Contains(t, fmt.Sprint(err), "does not exist")

	// some unknown error
	_, _, _, err = svc.OSVersions(test.UserContext(ctx, test.UserAdmin), ptr.Uint(4), ptr.String("darwin"), nil, nil, mobius.ListOptions{}, false)
	require.Error(t, err)
	require.Equal(t, "some unknown error", fmt.Sprint(err))
}

func TestOSVersionsListOptions(t *testing.T) {
	ds := new(mock.Store)
	svc, ctx := newTestService(t, ds, nil, nil)

	testVersions := []mobius.OSVersion{
		{HostsCount: 4, NameOnly: "Windows 11 Pro 22H2", Platform: "windows"},
		{HostsCount: 1, NameOnly: "macOS 12.1", Platform: "darwin"},
		{HostsCount: 2, NameOnly: "macOS 12.2", Platform: "darwin"},
		{HostsCount: 3, NameOnly: "Windows 11 Pro 21H2", Platform: "windows"},
		{HostsCount: 5, NameOnly: "Ubuntu 20.04", Platform: "ubuntu"},
		{HostsCount: 6, NameOnly: "Ubuntu 21.04", Platform: "ubuntu"},
	}

	ds.OSVersionsFunc = func(
		ctx context.Context, teamFilter *mobius.TeamFilter, platform *string, name *string, version *string,
	) (*mobius.OSVersions, error) {
		return &mobius.OSVersions{CountsUpdatedAt: time.Now(), OSVersions: testVersions}, nil
	}

	ds.ListVulnsByOsNameAndVersionFunc = func(ctx context.Context, name, version string, includeCVSS bool) (mobius.Vulnerabilities, error) {
		return mobius.Vulnerabilities{}, nil
	}

	// test default descending count sort
	opts := mobius.ListOptions{}
	vers, _, _, err := svc.OSVersions(test.UserContext(ctx, test.UserAdmin), nil, nil, nil, nil, opts, false)
	require.NoError(t, err)
	assert.Len(t, vers.OSVersions, 6)
	assert.Equal(t, "Ubuntu 21.04", vers.OSVersions[0].NameOnly)
	assert.Equal(t, "Ubuntu 20.04", vers.OSVersions[1].NameOnly)
	assert.Equal(t, "Windows 11 Pro 22H2", vers.OSVersions[2].NameOnly)
	assert.Equal(t, "Windows 11 Pro 21H2", vers.OSVersions[3].NameOnly)
	assert.Equal(t, "macOS 12.2", vers.OSVersions[4].NameOnly)
	assert.Equal(t, "macOS 12.1", vers.OSVersions[5].NameOnly)

	// test ascending count sort
	opts = mobius.ListOptions{OrderKey: "hosts_count", OrderDirection: mobius.OrderAscending}
	vers, _, _, err = svc.OSVersions(test.UserContext(ctx, test.UserAdmin), nil, nil, nil, nil, opts, false)
	require.NoError(t, err)
	assert.Len(t, vers.OSVersions, 6)
	assert.Equal(t, "macOS 12.1", vers.OSVersions[0].NameOnly)
	assert.Equal(t, "macOS 12.2", vers.OSVersions[1].NameOnly)
	assert.Equal(t, "Windows 11 Pro 21H2", vers.OSVersions[2].NameOnly)
	assert.Equal(t, "Windows 11 Pro 22H2", vers.OSVersions[3].NameOnly)
	assert.Equal(t, "Ubuntu 20.04", vers.OSVersions[4].NameOnly)
	assert.Equal(t, "Ubuntu 21.04", vers.OSVersions[5].NameOnly)

	// pagination
	opts = mobius.ListOptions{Page: 0, PerPage: 2}
	vers, _, _, err = svc.OSVersions(test.UserContext(ctx, test.UserAdmin), nil, nil, nil, nil, opts, false)
	require.NoError(t, err)
	assert.Len(t, vers.OSVersions, 2)
	assert.Equal(t, "Ubuntu 21.04", vers.OSVersions[0].NameOnly)
	assert.Equal(t, "Ubuntu 20.04", vers.OSVersions[1].NameOnly)

	opts = mobius.ListOptions{Page: 1, PerPage: 2}
	vers, _, _, err = svc.OSVersions(test.UserContext(ctx, test.UserAdmin), nil, nil, nil, nil, opts, false)
	require.NoError(t, err)
	assert.Len(t, vers.OSVersions, 2)
	assert.Equal(t, "Windows 11 Pro 22H2", vers.OSVersions[0].NameOnly)
	assert.Equal(t, "Windows 11 Pro 21H2", vers.OSVersions[1].NameOnly)

	// pagination + ascending hosts_count sort
	opts = mobius.ListOptions{Page: 0, PerPage: 2, OrderKey: "hosts_count", OrderDirection: mobius.OrderAscending}
	vers, _, _, err = svc.OSVersions(test.UserContext(ctx, test.UserAdmin), nil, nil, nil, nil, opts, false)
	require.NoError(t, err)
	assert.Len(t, vers.OSVersions, 2)
	assert.Equal(t, "macOS 12.1", vers.OSVersions[0].NameOnly)
	assert.Equal(t, "macOS 12.2", vers.OSVersions[1].NameOnly)

	// per page too high
	opts = mobius.ListOptions{Page: 0, PerPage: 1000}
	vers, _, _, err = svc.OSVersions(test.UserContext(ctx, test.UserAdmin), nil, nil, nil, nil, opts, false)
	require.NoError(t, err)
	assert.Len(t, vers.OSVersions, 6)

	// Page number too high
	opts = mobius.ListOptions{Page: 1000, PerPage: 2}
	vers, _, _, err = svc.OSVersions(test.UserContext(ctx, test.UserAdmin), nil, nil, nil, nil, opts, false)
	require.NoError(t, err)
	assert.Len(t, vers.OSVersions, 0)
}

func TestHostEncryptionKey(t *testing.T) {
	cases := []struct {
		name            string
		host            *mobius.Host
		allowedUsers    []*mobius.User
		disallowedUsers []*mobius.User
	}{
		{
			name: "global host",
			host: &mobius.Host{
				ID:       1,
				Platform: "darwin",
				NodeKey:  ptr.String("test_key"),
				Hostname: "test_hostname",
				UUID:     "test_uuid",
				TeamID:   nil,
			},
			allowedUsers: []*mobius.User{
				test.UserAdmin,
				test.UserMaintainer,
				test.UserObserver,
				test.UserObserverPlus,
			},
			disallowedUsers: []*mobius.User{
				test.UserTeamAdminTeam1,
				test.UserTeamMaintainerTeam1,
				test.UserTeamObserverTeam1,
				test.UserNoRoles,
			},
		},
		{
			name: "team host",
			host: &mobius.Host{
				ID:       2,
				Platform: "darwin",
				NodeKey:  ptr.String("test_key_2"),
				Hostname: "test_hostname_2",
				UUID:     "test_uuid_2",
				TeamID:   ptr.Uint(1),
			},
			allowedUsers: []*mobius.User{
				test.UserAdmin,
				test.UserMaintainer,
				test.UserObserver,
				test.UserObserverPlus,
				test.UserTeamAdminTeam1,
				test.UserTeamMaintainerTeam1,
				test.UserTeamObserverTeam1,
				test.UserTeamObserverPlusTeam1,
			},
			disallowedUsers: []*mobius.User{
				test.UserTeamAdminTeam2,
				test.UserTeamMaintainerTeam2,
				test.UserTeamObserverTeam2,
				test.UserTeamObserverPlusTeam2,
				test.UserNoRoles,
			},
		},
	}

	testCert, testKey, err := apple_mdm.NewSCEPCACertKey()
	require.NoError(t, err)
	testCertPEM := tokenpki.PEMCertificate(testCert.Raw)
	testKeyPEM := tokenpki.PEMRSAPrivateKey(testKey)

	mobiusCfg := config.TestConfig()
	config.SetTestMDMConfig(t, &mobiusCfg, testCertPEM, testKeyPEM, "")

	recoveryKey := "AAA-BBB-CCC"
	encryptedKey, err := pkcs7.Encrypt([]byte(recoveryKey), []*x509.Certificate{testCert})
	require.NoError(t, err)
	base64EncryptedKey := base64.StdEncoding.EncodeToString(encryptedKey)

	wstep, _, _, err := mobiusCfg.MDM.MicrosoftWSTEP()
	require.NoError(t, err)
	winEncryptedKey, err := pkcs7.Encrypt([]byte(recoveryKey), []*x509.Certificate{wstep.Leaf})
	require.NoError(t, err)
	winBase64EncryptedKey := base64.StdEncoding.EncodeToString(winEncryptedKey)

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			ds := new(mock.Store)
			ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
				return &mobius.AppConfig{MDM: mobius.MDM{EnabledAndConfigured: true}}, nil
			}
			svc, ctx := newTestServiceWithConfig(t, ds, mobiusCfg, nil, nil)

			ds.HostLiteFunc = func(ctx context.Context, id uint) (*mobius.Host, error) {
				require.Equal(t, tt.host.ID, id)
				return tt.host, nil
			}

			ds.GetHostDiskEncryptionKeyFunc = func(ctx context.Context, id uint) (*mobius.HostDiskEncryptionKey, error) {
				return &mobius.HostDiskEncryptionKey{
					Base64Encrypted: base64EncryptedKey,
					Decryptable:     ptr.Bool(true),
				}, nil
			}

			ds.NewActivityFunc = func(
				ctx context.Context, user *mobius.User, activity mobius.ActivityDetails, details []byte, createdAt time.Time,
			) error {
				act := activity.(mobius.ActivityTypeReadHostDiskEncryptionKey)
				require.Equal(t, tt.host.ID, act.HostID)
				require.Equal(t, []uint{tt.host.ID}, act.HostIDs())
				require.EqualValues(t, act.HostDisplayName, tt.host.DisplayName())
				return nil
			}

			ds.GetAllMDMConfigAssetsByNameFunc = func(ctx context.Context, assetNames []mobius.MDMAssetName,
				_ sqlx.QueryerContext,
			) (map[mobius.MDMAssetName]mobius.MDMConfigAsset, error) {
				return map[mobius.MDMAssetName]mobius.MDMConfigAsset{
					mobius.MDMAssetCACert: {Name: mobius.MDMAssetCACert, Value: testCertPEM},
					mobius.MDMAssetCAKey:  {Name: mobius.MDMAssetCAKey, Value: testKeyPEM},
				}, nil
			}

			t.Run("allowed users", func(t *testing.T) {
				for _, u := range tt.allowedUsers {
					_, err := svc.HostEncryptionKey(test.UserContext(ctx, u), tt.host.ID)
					require.NoError(t, err)
				}
			})

			t.Run("disallowed users", func(t *testing.T) {
				for _, u := range tt.disallowedUsers {
					_, err := svc.HostEncryptionKey(test.UserContext(ctx, u), tt.host.ID)
					require.Error(t, err)
					require.Contains(t, authz.ForbiddenErrorMessage, err.Error())
				}
			})

			t.Run("no user in context", func(t *testing.T) {
				_, err := svc.HostEncryptionKey(ctx, tt.host.ID)
				require.Error(t, err)
				require.Contains(t, authz.ForbiddenErrorMessage, err.Error())
			})
		})
	}

	t.Run("test error cases", func(t *testing.T) {
		ds := new(mock.Store)
		ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
			return &mobius.AppConfig{MDM: mobius.MDM{EnabledAndConfigured: true}}, nil
		}
		svc, ctx := newTestServiceWithConfig(t, ds, mobiusCfg, nil, nil)
		ctx = test.UserContext(ctx, test.UserAdmin)

		hostErr := errors.New("host error")
		ds.HostLiteFunc = func(ctx context.Context, id uint) (*mobius.Host, error) {
			return nil, hostErr
		}
		_, err := svc.HostEncryptionKey(ctx, 1)
		require.ErrorIs(t, err, hostErr)
		ds.HostLiteFunc = func(ctx context.Context, id uint) (*mobius.Host, error) {
			return &mobius.Host{}, nil
		}

		keyErr := errors.New("key error")
		ds.GetHostDiskEncryptionKeyFunc = func(ctx context.Context, id uint) (*mobius.HostDiskEncryptionKey, error) {
			return nil, keyErr
		}
		ds.GetAllMDMConfigAssetsByNameFunc = func(ctx context.Context, assetNames []mobius.MDMAssetName,
			_ sqlx.QueryerContext,
		) (map[mobius.MDMAssetName]mobius.MDMConfigAsset, error) {
			return map[mobius.MDMAssetName]mobius.MDMConfigAsset{
				mobius.MDMAssetCACert: {Name: mobius.MDMAssetCACert, Value: testCertPEM},
				mobius.MDMAssetCAKey:  {Name: mobius.MDMAssetCAKey, Value: testKeyPEM},
			}, nil
		}
		_, err = svc.HostEncryptionKey(ctx, 1)
		require.ErrorIs(t, err, keyErr)
		ds.GetHostDiskEncryptionKeyFunc = func(ctx context.Context, id uint) (*mobius.HostDiskEncryptionKey, error) {
			return &mobius.HostDiskEncryptionKey{Base64Encrypted: "key"}, nil
		}

		ds.NewActivityFunc = func(
			ctx context.Context, user *mobius.User, activity mobius.ActivityDetails, details []byte, createdAt time.Time,
		) error {
			return errors.New("activity error")
		}

		_, err = svc.HostEncryptionKey(ctx, 1)
		require.Error(t, err)
	})

	t.Run("host platform mdm enabled", func(t *testing.T) {
		cases := []struct {
			hostPlatform  string
			macMDMEnabled bool
			winMDMEnabled bool
			shouldFail    bool
		}{
			{"windows", true, false, true},
			{"windows", false, true, false},
			{"windows", true, true, false},
			{"darwin", true, false, false},
			{"darwin", false, true, true},
			{"darwin", true, true, false},
		}
		for _, c := range cases {
			t.Run(fmt.Sprintf("%s: mac mdm: %t; win mdm: %t", c.hostPlatform, c.macMDMEnabled, c.winMDMEnabled), func(t *testing.T) {
				ds := new(mock.Store)
				ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
					return &mobius.AppConfig{MDM: mobius.MDM{EnabledAndConfigured: c.macMDMEnabled, WindowsEnabledAndConfigured: c.winMDMEnabled}}, nil
				}
				ds.HostLiteFunc = func(ctx context.Context, id uint) (*mobius.Host, error) {
					return &mobius.Host{Platform: c.hostPlatform}, nil
				}
				ds.GetHostDiskEncryptionKeyFunc = func(ctx context.Context, id uint) (*mobius.HostDiskEncryptionKey, error) {
					key := base64EncryptedKey
					if c.hostPlatform == "windows" {
						key = winBase64EncryptedKey
					}
					return &mobius.HostDiskEncryptionKey{
						Base64Encrypted: key,
						Decryptable:     ptr.Bool(true),
					}, nil
				}
				ds.NewActivityFunc = func(
					ctx context.Context, user *mobius.User, activity mobius.ActivityDetails, details []byte, createdAt time.Time,
				) error {
					return nil
				}
				ds.GetAllMDMConfigAssetsByNameFunc = func(ctx context.Context, assetNames []mobius.MDMAssetName,
					_ sqlx.QueryerContext,
				) (map[mobius.MDMAssetName]mobius.MDMConfigAsset, error) {
					return map[mobius.MDMAssetName]mobius.MDMConfigAsset{
						mobius.MDMAssetCACert: {Name: mobius.MDMAssetCACert, Value: testCertPEM},
						mobius.MDMAssetCAKey:  {Name: mobius.MDMAssetCAKey, Value: testKeyPEM},
					}, nil
				}

				svc, ctx := newTestServiceWithConfig(t, ds, mobiusCfg, nil, nil)
				ctx = test.UserContext(ctx, test.UserAdmin)
				_, err := svc.HostEncryptionKey(ctx, 1)
				if c.shouldFail {
					require.Error(t, err)
					if c.macMDMEnabled && !c.winMDMEnabled && c.hostPlatform == "windows" {
						require.ErrorContains(t, err, mobius.ErrWindowsMDMNotConfigured.Error())
					} else {
						require.ErrorContains(t, err, mobius.ErrMDMNotConfigured.Error())
					}
				} else {
					require.NoError(t, err)
				}
			})
		}
	})

	t.Run("Linux encryption", func(t *testing.T) {
		ds := new(mock.Store)
		host := &mobius.Host{ID: 1, Platform: "ubuntu"}
		symmetricKey := "this_is_a_32_byte_symmetric_key!"
		passphrase := "this_is_a_passphrase"
		base64EncryptedKey, err := mdm.EncryptAndEncode(passphrase, symmetricKey)
		require.NoError(t, err)

		ds.HostLiteFunc = func(ctx context.Context, id uint) (*mobius.Host, error) {
			return host, nil
		}

		ds.NewActivityFunc = func(
			ctx context.Context, user *mobius.User, activity mobius.ActivityDetails, details []byte, createdAt time.Time,
		) error {
			return nil
		}
		ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) { // needed for new activity
			return &mobius.AppConfig{}, nil
		}

		// error when no server private key
		mobiusCfg.Server.PrivateKey = ""
		svc, ctx := newTestServiceWithConfig(t, ds, mobiusCfg, nil, nil)
		ctx = test.UserContext(ctx, test.UserAdmin)
		key, err := svc.HostEncryptionKey(ctx, 1)
		require.Error(t, err, "private key is unavailable")
		require.Nil(t, key)

		// error when key is not set
		ds.GetHostDiskEncryptionKeyFunc = func(ctx context.Context, id uint) (*mobius.HostDiskEncryptionKey, error) {
			return &mobius.HostDiskEncryptionKey{}, nil
		}
		mobiusCfg.Server.PrivateKey = symmetricKey
		svc, ctx = newTestServiceWithConfig(t, ds, mobiusCfg, nil, nil)
		ctx = test.UserContext(ctx, test.UserAdmin)
		key, err = svc.HostEncryptionKey(ctx, 1)
		require.Error(t, err, "host encryption key is not set")
		require.Nil(t, key)

		// error when key is not set
		ds.GetHostDiskEncryptionKeyFunc = func(ctx context.Context, id uint) (*mobius.HostDiskEncryptionKey, error) {
			return &mobius.HostDiskEncryptionKey{
				Base64Encrypted: "thisIsWrong",
				Decryptable:     ptr.Bool(true),
			}, nil
		}
		svc, ctx = newTestServiceWithConfig(t, ds, mobiusCfg, nil, nil)
		ctx = test.UserContext(ctx, test.UserAdmin)
		key, err = svc.HostEncryptionKey(ctx, 1)
		require.Error(t, err, "decrypt host encryption key")
		require.Nil(t, key)

		// happy path
		ds.GetHostDiskEncryptionKeyFunc = func(ctx context.Context, id uint) (*mobius.HostDiskEncryptionKey, error) {
			return &mobius.HostDiskEncryptionKey{
				Base64Encrypted: base64EncryptedKey,
				Decryptable:     ptr.Bool(true),
			}, nil
		}
		svc, ctx = newTestServiceWithConfig(t, ds, mobiusCfg, nil, nil)
		ctx = test.UserContext(ctx, test.UserAdmin)
		key, err = svc.HostEncryptionKey(ctx, 1)
		require.NoError(t, err)
		require.Equal(t, passphrase, key.DecryptedValue)
	})
}

// Fragile test: This test is fragile because of the large reliance on Datastore mocks. Consider refactoring test/logic or removing the test. It may be slowing us down more than helping us.
func TestHostMDMProfileDetail(t *testing.T) {
	ds := new(mock.Store)
	testCert, testKey, err := apple_mdm.NewSCEPCACertKey()
	require.NoError(t, err)
	testCertPEM := tokenpki.PEMCertificate(testCert.Raw)
	testKeyPEM := tokenpki.PEMRSAPrivateKey(testKey)

	mobiusCfg := config.TestConfig()
	config.SetTestMDMConfig(t, &mobiusCfg, testCertPEM, testKeyPEM, "")

	svc, ctx := newTestServiceWithConfig(t, ds, mobiusCfg, nil, nil)
	ctx = test.UserContext(ctx, test.UserAdmin)

	ds.HostFunc = func(ctx context.Context, id uint) (*mobius.Host, error) {
		return &mobius.Host{
			ID:       1,
			Platform: "darwin",
		}, nil
	}
	ds.LoadHostSoftwareFunc = func(ctx context.Context, host *mobius.Host, includeCVEScores bool) error {
		return nil
	}
	ds.ListLabelsForHostFunc = func(ctx context.Context, hid uint) ([]*mobius.Label, error) {
		return nil, nil
	}
	ds.ListPacksForHostFunc = func(ctx context.Context, hid uint) ([]*mobius.Pack, error) {
		return nil, nil
	}
	ds.ListHostBatteriesFunc = func(ctx context.Context, hid uint) ([]*mobius.HostBattery, error) {
		return nil, nil
	}
	ds.ListUpcomingHostMaintenanceWindowsFunc = func(ctx context.Context, hid uint) ([]*mobius.HostMaintenanceWindow, error) {
		return nil, nil
	}
	ds.GetHostMDMMacOSSetupFunc = func(ctx context.Context, hid uint) (*mobius.HostMDMMacOSSetup, error) {
		return nil, nil
	}
	ds.GetHostLockWipeStatusFunc = func(ctx context.Context, host *mobius.Host) (*mobius.HostLockWipeStatus, error) {
		return &mobius.HostLockWipeStatus{}, nil
	}
	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		return &mobius.AppConfig{
			MDM: mobius.MDM{
				EnabledAndConfigured: true,
			},
		}, nil
	}
	ds.ScimUserByHostIDFunc = func(ctx context.Context, hostID uint) (*mobius.ScimUser, error) {
		return nil, nil
	}
	ds.ListHostDeviceMappingFunc = func(ctx context.Context, id uint) ([]*mobius.HostDeviceMapping, error) {
		return nil, nil
	}
	ds.GetNanoMDMEnrollmentTimesFunc = func(ctx context.Context, hostUUID string) (*time.Time, *time.Time, error) {
		return nil, nil, nil
	}
	ds.UpdateHostIssuesFailingPoliciesFunc = func(ctx context.Context, hostIDs []uint) error {
		return nil
	}
	ds.GetHostIssuesLastUpdatedFunc = func(ctx context.Context, hostId uint) (time.Time, error) {
		return time.Time{}, nil
	}

	cases := []struct {
		name           string
		storedDetail   string
		expectedDetail string
	}{
		{
			name:           "no detail",
			storedDetail:   "",
			expectedDetail: "",
		},
		{
			name:           "other detail",
			storedDetail:   "other detail",
			expectedDetail: "other detail",
		},
		{
			name:           "failed was verifying",
			storedDetail:   string(mobius.HostMDMProfileDetailFailedWasVerifying),
			expectedDetail: mobius.HostMDMProfileDetailFailedWasVerifying.Message(),
		},
		{
			name:           "failed was verified",
			storedDetail:   string(mobius.HostMDMProfileDetailFailedWasVerified),
			expectedDetail: mobius.HostMDMProfileDetailFailedWasVerified.Message(),
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			ds.GetHostMDMAppleProfilesFunc = func(ctx context.Context, host_uuid string) ([]mobius.HostMDMAppleProfile, error) {
				return []mobius.HostMDMAppleProfile{
					{
						Name:          "test",
						Identifier:    "test",
						OperationType: mobius.MDMOperationTypeInstall,
						Status:        &mobius.MDMDeliveryFailed,
						Detail:        tt.storedDetail,
					},
				}, nil
			}

			h, err := svc.GetHost(ctx, uint(1), mobius.HostDetailOptions{})
			require.NoError(t, err)
			require.NotNil(t, h.MDM.Profiles)
			profs := *h.MDM.Profiles
			require.Len(t, profs, 1)
			require.Equal(t, tt.expectedDetail, profs[0].Detail)
		})
	}
}

func TestLockUnlockWipeHostAuth(t *testing.T) {
	ds := new(mock.Store)
	svc, ctx := newTestService(t, ds, nil, nil, &TestServerOpts{License: &mobius.LicenseInfo{Tier: mobius.TierPremium}})

	const (
		teamHostID   = 1
		globalHostID = 2
	)

	teamHost := &mobius.Host{TeamID: ptr.Uint(1), Platform: "darwin"}
	globalHost := &mobius.Host{Platform: "darwin"}

	ds.HostByIdentifierFunc = func(ctx context.Context, identifier string) (*mobius.Host, error) {
		if identifier == fmt.Sprint(teamHostID) {
			return teamHost, nil
		}

		return globalHost, nil
	}
	ds.LoadHostSoftwareFunc = func(ctx context.Context, host *mobius.Host, includeCVEScores bool) error {
		return nil
	}
	ds.ListPacksForHostFunc = func(ctx context.Context, hid uint) (packs []*mobius.Pack, err error) {
		return nil, nil
	}
	ds.ListHostBatteriesFunc = func(ctx context.Context, id uint) ([]*mobius.HostBattery, error) {
		return nil, nil
	}
	ds.ListUpcomingHostMaintenanceWindowsFunc = func(ctx context.Context, hid uint) ([]*mobius.HostMaintenanceWindow, error) {
		return nil, nil
	}
	ds.ListPoliciesForHostFunc = func(ctx context.Context, host *mobius.Host) ([]*mobius.HostPolicy, error) {
		return nil, nil
	}
	ds.ListLabelsForHostFunc = func(ctx context.Context, hid uint) ([]*mobius.Label, error) {
		return nil, nil
	}
	ds.GetHostMDMAppleProfilesFunc = func(ctx context.Context, hostUUID string) ([]mobius.HostMDMAppleProfile, error) {
		return nil, nil
	}
	ds.GetHostMDMWindowsProfilesFunc = func(ctx context.Context, hostUUID string) ([]mobius.HostMDMWindowsProfile, error) {
		return nil, nil
	}
	ds.GetHostMDMMacOSSetupFunc = func(ctx context.Context, hostID uint) (*mobius.HostMDMMacOSSetup, error) {
		return nil, nil
	}
	ds.GetHostLockWipeStatusFunc = func(ctx context.Context, host *mobius.Host) (*mobius.HostLockWipeStatus, error) {
		return &mobius.HostLockWipeStatus{}, nil
	}
	ds.LockHostViaScriptFunc = func(ctx context.Context, request *mobius.HostScriptRequestPayload, platform string) error {
		return nil
	}
	ds.HostLiteFunc = func(ctx context.Context, hostID uint) (*mobius.Host, error) {
		if hostID == teamHostID {
			return teamHost, nil
		}
		return globalHost, nil
	}
	ds.GetMDMWindowsBitLockerStatusFunc = func(ctx context.Context, host *mobius.Host) (*mobius.HostMDMDiskEncryption, error) {
		return nil, nil
	}
	ds.GetHostMDMFunc = func(ctx context.Context, hostID uint) (*mobius.HostMDM, error) {
		return &mobius.HostMDM{Enrolled: true, Name: mobius.WellKnownMDMMobius}, nil
	}
	ds.NewActivityFunc = func(
		ctx context.Context, user *mobius.User, activity mobius.ActivityDetails, details []byte, createdAt time.Time,
	) error {
		return nil
	}
	ds.UnlockHostManuallyFunc = func(ctx context.Context, hostID uint, platform string, ts time.Time) error {
		return nil
	}
	ds.IsHostConnectedToMobiusMDMFunc = func(ctx context.Context, host *mobius.Host) (bool, error) {
		return true, nil
	}
	ds.GetNanoMDMEnrollmentTimesFunc = func(ctx context.Context, hostUUID string) (*time.Time, *time.Time, error) {
		return nil, nil, nil
	}

	cases := []struct {
		name                  string
		user                  *mobius.User
		shouldFailGlobalWrite bool
		shouldFailTeamWrite   bool
	}{
		{
			name:                  "global observer",
			user:                  &mobius.User{GlobalRole: ptr.String(mobius.RoleObserver)},
			shouldFailGlobalWrite: true,
			shouldFailTeamWrite:   true,
		},
		{
			name:                  "team observer",
			user:                  &mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleObserver}}},
			shouldFailGlobalWrite: true,
			shouldFailTeamWrite:   true,
		},
		{
			name:                  "global observer plus",
			user:                  &mobius.User{GlobalRole: ptr.String(mobius.RoleObserverPlus)},
			shouldFailGlobalWrite: true,
			shouldFailTeamWrite:   true,
		},
		{
			name:                  "team observer plus",
			user:                  &mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleObserverPlus}}},
			shouldFailGlobalWrite: true,
			shouldFailTeamWrite:   true,
		},
		{
			name:                  "global admin",
			user:                  &mobius.User{GlobalRole: ptr.String(mobius.RoleAdmin)},
			shouldFailGlobalWrite: false,
			shouldFailTeamWrite:   false,
		},
		{
			name:                  "team admin",
			user:                  &mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleAdmin}}},
			shouldFailGlobalWrite: true,
			shouldFailTeamWrite:   false,
		},
		{
			name:                  "global maintainer",
			user:                  &mobius.User{GlobalRole: ptr.String(mobius.RoleMaintainer)},
			shouldFailGlobalWrite: false,
			shouldFailTeamWrite:   false,
		},
		{
			name:                  "team maintainer",
			user:                  &mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleMaintainer}}},
			shouldFailGlobalWrite: true,
			shouldFailTeamWrite:   false,
		},
		{
			name:                  "team admin wrong team",
			user:                  &mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 42}, Role: mobius.RoleAdmin}}},
			shouldFailGlobalWrite: true,
			shouldFailTeamWrite:   true,
		},
		{
			name:                  "team maintainer wrong team",
			user:                  &mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 42}, Role: mobius.RoleMaintainer}}},
			shouldFailGlobalWrite: true,
			shouldFailTeamWrite:   true,
		},
		{
			name:                  "global gitops",
			user:                  &mobius.User{GlobalRole: ptr.String(mobius.RoleGitOps)},
			shouldFailGlobalWrite: true,
			shouldFailTeamWrite:   true,
		},
		{
			name:                  "team gitops",
			user:                  &mobius.User{Teams: []mobius.UserTeam{{Team: mobius.Team{ID: 1}, Role: mobius.RoleGitOps}}},
			shouldFailGlobalWrite: true,
			shouldFailTeamWrite:   true,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
				return &mobius.AppConfig{
					MDM:            mobius.MDM{EnabledAndConfigured: true, WindowsEnabledAndConfigured: true},
					ServerSettings: mobius.ServerSettings{ScriptsDisabled: true}, // scripts being disabled shouldn't stop lock/unlock/wipe
				}, nil
			}
			ctx := viewer.NewContext(ctx, viewer.Viewer{User: tt.user})

			_, err := svc.LockHost(ctx, globalHostID, false)
			checkAuthErr(t, tt.shouldFailGlobalWrite, err)
			_, err = svc.LockHost(ctx, teamHostID, false)
			checkAuthErr(t, tt.shouldFailTeamWrite, err)

			// Pretend we locked the host
			ds.GetHostLockWipeStatusFunc = func(ctx context.Context, host *mobius.Host) (*mobius.HostLockWipeStatus, error) {
				return &mobius.HostLockWipeStatus{HostMobiusPlatform: host.MobiusPlatform(), LockMDMCommand: &mobius.MDMCommand{}, LockMDMCommandResult: &mobius.MDMCommandResult{Status: mobius.MDMAppleStatusAcknowledged}}, nil
			}

			_, err = svc.UnlockHost(ctx, globalHostID)
			checkAuthErr(t, tt.shouldFailGlobalWrite, err)
			_, err = svc.UnlockHost(ctx, teamHostID)
			checkAuthErr(t, tt.shouldFailTeamWrite, err)

			// Reset so we're now pretending host is unlocked
			ds.GetHostLockWipeStatusFunc = func(ctx context.Context, host *mobius.Host) (*mobius.HostLockWipeStatus, error) {
				return &mobius.HostLockWipeStatus{}, nil
			}

			err = svc.WipeHost(ctx, globalHostID, nil)
			checkAuthErr(t, tt.shouldFailGlobalWrite, err)
			err = svc.WipeHost(ctx, teamHostID, nil)
			checkAuthErr(t, tt.shouldFailTeamWrite, err)
		})
	}
}

func TestBulkOperationFilterValidation(t *testing.T) {
	ds := new(mock.Store)
	svc, ctx := newTestService(t, ds, nil, nil)
	viewerCtx := test.UserContext(ctx, test.UserAdmin)

	ds.ListHostsFunc = func(ctx context.Context, filter mobius.TeamFilter, opt mobius.HostListOptions) ([]*mobius.Host, error) {
		return []*mobius.Host{}, nil
	}

	ds.ListHostsInLabelFunc = func(ctx context.Context, filter mobius.TeamFilter, lid uint, opt mobius.HostListOptions) ([]*mobius.Host, error) {
		return []*mobius.Host{}, nil
	}

	// TODO(sarah): Future improvement to auto-generate a list of all possible filter values
	// from `mobius.HostListOptions` and iterate to test that only a limited subset of filter (i.e.
	// label_id, team_id, status, query) are allowed for bulk operations.
	tc := []struct {
		name      string
		filters   *map[string]interface{}
		has400Err bool
	}{
		{
			name: "valid status filter",
			filters: &map[string]interface{}{
				"status": "new",
			},
		},
		{
			name: "invalid status",
			filters: &map[string]interface{}{
				"status": "invalid",
			},
			has400Err: true,
		},
		{
			name: "empty status is invalid",
			filters: &map[string]interface{}{
				"status": "",
			},
			has400Err: true,
		},

		{
			name: "valid team filter",
			filters: &map[string]interface{}{
				"team_id": float64(1), // json unmarshals to float64
			},
		},
		{
			name: "invalid team_id type",
			filters: &map[string]interface{}{
				"team_id": "invalid",
			},
			has400Err: true,
		},
		{
			name: "valid label_id filter",
			filters: &map[string]interface{}{
				"label_id": float64(1),
			},
		},
		{
			name: "invalid label_id type",
			filters: &map[string]interface{}{
				"label_id": "invalid",
			},
			has400Err: true,
		},

		{
			name: "invalid status type",
			filters: &map[string]interface{}{
				"status": float64(1),
			},
			has400Err: true,
		},
		{
			name:    "empty filter",
			filters: &map[string]interface{}{},
		},
		{
			name: "valid query filter",
			filters: &map[string]interface{}{
				"query": "test",
			},
		},
		{
			name: "invalid query type",
			filters: &map[string]interface{}{
				"query": float64(1),
			},
			has400Err: true,
		},
		{
			name: "empty query is invalid",
			filters: &map[string]interface{}{
				"query": "",
			},
			has400Err: true,
		},
		{
			name: "multiple valid filters",
			filters: &map[string]interface{}{
				"status":  "new",
				"team_id": float64(1),
				"query":   "test",
			},
		},
		{
			name: "mixed valid and invalid filters",
			filters: &map[string]interface{}{
				"status":  "new",
				"team_id": "invalid",
			},
			has400Err: true,
		},
		{
			name: "mixed invalid filters and valid filters (different order)",
			filters: &map[string]interface{}{
				"status":  "invalid",
				"team_id": 1,
			},
			has400Err: true,
		},
		{
			name: "mixed valid and unknown filters",
			filters: &map[string]interface{}{
				"status":  "new",
				"unknown": "filter",
			},
			has400Err: true,
		},
		{
			name: "unknown filter",
			filters: &map[string]interface{}{
				"unknown": "filter",
			},
			has400Err: true,
		},
	}

	checkErr := func(t *testing.T, err error, has400Err bool) {
		if has400Err {
			require.Error(t, err)
			var be *mobius.BadRequestError
			require.ErrorAs(t, err, &be)
		} else {
			require.NoError(t, err)
		}
	}

	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			checkErr(t, svc.AddHostsToTeamByFilter(viewerCtx, nil, tt.filters), tt.has400Err)
			checkErr(t, svc.DeleteHosts(viewerCtx, nil, tt.filters), tt.has400Err)
		})
	}
}

func TestSetDiskEncryptionNotifications(t *testing.T) {
	ds := new(mock.Store)
	ctx := context.Background()
	svc := &Service{ds: ds, logger: kitlog.NewNopLogger()}

	tests := []struct {
		name                     string
		host                     *mobius.Host
		appConfig                *mobius.AppConfig
		diskEncryptionConfigured bool
		isConnectedToMobiusMDM    bool
		mdmInfo                  *mobius.HostMDM
		getHostDiskEncryptionKey func(context.Context, uint) (*mobius.HostDiskEncryptionKey, error)
		expectedNotifications    *mobius.OrbitConfigNotifications
		expectedError            bool
		disableCapability        bool
	}{
		{
			name: "no MDM configured",
			host: &mobius.Host{ID: 1, Platform: "darwin", OsqueryHostID: ptr.String("foo")},
			appConfig: &mobius.AppConfig{
				MDM: mobius.MDM{EnabledAndConfigured: false},
			},
			diskEncryptionConfigured: true,
			isConnectedToMobiusMDM:    true,
			mdmInfo:                  nil,
			getHostDiskEncryptionKey: nil,
			expectedNotifications:    &mobius.OrbitConfigNotifications{},
			expectedError:            false,
		},
		{
			name: "not connected to Mobius MDM",
			host: &mobius.Host{ID: 1, Platform: "darwin", OsqueryHostID: ptr.String("foo")},
			appConfig: &mobius.AppConfig{
				MDM: mobius.MDM{EnabledAndConfigured: true},
			},
			diskEncryptionConfigured: true,
			isConnectedToMobiusMDM:    false,
			mdmInfo:                  nil,
			getHostDiskEncryptionKey: nil,
			expectedNotifications:    &mobius.OrbitConfigNotifications{},
			expectedError:            false,
		},
		{
			name: "host not enrolled in osquery",
			host: &mobius.Host{ID: 1, Platform: "darwin", OsqueryHostID: nil},
			appConfig: &mobius.AppConfig{
				MDM: mobius.MDM{EnabledAndConfigured: true},
			},
			diskEncryptionConfigured: true,
			isConnectedToMobiusMDM:    true,
			mdmInfo:                  nil,
			getHostDiskEncryptionKey: nil,
			expectedNotifications:    &mobius.OrbitConfigNotifications{},
			expectedError:            false,
		},
		{
			name: "disk encryption not configured",
			host: &mobius.Host{ID: 1, Platform: "darwin", OsqueryHostID: ptr.String("foo")},
			appConfig: &mobius.AppConfig{
				MDM: mobius.MDM{EnabledAndConfigured: true},
			},
			diskEncryptionConfigured: false,
			isConnectedToMobiusMDM:    true,
			mdmInfo:                  nil,
			getHostDiskEncryptionKey: nil,
			expectedNotifications:    &mobius.OrbitConfigNotifications{},
			expectedError:            false,
		},
		{
			name: "darwin with decryptable key",
			host: &mobius.Host{ID: 1, Platform: "darwin", OsqueryHostID: ptr.String("foo")},
			appConfig: &mobius.AppConfig{
				MDM: mobius.MDM{EnabledAndConfigured: true},
			},
			diskEncryptionConfigured: true,
			isConnectedToMobiusMDM:    true,
			mdmInfo:                  nil,
			getHostDiskEncryptionKey: func(ctx context.Context, id uint) (*mobius.HostDiskEncryptionKey, error) {
				return &mobius.HostDiskEncryptionKey{Decryptable: ptr.Bool(true)}, nil
			},
			expectedNotifications: &mobius.OrbitConfigNotifications{
				RotateDiskEncryptionKey: false,
			},
			expectedError: false,
		},
		{
			name: "darwin needs rotation but client is old",
			host: &mobius.Host{ID: 1, Platform: "darwin", OsqueryHostID: ptr.String("foo")},
			appConfig: &mobius.AppConfig{
				MDM: mobius.MDM{EnabledAndConfigured: true},
			},
			diskEncryptionConfigured: true,
			isConnectedToMobiusMDM:    true,
			mdmInfo:                  nil,
			getHostDiskEncryptionKey: func(ctx context.Context, id uint) (*mobius.HostDiskEncryptionKey, error) {
				return &mobius.HostDiskEncryptionKey{Decryptable: ptr.Bool(false)}, nil
			},
			expectedNotifications: &mobius.OrbitConfigNotifications{
				RotateDiskEncryptionKey: true,
			},
			expectedError:     false,
			disableCapability: true,
		},
		{
			name: "darwin needs rotation",
			host: &mobius.Host{ID: 1, Platform: "darwin", OsqueryHostID: ptr.String("foo")},
			appConfig: &mobius.AppConfig{
				MDM: mobius.MDM{EnabledAndConfigured: true},
			},
			diskEncryptionConfigured: true,
			isConnectedToMobiusMDM:    true,
			mdmInfo:                  nil,
			getHostDiskEncryptionKey: func(ctx context.Context, id uint) (*mobius.HostDiskEncryptionKey, error) {
				return &mobius.HostDiskEncryptionKey{Decryptable: ptr.Bool(false)}, nil
			},
			expectedNotifications: &mobius.OrbitConfigNotifications{
				RotateDiskEncryptionKey: true,
			},
			expectedError: false,
		},
		{
			name: "windows server with no encryption needed",
			host: &mobius.Host{ID: 1, Platform: "windows", DiskEncryptionEnabled: ptr.Bool(true), OsqueryHostID: ptr.String("foo")},
			appConfig: &mobius.AppConfig{
				MDM: mobius.MDM{EnabledAndConfigured: true},
			},
			diskEncryptionConfigured: true,
			isConnectedToMobiusMDM:    true,
			mdmInfo:                  &mobius.HostMDM{IsServer: true},
			getHostDiskEncryptionKey: func(ctx context.Context, id uint) (*mobius.HostDiskEncryptionKey, error) {
				return nil, newNotFoundError()
			},
			expectedNotifications: &mobius.OrbitConfigNotifications{
				EnforceBitLockerEncryption: false,
			},
			expectedError: false,
		},
		{
			name: "windows with encryption enabled but key missing",
			host: &mobius.Host{ID: 1, Platform: "windows", DiskEncryptionEnabled: ptr.Bool(true), OsqueryHostID: ptr.String("foo")},
			appConfig: &mobius.AppConfig{
				MDM: mobius.MDM{EnabledAndConfigured: true},
			},
			diskEncryptionConfigured: true,
			isConnectedToMobiusMDM:    true,
			mdmInfo:                  &mobius.HostMDM{IsServer: false},
			getHostDiskEncryptionKey: func(ctx context.Context, id uint) (*mobius.HostDiskEncryptionKey, error) {
				return nil, newNotFoundError()
			},
			expectedNotifications: &mobius.OrbitConfigNotifications{
				EnforceBitLockerEncryption: true,
			},
			expectedError: false,
		},
		{
			name: "darwin with missing encryption key",
			host: &mobius.Host{ID: 1, Platform: "darwin", OsqueryHostID: ptr.String("foo")},
			appConfig: &mobius.AppConfig{
				MDM: mobius.MDM{EnabledAndConfigured: true},
			},
			diskEncryptionConfigured: true,
			isConnectedToMobiusMDM:    true,
			mdmInfo:                  nil,
			getHostDiskEncryptionKey: func(ctx context.Context, id uint) (*mobius.HostDiskEncryptionKey, error) {
				return nil, newNotFoundError()
			},
			expectedNotifications: &mobius.OrbitConfigNotifications{
				RotateDiskEncryptionKey: false,
			},
			expectedError: false,
		},
		{
			name: "windows with encryption key and not decryptable",
			host: &mobius.Host{ID: 1, Platform: "windows", DiskEncryptionEnabled: ptr.Bool(true), OsqueryHostID: ptr.String("foo")},
			appConfig: &mobius.AppConfig{
				MDM: mobius.MDM{EnabledAndConfigured: true},
			},
			diskEncryptionConfigured: true,
			isConnectedToMobiusMDM:    true,
			mdmInfo:                  &mobius.HostMDM{IsServer: false},
			getHostDiskEncryptionKey: func(ctx context.Context, id uint) (*mobius.HostDiskEncryptionKey, error) {
				return &mobius.HostDiskEncryptionKey{Decryptable: ptr.Bool(false)}, nil
			},
			expectedNotifications: &mobius.OrbitConfigNotifications{
				EnforceBitLockerEncryption: true,
			},
			expectedError: false,
		},
		{
			name: "windows with enforce BitLocker",
			host: &mobius.Host{ID: 1, Platform: "windows", DiskEncryptionEnabled: ptr.Bool(false), OsqueryHostID: ptr.String("foo")},
			appConfig: &mobius.AppConfig{
				MDM: mobius.MDM{EnabledAndConfigured: true},
			},
			diskEncryptionConfigured: true,
			isConnectedToMobiusMDM:    true,
			mdmInfo:                  &mobius.HostMDM{IsServer: false},
			getHostDiskEncryptionKey: func(ctx context.Context, id uint) (*mobius.HostDiskEncryptionKey, error) {
				return nil, newNotFoundError()
			},
			expectedNotifications: &mobius.OrbitConfigNotifications{
				EnforceBitLockerEncryption: true,
			},
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.getHostDiskEncryptionKey != nil {
				ds.GetHostDiskEncryptionKeyFunc = tt.getHostDiskEncryptionKey
			}
			ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
				return tt.appConfig, nil
			}

			if !tt.disableCapability {
				r := http.Request{
					Header: http.Header{mobius.CapabilitiesHeader: []string{string(mobius.CapabilityEscrowBuddy)}},
				}
				ctx = capabilities.NewContext(ctx, &r)
			}

			notifs := &mobius.OrbitConfigNotifications{}
			err := svc.setDiskEncryptionNotifications(ctx, notifs, tt.host, tt.appConfig, tt.diskEncryptionConfigured, tt.isConnectedToMobiusMDM, tt.mdmInfo)
			if tt.expectedError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tt.expectedNotifications.RotateDiskEncryptionKey, notifs.RotateDiskEncryptionKey)
		})
	}
}
