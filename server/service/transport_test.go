package service

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/notawar/mobius/server/ptr"

	"github.com/notawar/mobius/server/mobius"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListOptionsFromRequest(t *testing.T) {
	listOptionsTests := []struct {
		// url string to parse
		url string
		// expected list options
		listOptions mobius.ListOptions
		// should cause a BadRequest error
		shouldErr400 bool
	}{
		// both params provided
		{
			url:         "/foo?page=1&per_page=10",
			listOptions: mobius.ListOptions{Page: 1, PerPage: 10},
		},
		// only per_page (page should default to 0)
		{
			url:         "/foo?per_page=10",
			listOptions: mobius.ListOptions{Page: 0, PerPage: 10},
		},
		// only page (per_page should default to defaultPerPage
		{
			url:         "/foo?page=10",
			listOptions: mobius.ListOptions{Page: 10, PerPage: defaultPerPage},
		},
		// no params provided (defaults to empty ListOptions indicating
		// unlimited)
		{
			url:         "/foo?unrelated=foo",
			listOptions: mobius.ListOptions{},
		},

		// Both order params provided
		{
			url:         "/foo?order_key=foo&order_direction=desc",
			listOptions: mobius.ListOptions{OrderKey: "foo", OrderDirection: mobius.OrderDescending},
		},
		// Both order params provided (asc)
		{
			url:         "/foo?order_key=bar&order_direction=asc",
			listOptions: mobius.ListOptions{OrderKey: "bar", OrderDirection: mobius.OrderAscending},
		},
		// Default order direction
		{
			url:         "/foo?order_key=foo",
			listOptions: mobius.ListOptions{OrderKey: "foo", OrderDirection: mobius.OrderAscending},
		},

		// All params defined
		{
			url: "/foo?order_key=foo&order_direction=desc&page=1&per_page=100&after=bar",
			listOptions: mobius.ListOptions{
				OrderKey:       "foo",
				OrderDirection: mobius.OrderDescending,
				Page:           1,
				PerPage:        100,
				After:          "bar",
			},
		},

		// various 400 error cases
		{
			url:          "/foo?page=foo&per_page=10",
			shouldErr400: true,
		},
		{
			url:          "/foo?page=1&per_page=foo",
			shouldErr400: true,
		},
		{
			url:          "/foo?page=-1",
			shouldErr400: true,
		},
		{
			url:          "/foo?page=1&per_page=-10",
			shouldErr400: true,
		},
		// order_direction without order_key
		{
			url:          "/foo?page=1&order_direction=desc",
			shouldErr400: true,
		},
		// bad order_direction
		{
			url:          "/foo?&order_direction=foo&order_key=foo",
			shouldErr400: true,
		},
		// after without order_key
		{
			url:          "/foo?page=1&after=foo",
			shouldErr400: true,
		},
	}

	for _, tt := range listOptionsTests {
		t.Run(
			tt.url, func(t *testing.T) {
				urlStruct, _ := url.Parse(tt.url)
				req := &http.Request{URL: urlStruct}
				opt, err := listOptionsFromRequest(req)

				if tt.shouldErr400 {
					assert.NotNil(t, err)
					var be *mobius.BadRequestError
					require.ErrorAs(t, err, &be)
					return
				}

				assert.Nil(t, err)
				assert.Equal(t, tt.listOptions, opt)
			},
		)
	}
}

func TestHostListOptionsFromRequest(t *testing.T) {
	verified := mobius.OSSettingsVerified
	hostListOptionsTests := map[string]struct {
		// url string to parse
		url string
		// expected options
		hostListOptions mobius.HostListOptions
		// expected error message, if any
		errorMessage string
	}{
		"no params passed": {
			url:             "/foo",
			hostListOptions: mobius.HostListOptions{},
		},
		"embedded list options params defined": {
			url: "/foo?order_key=foo&order_direction=desc&page=1&per_page=100",
			hostListOptions: mobius.HostListOptions{
				ListOptions: mobius.ListOptions{
					OrderKey:       "foo",
					OrderDirection: mobius.OrderDescending,
					Page:           1,
					PerPage:        100,
				},
			},
		},
		"all params defined": {
			url: "/foo?order_key=foo&order_direction=asc&page=10&per_page=1&device_mapping=T&additional_info_filters" +
				"=filter1,filter2&status=new&team_id=2&policy_id=3&policy_response=passing&software_id=4&os_id=5" +
				"&os_name=osName&os_version=osVersion&os_version_id=5&disable_failing_policies=0&disable_issues=1&macos_settings=verified" +
				"&macos_settings_disk_encryption=enforcing&os_settings=pending&os_settings_disk_encryption=failed" +
				"&bootstrap_package=installed&mdm_id=6&mdm_name=mdmName&mdm_enrollment_status=automatic" +
				"&munki_issue_id=7&low_disk_space=99&vulnerability=CVE-2023-42887&populate_policies=true&profile_uuid=123-abc&profile_status=verified" +
				"&script_batch_execution_id=some-cool-batch-script-execution-id&script_batch_execution_status=pending",
			hostListOptions: mobius.HostListOptions{
				ListOptions: mobius.ListOptions{
					OrderKey:       "foo",
					OrderDirection: mobius.OrderAscending,
					Page:           10,
					PerPage:        1,
				},
				DeviceMapping:                     true,
				AdditionalFilters:                 []string{"filter1", "filter2"},
				StatusFilter:                      mobius.StatusNew,
				TeamFilter:                        ptr.Uint(2),
				PolicyIDFilter:                    ptr.Uint(3),
				PolicyResponseFilter:              ptr.Bool(true),
				SoftwareIDFilter:                  ptr.Uint(4),
				OSIDFilter:                        ptr.Uint(5),
				OSVersionIDFilter:                 ptr.Uint(5),
				OSNameFilter:                      ptr.String("osName"),
				OSVersionFilter:                   ptr.String("osVersion"),
				DisableIssues:                     true,
				MacOSSettingsFilter:               mobius.OSSettingsVerified,
				MacOSSettingsDiskEncryptionFilter: mobius.DiskEncryptionEnforcing,
				OSSettingsFilter:                  mobius.OSSettingsPending,
				OSSettingsDiskEncryptionFilter:    mobius.DiskEncryptionFailed,
				MDMBootstrapPackageFilter:         (*mobius.MDMBootstrapPackageStatus)(ptr.String(string(mobius.MDMBootstrapPackageInstalled))),
				MDMIDFilter:                       ptr.Uint(6),
				MDMNameFilter:                     ptr.String("mdmName"),
				MDMEnrollmentStatusFilter:         mobius.MDMEnrollStatusAutomatic,
				MunkiIssueIDFilter:                ptr.Uint(7),
				LowDiskSpaceFilter:                ptr.Int(99),
				VulnerabilityFilter:               ptr.String("CVE-2023-42887"),
				PopulatePolicies:                  true,
				ProfileUUIDFilter:                 ptr.String("123-abc"),
				ProfileStatusFilter:               &verified,
				BatchScriptExecutionStatusFilter:  mobius.BatchScriptExecutionPending,
				BatchScriptExecutionIDFilter:      ptr.String("some-cool-batch-script-execution-id"),
			},
		},
		"policy_id and policy_response params (for coverage)": {
			url: "/foo?policy_id=100&policy_response=failing",
			hostListOptions: mobius.HostListOptions{
				PolicyIDFilter:       ptr.Uint(100),
				PolicyResponseFilter: ptr.Bool(false),
			},
		},
		"error in page (embedded list options)": {
			url:          "/foo?page=-1",
			errorMessage: "negative page value",
		},
		"error in status": {
			url:          "/foo?status=foo",
			errorMessage: "Invalid status",
		},
		"error in team_id (number too large)": {
			url:          "/foo?team_id=9,223,372,036,854,775,808",
			errorMessage: "Invalid team_id",
		},
		"error in team_id (not a number)": {
			url:          "/foo?team_id=foo",
			errorMessage: "Invalid team_id",
		},
		"error in policy_id": {
			url:          "/foo?policy_id=foo",
			errorMessage: "Invalid policy_id",
		},
		"error when policy_response specified without policy_id": {
			url:          "/foo?policy_response=passing",
			errorMessage: "Missing policy_id",
		},
		"error in policy_response (invalid option)": {
			url:          "/foo?policy_id=1&policy_response=foo",
			errorMessage: "Invalid policy_response",
		},
		"error in software_id": {
			url:          "/foo?software_id=foo",
			errorMessage: "Invalid software_id",
		},
		"error in os_id": {
			url:          "/foo?os_id=foo",
			errorMessage: "Invalid os_id",
		},
		"error in disable_failing_policies": {
			url:          "/foo?disable_failing_policies=foo",
			errorMessage: "Invalid disable_failing_policies",
		},
		"error in disable_issues": {
			url:          "/foo?disable_issues=foo",
			errorMessage: "Invalid disable_issues",
		},
		"error in issues order key when disable_issues is set": {
			url:          "/foo?disable_issues=true&order_key=issues",
			errorMessage: "Invalid order_key",
		},
		"error in issues order key when disable_failing_policies is set": {
			url:          "/foo?disable_failing_policies=true&order_key=issues",
			errorMessage: "Invalid order_key",
		},
		"error in device_mapping": {
			url:          "/foo?device_mapping=foo",
			errorMessage: "Invalid device_mapping",
		},
		"error in mdm_id": {
			url:          "/foo?mdm_id=foo",
			errorMessage: "Invalid mdm_id",
		},
		"error in mdm_enrollment_status (invalid option)": {
			url:          "/foo?mdm_enrollment_status=foo",
			errorMessage: "Invalid mdm_enrollment_status",
		},
		"error in macos_settings (invalid option)": {
			url:          "/foo?macos_settings=foo",
			errorMessage: "Invalid macos_settings",
		},
		"error in macos_settings_disk_encryption (invalid option)": {
			url:          "/foo?macos_settings_disk_encryption=foo",
			errorMessage: "Invalid macos_settings_disk_encryption",
		},
		"error in os_settings (invalid option)": {
			url:          "/foo?os_settings=foo",
			errorMessage: "Invalid os_settings",
		},
		"error in os_settings_disk_encryption (invalid option)": {
			url:          "/foo?os_settings_disk_encryption=foo",
			errorMessage: "Invalid os_settings_disk_encryption",
		},
		"error in bootstrap_package (invalid option)": {
			url:          "/foo?bootstrap_package=foo",
			errorMessage: "Invalid bootstrap_package",
		},
		"error in munki_issue_id": {
			url:          "/foo?munki_issue_id=foo",
			errorMessage: "Invalid munki_issue_id",
		},
		"error in low_disk_space (not a number)": {
			url:          "/foo?low_disk_space=foo",
			errorMessage: "Invalid low_disk_space",
		},
		"error in low_disk_space (too low)": {
			url:          "/foo?low_disk_space=0",
			errorMessage: "Invalid low_disk_space",
		},
		"error in low_disk_space (too high)": {
			url:          "/foo?low_disk_space=101",
			errorMessage: "Invalid low_disk_space",
		},
		"error in os_name/os_version (os_name missing)": {
			url:          "/foo?os_version=1.0",
			errorMessage: "Invalid os_name",
		},
		"error in os_name/os_version (os_version missing)": {
			url:          "/foo?os_name=foo",
			errorMessage: "Invalid os_version",
		},
		"error in script_batch_execution_status": {
			url:          "/foo?script_batch_execution_id=abc123&script_batch_execution_status=foo",
			errorMessage: "Invalid script_batch_execution_status: foo",
		},
		"negative software_id": {
			url:          "/foo?software_id=-10",
			errorMessage: "Invalid software_id",
		},
		"negative software_version_id": {
			url:          "/foo?software_version_id=-10",
			errorMessage: "Invalid software_version_id",
		},
		"negative software_title_id": {
			url:          "/foo?software_title_id=-10",
			errorMessage: "Invalid software_title_id",
		},
		"software_title_id too big": {
			url:          "/foo?software_title_id=" + fmt.Sprint(1<<33),
			errorMessage: "Invalid software_title_id",
		},
		"software_version_id can be > 32bits": {
			url: "/foo?software_version_id=" + fmt.Sprint(1<<33),
			hostListOptions: mobius.HostListOptions{
				SoftwareVersionIDFilter: ptr.Uint(1 << 33),
			},
		},
		"good software_version_id": {
			url: "/foo?software_version_id=1",
			hostListOptions: mobius.HostListOptions{
				SoftwareVersionIDFilter: ptr.Uint(1),
			},
		},
		"good software_title_id": {
			url: "/foo?software_title_id=1",
			hostListOptions: mobius.HostListOptions{
				SoftwareTitleIDFilter: ptr.Uint(1),
			},
		},
		"invalid combination software_title_id and software_version_id": {
			url:          "/foo?software_title_id=1&software_version_id=2",
			errorMessage: "The combination of software_version_id and software_title_id is not allowed",
		},
		"invalid combination software_id and software_version_id": {
			url:          "/foo?software_id=1&software_version_id=2",
			errorMessage: "The combination of software_id and software_version_id is not allowed",
		},
		"invalid populate_policies": {
			url:          "/foo?populate_policies=foo",
			errorMessage: "populate_policies",
		},
		"invalid combination profile_uuid wihtout profile_status": {
			url: "/foo?profile_uuid=123-abc",
			hostListOptions: mobius.HostListOptions{
				ProfileUUIDFilter: ptr.String("123-abc"),
			},
			errorMessage: "Missing profile_status (it must be present when profile_uuid is specified)",
		},
		"invalid combination profile_status wihtout profile_uuid": {
			url: "/foo?profile_status=verified",
			hostListOptions: mobius.HostListOptions{
				ProfileStatusFilter: &verified,
			},
			errorMessage: "Missing profile_uuid (it must be present when profile_status is specified)",
		},
	}

	for name, tt := range hostListOptionsTests {
		t.Run(
			name, func(t *testing.T) {
				urlStruct, _ := url.Parse(tt.url)
				req := &http.Request{URL: urlStruct}
				opt, err := hostListOptionsFromRequest(req)

				if tt.errorMessage != "" {
					assert.NotNil(t, err)
					var be *mobius.BadRequestError
					require.ErrorAs(t, err, &be)
					require.Contains(t, err.Error(), tt.errorMessage)
					return
				}
				assert.Nil(t, err)
				assert.Equal(t, tt.hostListOptions, opt)
			},
		)
	}
}

func TestCarveListOptionsFromRequest(t *testing.T) {
	carveListOptionsTests := map[string]struct {
		// url string to parse
		url string
		// expected options
		carveListOptions mobius.CarveListOptions
		// expected error message, if any
		errorMessage string
	}{
		"no params passed": {
			url:              "/foo",
			carveListOptions: mobius.CarveListOptions{},
		},
		"embedded list options params defined": {
			url: "/foo?order_key=foo&order_direction=desc&page=1&per_page=100",
			carveListOptions: mobius.CarveListOptions{
				ListOptions: mobius.ListOptions{
					OrderKey:       "foo",
					OrderDirection: mobius.OrderDescending,
					Page:           1,
					PerPage:        100,
				},
			},
		},
		"all params defined": {
			url: "/foo?order_key=foo&order_direction=asc&page=10&per_page=1&expired=true",
			carveListOptions: mobius.CarveListOptions{
				ListOptions: mobius.ListOptions{
					OrderKey:       "foo",
					OrderDirection: mobius.OrderAscending,
					Page:           10,
					PerPage:        1,
				},
				Expired: true,
			},
		},
		"error in page (embedded list options)": {
			url:          "/foo?page=-1",
			errorMessage: "negative page value",
		},
		"error in expired": {
			url:          "/foo?expired=foo",
			errorMessage: "Invalid expired",
		},
	}

	for name, tt := range carveListOptionsTests {
		t.Run(
			name, func(t *testing.T) {
				urlStruct, _ := url.Parse(tt.url)
				req := &http.Request{URL: urlStruct}
				opt, err := carveListOptionsFromRequest(req)

				if tt.errorMessage != "" {
					assert.NotNil(t, err)
					var be *mobius.BadRequestError
					require.ErrorAs(t, err, &be)
					assert.True(
						t, strings.Contains(err.Error(), tt.errorMessage),
						"error message '%v' should contain '%v'", err.Error(), tt.errorMessage,
					)
					return
				}
				assert.Nil(t, err)
				assert.Equal(t, tt.carveListOptions, opt)
			},
		)
	}
}

func TestUserListOptionsFromRequest(t *testing.T) {
	userListOptionsTests := map[string]struct {
		// url string to parse
		url string
		// expected options
		userListOptions mobius.UserListOptions
		// expected error message, if any
		errorMessage string
	}{
		"no params passed": {
			url:             "/foo",
			userListOptions: mobius.UserListOptions{},
		},
		"embedded list options params defined": {
			url: "/foo?order_key=foo&order_direction=desc&page=1&per_page=100",
			userListOptions: mobius.UserListOptions{
				ListOptions: mobius.ListOptions{
					OrderKey:       "foo",
					OrderDirection: mobius.OrderDescending,
					Page:           1,
					PerPage:        100,
				},
			},
		},
		"all params defined": {
			url: "/foo?order_key=foo&order_direction=asc&page=10&per_page=1&team_id=1",
			userListOptions: mobius.UserListOptions{
				ListOptions: mobius.ListOptions{
					OrderKey:       "foo",
					OrderDirection: mobius.OrderAscending,
					Page:           10,
					PerPage:        1,
				},
				TeamID: 1,
			},
		},
		"error in page (embedded list options)": {
			url:          "/foo?page=-1",
			errorMessage: "negative page value",
		},
		"error in team_id (negative_number)": {
			url:          "/foo?team_id=-1",
			errorMessage: "Invalid team_id",
		},
		"error in team_id (not a number)": {
			url:          "/foo?team_id=foo",
			errorMessage: "Invalid team_id",
		},
	}

	for name, tt := range userListOptionsTests {
		t.Run(
			name, func(t *testing.T) {
				urlStruct, _ := url.Parse(tt.url)
				req := &http.Request{URL: urlStruct}
				opt, err := userListOptionsFromRequest(req)

				if tt.errorMessage != "" {
					assert.NotNil(t, err)
					var be *mobius.BadRequestError
					require.ErrorAs(t, err, &be)
					assert.True(
						t, strings.Contains(err.Error(), tt.errorMessage),
						"error message '%v' should contain '%v'", err.Error(), tt.errorMessage,
					)
					return
				}
				assert.Nil(t, err)
				assert.Equal(t, tt.userListOptions, opt)
			},
		)
	}
}
