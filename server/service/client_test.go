//go:build enterprise
// +build enterprise

package service

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/notawar/mobius/pkg/optjson"
	"github.com/notawar/mobius/pkg/spec"
	"github.com/notawar/mobius/server/mobius"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractAppConfigMacOSCustomSettings(t *testing.T) {
	cases := []struct {
		desc string
		yaml string
		want []mobius.MDMProfileSpec
	}{
		{
			"no settings",
			`
apiVersion: v1
kind: config
spec:
`,
			nil,
		},
		{
			"no custom settings",
			`
apiVersion: v1
kind: config
spec:
  org_info:
    org_name: "Mobius"
  mdm:
    macos_settings:
`,
			nil,
		},
		{
			"empty custom settings",
			`
apiVersion: v1
kind: config
spec:
  org_info:
    org_name: "Mobius"
  mdm:
    macos_settings:
      custom_settings:
`,
			[]mobius.MDMProfileSpec{},
		},
		{
			"custom settings specified",
			`
apiVersion: v1
kind: config
spec:
  org_info:
    org_name: "Mobius"
  mdm:
    macos_settings:
      custom_settings:
        - path: "a"
          labels:
            - "foo"
            - bar
        - path: "b"
`,
			[]mobius.MDMProfileSpec{{Path: "a", Labels: []string{"foo", "bar"}}, {Path: "b"}},
		},
		{
			"empty and invalid custom settings",
			`
apiVersion: v1
kind: config
spec:
  org_info:
    org_name: "Mobius"
  mdm:
    macos_settings:
      custom_settings:
        - path: "a"
          labels:
        - path: ""
          labels:
            - "foo"
        - path: 4
          labels:
            - "foo"
            - "bar"
        - path: "c"
          labels:
            - baz
`,
			[]mobius.MDMProfileSpec{{Path: "a"}, {Path: "c", Labels: []string{"baz"}}},
		},
		{
			"old custom settings specified",
			`
apiVersion: v1
kind: config
spec:
  org_info:
    org_name: "Mobius"
  mdm:
    macos_settings:
      custom_settings:
        - "a"
        - "b"
`,
			[]mobius.MDMProfileSpec{{Path: "a"}, {Path: "b"}},
		},
		{
			"old empty and invalid custom settings",
			`
apiVersion: v1
kind: config
spec:
  org_info:
    org_name: "Mobius"
  mdm:
    macos_settings:
      custom_settings:
        - "a"
        - ""
        - 4
        - "c"
`,
			[]mobius.MDMProfileSpec{{Path: "a"}, {Path: "c"}},
		},
	}
	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			specs, err := spec.GroupFromBytes([]byte(c.yaml))
			require.NoError(t, err)
			if specs.AppConfig != nil {
				// Legacy mobiuscli apply
				got := extractAppCfgMacOSCustomSettings(specs.AppConfig)
				assert.Equal(t, c.want, got)

				// GitOps
				mdm, ok := specs.AppConfig.(map[string]interface{})["mdm"].(map[string]interface{})
				require.True(t, ok)
				mdm["macos_settings"] = mobius.MacOSSettings{CustomSettings: c.want}
				got = extractAppCfgMacOSCustomSettings(specs.AppConfig)
				assert.Equal(t, c.want, got)
			}
		})
	}
}

func TestExtractAppConfigWindowsCustomSettings(t *testing.T) {
	cases := []struct {
		desc string
		yaml string
		want []mobius.MDMProfileSpec
	}{
		{
			"no settings",
			`
apiVersion: v1
kind: config
spec:
`,
			nil,
		},
		{
			"no custom settings",
			`
apiVersion: v1
kind: config
spec:
  org_info:
    org_name: "Mobius"
  mdm:
    windows_settings:
`,
			nil,
		},
		{
			"empty custom settings",
			`
apiVersion: v1
kind: config
spec:
  org_info:
    org_name: "Mobius"
  mdm:
    windows_settings:
      custom_settings:
`,
			[]mobius.MDMProfileSpec{},
		},
		{
			"custom settings specified",
			`
apiVersion: v1
kind: config
spec:
  org_info:
    org_name: "Mobius"
  mdm:
    windows_settings:
      custom_settings:
        - path: "a"
          labels:
            - "foo"
            - bar
        - path: "b"
`,
			[]mobius.MDMProfileSpec{{Path: "a", Labels: []string{"foo", "bar"}}, {Path: "b"}},
		},
		{
			"empty and invalid custom settings",
			`
apiVersion: v1
kind: config
spec:
  org_info:
    org_name: "Mobius"
  mdm:
    windows_settings:
      custom_settings:
        - path: "a"
          labels:
        - path: ""
          labels:
            - "foo"
        - path: 4
          labels:
            - "foo"
            - "bar"
        - path: "c"
          labels:
            - baz
`,
			[]mobius.MDMProfileSpec{{Path: "a"}, {Path: "c", Labels: []string{"baz"}}},
		},
		{
			"old custom settings specified",
			`
apiVersion: v1
kind: config
spec:
  org_info:
    org_name: "Mobius"
  mdm:
    windows_settings:
      custom_settings:
        - "a"
        - "b"
`,
			[]mobius.MDMProfileSpec{{Path: "a"}, {Path: "b"}},
		},
		{
			"old empty and invalid custom settings",
			`
apiVersion: v1
kind: config
spec:
  org_info:
    org_name: "Mobius"
  mdm:
    windows_settings:
      custom_settings:
        - "a"
        - ""
        - 4
        - "c"
`,
			[]mobius.MDMProfileSpec{{Path: "a"}, {Path: "c"}},
		},
	}
	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			specs, err := spec.GroupFromBytes([]byte(c.yaml))
			require.NoError(t, err)
			if specs.AppConfig != nil {
				// Legacy mobiuscli apply
				got := extractAppCfgWindowsCustomSettings(specs.AppConfig)
				assert.Equal(t, c.want, got)

				// GitOps
				mdm, ok := specs.AppConfig.(map[string]interface{})["mdm"].(map[string]interface{})
				require.True(t, ok)
				windowsSettings := mobius.WindowsSettings{}
				windowsSettings.CustomSettings = optjson.SetSlice(c.want)
				mdm["windows_settings"] = windowsSettings
				got = extractAppCfgWindowsCustomSettings(specs.AppConfig)
				assert.Equal(t, c.want, got)
			}
		})
	}
}

func TestExtractTeamSpecsMDMCustomSettings(t *testing.T) {
	cases := []struct {
		desc string
		yaml string
		want map[string]profileSpecsByPlatform
	}{
		{
			"no settings",
			`
apiVersion: v1
kind: team
spec:
  team:
`,
			nil,
		},
		{
			"no custom settings",
			`
apiVersion: v1
kind: team
spec:
  team:
    name: Mobius
    mdm:
      macos_settings:
      windows_settings:
---
apiVersion: v1
kind: team
spec:
  team:
    name: Mobius2
    mdm:
      macos_settings:
      windows_settings:
`,
			nil,
		},
		{
			"empty custom settings",
			`
apiVersion: v1
kind: team
spec:
  team:
    name: "Mobius"
    mdm:
      macos_settings:
        custom_settings:
      windows_settings:
        custom_settings:
---
apiVersion: v1
kind: team
spec:
  team:
    name: "Mobius2"
    mdm:
      macos_settings:
        custom_settings:
      windows_settings:
        custom_settings:
`,
			map[string]profileSpecsByPlatform{"Mobius": {windows: []mobius.MDMProfileSpec{}, macos: []mobius.MDMProfileSpec{}}, "Mobius2": {windows: []mobius.MDMProfileSpec{}, macos: []mobius.MDMProfileSpec{}}},
		},
		{
			"custom settings specified",
			`
apiVersion: v1
kind: team
spec:
  team:
    name: "Mobius"
    mdm:
      macos_settings:
        custom_settings:
          - path: "a"
            labels:
              - "foo"
              - bar
          - path: "b"
      windows_settings:
        custom_settings:
           - path: "c"
           - path: "d"
             labels:
               - "foo"
               - baz
`,
			map[string]profileSpecsByPlatform{"Mobius": {
				macos: []mobius.MDMProfileSpec{
					{Path: "a", Labels: []string{"foo", "bar"}},
					{Path: "b"},
				},
				windows: []mobius.MDMProfileSpec{
					{Path: "c"},
					{Path: "d", Labels: []string{"foo", "baz"}},
				},
			}},
		},
		{
			"old custom settings specified",
			`
apiVersion: v1
kind: team
spec:
  team:
    name: "Mobius"
    mdm:
      macos_settings:
        custom_settings:
          - "a"
          - "b"
      windows_settings:
        custom_settings:
          - "c"
          - "d"
`,
			map[string]profileSpecsByPlatform{"Mobius": {
				macos: []mobius.MDMProfileSpec{{Path: "a"}, {Path: "b"}},
				windows: []mobius.MDMProfileSpec{
					{Path: "c"},
					{Path: "d"},
				},
			}},
		},
		{
			"invalid custom settings",
			`
apiVersion: v1
kind: team
spec:
  team:
    name: "Mobius"
    mdm:
      macos_settings:
        custom_settings:
          - path: "a"
            labels:
              - "y"
          - path: ""
          - path: 42
            labels:
              - "x"
          - path: "c"
      windows_settings:
        custom_settings:
          - path: "x"
          - path: ""
            labels:
              - "x"
          - path: 24
          - path: "y"
`,
			map[string]profileSpecsByPlatform{},
		},
		{
			"old invalid custom settings",
			`
apiVersion: v1
kind: team
spec:
  team:
    name: "Mobius"
    mdm:
      macos_settings:
        custom_settings:
          - "a"
          - ""
          - 42
          - "c"
      windows_settings:
        custom_settings:
          - "x"
          - ""
          - 24
          - "y"
`,
			map[string]profileSpecsByPlatform{},
		},
	}
	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			specs, err := spec.GroupFromBytes([]byte(c.yaml))
			require.NoError(t, err)
			if len(specs.Teams) > 0 {
				gotSpecs := extractTmSpecsMDMCustomSettings(specs.Teams)
				for k, wantProfs := range c.want {
					gotProfs, ok := gotSpecs[k]
					require.True(t, ok)
					require.Equal(t, wantProfs.macos, gotProfs.macos)
					require.Equal(t, wantProfs.windows, gotProfs.windows)
				}
			}
		})
	}
}

func TestGetProfilesContents(t *testing.T) {
	tempDir := t.TempDir()
	darwinProfile := mobileconfigForTest("bar", "I")
	darwinProfileWithFooEnv := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array/>
	<key>PayloadDisplayName</key>
	<string>bar</string>
	<key>PayloadIdentifier</key>
	<string>123</string>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadUUID</key>
	<string>123</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
	<key>someConfig</key>
	<integer>$FOO</integer>
</dict>
</plist>`
	windowsProfile := syncMLForTest("./some/path")
	windowsProfileWithBarEnv := `<Add>
  <Item>
    <Target>
      <LocURI>./some/path</LocURI>
    </Target>
  </Item>
</Add>
<Replace>
  <Item>
    <Target>
      <LocURI>${BAR}/some/path</LocURI>
    </Target>
  </Item>
</Replace>`

	tests := []struct {
		name          string
		baseDir       string
		macSetupFiles [][2]string
		winSetupFiles [][2]string
		labels        []string
		environment   map[string]string
		expandEnv     bool
		expectError   bool
		want          []mobius.MDMProfileBatchPayload
		wantErr       string
	}{
		{
			name:    "invalid darwin xml",
			baseDir: tempDir,
			macSetupFiles: [][2]string{
				{"foo.mobileconfig", `<?xml version="1.0" encoding="UTF-8"?>`},
			},
			expectError: true,
			want:        []mobius.MDMProfileBatchPayload{{Name: "foo"}},
		},
		{
			name:    "windows and darwin files",
			baseDir: tempDir,
			macSetupFiles: [][2]string{
				{"bar.mobileconfig", string(darwinProfile)},
			},
			winSetupFiles: [][2]string{
				{"foo.xml", string(windowsProfile)},
			},
			expectError: false,
			want: []mobius.MDMProfileBatchPayload{
				{Name: "foo", Contents: windowsProfile},
				{Name: "bar", Contents: darwinProfile},
			},
		},
		{
			name:    "windows and darwin files with labels",
			baseDir: tempDir,
			macSetupFiles: [][2]string{
				{"bar.mobileconfig", string(darwinProfile)},
			},
			winSetupFiles: [][2]string{
				{"foo.xml", string(windowsProfile)},
			},
			labels:      []string{"foo", "bar"},
			expectError: false,
			want: []mobius.MDMProfileBatchPayload{
				{Name: "foo", Contents: windowsProfile, Labels: []string{"foo", "bar"}},
				{Name: "bar", Contents: darwinProfile, Labels: []string{"foo", "bar"}},
			},
		},
		{
			name:    "darwin files with file name != PayloadDisplayName",
			baseDir: tempDir,
			macSetupFiles: [][2]string{
				{"bar.mobileconfig", string(darwinProfile)},
			},
			winSetupFiles: [][2]string{
				{"foo.xml", string(windowsProfile)},
			},
			expectError: false,
			want: []mobius.MDMProfileBatchPayload{
				{Name: "foo", Contents: windowsProfile},
				{Name: "bar", Contents: darwinProfile},
			},
		},
		{
			name:    "duplicate names across windows and darwin",
			baseDir: tempDir,
			macSetupFiles: [][2]string{
				{"bar.mobileconfig", string(mobileconfigForTest("baz", "I"))},
			},
			winSetupFiles: [][2]string{
				{"baz.xml", string(windowsProfile)},
			},
			expectError: true,
		},
		{
			name:    "duplicate file names",
			baseDir: tempDir,
			winSetupFiles: [][2]string{
				{"baz.xml", string(windowsProfile)},
				{"baz.xml", string(windowsProfile)},
			},
			expectError: true,
		},
		{
			name:    "with environment variables",
			baseDir: tempDir,
			macSetupFiles: [][2]string{
				{"bar.mobileconfig", darwinProfileWithFooEnv},
			},
			winSetupFiles: [][2]string{
				{"foo.xml", windowsProfileWithBarEnv},
			},
			environment: map[string]string{"FOO": "42", "BAR": "24"},
			expandEnv:   true,
			expectError: false,
			want: []mobius.MDMProfileBatchPayload{
				{
					Name: "bar",
					Contents: []byte(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array/>
	<key>PayloadDisplayName</key>
	<string>bar</string>
	<key>PayloadIdentifier</key>
	<string>123</string>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadUUID</key>
	<string>123</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
	<key>someConfig</key>
	<integer>42</integer>
</dict>
</plist>`),
				},
				{
					Name: "foo",
					Contents: []byte(`<Add>
  <Item>
    <Target>
      <LocURI>./some/path</LocURI>
    </Target>
  </Item>
</Add>
<Replace>
  <Item>
    <Target>
      <LocURI>24/some/path</LocURI>
    </Target>
  </Item>
</Replace>`),
				},
			},
		},
		{
			name:    "with environment variables but not set",
			baseDir: tempDir,
			macSetupFiles: [][2]string{
				{"bar.mobileconfig", darwinProfileWithFooEnv},
			},
			winSetupFiles: [][2]string{
				{"foo.xml", windowsProfileWithBarEnv},
			},
			environment: map[string]string{},
			expandEnv:   true,
			expectError: true,
		},
		{
			name:    "with unprocessable json",
			baseDir: tempDir,
			macSetupFiles: [][2]string{
				{"bar.json", string(windowsProfile)},
			},
			expectError: true,
			wantErr:     "Couldn't edit macos_settings.custom_settings (bar.json): Declaration profiles should include valid JSON",
		},
		{
			name:    "with unprocessable xml",
			baseDir: tempDir,
			winSetupFiles: [][2]string{
				{"bar.xml", string(darwinProfile)},
			},
			expectError: true,
			wantErr:     "Couldn't edit windows_settings.custom_settings (bar.xml): Windows configuration profiles can only have <Replace> or <Add> top level elements",
		},
		{
			name:    "with unsupported extension",
			baseDir: tempDir,
			macSetupFiles: [][2]string{
				{"bar.cfg", string(darwinProfile)},
			},
			expectError: true,
			wantErr:     "Couldn't edit macos_settings.custom_settings (bar.cfg): macOS configuration profiles must be .mobileconfig or .json files",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.expandEnv {
				if len(tt.environment) > 0 {
					for k, v := range tt.environment {
						os.Setenv(k, v)
					}
					t.Cleanup(func() {
						for k := range tt.environment {
							os.Unsetenv(k)
						}
					})
				}
			}
			macPaths := []mobius.MDMProfileSpec{}
			for _, fileSpec := range tt.macSetupFiles {
				filePath := filepath.Join(tempDir, fileSpec[0])
				require.NoError(t, os.WriteFile(filePath, []byte(fileSpec[1]), 0o644))
				macPaths = append(macPaths, mobius.MDMProfileSpec{Path: filePath, Labels: tt.labels})
			}

			winPaths := []mobius.MDMProfileSpec{}
			for _, fileSpec := range tt.winSetupFiles {
				filePath := filepath.Join(tempDir, fileSpec[0])
				require.NoError(t, os.WriteFile(filePath, []byte(fileSpec[1]), 0o644))
				winPaths = append(winPaths, mobius.MDMProfileSpec{Path: filePath, Labels: tt.labels})
			}

			profileContents, err := getProfilesContents(tt.baseDir, macPaths, winPaths, tt.expandEnv)

			if tt.expectError {
				require.Error(t, err)
				if tt.wantErr != "" {
					require.Contains(t, err.Error(), tt.wantErr)
				}
			} else {
				require.NoError(t, err)
				require.NotNil(t, profileContents)
				require.Len(t, profileContents, len(tt.want))
				require.ElementsMatch(t, tt.want, profileContents)
			}
		})
	}
}

func TestGitOpsErrors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	client, err := NewClient("https://foo.bar", true, "", "")
	require.NoError(t, err)

	tests := []struct {
		name    string
		rawJSON string
		wantErr string
	}{
		{
			name:    "invalid integrations value",
			rawJSON: `{ "integrations": false }`,
			wantErr: "org_settings.integrations",
		},
		{
			name:    "invalid ndes_scep_proxy value",
			rawJSON: `{ "integrations": { "ndes_scep_proxy": [] } }`,
			wantErr: "org_settings.integrations.ndes_scep_proxy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &spec.GitOps{}
			config.OrgSettings = make(map[string]interface{})
			// Signal that we don't want to send any labels.
			// This avoids this test attempting to make a request to the GetLabels endpoint.
			config.Labels = make([]*mobius.LabelSpec, 0)
			err = json.Unmarshal([]byte(tt.rawJSON), &config.OrgSettings)
			require.NoError(t, err)
			config.OrgSettings["secrets"] = []*mobius.EnrollSecret{}
			_, _, err = client.DoGitOps(ctx, config, "/filename", nil, false, nil, nil, nil, nil, nil)
			assert.ErrorContains(t, err, tt.wantErr)
		})
	}
}
