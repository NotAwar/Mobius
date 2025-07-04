package nvd

import (
	"testing"

	"github.com/notawar/mobius/server/mobius"
	"github.com/stretchr/testify/require"
)

func TestVariations(t *testing.T) {
	variationsTestCases := []struct {
		software          mobius.Software
		vendorVariations  []string
		productVariations []string
	}{
		{
			software:          mobius.Software{Name: "1Password – Password Manager", Version: "2.3.8", Source: "chrome_extensions"},
			productVariations: []string{"1password"},
		},

		{
			software:          mobius.Software{Name: "AdBlock — best ad blocker", Version: "5.1.1", Source: "chrome_extensions"},
			productVariations: []string{"adblock"},
		},
		{
			software:          mobius.Software{Name: "Adblock Plus - free ad blocker", Version: "3.14.2", Source: "chrome_extensions"},
			productVariations: []string{"adblockplus", "adblock_plus"},
		},
		{
			software:          mobius.Software{Name: "uBlock Origin", Version: "1.44.4", Source: "chrome_extensions"},
			productVariations: []string{"ublockorigin", "ublock_origin"},
		},
		{
			software:          mobius.Software{Name: "Adobe Acrobat DC (64-bit)", Version: "22.002.20212", Source: "programs", Vendor: "Adobe"},
			vendorVariations:  []string{"adobe"},
			productVariations: []string{"acrobatdc", "acrobat_dc"},
		},
		{
			software:          mobius.Software{Name: "Bing", Version: "1.3", Source: "firefox_addons"},
			productVariations: []string{"bing"},
		},
		{
			software:          mobius.Software{Name: "Brave", Version: "105.1.43.93", Source: "programs", Vendor: "Brave Software Inc"},
			vendorVariations:  []string{"brave", "brave_software_inc", "bravesoftwareinc"},
			productVariations: []string{"brave"},
		},
		{
			software:          mobius.Software{Name: "Docker Desktop", Version: "4.12.0", Source: "programs", Vendor: "Docker Inc."},
			vendorVariations:  []string{"docker", "docker_inc.", "dockerinc."},
			productVariations: []string{"desktop", "docker_desktop", "dockerdesktop"},
		},
		{
			software:          mobius.Software{Name: "Dropbox", Version: "157.4.4808", Source: "programs", Vendor: "Dropbox, Inc."},
			vendorVariations:  []string{"dropbox,_inc.", "dropbox,inc.", "dropbox,"},
			productVariations: []string{"dropbox"},
		},
		{
			software:          mobius.Software{Name: "DuckDuckGo", Version: "1.1", Source: "firefox_addons"},
			productVariations: []string{"duckduckgo"},
		},
		{
			software:          mobius.Software{Name: "Git", Version: "2.37.1", Source: "programs", Vendor: "The Git Development Community"},
			vendorVariations:  []string{"git", "thegitdevelopmentcommunity", "development", "community", "the_git_development_community"},
			productVariations: []string{"git"},
		},
		{
			software:          mobius.Software{Name: "Google Chrome", Version: "105.0.5195.127", Source: "programs", Vendor: "Google LLC"},
			vendorVariations:  []string{"google_llc", "googlellc", "google", "llc"},
			productVariations: []string{"chrome", "google_chrome", "googlechrome"},
		},
		{
			software:          mobius.Software{Name: "Microsoft Edge", Version: "105.0.1343.50", Source: "programs", Vendor: "Microsoft Corporation"},
			vendorVariations:  []string{"microsoft", "microsoft_corporation", "microsoftcorporation"},
			productVariations: []string{"edge", "microsoft_edge", "microsoftedge"},
		},
		{
			software:          mobius.Software{Name: "Microsoft OneDrive", Version: "22.181.0828.0002", Source: "programs", Vendor: "Microsoft Corporation"},
			vendorVariations:  []string{"microsoft_corporation", "microsoftcorporation", "microsoft"},
			productVariations: []string{"onedrive", "microsoft_onedrive", "microsoftonedrive"},
		},
		{
			software:          mobius.Software{Name: "Microsoft Visual Studio Code (User)", Version: "1.71.2", Source: "programs", Vendor: "Microsoft Corporation"},
			vendorVariations:  []string{"microsoft", "microsoft_corporation", "microsoftcorporation"},
			productVariations: []string{"visualstudiocode", "visual_studio_code", "microsoft_visual_studio_code", "microsoftvisualstudiocode"},
		},
		{
			software:          mobius.Software{Name: "Mozilla Firefox (x64 en-US)", Version: "105.0.1", Source: "programs", Vendor: "Mozilla"},
			vendorVariations:  []string{"mozilla"},
			productVariations: []string{"firefox"},
		},
		{
			software:          mobius.Software{Name: "Oracle VM VirtualBox 6.1.38", Version: "6.1.38", Source: "programs", Vendor: "Oracle Corporation"},
			vendorVariations:  []string{"oracle", "oracle_corporation", "oraclecorporation"},
			productVariations: []string{"vmvirtualbox", "vm_virtualbox", "oracle_vm_virtualbox", "oraclevmvirtualbox"},
		},
		{
			software:          mobius.Software{Name: "Python 3.10.6 (64-bit)", Version: "3.10.6150.0", Source: "programs", Vendor: "Python Software Foundation"},
			vendorVariations:  []string{"python", "python_software_foundation", "pythonsoftwarefoundation"},
			productVariations: []string{"python"},
		},
		{
			software:          mobius.Software{Name: "VLC media player", Version: "3.0.17.4", Source: "programs", Vendor: "VideoLAN"},
			vendorVariations:  []string{"videolan"},
			productVariations: []string{"vlcmediaplayer", "vlc_media_player"},
		},
		{
			software:          mobius.Software{Name: "Visual Studio Community 2022", Version: "17.2.5", Source: "programs", Vendor: "Microsoft Corporation"},
			vendorVariations:  []string{"microsoft", "microsoft_corporation", "microsoftcorporation"},
			productVariations: []string{"visualstudiocommunity", "visual_studio_community"},
		},
		{
			software:          mobius.Software{Name: "uBlock Origin", Version: "1.44.0", Source: "chrome_extensions"},
			productVariations: []string{"ublockorigin", "ublock_origin"},
		},
		{
			software:          mobius.Software{Name: "Adobe Acrobat Reader DC.app", Version: "22.002.20191", BundleIdentifier: "com.adobe.Reader", Source: "apps"},
			vendorVariations:  []string{"adobe", "reader"},
			productVariations: []string{"acrobatreaderdc", "acrobat_reader_dc"},
		},
		{
			software:          mobius.Software{Name: "Adobe Lightroom.app", Version: "5.5", BundleIdentifier: "com.adobe.mas.lightroomCC", Source: "apps"},
			vendorVariations:  []string{"adobe", "mas", "lightroomcc"},
			productVariations: []string{"lightroom"},
		},
		{
			software:          mobius.Software{Name: "Finder.app", Version: "12.5", BundleIdentifier: "com.apple.finder", Source: "apps"},
			vendorVariations:  []string{"apple", "finder"},
			productVariations: []string{"finder"},
		},
		{
			software:          mobius.Software{Name: "Firefox.app", Version: "105.0.1", BundleIdentifier: "org.mozilla.firefox", Source: "apps"},
			vendorVariations:  []string{"mozilla", "firefox"},
			productVariations: []string{"firefox"},
		},
		{
			software:          mobius.Software{Name: "Google Chrome.app", Version: "105.0.5195.125", BundleIdentifier: "com.google.Chrome", Source: "apps"},
			vendorVariations:  []string{"chrome", "google"},
			productVariations: []string{"chrome"},
		},
		{
			software:          mobius.Software{Name: "Microsoft Excel.app", Version: "16.65", BundleIdentifier: "com.microsoft.Excel", Source: "apps"},
			vendorVariations:  []string{"microsoft", "excel"},
			productVariations: []string{"excel"},
		},
		{
			software:          mobius.Software{Name: "OneDrive.app", Version: "22.186.0904", BundleIdentifier: "com.microsoft.OneDrive-mac", Source: "apps"},
			vendorVariations:  []string{"microsoft", "onedrive-mac"},
			productVariations: []string{"onedrive"},
		},
		{
			software:          mobius.Software{Name: "Python.app", Version: "3.10.7", BundleIdentifier: "org.python.python", Source: "apps"},
			vendorVariations:  []string{"python"},
			productVariations: []string{"python"},
		},
		{
			software:          mobius.Software{Name: "Python.app", Version: "3.8.9", BundleIdentifier: "com.apple.python3", Source: "apps"},
			vendorVariations:  []string{"apple", "python3"},
			productVariations: []string{"python"},
		},
		{
			software:          mobius.Software{Name: "ms-python.python", Version: "3.8.9", BundleIdentifier: "", Source: "vscode_extensions", Vendor: "Microsoft"},
			vendorVariations:  []string{"microsoft", "ms-python"},
			productVariations: []string{"python", "ms-python.python"},
		},
	}

	for _, tc := range variationsTestCases {
		tc := tc
		require.ElementsMatch(t, tc.productVariations, productVariations(&tc.software), tc.software)
		require.ElementsMatch(t, tc.vendorVariations, vendorVariations(&tc.software), tc.software)
	}
}

func TestSanitizedSoftwareName(t *testing.T) {
	t.Run("removes arch from name", func(t *testing.T) {
		testCases := []struct {
			software mobius.Software
			expected string
		}{
			{
				software: mobius.Software{
					Name:    "Adobe Acrobat DC (64-bit)",
					Version: "22.002.20212",
					Vendor:  "Adobe",
					Source:  "programs",
				},
				expected: "acrobat dc",
			},
			{
				software: mobius.Software{
					Name:    "Mozilla Firefox (x64)",
					Version: "105.0.1",
					Vendor:  "Mozilla",
					Source:  "programs",
				},
				expected: "firefox",
			},
			{
				software: mobius.Software{
					Name:    "Python (64-bit)",
					Version: "3.10.6150.0",
					Vendor:  "Python Software Foundation",
					Source:  "programs",
				},
				expected: "python",
			},
		}

		for _, tc := range testCases {
			tc := tc
			actual := sanitizeSoftwareName(&tc.software)
			require.Equal(t, tc.expected, actual)
		}
	})

	t.Run("removes version from the name", func(t *testing.T) {
		testCases := []struct {
			software mobius.Software
			expected string
		}{
			{
				software: mobius.Software{
					Name:    "Oracle VM VirtualBox 6.1.38",
					Version: "6.1.38",
					Vendor:  "Oracle Corporation",
					Source:  "programs",
				},
				expected: "oracle vm virtualbox",
			},
			{
				software: mobius.Software{
					Name:    "Python 3.10.6 (64-bit)",
					Version: "3.10.6150.0",
					Vendor:  "Python Software Foundation",
					Source:  "programs",
				},
				expected: "python",
			},
		}

		for _, tc := range testCases {
			tc := tc
			actual := sanitizeSoftwareName(&tc.software)
			require.Equal(t, tc.expected, actual)
		}
	})

	t.Run("removes any extra comments", func(t *testing.T) {
		testCases := []struct {
			software mobius.Software
			expected string
		}{
			{
				software: mobius.Software{
					Name:    "1Password – Password Manager",
					Version: "2.3.8",
					Source:  "chrome_extensions",
				},
				expected: "1password",
			},
			{
				software: mobius.Software{
					Name:    "Adblock Plus - free ad blocker",
					Version: "3.14.2",
					Source:  "chrome_extensions",
				},
				expected: "adblock plus",
			},
			{
				software: mobius.Software{
					Name:    "AdBlock — best ad blocker",
					Version: "5.1.1",
					Vendor:  "",
					Source:  "chrome_extensions",
				},
				expected: "adblock",
			},
		}

		for _, tc := range testCases {
			tc := tc
			actual := sanitizeSoftwareName(&tc.software)
			require.Equal(t, tc.expected, actual)
		}
	})

	t.Run("removes any language codes", func(t *testing.T) {
		testCases := []struct {
			software mobius.Software
			expected string
		}{
			{
				software: mobius.Software{
					Name:    "Mozilla Firefox (x64 en-US)",
					Version: "105.0.1",
					Vendor:  "Mozilla",
					Source:  "programs",
				},
				expected: "firefox",
			},
		}

		for _, tc := range testCases {
			tc := tc
			actual := sanitizeSoftwareName(&tc.software)
			require.Equal(t, tc.expected, actual)
		}
	})

	t.Run("removes any () and its contents", func(t *testing.T) {
		testCases := []struct {
			software mobius.Software
			expected string
		}{
			{
				software: mobius.Software{
					Name:    "Microsoft Visual Studio Code (User)",
					Version: "1.71.2",
					Vendor:  "Microsoft Corporation",
					Source:  "programs",
				},
				expected: "microsoft visual studio code",
			},
		}

		for _, tc := range testCases {
			tc := tc
			actual := sanitizeSoftwareName(&tc.software)
			require.Equal(t, tc.expected, actual)
		}
	})

	t.Run("removes .app and bundle parts from the name", func(t *testing.T) {
		testCases := []struct {
			software mobius.Software
			expected string
		}{
			{
				software: mobius.Software{
					Name:             "Google Chrome.app",
					Version:          "105.0.5195.125",
					BundleIdentifier: "com.google.Chrome",
					Source:           "apps",
				},
				expected: "chrome",
			},
			{
				software: mobius.Software{
					Name:             "Microsoft Excel.app",
					Version:          "16.65",
					BundleIdentifier: "com.microsoft.Excel",
					Source:           "apps",
				},
				expected: "excel",
			},
			{
				software: mobius.Software{
					Name:             "TextEdit.app",
					Version:          "1.17",
					BundleIdentifier: "com.apple.TextEdit",
					Source:           "apps",
				},
				expected: "textedit",
			},
			{
				software: mobius.Software{
					Name:             "Firefox.app",
					Version:          "105.0.1",
					BundleIdentifier: "org.mozilla.firefox",
					Source:           "apps",
				},
				expected: "firefox",
			},
		}
		for _, tc := range testCases {
			tc := tc
			actual := sanitizeSoftwareName(&tc.software)
			require.Equal(t, tc.expected, actual)
		}
	})
}

func TestParseUpdateFromVersion(t *testing.T) {
	testCases := []struct {
		desc            string
		originalVersion string
		expectedVersion string
		expectedUpdate  string
	}{
		{
			desc:            "alpha release",
			originalVersion: "3.14.0a1",
			expectedVersion: "3.14.0",
			expectedUpdate:  "alpha1",
		},
		{
			desc:            "beta release",
			originalVersion: "3.14.0b2",
			expectedVersion: "3.14.0",
			expectedUpdate:  "beta2",
		},
		{
			desc:            "release candidate",
			originalVersion: "3.14.0rc1",
			expectedVersion: "3.14.0",
			expectedUpdate:  "rc1",
		},
		{
			desc:            "no update",
			originalVersion: "3.14.0",
			expectedVersion: "3.14.0",
			expectedUpdate:  "",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			version, update := parseUpdateFromVersion(tc.originalVersion)
			require.Equal(t, tc.expectedVersion, version)
			require.Equal(t, tc.expectedUpdate, update)
		})
	}
}
