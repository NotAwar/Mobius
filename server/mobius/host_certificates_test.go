package mobius

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExtractHostCertificateNameDetails(t *testing.T) {
	expected := HostCertificateNameDetails{
		Country:            "US",
		Organization:       "Mobius Device Management Inc.",
		OrganizationalUnit: "Mobius Device Management Inc.",
		CommonName:         "MobiusDM",
	}

	cases := []struct {
		name     string
		input    string
		expected *HostCertificateNameDetails
		err      bool
	}{
		{
			name:     "valid",
			input:    "/C=US/O=Mobius Device Management Inc./OU=Mobius Device Management Inc./CN=MobiusDM",
			expected: &expected,
		},
		{
			name:     "valid with different order",
			input:    "/O=Mobius Device Management Inc./OU=Mobius Device Management Inc./CN=MobiusDM/C=US",
			expected: &expected,
		},
		{
			name:  "valid with missing key",
			input: "/C=US/O=Mobius Device Management Inc./CN=MobiusDM ",
			expected: &HostCertificateNameDetails{
				Country:            "US",
				Organization:       "Mobius Device Management Inc.",
				OrganizationalUnit: "",
				CommonName:         "MobiusDM",
			},
		},
		{
			name:     "valid with additional keyr",
			input:    "/C=US/O=Mobius Device Management Inc./OU=Mobius Device Management Inc./CN=MobiusDM/L=SomeCity",
			expected: &expected,
		},
		{
			name:  "invalid format with extra slash",
			input: "/C=US/O=Mobius Device Management Inc./OU=Mobius Device Management Inc./CN=MobiusDM/invalid",
			err:   true,
		},
		{
			name:  "invalid format with wrong separator",
			input: "C=US,O=Mobius Device Management Inc.,OU=Mobius Device Management Inc.,CN=MobiusDM",
			err:   true,
		},
		{
			name:  "invalid format with extra equal",
			input: "/C=US=/O=Mobius Device Management Inc./OU=Mobius Device Management Inc./CN=MobiusDM",
			err:   true,
		},
		{
			name:  "invalid format with malformed key values",
			input: "/C=US/O/OU=Mobius Device Management Inc./=/CN=MobiusDM",
			err:   true,
		},
		{
			name:  "empty",
			input: "",
			err:   true,
		},
		{
			name:  "missing value",
			input: "/C=US/O=Mobius Device Management Inc./OU=Mobius Device Management Inc./CN=",
			expected: &HostCertificateNameDetails{
				Country:            "US",
				Organization:       "Mobius Device Management Inc.",
				OrganizationalUnit: "Mobius Device Management Inc.",
				CommonName:         "",
			},
		},
		{
			name:     "missing first slash",
			input:    "C=US/O=Mobius Device Management Inc./OU=Mobius Device Management Inc./CN=MobiusDM",
			expected: &expected,
		},
		{
			name:     "trailing slash",
			input:    "/C=US/O=Mobius Device Management Inc./OU=Mobius Device Management Inc./CN=MobiusDM/",
			expected: &expected,
		},
		{
			name:  "simple common name",
			input: "/CN=MobiusDM",
			expected: &HostCertificateNameDetails{
				Country:            "",
				Organization:       "",
				OrganizationalUnit: "",
				CommonName:         "MobiusDM",
			},
		},
		{
			name:  "simple common name with no leading slash",
			input: "CN=MobiusDM",
			expected: &HostCertificateNameDetails{
				Country:            "",
				Organization:       "",
				OrganizationalUnit: "",
				CommonName:         "MobiusDM",
			},
		},
		{
			name:  "invalid separator",
			input: "/C=US,O=Mobius Device Management Inc.,OU=Mobius Device Management Inc.,CN=MobiusDM",
			err:   true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := ExtractDetailsFromOsqueryDistinguishedName(tc.input)
			if tc.err {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expected, actual)
			}
		})
	}
}
