package apple_mdm

import (
	"testing"

	"github.com/notawar/mobius/server/mobius"
	"github.com/stretchr/testify/require"
)

func TestMDMAppleEnrollURL(t *testing.T) {
	cases := []struct {
		appConfig   *mobius.AppConfig
		expectedURL string
	}{
		{
			appConfig: &mobius.AppConfig{
				ServerSettings: mobius.ServerSettings{
					ServerURL: "https://foo.example.com",
				},
			},
			expectedURL: "https://foo.example.com/api/mdm/apple/enroll?token=tok",
		},
		{
			appConfig: &mobius.AppConfig{
				ServerSettings: mobius.ServerSettings{
					ServerURL: "https://foo.example.com/",
				},
			},
			expectedURL: "https://foo.example.com/api/mdm/apple/enroll?token=tok",
		},
	}

	for _, tt := range cases {
		enrollURL, err := EnrollURL("tok", tt.appConfig)
		require.NoError(t, err)
		require.Equal(t, tt.expectedURL, enrollURL)
	}
}
