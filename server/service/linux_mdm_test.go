package service

import (
	"context"
	"testing"
	"time"

	"github.com/notawar/mobius/server/mobius"
	"github.com/notawar/mobius/server/mock"
	"github.com/notawar/mobius/server/ptr"
	"github.com/stretchr/testify/assert"
)

func TestLinuxHostDiskEncryptionStatus(t *testing.T) {
	ds := new(mock.Store)
	svc, ctx := newTestService(t, ds, nil, nil)

	actionRequired := mobius.DiskEncryptionActionRequired
	verified := mobius.DiskEncryptionVerified
	failed := mobius.DiskEncryptionFailed

	testcases := []struct {
		name              string
		host              mobius.Host
		keyExists         bool
		clientErrorExists bool
		status            mobius.HostMDMDiskEncryption
		notFound          bool
	}{
		{
			name:              "no key",
			host:              mobius.Host{ID: 1, Platform: "ubuntu"},
			keyExists:         false,
			clientErrorExists: false,
			status: mobius.HostMDMDiskEncryption{
				Status: &actionRequired,
			},
		},
		{
			name:              "key exists",
			host:              mobius.Host{ID: 1, Platform: "ubuntu"},
			keyExists:         true,
			clientErrorExists: false,
			status: mobius.HostMDMDiskEncryption{
				Status: &verified,
			},
		},
		{
			name:              "key exists && client error",
			host:              mobius.Host{ID: 1, Platform: "ubuntu"},
			keyExists:         true,
			clientErrorExists: true,
			status: mobius.HostMDMDiskEncryption{
				Status: &failed,
				Detail: "client error",
			},
		},
		{
			name:              "no key && client error",
			host:              mobius.Host{ID: 1, Platform: "ubuntu"},
			keyExists:         false,
			clientErrorExists: true,
			status: mobius.HostMDMDiskEncryption{
				Status: &failed,
				Detail: "client error",
			},
		},
		{
			name:              "key not found",
			host:              mobius.Host{ID: 1, Platform: "ubuntu"},
			keyExists:         false,
			clientErrorExists: false,
			status: mobius.HostMDMDiskEncryption{
				Status: &actionRequired,
			},
			notFound: true,
		},
		{
			name:   "unsupported platform",
			host:   mobius.Host{ID: 1, Platform: "amzn"},
			status: mobius.HostMDMDiskEncryption{},
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			ds.GetHostDiskEncryptionKeyFunc = func(ctx context.Context, hostID uint) (*mobius.HostDiskEncryptionKey, error) {
				var encrypted string
				if tt.keyExists {
					encrypted = "encrypted"
				}

				var clientError string
				if tt.clientErrorExists {
					clientError = "client error"
				}

				var nfe notFoundError
				if tt.notFound {
					return nil, &nfe
				}

				return &mobius.HostDiskEncryptionKey{
					HostID:          hostID,
					Base64Encrypted: encrypted,
					Decryptable:     ptr.Bool(true),
					UpdatedAt:       time.Now(),
					ClientError:     clientError,
				}, nil
			}

			status, err := svc.LinuxHostDiskEncryptionStatus(ctx, tt.host)
			assert.Nil(t, err)

			assert.Equal(t, tt.status, status)
		})
	}
}
