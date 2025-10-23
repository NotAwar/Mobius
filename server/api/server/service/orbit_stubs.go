package service

import (
	"context"
	"errors"

	"github.com/notawar/mobius/mobius-server/server/mobius"
)

// AuthenticateOrbitHost is a stub implementation that returns an error
// indicating this feature is not supported in the API-first architecture.
func (svc *Service) AuthenticateOrbitHost(ctx context.Context, nodeKey string) (*mobius.Host, bool, error) {
	return nil, false, errors.New("agent not supported in API-first architecture")
}

// EnrollOrbit is a stub implementation that returns an error
// indicating this feature is not supported in the API-first architecture.
func (svc *Service) EnrollOrbit(ctx context.Context, hostInfo mobius.OrbitHostInfo, enrollSecret string) (string, error) {
	return "", errors.New("agent not supported in API-first architecture")
}

// GetOrbitConfig is a stub implementation that returns an error
// indicating this feature is not supported in the API-first architecture.
func (svc *Service) GetOrbitConfig(ctx context.Context) (mobius.OrbitConfig, error) {
	return mobius.OrbitConfig{}, errors.New("agent not supported in API-first architecture")
}

// SetOrUpdateDeviceAuthToken is a stub implementation that returns an error
// indicating this feature is not supported in the API-first architecture.
func (svc *Service) SetOrUpdateDeviceAuthToken(ctx context.Context, authToken string) error {
	return errors.New("agent not supported in API-first architecture")
}

// GetHostScript is a stub implementation that returns an error
// indicating this feature is not supported in the API-first architecture.
func (svc *Service) GetHostScript(ctx context.Context, execID string) (*mobius.HostScriptResult, error) {
	return nil, errors.New("agent not supported in API-first architecture")
}

// SaveHostScriptResult is a stub implementation that returns an error
// indicating this feature is not supported in the API-first architecture.
func (svc *Service) SaveHostScriptResult(ctx context.Context, result *mobius.HostScriptResultPayload) error {
	return errors.New("agent not supported in API-first architecture")
}

// SetOrUpdateDiskEncryptionKey is a stub implementation that returns an error
// indicating this feature is not supported in the API-first architecture.
func (svc *Service) SetOrUpdateDiskEncryptionKey(ctx context.Context, encryptionKey, clientError string) error {
	return errors.New("agent not supported in API-first architecture")
}

// EscrowLUKSData is a stub implementation that returns an error
// indicating this feature is not supported in the API-first architecture.
func (svc *Service) EscrowLUKSData(ctx context.Context, passphrase string, salt string, keySlot *uint, clientError string) error {
	return errors.New("agent not supported in API-first architecture")
}

// GetOrbitSetupExperienceStatus is a stub implementation that returns an error
// indicating this feature is not supported in the API-first architecture.
func (svc *Service) GetOrbitSetupExperienceStatus(ctx context.Context, nodeKey string, forceRelease bool) (*mobius.SetupExperienceStatusPayload, error) {
	return nil, errors.New("agent not supported in API-first architecture")
}

// GetSoftwareInstallDetails is a stub implementation that returns an error
// indicating software install details are not available in the API-first architecture.
func (svc *Service) GetSoftwareInstallDetails(ctx context.Context, installUUID string) (*mobius.SoftwareInstallDetails, error) {
	return nil, errors.New("software install details not available in API-first architecture")
}

// OrbitDownloadSoftwareInstaller is a stub implementation that returns an error
// indicating this feature is not supported in the API-first architecture.
func (svc *Service) OrbitDownloadSoftwareInstaller(ctx context.Context, installerID uint) (*mobius.DownloadSoftwareInstallerPayload, error) {
	return nil, errors.New("agent not supported in API-first architecture")
}

// SaveHostSoftwareInstallResult is a stub implementation that returns an error
// indicating this feature is not supported in the API-first architecture.
func (svc *Service) SaveHostSoftwareInstallResult(ctx context.Context, result *mobius.HostSoftwareInstallResultPayload) error {
	return errors.New("agent not supported in API-first architecture")
}
