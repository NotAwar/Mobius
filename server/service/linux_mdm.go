package service

import (
	"context"

	"github.com/notawar/mobius/server/contexts/ctxerr"
	"github.com/notawar/mobius/server/mobius"
)

func (svc *Service) LinuxHostDiskEncryptionStatus(ctx context.Context, host mobius.Host) (mobius.HostMDMDiskEncryption, error) {
	if !host.IsLUKSSupported() {
		return mobius.HostMDMDiskEncryption{}, nil
	}

	actionRequired := mobius.DiskEncryptionActionRequired
	verified := mobius.DiskEncryptionVerified
	failed := mobius.DiskEncryptionFailed

	key, err := svc.ds.GetHostDiskEncryptionKey(ctx, host.ID)
	if err != nil {
		if mobius.IsNotFound(err) {
			return mobius.HostMDMDiskEncryption{
				Status: &actionRequired,
			}, nil
		}
		return mobius.HostMDMDiskEncryption{}, err
	}

	if key.ClientError != "" {
		return mobius.HostMDMDiskEncryption{
			Status: &failed,
			Detail: key.ClientError,
		}, nil
	}

	if key.Base64Encrypted == "" {
		return mobius.HostMDMDiskEncryption{
			Status: &actionRequired,
		}, nil
	}

	return mobius.HostMDMDiskEncryption{
		Status: &verified,
	}, nil
}

func (svc *Service) GetMDMLinuxProfilesSummary(ctx context.Context, teamId *uint) (summary mobius.MDMProfilesSummary, err error) {
	if err = svc.authz.Authorize(ctx, mobius.MDMConfigProfileAuthz{TeamID: teamId}, mobius.ActionRead); err != nil {
		return summary, ctxerr.Wrap(ctx, err)
	}

	// Linux doesn't have configuration profiles, so if we aren't enforcing disk encryption we have nothing to report
	includeDiskEncryptionStats, err := svc.ds.GetConfigEnableDiskEncryption(ctx, teamId)
	if err != nil {
		return summary, ctxerr.Wrap(ctx, err)
	} else if !includeDiskEncryptionStats {
		return summary, nil
	}

	counts, err := svc.ds.GetLinuxDiskEncryptionSummary(ctx, teamId)
	if err != nil {
		return summary, ctxerr.Wrap(ctx, err)
	}

	return mobius.MDMProfilesSummary{
		Verified: counts.Verified,
		Pending:  counts.ActionRequired,
		Failed:   counts.Failed,
	}, nil
}
