import React, { useCallback, useContext, useState } from "react";

import softwareAPI from "services/entities/software";
import { NotificationContext } from "context/notification";

import { getErrorReason } from "interfaces/errors";

import Modal from "components/Modal";
import Button from "components/buttons/Button";
import InfoBanner from "components/InfoBanner";

const baseClass = "delete-software-modal";

const DELETE_SW_USED_BY_POLICY_ERROR_MSG =
  "Couldn't delete. Policy automation uses this software. Please disable policy automation for this software and try again.";
const DELETE_SW_INSTALLED_DURING_SETUP_ERROR_MSG =
  "Couldn't delete. This software is installed when new Macs boot. Please remove software in Controls > Setup experience and try again.";

interface IDeleteSoftwareModalProps {
  softwareId: number;
  teamId: number;
  softwareInstallerName?: string;
  onExit: () => void;
  onSuccess: () => void;
  gitOpsModeEnabled?: boolean;
}

const DeleteSoftwareModal = ({
  softwareId,
  teamId,
  softwareInstallerName,
  onExit,
  onSuccess,
  gitOpsModeEnabled,
}: IDeleteSoftwareModalProps) => {
  const { renderFlash } = useContext(NotificationContext);
  const [isDeleting, setIsDeleting] = useState(false);

  const onDeleteSoftware = useCallback(async () => {
    setIsDeleting(true);
    try {
      await softwareAPI.deleteSoftwareInstaller(softwareId, teamId);
      renderFlash("success", "Software deleted successfully!");
      onSuccess();
    } catch (error) {
      const reason = getErrorReason(error);
      if (reason.includes("Policy automation uses this software")) {
        renderFlash("error", DELETE_SW_USED_BY_POLICY_ERROR_MSG);
      } else if (reason.includes("This software is installed when")) {
        renderFlash("error", DELETE_SW_INSTALLED_DURING_SETUP_ERROR_MSG);
      } else {
        renderFlash("error", "Couldn't delete. Please try again.");
      }
    }
    setIsDeleting(false);
    onExit();
  }, [softwareId, teamId, renderFlash, onSuccess, onExit]);

  return (
    <Modal
      className={baseClass}
      title="Delete software"
      onExit={onExit}
      isContentDisabled={isDeleting}
    >
      <>
        {gitOpsModeEnabled && (
          <InfoBanner className={`${baseClass}__gitops-warning`}>
            You are currently in GitOps mode. If the package is defined in
            GitOps, it will reappear when GitOps runs.
          </InfoBanner>
        )}
        <p>
          Software won&apos;t be uninstalled from existing hosts, but any
          pending installs and uninstalls{" "}
          {softwareInstallerName ? (
            <>
              for <b> {softwareInstallerName}</b>{" "}
            </>
          ) : (
            ""
          )}
          will be canceled.
        </p>
        <p>
          Installs or uninstalls currently running on a host will still
          complete, but results won&apos;t appear in Mobius.
        </p>
        <p>You cannot undo this action.</p>
        <div className="modal-cta-wrap">
          <Button
            variant="alert"
            onClick={onDeleteSoftware}
            isLoading={isDeleting}
          >
            Delete
          </Button>
          <Button variant="inverse-alert" onClick={onExit}>
            Cancel
          </Button>
        </div>
      </>
    </Modal>
  );
};

export default DeleteSoftwareModal;
