import React, { useContext } from "react";

import { AppContext } from "context/app";
import { IIntegrationType } from "interfaces/integration";
import Modal from "components/Modal";
import Button from "components/buttons/Button";
import CustomLink from "components/CustomLink";

import PlaceholderImage from "../../../../../../assets/images/mobius-logo.png";

const baseClass = "preview-ticket-modal";

interface IPreviewTicketModalProps {
  onCancel: () => void;
  integrationType: IIntegrationType;
}

const PreviewTicketModal = ({
  onCancel,
  integrationType,
}: IPreviewTicketModalProps): JSX.Element => {
  const { isPremiumTier } = useContext(AppContext);
  const screenshot =
    integrationType === "jira" ? (
      <img
        src={PlaceholderImage}
        alt="Jira ticket"
        className={`${baseClass}__jira-screenshot`}
      />
    ) : (
      <img
        src={PlaceholderImage}
        alt="Zendesk ticket"
        className={`${baseClass}__zendesk-screenshot`}
      />
    );

  return (
    <Modal
      title="Example ticket"
      onExit={onCancel}
      onEnter={onCancel}
      className={baseClass}
      width="large"
    >
      <>
        <p className="automations-learn-more">
          Want to learn more about how automations in Mobius work?{" "}
          <CustomLink
            url="https://mobius-mdm.org/docs/using-mobius/automations"
            text="Check out the Mobius documentation"
            newTab
          />
        </p>
        <div className={`${baseClass}__example`}>{screenshot}</div>
        <div className="modal-cta-wrap">
          <Button onClick={onCancel}>Done</Button>
        </div>
      </>
    </Modal>
  );
};

export default PreviewTicketModal;
