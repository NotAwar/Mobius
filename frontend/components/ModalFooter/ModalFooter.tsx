import React from "react";
import classnames from "classnames";
import { COLORS } from "styles/var/colors";

const baseClass = "modal-footer";

interface IModalFooterProps {
  primaryButtons: React.ReactNode;
  secondaryButtons?: React.ReactNode;
  className?: string;
  /** Renders a line above action buttons to indicate scrollability */
  isTopScrolling?: boolean;
}

const ModalFooter = ({
  primaryButtons,
  secondaryButtons,
  className,
  isTopScrolling = false,
}: IModalFooterProps): JSX.Element => {
  const classes = classnames(className, `${baseClass}__content-wrapper`);

  return (
    <div
      className={classes}
      style={{
        borderTop: isTopScrolling
          ? `1px solid ${COLORS["ui-mobius-black-10"]}`
          : "none",
      }}
    >
      <div className={`${baseClass}__primary-buttons-wrapper`}>
        {primaryButtons}
      </div>
      {secondaryButtons && (
        <div className={`${baseClass}__secondary-buttons-wrapper`}>
          {secondaryButtons}
        </div>
      )}
    </div>
  );
};

export default ModalFooter;
