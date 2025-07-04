import React from "react";
import classnames from "classnames";

import MobiusIcon from "components/icons/MobiusIcon";
import platformIconClass from "utilities/platform_icon_class";

interface IPlatformIconProps {
  className?: string;
  fw?: boolean;
  name: string;
  size?: string;
  title?: string;
}

const baseClass = "platform-icon";

const PlatformIcon = ({
  className,
  name,
  fw,
  size,
  title,
}: IPlatformIconProps): JSX.Element => {
  const iconClasses = classnames(baseClass, className);
  let iconName = platformIconClass(name);

  if (!iconName) {
    iconName = "single-host";
  }

  return (
    <MobiusIcon
      className={iconClasses}
      fw={fw}
      name={iconName}
      size={size}
      title={title}
    />
  );
};

export default PlatformIcon;
