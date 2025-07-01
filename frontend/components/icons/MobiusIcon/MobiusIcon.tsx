import React from "react";
import classnames from "classnames";

interface IMobiusIconProps {
  className?: string;
  fw?: boolean;
  name: string;
  size?: string;
  title?: string;
}

const baseClass = "mobiusicon";

const MobiusIcon = ({
  className,
  fw,
  name,
  size,
  title,
}: IMobiusIconProps): JSX.Element => {
  const iconClasses = classnames(baseClass, `${baseClass}-${name}`, className, {
    [`${baseClass}-fw`]: fw,
    [`${baseClass}-${size}`]: !!size,
  });

  return <i className={iconClasses} title={title} />;
};

export default MobiusIcon;
