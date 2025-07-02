import React from "react";

import CustomLink from "components/CustomLink";
import Icon from "components/Icon";

const baseClass = "learn-mobius";

const LearnMobius = (): JSX.Element => {
  return (
    <div className={baseClass}>
      <div className={`${baseClass}__content`}>
        <div className={`${baseClass}__icon`}>
          <Icon name="external-link" size="medium" />
        </div>
        <div className={`${baseClass}__text`}>
          <h3>Learn how to use Mobius MDM</h3>
          <p>
            Get started with Mobius device management by exploring our guides
            and documentation. Learn how to deploy configurations, manage
            policies, and secure your devices.
          </p>
        </div>
        <div className={`${baseClass}__actions`}>
          <CustomLink
            url="https://mobius-mdm.org/docs"
            text="Read the docs"
            newTab
            className={`${baseClass}__link`}
          />
        </div>
      </div>
    </div>
  );
};

export default LearnMobius;
