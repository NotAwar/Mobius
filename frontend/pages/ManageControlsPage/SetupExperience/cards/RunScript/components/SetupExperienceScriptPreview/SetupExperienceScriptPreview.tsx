import React from "react";

import Card from "components/Card";

import SetupExperienceRunScriptPreview from "../../../../../../../../assets/images/mobius-logo.png";

const baseClass = "setup-experience-script-preview";

const SetupExperienceScriptPreview = () => {
  return (
    <Card color="grey" paddingSize="xxlarge" className={baseClass}>
      <h3>End user experience</h3>
      <p>
        After software is installed, the end user will see the script being run.
        They will not be able to continue until the script runs.
      </p>
      <p>
        If there are any errors, they will be able to continue and will be
        instructed to contact their IT admin.
      </p>
      <img
        className={`${baseClass}__preview-img`}
        src={SetupExperienceRunScriptPreview}
        alt="End user experience during the macOS setup assistant with the uploaded
        script being run"
      />
    </Card>
  );
};

export default SetupExperienceScriptPreview;
