import React, { useState } from "react";

import Button from "components/buttons/Button";
// @ts-ignore
import InputField from "components/forms/fields/InputField";
import validUrl from "components/forms/validators/valid_url";
import SectionHeader from "components/SectionHeader";
import GitOpsModeTooltipWrapper from "components/GitOpsModeTooltipWrapper";
import CustomLink from "components/CustomLink";

import {
  DEFAULT_TRANSPARENCY_URL,
  IAppConfigFormProps,
  IFormField,
} from "../constants";

interface IMobiusDesktopFormData {
  transparencyUrl: string;
}
interface IMobiusDesktopFormErrors {
  transparency_url?: string | null;
}
const baseClass = "app-config-form";

const MobiusDesktop = ({
  appConfig,
  handleSubmit,
  isPremiumTier,
  isUpdatingSettings,
}: IAppConfigFormProps): JSX.Element => {
  const gitOpsModeEnabled = appConfig.gitops.gitops_mode_enabled;

  const [formData, setFormData] = useState<IMobiusDesktopFormData>({
    transparencyUrl:
      appConfig.mobius_desktop?.transparency_url || DEFAULT_TRANSPARENCY_URL,
  });

  const [formErrors, setFormErrors] = useState<IMobiusDesktopFormErrors>({});

  const onInputChange = ({ value }: IFormField) => {
    setFormData({ transparencyUrl: value.toString() });
    setFormErrors({});
  };

  const validateForm = () => {
    const { transparencyUrl } = formData;

    const errors: IMobiusDesktopFormErrors = {};
    if (transparencyUrl && !validUrl({ url: transparencyUrl })) {
      errors.transparency_url = `${transparencyUrl} is not a valid URL`;
    }

    setFormErrors(errors);
  };

  const onFormSubmit = (evt: React.MouseEvent<HTMLFormElement>) => {
    evt.preventDefault();

    const formDataForAPI = {
      mobius_desktop: {
        transparency_url: formData.transparencyUrl,
      },
    };

    handleSubmit(formDataForAPI);
  };

  if (!isPremiumTier) {
    return <></>;
  }

  return (
    <div className={baseClass}>
      <div className={`${baseClass}__section`}>
        <SectionHeader title="Mobius Desktop" />
        <form onSubmit={onFormSubmit} autoComplete="off">
          <p className={`${baseClass}__section-description`}>
            When an end user clicks “About Mobius” in the Mobius Desktop menu,
            by default they are taken to{" "}
            <CustomLink
              url="https://mobius-mdm.org/transparency"
              text="https://mobius-mdm.org/transparency"
              newTab
              multiline
            />{" "}
            . You can override the URL to take them to a resource of your
            choice.
          </p>
          <InputField
            label="Custom transparency URL"
            onChange={onInputChange}
            name="transparency_url"
            value={formData.transparencyUrl}
            parseTarget
            onBlur={validateForm}
            error={formErrors.transparency_url}
            placeholder="https://mobius-mdm.org/transparency"
            disabled={gitOpsModeEnabled}
          />
          <GitOpsModeTooltipWrapper
            tipOffset={-8}
            renderChildren={(disableChildren) => (
              <Button
                type="submit"
                disabled={Object.keys(formErrors).length > 0 || disableChildren}
                className="button-wrap"
                isLoading={isUpdatingSettings}
              >
                Save
              </Button>
            )}
          />
        </form>
      </div>
    </div>
  );
};

export default MobiusDesktop;
