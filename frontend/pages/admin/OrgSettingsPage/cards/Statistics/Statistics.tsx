import React, { useState } from "react";

import Button from "components/buttons/Button";
import Checkbox from "components/forms/fields/Checkbox";
import SectionHeader from "components/SectionHeader";

import CustomLink from "components/CustomLink";
import GitOpsModeTooltipWrapper from "components/GitOpsModeTooltipWrapper";

import { IAppConfigFormProps, IFormField } from "../constants";

const baseClass = "app-config-form";

interface IStatisticsFormData {
  enableUsageStatistics: boolean;
}

const Statistics = ({
  appConfig,
  handleSubmit,
  isPremiumTier,
  isUpdatingSettings,
}: IAppConfigFormProps): JSX.Element => {
  const [formData, setFormData] = useState<IStatisticsFormData>({
    enableUsageStatistics: appConfig.server_settings.enable_analytics,
  });

  const { enableUsageStatistics } = formData;

  const onInputChange = ({ name, value }: IFormField) => {
    setFormData({ ...formData, [name]: value });
  };

  const onFormSubmit = (evt: React.MouseEvent<HTMLFormElement>) => {
    evt.preventDefault();

    // Formatting of API not UI
    const formDataToSubmit = {
      server_settings: {
        enable_analytics: enableUsageStatistics,
        deferred_save_host: appConfig.server_settings.deferred_save_host,
        query_reports_disabled:
          appConfig.server_settings.query_reports_disabled,
        scripts_disabled: appConfig.server_settings.scripts_disabled,
      },
    };

    handleSubmit(formDataToSubmit);
  };

  const telemetryAlwaysEnabled =
    isPremiumTier && !appConfig.license.allow_disable_telemetry;

  return (
    <div className={baseClass}>
      <div className={`${baseClass}__section`}>
        <SectionHeader title="Usage statistics" />
        <form onSubmit={onFormSubmit} autoComplete="off">
          <p className={`${baseClass}__section-description`}>
            Help us improve Mobius by sending us anonymous usage statistics.
            <br />
            <br />
            This information helps our team better understand feature adoption
            and usage, and allows us to see how Mobius is adding value, so that
            we can make better product decisions. Mobius Pro customers always
            submit usage statistics data.
            <br />
            <br />
            <CustomLink
              url="https://mobius-mdm.org/docs/using-mobius/usage-statistics#usage-statistics"
              text="Learn more about usage statistics"
              newTab
            />
          </p>
          <Checkbox
            onChange={onInputChange}
            name="enableUsageStatistics"
            value={telemetryAlwaysEnabled ? true : enableUsageStatistics} // Set to true for all premium customers
            parseTarget
            disabled={telemetryAlwaysEnabled}
          >
            Enable usage statistics
          </Checkbox>
          <GitOpsModeTooltipWrapper
            tipOffset={-8}
            renderChildren={(disableChildren) => (
              <Button
                type="submit"
                disabled={disableChildren}
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

export default Statistics;
