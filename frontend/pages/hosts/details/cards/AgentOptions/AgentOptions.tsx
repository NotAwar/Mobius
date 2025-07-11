import React from "react";
import classnames from "classnames";
import TooltipWrapper from "components/TooltipWrapper";

import { secondsToHms } from "utilities/helpers";

import DataSet from "components/DataSet";
import Card from "components/Card";
import CardHeader from "components/CardHeader";

const baseClass = "agent-options-card";
interface IAgentOptionsProps {
  osqueryData: { [key: string]: any };
  wrapMobiusHelper: (helperFn: (value: any) => string, value: string) => string;
  isChromeOS?: boolean;
  className?: string;
}

const CHROMEOS_AGENT_OPTIONS = ["Not supported", "Not supported", "10 secs"];
const CHROMEOS_AGENT_OPTIONS_TOOLTIP_MESSAGE =
  "Chromebooks ignore Mobius’s agent options configuration. The options displayed below are the same for all Chromebooks.";
const AgentOptions = ({
  osqueryData,
  wrapMobiusHelper,
  isChromeOS = false,
  className,
}: IAgentOptionsProps): JSX.Element => {
  const classNames = classnames(baseClass, className, {
    [`${baseClass}__chrome-os`]: isChromeOS,
  });

  let configTLSRefresh;
  let loggerTLSPeriod;
  let distributedInterval;

  if (isChromeOS) {
    [
      configTLSRefresh,
      loggerTLSPeriod,
      distributedInterval,
    ] = CHROMEOS_AGENT_OPTIONS;
  } else {
    configTLSRefresh = wrapMobiusHelper(
      secondsToHms,
      osqueryData.config_tls_refresh
    );
    loggerTLSPeriod = wrapMobiusHelper(
      secondsToHms,
      osqueryData.logger_tls_period
    );
    distributedInterval = wrapMobiusHelper(
      secondsToHms,
      osqueryData.distributed_interval
    );
  }

  return (
    <Card
      borderRadiusSize="xxlarge"
      paddingSize="xlarge"
      includeShadow
      className={classNames}
    >
      <CardHeader
        header={
          isChromeOS ? (
            <TooltipWrapper tipContent={CHROMEOS_AGENT_OPTIONS_TOOLTIP_MESSAGE}>
              Agent options
            </TooltipWrapper>
          ) : (
            "Agent options"
          )
        }
      />
      <div className={`${baseClass}__data`}>
        <DataSet title="Config TLS refresh" value={configTLSRefresh} />
        <DataSet title="Logger TLS period" value={loggerTLSPeriod} />
        <DataSet title="Distributed interval" value={distributedInterval} />
      </div>
    </Card>
  );
};

export default AgentOptions;
