import React from "react";

import { uniqueId } from "lodash";
import { humanLastSeen, internationalTimeFormat } from "utilities/helpers";
import { INITIAL_MOBIUS_DATE } from "utilities/constants";
import ReactTooltip, { Place } from "react-tooltip";

interface IHumanTimeDiffWithDateTip {
  timeString: string;
  cutoffBeforeMobiusLaunch?: boolean;
  tooltipPosition?: Place;
}

/** Returns "Unavailable" if date is empty string or "Unavailable"
 * Returns "Invalid date" if date is invalid
 * Returns "Never" if cutoffBeforeMobiusLaunch is true and date is before the
 * initial launch of Mobius */
export const HumanTimeDiffWithDateTip = ({
  timeString,
  cutoffBeforeMobiusLaunch = false,
  tooltipPosition = "top",
}: IHumanTimeDiffWithDateTip): JSX.Element => {
  const id = uniqueId();

  if (timeString === "Unavailable" || timeString === "") {
    return <span>Unavailable</span>;
  }

  // There are cases where dates are set in Mobius to be the "zero date" which
  // serves as an indicator that a particular date isn't set.
  if (cutoffBeforeMobiusLaunch && timeString < INITIAL_MOBIUS_DATE) {
    return <span>Never</span>;
  }

  try {
    return (
      <>
        <span className="date-tooltip" data-tip data-for={`tooltip-${id}`}>
          {humanLastSeen(timeString)}
        </span>
        <ReactTooltip
          className="date-tooltip-text"
          place={tooltipPosition}
          type="dark"
          effect="solid"
          id={`tooltip-${id}`}
          backgroundColor="#3e4771"
        >
          {internationalTimeFormat(new Date(timeString))}
        </ReactTooltip>
      </>
    );
  } catch (e) {
    if (e instanceof RangeError) {
      return <span>Invalid date</span>;
    }
    return <span>Unavailable</span>;
  }
};

/** Returns a HumanTimeDiffWithDateTip configured to return "Never" in the case
 * that the timeString is before the launch date of Mobius */
export const HumanTimeDiffWithMobiusLaunchCutoff = ({
  timeString,
}: IHumanTimeDiffWithDateTip): JSX.Element => {
  return (
    <HumanTimeDiffWithDateTip timeString={timeString} cutoffBeforeMobiusLaunch />
  );
};
