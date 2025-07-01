import React from "react";

import { formatScriptNameForActivityItem } from "utilities/helpers";

import ActivityItem from "components/ActivityItem";
import { IHostActivityItemComponentPropsWithShowDetails } from "../../ActivityConfig";

const baseClass = "ran-script-activity-item";

const RanScriptActivityItem = ({
  tab,
  activity,
  onShowDetails,
  onCancel,
  isSoloActivity,
  hideCancel,
}: IHostActivityItemComponentPropsWithShowDetails) => {
  let ranScriptPrefix = tab === "past" ? "ran" : "told Mobius to run";
  if (tab !== "past" && activity.mobius_initiated) {
    ranScriptPrefix = "will run";
  }

  return (
    <ActivityItem
      className={baseClass}
      activity={activity}
      onShowDetails={onShowDetails}
      onCancel={onCancel}
      isSoloActivity={isSoloActivity}
      hideCancel={hideCancel}
    >
      <b>{activity.actor_full_name ?? "Mobius"}</b>
      <>
        {" "}
        {ranScriptPrefix}{" "}
        {formatScriptNameForActivityItem(activity.details?.script_name)} on this
        host.{" "}
      </>
    </ActivityItem>
  );
};

export default RanScriptActivityItem;
