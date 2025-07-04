// Used on: Dashboard > activity, Host details > past activity
// Also used on Self-service failed install details

import React from "react";
import { useQuery } from "react-query";
import { formatDistanceToNow } from "date-fns";
import { AxiosError } from "axios";

import { IActivityDetails } from "interfaces/activity";
import {
  ISoftwareInstallResult,
  ISoftwareInstallResults,
} from "interfaces/software";
import softwareAPI from "services/entities/software";
import deviceUserAPI from "services/entities/device_user";

import Modal from "components/Modal";
import Button from "components/buttons/Button";
import Icon from "components/Icon";
import Textarea from "components/Textarea";
import DataError from "components/DataError/DataError";
import DeviceUserError from "components/DeviceUserError";
import Spinner from "components/Spinner/Spinner";
import {
  INSTALL_DETAILS_STATUS_ICONS,
  SOFTWARE_INSTALL_OUTPUT_DISPLAY_LABELS,
  getInstallDetailsStatusPredicate,
} from "../constants";

const baseClass = "software-install-details";

// TODO: Expand to include more details as needed
export type IPackageInstallDetails = Pick<
  IActivityDetails,
  "install_uuid" | "host_display_name"
> & {
  deviceAuthToken?: string;
};

const StatusMessage = ({
  result: {
    host_display_name,
    software_package,
    software_title,
    status,
    updated_at,
    created_at,
  },
}: {
  result: ISoftwareInstallResult;
}) => {
  const formattedHost = host_display_name ? (
    <b>{host_display_name}</b>
  ) : (
    "the host"
  );

  // TODO: Potential implementation HumanTimeDiffWithDateTip for consistency
  // Design currently looks weird since displayTimeStamp might split to multiple lines
  const timeStamp = updated_at || created_at;
  const displayTimeStamp = ["failed_install", "installed"].includes(
    status || ""
  )
    ? ` (${formatDistanceToNow(new Date(timeStamp), {
        includeSeconds: true,
        addSuffix: true,
      })})`
    : "";
  return (
    <div className={`${baseClass}__status-message`}>
      <Icon name={INSTALL_DETAILS_STATUS_ICONS[status] ?? "pending-outline"} />
      <span>
        Mobius {getInstallDetailsStatusPredicate(status)}{" "}
        <b>{software_title}</b> ({software_package}) on {formattedHost}
        {status === "pending_install" ? " when it comes online" : ""}
        {displayTimeStamp}.
      </span>
    </div>
  );
};

const Output = ({
  displayKey,
  result,
}: {
  displayKey: keyof typeof SOFTWARE_INSTALL_OUTPUT_DISPLAY_LABELS;
  result: ISoftwareInstallResult;
}) => {
  return (
    <Textarea
      label={`${SOFTWARE_INSTALL_OUTPUT_DISPLAY_LABELS[displayKey]}:`}
      variant="code"
    >
      {result[displayKey]}
    </Textarea>
  );
};

export const SoftwareInstallDetails = ({
  host_display_name = "",
  install_uuid = "",
  deviceAuthToken,
}: IPackageInstallDetails) => {
  const { data: result, isLoading, isError, error } = useQuery<
    ISoftwareInstallResults,
    AxiosError,
    ISoftwareInstallResult
  >(
    ["softwareInstallResults", install_uuid],
    () => {
      return deviceAuthToken
        ? deviceUserAPI.getSoftwareInstallResult(deviceAuthToken, install_uuid)
        : softwareAPI.getSoftwareInstallResult(install_uuid);
    },
    {
      refetchOnWindowFocus: false,
      staleTime: 3000,
      select: (data) => data.results,
      retry: (failureCount, err) => err?.status !== 404 && failureCount < 3,
    }
  );

  if (isLoading) {
    return <Spinner />;
  }

  if (isError) {
    if (error?.status === 404) {
      return deviceAuthToken ? (
        <DeviceUserError />
      ) : (
        <DataError
          description="Install details are no longer available for this activity."
          excludeIssueLink
        />
      );
    }

    if (error?.status === 401) {
      return deviceAuthToken ? (
        <DeviceUserError />
      ) : (
        <DataError description="Close this modal and try again." />
      );
    }
  }

  if (!result) {
    // FIXME: Find a better solution for this.
    return deviceAuthToken ? (
      <DeviceUserError />
    ) : (
      <DataError description="No data returned." />
    );
  }

  return (
    <>
      <StatusMessage
        result={
          result.host_display_name ? result : { ...result, host_display_name } // prefer result.host_display_name (it may be empty if the host was deleted) otherwise default to whatever we received via props
        }
      />
      {result.status !== "pending_install" && (
        <>
          {result.pre_install_query_output && (
            <Output displayKey="pre_install_query_output" result={result} />
          )}
          {result.output && <Output displayKey="output" result={result} />}
          {result.post_install_script_output && (
            <Output displayKey="post_install_script_output" result={result} />
          )}
        </>
      )}
    </>
  );
};

export const SoftwareInstallDetailsModal = ({
  details,
  onCancel,
  deviceAuthToken,
}: {
  details: IPackageInstallDetails;
  onCancel: () => void;
  deviceAuthToken?: string;
}) => {
  return (
    <Modal
      title="Install details"
      onExit={onCancel}
      onEnter={onCancel}
      className={baseClass}
    >
      <>
        <div className={`${baseClass}__modal-content`}>
          <SoftwareInstallDetails
            {...details}
            deviceAuthToken={deviceAuthToken}
          />
        </div>
        <div className="modal-cta-wrap">
          <Button onClick={onCancel}>Done</Button>
        </div>
      </>
    </Modal>
  );
};
