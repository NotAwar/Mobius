import React, {
  useCallback,
  useContext,
  useRef,
  useState,
  useEffect,
} from "react";
import { format } from "date-fns";
import {
  useQuery,
  RefetchOptions,
  RefetchQueryFilters,
  QueryObserverResult,
} from "react-query";
import FileSaver from "file-saver";

import { AppContext } from "context/app";
import { NotificationContext } from "context/notification";
import scriptAPI, { IHostScriptsResponse } from "services/entities/scripts";
import { IHostScript } from "interfaces/script";
import { IApiError, getErrorReason } from "interfaces/errors";

import Modal from "components/Modal";
import ModalFooter from "components/ModalFooter";
import Button from "components/buttons/Button";
import Spinner from "components/Spinner";
import Icon from "components/Icon";
import Textarea from "components/Textarea";
import CustomLink from "components/CustomLink";
import DataError from "components/DataError";
import paths from "router/paths";
import ActionsDropdown from "components/ActionsDropdown";
import { generateActionDropdownOptions } from "pages/hosts/details/HostDetailsPage/modals/RunScriptModal/ScriptsTableConfig";
import GitOpsModeTooltipWrapper from "components/GitOpsModeTooltipWrapper";
import { getPathWithQueryParams } from "utilities/url";
import { IPaginatedListScript } from "pages/hosts/ManageHostsPage/components/RunScriptBatchPaginatedList/RunScriptBatchPaginatedList";

const baseClass = "script-details-modal";

type PartialOrFullHostScript =
  | Pick<IHostScript, "script_id" | "name"> // Use on Scripts page does not include last_execution
  | IHostScript;

interface IScriptDetailsModalProps {
  onCancel: () => void;
  onDelete?: () => void;
  runScriptHelpText?: boolean;
  showHostScriptActions?: boolean;
  setRunScriptRequested?: (value: boolean) => void;
  hostId?: number | null;
  hostTeamId?: number | null;
  refetchHostScripts?: <TPageData>(
    options?: (RefetchOptions & RefetchQueryFilters<TPageData>) | undefined
  ) => Promise<QueryObserverResult<IHostScriptsResponse, IApiError>>;
  selectedScriptDetails?: PartialOrFullHostScript | IPaginatedListScript;
  selectedScriptContent?: string;
  isLoadingScriptContent?: boolean;
  isScriptContentError?: Error | null;
  isHidden?: boolean;
  onClickRunDetails?: (scriptExecutionId: string) => void;
  teamIdForApi?: number;
  suppressSecondaryActions?: boolean;
  customPrimaryButtons?: React.ReactNode;
}

const ScriptDetailsModal = ({
  onCancel,
  onDelete,
  runScriptHelpText = false,
  showHostScriptActions = false,
  setRunScriptRequested,
  hostId,
  hostTeamId,
  refetchHostScripts,
  selectedScriptDetails,
  selectedScriptContent,
  isLoadingScriptContent,
  isScriptContentError,
  isHidden = false,
  onClickRunDetails,
  teamIdForApi,
  suppressSecondaryActions = false,
  customPrimaryButtons,
}: IScriptDetailsModalProps) => {
  // For scrollable modal
  const [isTopScrolling, setIsTopScrolling] = useState(false);
  const topDivRef = useRef<HTMLDivElement>(null);
  const checkScroll = () => {
    if (topDivRef.current) {
      const isScrolling =
        topDivRef.current.scrollHeight > topDivRef.current.clientHeight;
      setIsTopScrolling(isScrolling);
    }
  };

  const { currentUser } = useContext(AppContext);
  const { renderFlash } = useContext(NotificationContext);

  // handle multiple possibilities for `selectedScriptDetails`
  let scriptId: number | null = null;
  if (selectedScriptDetails) {
    if ("script_id" in selectedScriptDetails) {
      scriptId = selectedScriptDetails.script_id;
    } else if ("id" in selectedScriptDetails) {
      scriptId = selectedScriptDetails.id;
    }
  }

  const {
    data: scriptContent,
    error: isSelectedScriptContentError,
    isLoading: isLoadingSelectedScriptContent,
  } = useQuery<any, Error>(
    ["scriptContent", scriptId],
    () =>
      scriptId
        ? // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
          scriptAPI.downloadScript(scriptId)
        : Promise.resolve(null),
    {
      refetchOnWindowFocus: false,
      enabled: !selectedScriptContent && !!scriptId,
    }
  );

  // For scrollable modal
  useEffect(() => {
    checkScroll();
    window.addEventListener("resize", checkScroll);
    return () => window.removeEventListener("resize", checkScroll);
  }, [scriptContent]); // Re-run when data changes

  const getScriptContent = async () => {
    try {
      const content = selectedScriptContent || scriptContent;
      const formatDate = format(new Date(), "yyyy-MM-dd");
      const filename = `${formatDate} ${
        selectedScriptDetails?.name || "Script details"
      }`;
      const file = new File([content], filename);
      FileSaver.saveAs(file);
    } catch {
      renderFlash("error", "Couldn’t Download. Please try again.");
    }
  };

  const onClickDownload = () => {
    if (selectedScriptContent) {
      const formatDate = format(new Date(), "yyyy-MM-dd");
      const filename = `${formatDate} ${selectedScriptDetails?.name}`;
      const file = new File([selectedScriptContent], filename);
      FileSaver.saveAs(file);
    } else {
      getScriptContent();
    }
  };

  const onSelectMoreActions = useCallback(
    async (action: string, script: IHostScript) => {
      if (hostId && !!setRunScriptRequested && !!refetchHostScripts) {
        switch (action) {
          case "showRunDetails": {
            if (script.last_execution?.execution_id) {
              onClickRunDetails &&
                onClickRunDetails(script.last_execution?.execution_id);
            }
            break;
          }
          case "run": {
            try {
              setRunScriptRequested && setRunScriptRequested(true);
              await scriptAPI.runScript({
                host_id: hostId,
                script_id: script.script_id,
              });
              renderFlash(
                "success",
                "Script is running or will run when the host comes online."
              );
              refetchHostScripts();

              onCancel(); // Running a script returns to previous state
            } catch (e) {
              renderFlash("error", getErrorReason(e));
              setRunScriptRequested(false);
            }
            break;
          }
          default: // do nothing
        }
      }
    },
    [
      hostId,
      onClickRunDetails,
      setRunScriptRequested,
      refetchHostScripts,
      renderFlash,
      onCancel,
    ]
  );

  const shouldShowFooter =
    !isLoadingScriptContent && selectedScriptDetails !== undefined;

  const renderFooter = () => {
    if (!shouldShowFooter) {
      return null;
    }

    return (
      <ModalFooter
        isTopScrolling={isTopScrolling}
        secondaryButtons={
          suppressSecondaryActions ? undefined : (
            <>
              <Button
                className={`${baseClass}__action-button`}
                variant="icon"
                onClick={() => onClickDownload()}
              >
                <Icon name="download" />
              </Button>
              <GitOpsModeTooltipWrapper
                position="bottom"
                renderChildren={(disableChildren) => (
                  <Button
                    disabled={disableChildren}
                    className={`${baseClass}__action-button`}
                    variant="icon"
                    onClick={onDelete}
                  >
                    <Icon name="trash" color="ui-mobius-black-75" />
                  </Button>
                )}
              />
            </>
          )
        }
        primaryButtons={
          customPrimaryButtons || (
            <>
              {showHostScriptActions && selectedScriptDetails && (
                <div className={`${baseClass}__manage-automations-wrapper`}>
                  <ActionsDropdown
                    className={`${baseClass}__manage-automations-dropdown`}
                    onChange={(value) =>
                      onSelectMoreActions(
                        value,
                        selectedScriptDetails as IHostScript
                      )
                    }
                    placeholder="More actions"
                    isSearchable={false}
                    options={generateActionDropdownOptions(
                      currentUser,
                      hostTeamId || null,
                      selectedScriptDetails as IHostScript
                    )}
                    menuPlacement="top"
                  />
                </div>
              )}
              <Button onClick={onCancel}>Done</Button>
            </>
          )
        }
      />
    );
  };

  const renderContent = () => {
    if (isLoadingScriptContent || isLoadingSelectedScriptContent) {
      return <Spinner />;
    }

    if (isScriptContentError || isSelectedScriptContentError) {
      return <DataError description="Close this modal and try again." />;
    }

    return (
      <div
        className={`${baseClass}__script-content  modal-scrollable-content`}
        ref={topDivRef}
      >
        <Textarea label="Script content:" variant="code">
          {scriptContent}
        </Textarea>
        {runScriptHelpText && (
          <div className="form-field__help-text">
            To run this script on a host, go to the{" "}
            <CustomLink
              text="Hosts"
              url={getPathWithQueryParams(paths.MANAGE_HOSTS, {
                team_id: teamIdForApi,
              })}
            />{" "}
            page and select a host.
            <br />
            To run the script across multiple hosts, add a policy automation on
            the{" "}
            <CustomLink
              text="Policies"
              url={getPathWithQueryParams(paths.MANAGE_POLICIES, {
                team_id: teamIdForApi,
              })}
            />{" "}
            page.
          </div>
        )}
      </div>
    );
  };

  return (
    <Modal
      className={baseClass}
      title={selectedScriptDetails?.name || "Script details"}
      width="large"
      onExit={onCancel}
      isHidden={isHidden}
    >
      <>
        {renderContent()}
        {shouldShowFooter ? renderFooter() : undefined}
      </>
    </Modal>
  );
};

export default ScriptDetailsModal;
