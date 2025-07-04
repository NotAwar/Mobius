import React, { useState, useContext } from "react";
import { Tab, Tabs, TabList, TabPanel } from "react-tabs";
import classnames from "classnames";
import FileSaver from "file-saver";
import { get } from "lodash";
import { PolicyContext } from "context/policy";

import {
  generateCSVFilename,
  generateCSVPolicyResults,
  generateCSVPolicyErrors,
} from "utilities/generate_csv";
import { ICampaign } from "interfaces/campaign";
import { ITarget } from "interfaces/target";

import Button from "components/buttons/Button";
import Icon from "components/Icon/Icon";
import TabNav from "components/TabNav";
import TabText from "components/TabText";
import InfoBanner from "components/InfoBanner";
import ShowQueryModal from "components/modals/ShowQueryModal";
import TooltipWrapper from "components/TooltipWrapper";

import LiveResultsHeading from "components/queries/LiveResults/LiveResultsHeading";
import AwaitingResults from "components/queries/LiveResults/AwaitingResults";

import PolicyResultsTable from "../PolicyResultsTable/PolicyResultsTable";
import PolicyQueriesErrorsTable from "../PolicyErrorsTable/PolicyErrorsTable";
import { getYesNoCounts } from "./helpers";

interface IPolicyResultsProps {
  campaign: ICampaign;
  isQueryFinished: boolean;
  policyName?: string;
  onRunQuery: (evt: React.MouseEvent<HTMLButtonElement>) => void;
  onStopQuery: (evt: React.MouseEvent<HTMLButtonElement>) => void;
  setSelectedTargets: (value: ITarget[]) => void;
  goToQueryEditor: () => void;
  targetsTotalCount: number;
}

const baseClass = "query-results";
const CSV_TITLE = "New Policy";
const NAV_TITLES = {
  RESULTS: "Results",
  ERRORS: "Errors",
};

const PolicyResults = ({
  campaign,
  isQueryFinished,
  policyName,
  onRunQuery,
  onStopQuery,
  setSelectedTargets,
  goToQueryEditor,
  targetsTotalCount,
}: IPolicyResultsProps): JSX.Element => {
  const { lastEditedQueryBody } = useContext(PolicyContext);

  const { hosts: hostResponses, uiHostCounts, serverHostCounts, errors } =
    campaign || {};

  const totalRowsCount = get(campaign, ["hosts_count", "successful"], 0);

  const [navTabIndex, setNavTabIndex] = useState(0);
  const [showQueryModal, setShowQueryModal] = useState(false);

  const onExportResults = (evt: React.MouseEvent<HTMLButtonElement>) => {
    evt.preventDefault();

    if (hostResponses) {
      const hostsExport = hostResponses.map((host) => {
        return {
          host: host.display_name,
          status:
            host.query_results && host.query_results.length ? "yes" : "no",
        };
      });

      FileSaver.saveAs(
        generateCSVPolicyResults(
          hostsExport,
          generateCSVFilename(`${policyName || CSV_TITLE} - Results`)
        )
      );
    }
  };

  const onExportErrorsResults = (evt: React.MouseEvent<HTMLButtonElement>) => {
    evt.preventDefault();

    if (errors) {
      FileSaver.saveAs(
        generateCSVPolicyErrors(
          errors,
          generateCSVFilename(`${policyName || CSV_TITLE} - Errors`)
        )
      );
    }
  };

  const onShowQueryModal = () => {
    setShowQueryModal(!showQueryModal);
  };

  const onQueryDone = () => {
    setSelectedTargets([]);
    goToQueryEditor();
  };

  const renderTableButtons = (tableType: "results" | "errors") => {
    return (
      <div className={`${baseClass}__results-cta`}>
        <Button
          className={`${baseClass}__show-query-btn`}
          onClick={onShowQueryModal}
          variant="text-icon"
        >
          <>
            Show query <Icon name="eye" />
          </>
        </Button>
        <Button
          className={`${baseClass}__export-btn`}
          onClick={
            tableType === "errors" ? onExportErrorsResults : onExportResults
          }
          variant="text-icon"
        >
          <>
            Export {tableType}
            <Icon name="download" color="core-mobius-blue" />
          </>
        </Button>
      </div>
    );
  };

  const renderPassFailPcts = () => {
    const { yes: yesCt, no: noCt } = getYesNoCounts(hostResponses);
    return (
      <span className={`${baseClass}__results-pass-fail-pct`}>
        {" "}
        (Yes:{" "}
        <TooltipWrapper tipContent={`${yesCt} host${yesCt !== 1 ? "s" : ""}`}>
          {Math.round((yesCt / uiHostCounts.successful) * 100)}%
        </TooltipWrapper>
        , No:{" "}
        <TooltipWrapper tipContent={`${noCt} host${noCt !== 1 ? "s" : ""}`}>
          {Math.round((noCt / uiHostCounts.successful) * 100)}%
        </TooltipWrapper>
        )
      </span>
    );
  };

  const renderResultsTable = () => {
    const emptyResults =
      !hostResponses || !hostResponses.length || !uiHostCounts.successful;
    const hasNoResultsYet = !isQueryFinished && emptyResults;
    const finishedWithNoResults =
      isQueryFinished && (!uiHostCounts.successful || emptyResults);

    if (hasNoResultsYet) {
      return <AwaitingResults />;
    }

    if (finishedWithNoResults) {
      return (
        <p className="no-results-message">
          Your live query returned no results.
          <span>
            Expecting to see results? Check to see if the host
            {`${targetsTotalCount > 1 ? "s" : ""}`} you targeted reported
            &ldquo;Online&rdquo; or check out the &ldquo;Errors&rdquo; table.
          </span>
        </p>
      );
    }

    return (
      <div className={`${baseClass}__results-table-container`}>
        <InfoBanner>
          Hosts that responded with results are marked <strong>Yes</strong>.
          Hosts that responded with no results are marked <strong>No</strong>.
        </InfoBanner>
        <div className={`${baseClass}__results-table-header`}>
          <span className={`${baseClass}__results-meta`}>
            <span className={`${baseClass}__results-count`}>
              {uiHostCounts.successful} result
              {uiHostCounts.successful !== 1 && "s"}
            </span>
            {isQueryFinished && renderPassFailPcts()}
          </span>
          <div className={`${baseClass}__results-cta`}>
            {renderTableButtons("results")}
          </div>
        </div>
        <PolicyResultsTable
          isLoading={false}
          hostResponses={hostResponses}
          resultsTitle="hosts"
        />
      </div>
    );
  };

  const renderErrorsTable = () => {
    return (
      <div className={`${baseClass}__error-table-container`}>
        <div className={`${baseClass}__errors-table-header`}>
          {errors && (
            <span className={`${baseClass}__error-count`}>
              {errors.length} error{errors.length !== 1 && "s"}
            </span>
          )}
          <div className={`${baseClass}__errors-cta`}>
            {renderTableButtons("errors")}
          </div>
        </div>
        <PolicyQueriesErrorsTable
          isLoading={false}
          errorsList={errors}
          resultsTitle="errors"
        />
      </div>
    );
  };

  const firstTabClass = classnames("react-tabs__tab", "no-count", {
    "errors-empty": !errors || errors?.length === 0,
  });

  return (
    <div className={baseClass}>
      <LiveResultsHeading
        numHostsTargeted={targetsTotalCount}
        numHostsResponded={uiHostCounts.total}
        numHostsRespondedResults={serverHostCounts.countOfHostsWithResults}
        numHostsRespondedNoErrorsAndNoResults={
          serverHostCounts.countOfHostsWithNoResults
        }
        numHostsRespondedErrors={uiHostCounts.failed}
        isFinished={isQueryFinished}
        onClickDone={onQueryDone}
        onClickRunAgain={onRunQuery}
        onClickStop={onStopQuery}
        resultsType="policy"
      />
      <TabNav>
        <Tabs selectedIndex={navTabIndex} onSelect={(i) => setNavTabIndex(i)}>
          <TabList>
            <Tab className={firstTabClass}>
              <TabText>{NAV_TITLES.RESULTS}</TabText>
            </Tab>
            <Tab disabled={!errors?.length}>
              <TabText count={errors?.length} isErrorCount>
                {NAV_TITLES.ERRORS}
              </TabText>
            </Tab>
          </TabList>
          <TabPanel>{renderResultsTable()}</TabPanel>
          <TabPanel>{renderErrorsTable()}</TabPanel>
        </Tabs>
      </TabNav>
      {showQueryModal && (
        <ShowQueryModal
          query={lastEditedQueryBody}
          onCancel={onShowQueryModal}
        />
      )}
    </div>
  );
};

export default PolicyResults;
