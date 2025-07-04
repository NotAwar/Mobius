import React, { useMemo, useState } from "react";
import { Tab, Tabs, TabList, TabPanel } from "react-tabs";

import {
  IMunkiIssuesAggregate,
  IMunkiVersionsAggregate,
} from "interfaces/macadmins";

import TabNav from "components/TabNav";
import TabText from "components/TabText";
import TableContainer from "components/TableContainer";
import Spinner from "components/Spinner";
import TableDataError from "components/DataError";
import EmptyTable from "components/EmptyTable";
import CustomLink from "components/CustomLink";

import munkiVersionsTableHeaders from "./MunkiVersionsTableConfig";
import generateMunkiIssuesTableHeaders from "./MunkiIssuesTableConfig";

interface IMunkiCardProps {
  errorMacAdmins: Error | null;
  isMacAdminsFetching: boolean;
  munkiIssuesData: IMunkiIssuesAggregate[];
  munkiVersionsData: IMunkiVersionsAggregate[];
  selectedTeamId?: number;
}

const DEFAULT_SORT_DIRECTION = "desc";
const DEFAULT_SORT_HEADER = "hosts_count";
const PAGE_SIZE = 8;
const baseClass = "home-munki";

const Munki = ({
  errorMacAdmins,
  isMacAdminsFetching,
  munkiIssuesData,
  munkiVersionsData,
  selectedTeamId,
}: IMunkiCardProps): JSX.Element => {
  const [navTabIndex, setNavTabIndex] = useState<number>(0);

  const tableHeaders = useMemo(
    () => generateMunkiIssuesTableHeaders(selectedTeamId),
    [selectedTeamId]
  );

  const onTabChange = (index: number) => {
    setNavTabIndex(index);
  };

  // Renders opaque information as host information is loading
  const opacity = isMacAdminsFetching ? { opacity: 0 } : { opacity: 1 };

  return (
    <div className={baseClass}>
      {isMacAdminsFetching && (
        <div className="spinner">
          <Spinner />
        </div>
      )}
      <div style={opacity}>
        <TabNav>
          <Tabs selectedIndex={navTabIndex} onSelect={onTabChange}>
            <TabList>
              <Tab>
                <TabText>Issues</TabText>
              </Tab>
              <Tab>
                <TabText>Versions</TabText>
              </Tab>
            </TabList>
            <TabPanel>
              {errorMacAdmins ? (
                <TableDataError verticalPaddingSize="pad-large" />
              ) : (
                <TableContainer
                  columnConfigs={tableHeaders}
                  data={munkiIssuesData || []}
                  isLoading={isMacAdminsFetching}
                  defaultSortHeader={DEFAULT_SORT_HEADER}
                  defaultSortDirection={DEFAULT_SORT_DIRECTION}
                  resultsTitle="Munki"
                  emptyComponent={() => (
                    <EmptyTable
                      header="No Munki issues detected"
                      info="This report is updated every hour to protect the performance of your
      devices."
                    />
                  )}
                  showMarkAllPages={false}
                  isAllPagesSelected={false}
                  isClientSidePagination
                  disableCount
                  disablePagination
                  pageSize={PAGE_SIZE}
                />
              )}
            </TabPanel>
            <TabPanel>
              {errorMacAdmins ? (
                <TableDataError verticalPaddingSize="pad-large" />
              ) : (
                <TableContainer
                  columnConfigs={munkiVersionsTableHeaders}
                  data={munkiVersionsData || []}
                  isLoading={isMacAdminsFetching}
                  defaultSortHeader={DEFAULT_SORT_HEADER}
                  defaultSortDirection={DEFAULT_SORT_DIRECTION}
                  resultsTitle="Munki"
                  emptyComponent={() => (
                    <EmptyTable
                      header="Unable to detect Munki versions"
                      info={
                        <>
                          To see Munki versions, deploy&nbsp;
                          <CustomLink
                            url="https://mobius-mdm.org/learn-more-about/mobiusdaemon"
                            text="Mobius's agent (mobiusdaemon)"
                            newTab
                          />
                          .
                        </>
                      }
                    />
                  )}
                  showMarkAllPages={false}
                  isAllPagesSelected={false}
                  isClientSidePagination
                  disableCount
                  disablePagination
                  pageSize={PAGE_SIZE}
                />
              )}
            </TabPanel>
          </Tabs>
        </TabNav>
      </div>
    </div>
  );
};

export default Munki;
