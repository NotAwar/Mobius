import React, { useContext } from "react";
import { InjectedRouter } from "react-router";
import { Location } from "history";
import { useQuery } from "react-query";
import { AxiosError } from "axios";
import { omit } from "lodash";

import softwareAPI, {
  ISoftwareMobiusMaintainedAppsQueryParams,
  ISoftwareMobiusMaintainedAppsResponse,
} from "services/entities/software";
import { DEFAULT_USE_QUERY_OPTIONS } from "utilities/constants";
import { AppContext } from "context/app";

import Spinner from "components/Spinner";
import DataError from "components/DataError";
import PremiumFeatureMessage from "components/PremiumFeatureMessage";

import MobiusMaintainedAppsTable from "./MobiusMaintainedAppsTable";
import { ISoftwareAddPageQueryParams } from "../SoftwareAddPage";

const baseClass = "software-mobius-maintained";

const DATA_STALE_TIME = 30000;
const QUERY_OPTIONS = {
  keepPreviousData: true,
  staleTime: DATA_STALE_TIME,
};

interface IQueryKey extends ISoftwareMobiusMaintainedAppsQueryParams {
  scope?: "mobius-maintained-apps";
}

interface ISoftwareMobiusMaintainedProps {
  currentTeamId: number;
  router: InjectedRouter;
  location: Location<ISoftwareAddPageQueryParams>;
}

// default values for query params used on this page if not provided
const DEFAULT_SORT_DIRECTION = "asc";
const DEFAULT_SORT_HEADER = "name";
/** Team decision to avoid UI pagination because API needs revamp to properly
 * handle pagination serverside, so rather break API than add more helper logic to
 * handle clientside pagination when we know API will be revamped and would need
 * to convert back to serverside after API fix.
 */
const DEFAULT_PAGE_SIZE = 999;
const DEFAULT_PAGE = 0;

const SoftwareMobiusMaintained = ({
  currentTeamId,
  router,
  location,
}: ISoftwareMobiusMaintainedProps) => {
  const { isPremiumTier } = useContext(AppContext);

  const {
    order_key = DEFAULT_SORT_HEADER,
    order_direction = DEFAULT_SORT_DIRECTION,
    query = "",
    page,
  } = location.query;
  const currentPage = page ? parseInt(page, 10) : DEFAULT_PAGE;

  const { data, isLoading, isFetching, isError } = useQuery<
    ISoftwareMobiusMaintainedAppsResponse,
    AxiosError,
    ISoftwareMobiusMaintainedAppsResponse,
    [IQueryKey]
  >(
    [
      {
        scope: "mobius-maintained-apps",
        page: currentPage,
        per_page: DEFAULT_PAGE_SIZE,
        query,
        order_direction,
        order_key,
        team_id: currentTeamId,
      },
    ],
    ({ queryKey: [queryKey] }) => {
      return softwareAPI.getMobiusMaintainedApps(omit(queryKey, "scope"));
    },
    {
      ...DEFAULT_USE_QUERY_OPTIONS,
      ...QUERY_OPTIONS,
    }
  );

  if (!isPremiumTier) {
    return (
      <PremiumFeatureMessage className={`${baseClass}__premium-message`} />
    );
  }

  if (isLoading) {
    return <Spinner />;
  }

  if (isError) {
    return <DataError verticalPaddingSize="pad-xxxlarge" />;
  }

  return (
    <div className={baseClass}>
      <MobiusMaintainedAppsTable
        data={data}
        isLoading={isFetching}
        router={router}
        query={query}
        teamId={currentTeamId}
        orderDirection={order_direction}
        orderKey={order_key}
        perPage={DEFAULT_PAGE_SIZE}
        currentPage={currentPage}
      />
    </div>
  );
};

export default SoftwareMobiusMaintained;
