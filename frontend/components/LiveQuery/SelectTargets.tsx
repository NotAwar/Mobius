import React, { useContext, useEffect, useState, useRef } from "react";
import { Row } from "react-table";
import { useQuery } from "react-query";
import { useDebouncedCallback } from "use-debounce";

import { AppContext } from "context/app";

import { IHost } from "interfaces/host";
import { ILabel, ILabelSummary } from "interfaces/label";
import {
  ITarget,
  ISelectLabel,
  ISelectTeam,
  ISelectTargetsEntity,
  ISelectedTargetsForApi,
} from "interfaces/target";
import { ITeam } from "interfaces/team";

import labelsAPI, { ILabelsSummaryResponse } from "services/entities/labels";
import targetsAPI, {
  ITargetsCountResponse,
  ITargetsSearchResponse,
} from "services/entities/targets";
import teamsAPI, { ILoadTeamsResponse } from "services/entities/teams";
import { formatSelectedTargetsForApi } from "utilities/helpers";
import { capitalize } from "lodash";
import permissions from "utilities/permissions";

import PageError from "components/DataError";
import TargetsInput from "components/LiveQuery/TargetsInput";
import Button from "components/buttons/Button";
import Spinner from "components/Spinner";
import TooltipWrapper from "components/TooltipWrapper";
import SearchField from "components/forms/fields/SearchField";
import RevealButton from "components/buttons/RevealButton";
import TargetPillSelector from "./TargetChipSelector";
import { generateTableHeaders } from "./TargetsInput/TargetsInputHostsTableConfig";

interface ISelectTargetsProps {
  baseClass: string;
  queryId?: number | null;
  selectedTargets: ITarget[];
  targetedHosts: IHost[];
  targetedLabels: ILabel[];
  targetedTeams: ITeam[];
  goToQueryEditor: () => void;
  goToRunQuery: () => void;
  setSelectedTargets: // TODO: Refactor policy targets to streamline selectedTargets/selectedTargetsByType
  | React.Dispatch<React.SetStateAction<ITarget[]>> // Used for policies page level useState hook
    | ((value: ITarget[]) => void); // Used for queries app level QueryContext
  setTargetedHosts: React.Dispatch<React.SetStateAction<IHost[]>>;
  setTargetedLabels: React.Dispatch<React.SetStateAction<ILabel[]>>;
  setTargetedTeams: React.Dispatch<React.SetStateAction<ITeam[]>>;
  setTargetsTotalCount: React.Dispatch<React.SetStateAction<number>>;
  isLivePolicy?: boolean;
  isObserverCanRunQuery?: boolean;
}

interface ILabelsByType {
  allHosts: ILabelSummary[];
  platforms: ILabelSummary[];
  other: ILabelSummary[];
}

interface ITargetsQueryKey {
  scope: string;
  query_id?: number | null;
  query?: string | null;
  selected?: ISelectedTargetsForApi | null;
}

const DEBOUNCE_DELAY = 500;
const STALE_TIME = 60000;
const SECTION_CHARACTER_LIMIT = 600;

const isLabel = (entity: ISelectTargetsEntity) => "label_type" in entity;
const isAllHosts = (entity: ISelectTargetsEntity) =>
  "label_type" in entity &&
  entity.name === "All Hosts" &&
  entity.label_type === "builtin";

const parseLabels = (list?: ILabelSummary[]) => {
  const allHosts = list?.filter((l) => l.name === "All Hosts") || [];
  const platforms =
    list?.filter(
      (l) =>
        l.name === "macOS" ||
        l.name === "MS Windows" ||
        l.name === "All Linux" ||
        l.name === "chrome"
    ) || [];
  const other = list?.filter((l) => l.label_type === "regular") || [];

  return { allHosts, platforms, other };
};

/** Returns the index at which the sum of the names in the list exceed the maximum character length */
const getTruncatedEntityCount = (
  list: ISelectLabel[] | ISelectTeam[],
  maxLength: number
): number => {
  let totalLength = 0;
  let index = 0;
  while (index < list.length && totalLength < maxLength) {
    totalLength += list[index].name.length;
    index += 1;
  }
  return index;
};

const SelectTargets = ({
  baseClass,
  queryId,
  selectedTargets,
  targetedHosts,
  targetedLabels,
  targetedTeams,
  goToQueryEditor,
  goToRunQuery,
  setSelectedTargets,
  setTargetedHosts,
  setTargetedLabels,
  setTargetedTeams,
  setTargetsTotalCount,
  isLivePolicy,
  isObserverCanRunQuery,
}: ISelectTargetsProps): JSX.Element => {
  const isMountedRef = useRef(false);
  const { isPremiumTier, isOnGlobalTeam, currentUser } = useContext(AppContext);

  const [labels, setLabels] = useState<ILabelsByType | null>(null);
  const [searchTextHosts, setSearchTextHosts] = useState("");
  const [searchTextTeams, setSearchTextTeams] = useState("");
  const [searchTextLabels, setSearchTextLabels] = useState("");
  const [isTeamListExpanded, setIsTeamListExpanded] = useState(false);
  const [isLabelsListExpanded, setIsLabelsListExpanded] = useState(false);
  const [debouncedSearchText, setDebouncedSearchText] = useState("");
  const [isDebouncing, setIsDebouncing] = useState(false);

  const debounceSearch = useDebouncedCallback(
    (search: string) => {
      setDebouncedSearchText(search);
      setIsDebouncing(false);
    },
    DEBOUNCE_DELAY,
    { trailing: true }
  );

  const {
    data: teams,
    error: errorTeams,
    isLoading: isLoadingTeams,
  } = useQuery<ILoadTeamsResponse, Error, ITeam[]>(
    ["teams"],
    () => teamsAPI.loadAll(),
    {
      select: (data) => data.teams,
      enabled: isPremiumTier,
      staleTime: STALE_TIME, // TODO: confirm
    }
  );

  const {
    data: labelsSummary,
    error: errorLabels,
    isLoading: isLoadingLabels,
  } = useQuery<ILabelsSummaryResponse, Error, ILabelSummary[]>(
    ["labelsSummary"],
    labelsAPI.summary,
    {
      select: (data) => data.labels,
      staleTime: STALE_TIME, // TODO: confirm
    }
  );

  const {
    data: searchResults,
    isFetching: isFetchingSearchResults,
    error: errorSearchResults,
  } = useQuery<ITargetsSearchResponse, Error, IHost[], ITargetsQueryKey[]>(
    [
      {
        scope: "targetsSearch", // TODO: shared scope?
        query_id: queryId,
        query: debouncedSearchText,
        selected: formatSelectedTargetsForApi(selectedTargets),
      },
    ],
    ({ queryKey }) => {
      const { query_id, query, selected } = queryKey[0];
      return targetsAPI.search({
        query_id: query_id || null,
        query: query || "",
        excluded_host_ids: selected?.hosts || null,
      });
    },
    {
      select: (data) => data.hosts,
      enabled: !!debouncedSearchText,
      // staleTime: 5000, // TODO: try stale time if further performance optimizations are needed
    }
  );

  const {
    data: counts,
    error: errorCounts,
    isFetching: isFetchingCounts,
  } = useQuery<
    ITargetsCountResponse,
    Error,
    ITargetsCountResponse,
    ITargetsQueryKey[]
  >(
    [
      {
        scope: "targetsCount", // Note: Scope is shared with QueryPage?
        query_id: queryId,
        selected: formatSelectedTargetsForApi(selectedTargets),
      },
    ],
    ({ queryKey }) => {
      const { query_id, selected } = queryKey[0];
      return targetsAPI.count({ query_id, selected: selected || null });
    },
    {
      enabled: !!selectedTargets.length,
      onSuccess: (data) => {
        setTargetsTotalCount(data.targets_count || 0);
      },
      staleTime: STALE_TIME, // TODO: confirm
    }
  );

  // Ensure that the team or label list is expanded on the first load only if a hidden entity is already selected
  const shouldExpandList = (
    targetedList: ISelectLabel[] | ISelectTeam[],
    truncatedList: ISelectLabel[] | ISelectTeam[]
  ) => {
    // Set used to improve lookup time
    const truncatedIds = new Set(truncatedList.map((entity) => entity.id));

    // Check if any entity targeted is not in truncated list shown
    return targetedList.some((entity) => !truncatedIds.has(entity.id));
  };

  const expandListsOnInitialLoad = () => {
    if (!isMountedRef.current && teams && labels) {
      const truncatedLabels =
        labels?.other?.slice(
          0,
          getTruncatedEntityCount(labels?.other, SECTION_CHARACTER_LIMIT)
        ) || [];
      const truncatedTeams =
        teams?.slice(
          0,
          getTruncatedEntityCount(teams, SECTION_CHARACTER_LIMIT)
        ) || [];

      if (shouldExpandList(targetedLabels, truncatedLabels)) {
        setIsLabelsListExpanded(true);
      }

      if (shouldExpandList(targetedTeams, truncatedTeams)) {
        setIsTeamListExpanded(true);
      }

      isMountedRef.current = true;
    }
  };

  useEffect(expandListsOnInitialLoad, [
    targetedTeams,
    targetedLabels,
    labels,
    teams,
    isMountedRef,
  ]);

  useEffect(() => {
    const selected = [...targetedHosts, ...targetedLabels, ...targetedTeams];
    setSelectedTargets(selected);
  }, [targetedHosts, targetedLabels, targetedTeams]);

  useEffect(() => {
    labelsSummary && setLabels(parseLabels(labelsSummary));
  }, [labelsSummary]);

  useEffect(() => {
    setIsDebouncing(true);
    debounceSearch(searchTextHosts);
  }, [searchTextHosts]);

  const handleClickCancel = () => {
    goToQueryEditor();
  };

  const handleButtonSelect = (selectedEntity: ISelectTargetsEntity) => (
    e: React.MouseEvent<HTMLButtonElement>
  ): void => {
    e.preventDefault();

    const prevTargets: ISelectTargetsEntity[] = isLabel(selectedEntity)
      ? targetedLabels
      : targetedTeams;

    // if the target was previously selected, we want to remove it now
    let newTargets = prevTargets.filter((t) => t.id !== selectedEntity.id);
    // if the length remains the same, the target was not previously selected so we want to add it now
    prevTargets.length === newTargets.length && newTargets.push(selectedEntity);

    // Logic when to deselect/select "all hosts" when using more granulated filters
    // If "all hosts" is selected
    if (isAllHosts(selectedEntity)) {
      // and "all hosts" is already selected, deselect it
      if (targetedLabels.some((t) => isAllHosts(t))) {
        newTargets = [];
      } // else deselect everything but "all hosts"
      else {
        newTargets = [selectedEntity];
      }
      setTargetedTeams([]);
      setTargetedHosts([]);
    }
    // else deselect "all hosts"
    else {
      if (targetedLabels.some((t) => isAllHosts(t))) {
        setTargetedLabels([]);
      }
      newTargets = newTargets.filter((t) => !isAllHosts(t));
    }

    isLabel(selectedEntity)
      ? setTargetedLabels(newTargets as ILabel[])
      : setTargetedTeams(newTargets as ITeam[]);
  };

  const handleRowSelect = (row: Row<IHost>) => {
    setTargetedHosts((prevHosts) => prevHosts.concat(row.original));
    setSearchTextHosts("");

    // If "all hosts" is already selected when using host target picker, deselect "all hosts"
    if (targetedLabels.some((t) => isAllHosts(t))) {
      setTargetedLabels([]);
    }
  };

  const handleRowRemove = (row: Row<IHost>) => {
    const removedHost = row.original;
    setTargetedHosts((prevHosts) =>
      prevHosts.filter((h) => h.id !== removedHost.id)
    );
  };

  const onClickRun = () => {
    setTargetsTotalCount(counts?.targets_count || 0);
    goToRunQuery();
  };

  const renderTargetEntitySection = (
    entityType: string,
    entityList: ISelectLabel[] | ISelectTeam[]
  ): JSX.Element => {
    const isSearchEnabled = entityType === "teams" || entityType === "labels";
    const searchTerm = (
      (entityType === "teams" ? searchTextTeams : searchTextLabels) || ""
    ).toLowerCase();
    const arrFixed = entityList as Array<typeof entityList[number]>;
    const filteredEntities = isSearchEnabled
      ? arrFixed.filter((entity: ISelectLabel | ISelectTeam) => {
          if (isSearchEnabled) {
            return searchTerm
              ? entity.name.toLowerCase().includes(searchTerm)
              : true;
          }
          return true;
        })
      : arrFixed;

    const isListExpanded =
      entityType === "teams" ? isTeamListExpanded : isLabelsListExpanded;
    const truncatedEntities = filteredEntities.slice(
      0,
      getTruncatedEntityCount(filteredEntities, SECTION_CHARACTER_LIMIT)
    );
    const hiddenEntityCount =
      filteredEntities.length - truncatedEntities.length;

    const toggleExpansion = () => {
      entityType === "teams"
        ? setIsTeamListExpanded(!isTeamListExpanded)
        : setIsLabelsListExpanded(!isLabelsListExpanded);
    };

    const entitiesToDisplay = isListExpanded
      ? filteredEntities
      : truncatedEntities;

    const emptySearchString = `No matching ${entityType}.`;

    const renderEmptySearchString = () => {
      if (entitiesToDisplay.length === 0 && searchTerm !== "") {
        return (
          <div className={`${baseClass}__empty-entity-search`}>
            {emptySearchString}
          </div>
        );
      }
      return undefined;
    };

    return (
      <>
        {entityType && <h3>{capitalize(entityType)}</h3>}
        {isSearchEnabled && (
          <>
            <SearchField
              placeholder={`Search ${entityType}`}
              onChange={(searchString) => {
                entityType === "teams"
                  ? setSearchTextTeams(searchString)
                  : setSearchTextLabels(searchString);
              }}
              clearButton
            />
            {renderEmptySearchString()}
          </>
        )}
        <div className="selector-block">
          {entitiesToDisplay?.map((entity: ISelectLabel | ISelectTeam) => {
            const targetList = isLabel(entity) ? targetedLabels : targetedTeams;
            return (
              <TargetPillSelector
                key={`${isLabel(entity) ? "label" : "team"}__${entity.id}`}
                entity={entity}
                isSelected={targetList.some((t) => t.id === entity.id)}
                onClick={handleButtonSelect}
              />
            );
          })}
        </div>
        {hiddenEntityCount > 0 && (
          <div className="expand-button-wrap">
            <RevealButton
              onClick={toggleExpansion}
              caretPosition="after"
              showText="Show more"
              hideText="Show less"
              isShowing={isListExpanded}
            />
          </div>
        )}
      </>
    );
  };

  const renderTargetsCount = (): JSX.Element | null => {
    if (isFetchingCounts) {
      return (
        <>
          <Spinner
            size="x-small"
            includeContainer={false}
            centered={false}
            className={`${baseClass}__count-spinner`}
          />
          <i style={{ color: "#8b8fa2" }}>Counting hosts</i>
        </>
      );
    }

    if (errorCounts) {
      return (
        <b style={{ color: "#d66c7b", margin: 0 }}>
          There was a problem counting hosts. Please try again later.
        </b>
      );
    }

    if (!counts) {
      return null;
    }

    const { targets_count: total, targets_online: online } = counts;
    const onlinePercentage = () => {
      if (total === 0 || online === 0) {
        return 0;
      }
      // If at least 1 host is online, displays <1% instead of 0%
      const roundPercentage =
        Math.round((online / total) * 100) === 0
          ? "<1"
          : Math.round((online / total) * 100);
      return roundPercentage;
    };

    return (
      <>
        <b>{total.toLocaleString()}</b>&nbsp;host
        {total > 1 || total === 0 ? `s` : ``} targeted&nbsp; (
        {onlinePercentage()}
        %&nbsp;
        <TooltipWrapper
          tipContent={
            <>
              Hosts are online if they <br />
              have recently checked <br />
              into Mobius.
            </>
          }
        >
          online
        </TooltipWrapper>
        ){" "}
      </>
    );
  };

  if (errorLabels || errorTeams) {
    return (
      <div className={`${baseClass}__wrapper`}>
        <h1>Select targets</h1>
        <PageError />
      </div>
    );
  }

  const resultsTableConfig = generateTableHeaders();
  const selectedHostsTableConfig = generateTableHeaders(handleRowRemove);

  // Filter out observer teams that break live query/policy API
  const filterTeamObserverTeams = () => {
    // API blocks live policy if a team level user is able to select the team they are an observer on
    if (isLivePolicy) {
      return (
        teams?.filter(
          (team) =>
            !permissions.isTeamObserver(currentUser, team.id) ||
            permissions.isTeamObserverPlus(currentUser, team.id)
        ) || []
      );
    }

    // API blocks live query if a team level user is able to select the team they are an observer on
    // AND the query does not have observer can run enabled
    return (
      teams?.filter(
        (team) =>
          !permissions.isTeamObserver(currentUser, team.id) ||
          permissions.isTeamObserverPlus(currentUser, team.id) ||
          isObserverCanRunQuery
      ) || []
    );
  };

  if (isLoadingLabels || isLoadingTeams) {
    return <Spinner />;
  }

  return (
    <div className={`${baseClass}__wrapper`}>
      <h1>Select targets</h1>
      <div className={`${baseClass}__target-selectors`}>
        {!!labels?.allHosts.length &&
          renderTargetEntitySection("", labels.allHosts)}
        {!!labels?.platforms?.length &&
          renderTargetEntitySection("Platforms", labels.platforms)}
        {!!teams?.length &&
          (isOnGlobalTeam
            ? renderTargetEntitySection("teams", [
                { id: 0, name: "No team" },
                ...teams,
              ])
            : renderTargetEntitySection("teams", filterTeamObserverTeams()))}
        {!!labels?.other?.length &&
          renderTargetEntitySection("labels", labels.other)}
      </div>
      <TargetsInput
        autofocus
        searchResultsTableConfig={resultsTableConfig}
        selectedHostsTableConifg={selectedHostsTableConfig}
        searchText={searchTextHosts}
        searchResults={searchResults || []}
        isTargetsLoading={isFetchingSearchResults || isDebouncing}
        targetedHosts={targetedHosts}
        hasFetchError={!!errorSearchResults}
        setSearchText={setSearchTextHosts}
        handleRowSelect={handleRowSelect}
        disablePagination
      />
      <div className={`${baseClass}__targets-button-wrap`}>
        <Button
          className={`${baseClass}__btn`}
          onClick={handleClickCancel}
          variant="text-link"
        >
          Cancel
        </Button>
        <Button
          className={`${baseClass}__btn`}
          type="button"
          variant="success"
          disabled={isFetchingCounts || !counts?.targets_count} // TODO: confirm
          onClick={onClickRun}
        >
          Run
        </Button>
        <div className={`${baseClass}__targets-total-count`}>
          {renderTargetsCount()}
        </div>
      </div>
    </div>
  );
};

export default SelectTargets;
