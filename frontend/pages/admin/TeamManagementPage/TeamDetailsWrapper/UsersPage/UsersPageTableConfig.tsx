import React from "react";

import stringUtils from "utilities/strings";
import { IUser, UserRole } from "interfaces/user";
import { ITeam } from "interfaces/team";
import { IDropdownOption } from "interfaces/dropdownOption";

import TextCell from "components/TableContainer/DataTable/TextCell/TextCell";
import TooltipTruncatedTextCell from "components/TableContainer/DataTable/TooltipTruncatedTextCell";
import ActionsDropdown from "components/ActionsDropdown";
import CustomLink from "components/CustomLink";
import TooltipWrapper from "components/TooltipWrapper";
import GitOpsModeTooltipWrapper from "components/GitOpsModeTooltipWrapper";

interface IHeaderProps {
  column: {
    title: string;
    isSortedDesc: boolean;
  };
}

interface IRowProps {
  row: {
    original: IUser;
  };
}

interface ICellProps extends IRowProps {
  cell: {
    value: string | number | boolean;
  };
}

interface IActionsDropdownProps extends IRowProps {
  cell: {
    value: IDropdownOption[];
  };
}

interface IDataColumn {
  title: string;
  Header: ((props: IHeaderProps) => JSX.Element) | string;
  accessor: string;
  Cell:
    | ((props: ICellProps) => JSX.Element)
    | ((props: IActionsDropdownProps) => JSX.Element);
  disableHidden?: boolean;
  disableSortBy?: boolean;
  sortType?: string;
}

export interface ITeamUsersTableData {
  name: string;
  email: string;
  role: UserRole;
  teams: ITeam[];
  actions: IDropdownOption[];
  id: number;
}

export const renderApiUserIndicator = () => {
  return (
    <TooltipWrapper
      className="api-only-tooltip"
      tipContent={
        <>
          This user was created using MobiusCLI and
          <br /> only has API access.{" "}
          <CustomLink
            text="Learn more"
            newTab
            url="https://mobius-mdm.org/docs/using-mobius/MobiusCLI-cli#using-MobiusCLI-with-an-api-only-user"
            variant="tooltip-link"
          />
        </>
      }
      tipOffset={14}
      position="top"
      showArrow
      underline={false}
    >
      <span className="team-users__api-only-user">API</span>
    </TooltipWrapper>
  );
};

// NOTE: cellProps come from react-table
// more info here https://react-table.tanstack.com/docs/api/useTable#cell-properties
const generateColumnConfigs = (
  actionSelectHandler: (value: string, user: IUser) => void
): IDataColumn[] => {
  return [
    {
      title: "Name",
      Header: "Name",
      disableSortBy: true,
      sortType: "caseInsensitive",
      accessor: "name",
      Cell: (cellProps: ICellProps) => {
        const apiOnlyUser =
          "api_only" in cellProps.row.original
            ? cellProps.row.original.api_only
            : false;

        return (
          <TooltipTruncatedTextCell
            value={cellProps.cell.value}
            suffix={apiOnlyUser && renderApiUserIndicator()}
          />
        );
      },
    },
    {
      title: "Role",
      Header: "Role",
      disableSortBy: true,
      accessor: "role",
      Cell: (cellProps: ICellProps) => {
        if (cellProps.cell.value === "GitOps") {
          return (
            <TooltipWrapper
              tipContent={
                <>
                  The GitOps role is only available on the command-line
                  <br />
                  when creating an API-only user. This user has no
                  <br />
                  access to the UI.
                </>
              }
            >
              GitOps
            </TooltipWrapper>
          );
        }
        if (cellProps.cell.value === "Observer+") {
          return (
            <TooltipWrapper
              tipContent={
                <>
                  Users with the Observer+ role have access to all of
                  <br />
                  the same functions as an Observer, with the added
                  <br />
                  ability to run any live query against all hosts.
                </>
              }
            >
              {cellProps.cell.value}
            </TooltipWrapper>
          );
        }
        return <TextCell value={cellProps.cell.value} />;
      },
    },
    {
      title: "Email",
      Header: "Email",
      disableSortBy: true,
      accessor: "email",
      Cell: (cellProps: ICellProps) => (
        <TextCell className="w400" value={cellProps.cell.value} />
      ),
    },
    {
      title: "Actions",
      Header: "",
      disableSortBy: true,
      accessor: "actions",
      Cell: (cellProps: IActionsDropdownProps) => (
        <ActionsDropdown
          options={cellProps.cell.value}
          onChange={(value: string) =>
            actionSelectHandler(value, cellProps.row.original)
          }
          placeholder="Actions"
        />
      ),
    },
  ];
};

const generateActionDropdownOptions = (): IDropdownOption[] => {
  return [
    {
      label: "Edit",
      disabled: false,
      value: "edit",
    },
    {
      label: "Remove",
      disabled: false,
      value: "remove",
    },
  ];
};
const generateRole = (teamId: number, teams: ITeam[]): UserRole => {
  const role = teams.find((team) => teamId === team.id)?.role ?? "Unassigned";
  return stringUtils.capitalizeRole(role);
};

const enhanceUsersData = (
  teamId: number,
  users: IUser[]
): ITeamUsersTableData[] => {
  return Object.values(users).map((user) => {
    return {
      name: user.name,
      email: user.email,
      role: generateRole(teamId, user.teams),
      teams: user.teams,
      sso_enabled: user.sso_enabled,
      mfa_enabled: user.mfa_enabled,
      global_role: user.global_role,
      actions: generateActionDropdownOptions(),
      id: user.id,
      api_only: user.api_only,
    };
  });
};

const generateDataSet = (
  teamId: number,
  users: IUser[]
): ITeamUsersTableData[] => {
  return [...enhanceUsersData(teamId, users)];
};

export { generateColumnConfigs, generateDataSet };
