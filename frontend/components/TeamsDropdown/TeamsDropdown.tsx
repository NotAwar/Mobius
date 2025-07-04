import React, { useMemo } from "react";
import Select, {
  components,
  DropdownIndicatorProps,
  GroupBase,
  OptionProps,
  StylesConfig,
} from "react-select-5";

import { COLORS } from "styles/var/colors";
import { PADDING } from "styles/var/padding";
import { FONT_SIZES, FONT_WEIGHTS } from "styles/var/fonts";

import classnames from "classnames";

import { IDropdownOption } from "interfaces/dropdownOption";
import {
  APP_CONTEXT_ALL_TEAMS_SUMMARY,
  ITeamSummary,
  APP_CONTEXT_NO_TEAM_SUMMARY,
} from "interfaces/team";

import Icon from "components/Icon";

export interface INumberDropdownOption extends Omit<IDropdownOption, "value"> {
  value: number; // Redefine the value property to be just number
}

const generateDropdownOptions = (
  teams: ITeamSummary[] | undefined,
  includeAll: boolean,
  includeNoTeams?: boolean
): INumberDropdownOption[] => {
  if (!teams) {
    return [];
  }

  const options: INumberDropdownOption[] = teams.map((team) => ({
    disabled: false,
    label: team.name,
    value: team.id,
  }));

  const filtered = options.filter(
    (o) =>
      !(
        (o.label === APP_CONTEXT_NO_TEAM_SUMMARY.name && !includeNoTeams) ||
        (o.label === APP_CONTEXT_ALL_TEAMS_SUMMARY.name && !includeAll)
      )
  );

  return filtered;
};

const getOptionBackgroundColor = (
  state: OptionProps<
    INumberDropdownOption,
    false,
    GroupBase<INumberDropdownOption>
  >
) => {
  return state.isFocused ? COLORS["ui-vibrant-blue-10"] : "transparent";
};

interface ITeamsDropdownProps {
  currentUserTeams: ITeamSummary[];
  selectedTeamId?: number;
  includeAll?: boolean; // Include the "All Teams" option;
  includeNoTeams?: boolean;
  isDisabled?: boolean;
  onChange: (newSelectedValue: number) => void;
  onOpen?: () => void;
  onClose?: () => void;
}

const baseClass = "team-dropdown";

const TeamsDropdown = ({
  currentUserTeams,
  selectedTeamId,
  includeAll = true,
  includeNoTeams = false,
  isDisabled = false,
  onChange,
  onOpen,
  onClose,
}: ITeamsDropdownProps): JSX.Element => {
  const teamOptions: INumberDropdownOption[] = useMemo(
    () => generateDropdownOptions(currentUserTeams, includeAll, includeNoTeams),
    [currentUserTeams, includeAll, includeNoTeams]
  );

  const selectedValue = teamOptions.find(
    (option) => selectedTeamId === option.value
  )
    ? selectedTeamId
    : teamOptions[0]?.value;

  const dropdownWrapperClasses = classnames(`${baseClass}-wrapper`, {
    disabled: isDisabled || undefined,
  });

  const CustomDropdownIndicator = (
    props: DropdownIndicatorProps<any, false, any>
  ) => {
    const { isFocused, selectProps } = props;
    const color =
      isFocused || selectProps.menuIsOpen
        ? "core-mobius-blue"
        : "core-mobius-black";

    return (
      <components.DropdownIndicator {...props} className={baseClass}>
        <Icon
          name="chevron-down"
          color={color}
          className={`${baseClass}__icon`}
        />
      </components.DropdownIndicator>
    );
  };

  // see https://react-select.com/styles#the-styles-prop
  const customStyles: StylesConfig<INumberDropdownOption, false> = {
    control: (baseStyles, state) => ({
      ...baseStyles,
      display: "flex",
      flexDirection: "row",
      padding: "8px 0",
      backgroundColor: "initial",
      border: 0,
      borderRadius: "4px",
      boxShadow: "none",
      cursor: "pointer",
      "&:hover": {
        boxShadow: "none",
        ".team-dropdown__single-value": {
          color: COLORS["core-mobius-blue"],
        },
        ".team-dropdown__indicator path": {
          stroke: COLORS["core-vibrant-blue-over"],
        },
      },
      // When tabbing
      // Relies on --is-focused for styling as &:focus-visible cannot be applied
      "&.team-dropdown__control--is-focused": {
        ".team-dropdown__indicator path": {
          stroke: COLORS["core-vibrant-blue-over"],
        },
      },
      ...(state.isDisabled && {
        ".team-dropdown__single-value": {
          color: COLORS["ui-mobius-black-50"],
        },
        ".team-dropdown__indicator path": {
          stroke: COLORS["ui-mobius-black-50"],
        },
      }),
      // When clicking
      "&:active": {
        ".team-dropdown__single-value": {
          color: COLORS["core-vibrant-blue-down"],
        },
        ".team-dropdown__indicator path": {
          stroke: COLORS["core-vibrant-blue-down"],
        },
      },
      ...(state.menuIsOpen && {
        ".team-dropdown__indicator svg": {
          transform: "rotate(180deg)",
          transition: "transform 0.25s ease",
        },
      }),
    }),
    singleValue: (baseStyles) => ({
      ...baseStyles,
      fontSize: "24px",
      lineHeight: "normal",
      paddingLeft: 0,
      paddingRight: "8px",
      margin: 0,
      // omit grid-column-end for automatic width
      gridArea: "1/1/2",
    }),
    dropdownIndicator: (baseStyles) => ({
      ...baseStyles,
      display: "flex",
      padding: "2px",
      margin: "0 5px",
      svg: {
        transition: "transform 0.25s ease",
      },
    }),
    menu: (baseStyles) => ({
      ...baseStyles,
      boxShadow: "0 2px 6px rgba(0, 0, 0, 0.1)",
      borderRadius: "4px",
      zIndex: 6,
      overflow: "hidden",
      border: 0,
      marginTop: 0,
      minWidth: "330px",
      maxHeight: "none",
      position: "absolute",
      left: "0",
      animation: "fade-in 150ms ease-out",
    }),
    // Placeholder is never shown on teams dropdown
    menuList: (baseStyles) => ({
      ...baseStyles,
      padding: PADDING["pad-small"],
      ".team-dropdown__menu-notice--no-options": {
        textAlign: "left",
        color: COLORS["ui-mobius-black-50"],
        fontSize: FONT_SIZES["xx-small"],
        fontWeight: FONT_WEIGHTS.regular,
      },
    }),
    valueContainer: (baseStyles) => ({
      ...baseStyles,
      padding: 0,
    }),
    input: (baseStyles) => ({
      ...baseStyles,
      overflow: "hidden",
      textOverflow: "ellipsis",
      whiteSpace: "nowrap",
    }),
    option: (baseStyles, state) => ({
      ...baseStyles,
      padding: "10px 8px",
      fontSize: "14px",
      borderRadius: "4px",
      backgroundColor: getOptionBackgroundColor(state),
      fontWeight: state.isSelected ? "bold" : "normal",
      color: COLORS["core-mobius-black"],
      "&:hover": {
        backgroundColor: state.isDisabled
          ? "transparent"
          : COLORS["ui-vibrant-blue-10"],
      },
      "&:active": {
        backgroundColor: state.isDisabled
          ? "transparent"
          : COLORS["ui-vibrant-blue-25"],
      },
      ...(state.isDisabled && {
        color: COLORS["ui-mobius-black-50"],
        fontStyle: "italic",
      }),
    }),
  };

  const renderDropdown = () => {
    if (teamOptions.length) {
      return (
        <Select<INumberDropdownOption, false>
          options={teamOptions}
          placeholder="All teams"
          onChange={(newValue) => {
            if (newValue) {
              onChange(newValue.value);
            }
            // If newValue is null or undefined, we don't call onChange
          }}
          isDisabled={isDisabled}
          isSearchable
          noOptionsMessage={() => "No matching teams"}
          styles={customStyles}
          components={{
            DropdownIndicator: CustomDropdownIndicator,
            IndicatorSeparator: () => null,
          }}
          value={teamOptions.find((option) => option.value === selectedValue)}
          isOptionSelected={() => false} // Hides any styling on selected option
          className={baseClass}
          classNamePrefix={baseClass}
          onMenuOpen={onOpen}
          onMenuClose={onClose}
        />
      );
    }
  };

  return <div className={dropdownWrapperClasses}>{renderDropdown()}</div>;
};

export default TeamsDropdown;
