/**
 * This is a new component built off react-select 5.4
 * meant to replace Dropdown.jsx built off react-select 1.3
 *
 * See storybook component for current functionality
 *
 * Prototyped on UserForm.tsx but added and tested the following:
 * Options: text, disabled, option helptext, option tooltip
 * Other: label text, dropdown help text, dropdown error
 */

import classnames from "classnames";
import React from "react";
import Select, {
  components,
  DropdownIndicatorProps,
  GroupBase,
  OptionProps,
  PropsValue,
  SingleValue,
  StylesConfig,
  ValueContainerProps,
} from "react-select-5";

import { COLORS } from "styles/var/colors";
import { PADDING } from "styles/var/padding";

import FormField from "components/forms/FormField";
import DropdownOptionTooltipWrapper from "components/forms/fields/Dropdown/DropdownOptionTooltipWrapper";
import Icon from "components/Icon";
import { IconNames } from "components/icons";
import { TooltipContent } from "interfaces/dropdownOption";

export interface CustomOptionType {
  label: React.ReactNode;
  value: string;
  tooltipContent?: TooltipContent;
  helpText?: string;
  isDisabled?: boolean;
  iconName?: IconNames;
}

type DropdownWrapperVariant = "table-filter" | "button";

export interface IDropdownWrapper {
  options: CustomOptionType[];
  value?: PropsValue<CustomOptionType> | string;
  onChange: (newValue: SingleValue<CustomOptionType>) => void;
  name: string;
  className?: string;
  wrapperClassname?: string;
  labelClassname?: string;
  error?: string;
  label?: JSX.Element | string;
  helpText?: JSX.Element | string;
  isSearchable?: boolean;
  isDisabled?: boolean;
  iconName?: IconNames;
  placeholder?: string;
  /** E.g. scroll to view dropdown menu in a scrollable parent container */
  onMenuOpen?: () => void;
  /** Table filter dropdowns have filter icon and height: 40px
   *  Button dropdowns have hover/active state, padding, height matching actual buttons, and no selected option styling */
  variant?: DropdownWrapperVariant;
  /** This makes the menu fit all text without wrapping,
   * aligning right to fit text on screen */
  nowrapMenu?: boolean;
}

const getOptionBackgroundColor = (
  state: OptionProps<CustomOptionType, false>
) => {
  return state.isFocused ? COLORS["ui-vibrant-blue-10"] : "transparent";
};

const getOptionFontWeight = (
  state: OptionProps<CustomOptionType, false>,
  variant?: DropdownWrapperVariant
) => {
  // For "button" dropdowns, selected options are not styled differently
  if (variant === "button") {
    return "normal";
  }

  // For other variants, selected options are bold
  return state.isSelected ? "bold" : "normal";
};

const baseClass = "dropdown-wrapper";

const DropdownWrapper = ({
  options,
  value,
  onChange,
  name,
  className,
  labelClassname,
  wrapperClassname,
  error,
  label,
  helpText,
  isSearchable = false,
  isDisabled = false,
  iconName,
  placeholder,
  onMenuOpen,
  variant,
  nowrapMenu,
}: IDropdownWrapper) => {
  const wrapperClassNames = classnames(baseClass, className, {
    [`${baseClass}__table-filter`]: variant === "table-filter",
    [`${wrapperClassname}`]: !!wrapperClassname,
  });

  const handleChange = (newValue: SingleValue<CustomOptionType>) => {
    onChange(newValue);
  };

  // Ability to handle value of type string or CustomOptionType
  const getCurrentValue = () => {
    if (typeof value === "string") {
      return options.find((option) => option.value === value) || null;
    }
    return value;
  };

  interface CustomOptionProps
    extends Omit<OptionProps<CustomOptionType, false>, "data"> {
    data: CustomOptionType;
  }

  const CustomOption = (props: CustomOptionProps) => {
    const { data, ...rest } = props;

    const optionContent = (
      <div className={`${baseClass}__option`}>
        {data.label}
        {data.helpText && (
          <span className={`${baseClass}__help-text`}>{data.helpText}</span>
        )}
      </div>
    );

    return (
      <components.Option {...rest} data={data}>
        {data.tooltipContent ? (
          <DropdownOptionTooltipWrapper tipContent={data.tooltipContent}>
            {optionContent}
          </DropdownOptionTooltipWrapper>
        ) : (
          optionContent
        )}
      </components.Option>
    );
  };

  const CustomDropdownIndicator = (
    props: DropdownIndicatorProps<
      CustomOptionType,
      false,
      GroupBase<CustomOptionType>
    >
  ) => {
    const { isFocused, selectProps } = props;
    const color =
      isFocused || selectProps.menuIsOpen
        ? "core-mobius-blue"
        : "core-mobius-black";

    return (
      <components.DropdownIndicator
        {...props}
        className={`${baseClass}__indicator`}
      >
        <Icon
          name="chevron-down"
          color={color}
          className={`${baseClass}__icon`}
        />
      </components.DropdownIndicator>
    );
  };

  const ValueContainer = ({
    children,
    ...props
  }: ValueContainerProps<CustomOptionType, false>) => {
    const iconToDisplay =
      iconName || (variant === "table-filter" ? "filter" : null);

    return (
      components.ValueContainer && (
        <components.ValueContainer {...props}>
          {!!children && iconToDisplay && (
            <Icon name={iconToDisplay} className="filter-icon" />
          )}
          {children}
        </components.ValueContainer>
      )
    );
  };

  const customStyles: StylesConfig<CustomOptionType, false> = {
    container: (provided) => {
      const buttonVariantContainer = {
        borderRadius: "6px",
        "&:active": {
          backgroundColor: "rgba(25, 33, 71, 0.05)",
        },
        height: "38px",
      };

      return {
        ...provided,
        width: "100%",
        height: "40px",
        ...(variant === "button" && buttonVariantContainer),
      };
    },

    control: (provided, state) => {
      if (variant === "button")
        return {
          backgroundColor: "initial",
          borderColor: "none",
          display: "flex",
          flexDirection: "row",
          width: "max-content",
          padding: PADDING["pad-small"],
          border: 0,
          borderRadius: "6px",
          boxShadow: "none",
          cursor: "pointer",
          ".dropdown-wrapper__indicator path": {
            stroke: COLORS["core-mobius-blue"],
          },
          "&:hover": {
            backgroundColor: "rgba(25, 33, 71, 0.05)",
            boxShadow: "none",
            ".dropdown-wrapper__placeholder": {
              color: COLORS["core-vibrant-blue-over"],
            },
            ".dropdown-wrapper__indicator path": {
              stroke: COLORS["core-vibrant-blue-over"],
            },
          },
          ".react-select__control--is-focused": {
            backgroundColor: "rgba(25, 33, 71, 0.05)",
            boxShadow: "none",
            ".dropdown-wrapper__placeholder": {
              color: COLORS["core-vibrant-blue-down"],
            },
            ".dropdown-wrapper__indicator path": {
              stroke: COLORS["core-vibrant-blue-down"],
            },
          },
          ...(state.isFocused && {
            backgroundColor: "rgba(25, 33, 71, 0.05)",
            ".dropdown-wrapper__placeholder": {
              color: COLORS["core-vibrant-blue-down"],
            },
            ".dropdown-wrapper__indicator path": {
              stroke: COLORS["core-vibrant-blue-down"],
            },
          }),
          // TODO: Figure out a way to apply separate &:focus-visible styling
          // Currently only relying on &:focus styling for tabbing through app
          ...(state.menuIsOpen && {
            ".dropdown-wrapper__indicator svg": {
              transform: "rotate(180deg)",
              transition: "transform 0.25s ease",
            },
          }),
          ...(variant === "button" && { height: "22px" }),
        };

      return {
        ...provided,
        display: "flex",
        flexDirection: "row",
        width: "100%",
        backgroundColor: COLORS["ui-off-white"],
        paddingLeft: "8px", // TODO: Update to match styleguide of (16px) when updating rest of UI (8px)
        paddingRight: "8px",
        cursor: "pointer",
        boxShadow: "none",
        borderRadius: "4px",
        borderColor: state.isFocused
          ? COLORS["core-mobius-blue"]
          : COLORS["ui-mobius-black-10"],
        "&:hover": {
          boxShadow: "none",
          borderColor: COLORS["core-vibrant-blue-over"],
          ".dropdown-wrapper__single-value": {
            color: COLORS["core-vibrant-blue-over"],
          },
          ".dropdown-wrapper__indicator path": {
            stroke: COLORS["core-vibrant-blue-over"],
          },
          ".filter-icon path": {
            fill: COLORS["core-vibrant-blue-over"],
          },
        },
        // When tabbing
        // Relies on --is-focused for styling as &:focus-visible cannot be applied
        "&.react-select__control--is-focused": {
          borderColor: state.isFocused
            ? COLORS["core-vibrant-blue-down"]
            : COLORS["ui-mobius-black-10"],
          ".dropdown-wrapper__indicator path": {
            stroke: COLORS["core-vibrant-blue-down"],
          },
          ".filter-icon path": {
            fill: COLORS["core-vibrant-blue-down"],
          },
        },
        ...(state.isFocused && {
          ".dropdown-wrapper__placeholder": {
            color: COLORS["core-vibrant-blue-down"],
          },
          ".dropdown-wrapper__indicator path": {
            stroke: COLORS["core-vibrant-blue-down"],
          },
        }),
        ...(state.isDisabled && {
          ".dropdown-wrapper__single-value": {
            color: COLORS["ui-mobius-black-50"],
          },
          ".dropdown-wrapper__indicator path": {
            stroke: COLORS["ui-mobius-black-50"],
          },
          ".filter-icon path": {
            fill: COLORS["ui-mobius-black-50"],
          },
        }),
        "&:active": {
          ".dropdown-wrapper__single-value": {
            color: COLORS["core-vibrant-blue-down"],
          },
          ".dropdown-wrapper__indicator path": {
            stroke: COLORS["core-vibrant-blue-down"],
          },
          ".filter-icon path": {
            fill: COLORS["core-vibrant-blue-down"],
          },
        },
        ...(state.menuIsOpen && {
          ".dropdown-wrapper__indicator svg": {
            transform: "rotate(180deg)",
            transition: "transform 0.25s ease",
          },
        }),
      };
    },
    placeholder: (provided, state) => {
      const buttonVariantPlaceholder = {
        color: state.isFocused
          ? COLORS["core-vibrant-blue-over"]
          : COLORS["core-mobius-blue"],
        fontSize: "14px",
        fontWeight: "bold",
        lineHeight: "normal",
        paddingLeft: 0,
        opacity: isDisabled ? 0.5 : 1,
        marginTop: variant === "button" ? "-1px" : "1px", // TODO: Figure out vertical centering to not need pixel fix
      };

      return {
        ...provided,
        ...(variant === "button" && buttonVariantPlaceholder),
      };
    },
    singleValue: (provided) => ({
      ...provided,
      fontSize: "14px",
      margin: 0,
      padding: 0,
    }),
    dropdownIndicator: (provided) => ({
      ...provided,
      display: "flex",
      padding: "2px",
      svg: {
        transition: "transform 0.25s ease",
      },
      opacity: isDisabled ? 0.5 : 1,
    }),
    menu: (provided) => ({
      ...provided,
      boxShadow: "0 2px 6px rgba(0, 0, 0, 0.1)",
      borderRadius: "4px",
      zIndex: 6,
      overflow: "hidden",
      border: 0,
      marginTop: variant === "button" ? "3px" : 0,
      left: 0,
      maxHeight: "none",
      position: "absolute",
      animation: "fade-in 150ms ease-out",
      ...(nowrapMenu && {
        width: "fit-content",
        left: "auto",
        right: "0",
      }),
    }),
    menuList: (provided) => ({
      ...provided,
      padding: PADDING["pad-small"],
      maxHeight: "none",
      ...(nowrapMenu && { width: "fit-content" }),
    }),
    valueContainer: (provided) => ({
      ...provided,
      padding: 0,
      display: "flex",
      gap: PADDING[variant === "button" ? "pad-xsmall" : "pad-small"],
    }),
    option: (provided, state) => ({
      ...provided,
      padding: "10px 8px",
      fontSize: "14px",
      borderRadius: "4px",
      backgroundColor: getOptionBackgroundColor(state),
      fontWeight: getOptionFontWeight(state, variant),
      color: COLORS["core-mobius-black"],
      "&:hover": {
        backgroundColor: state.isDisabled
          ? "transparent"
          : COLORS["ui-vibrant-blue-10"],
        cursor: state.isDisabled ? "not-allowed" : "pointer",
      },
      "&:active": {
        backgroundColor: state.isDisabled
          ? "transparent"
          : COLORS["ui-vibrant-blue-25"],
      },
      ...(state.isDisabled && {
        color: COLORS["ui-mobius-black-50"],
        fontStyle: "italic",
        cursor: "not-allowed",
      }),
      // Styles for custom option
      ".dropdown-wrapper__option": {
        display: "flex",
        flexDirection: "column",
        gap: "8px",
        width: "100%",
        whiteSpace: nowrapMenu ? "nowrap" : "normal",
      },
      ".dropdown-wrapper__help-text": {
        fontSize: "12px",
        width: "100%",
        whiteSpace: nowrapMenu ? "nowrap" : "normal",
        color: state.isDisabled
          ? COLORS["ui-mobius-black-50"]
          : COLORS["ui-mobius-black-75"],
        fontStyle: "italic",
        fontWeight: "normal",
      },
    }),
    menuPortal: (base) => ({ ...base, zIndex: 999 }), // Not hidden beneath scrollable sections
    noOptionsMessage: (provided) => ({
      ...provided,
      textAlign: "left",
      fontSize: "14px",
      padding: "10px 8px",
    }),
  };

  const renderLabel = () => {
    const labelWrapperClasses = classnames(
      `${baseClass}__label`,
      labelClassname,
      {
        [`${baseClass}__label--error`]: !!error,
        [`${baseClass}__label--disabled`]: isDisabled,
      }
    );

    if (!label) {
      return "";
    }

    return (
      <label className={labelWrapperClasses} htmlFor={name}>
        {error || label}
      </label>
    );
  };

  return (
    <FormField
      name={name}
      label={renderLabel()}
      helpText={helpText}
      type="dropdown"
      className={wrapperClassNames}
    >
      <Select<CustomOptionType, false>
        classNamePrefix="react-select"
        isSearchable={isSearchable}
        styles={customStyles}
        options={options}
        components={{
          Option: CustomOption,
          DropdownIndicator: CustomDropdownIndicator,
          IndicatorSeparator: () => null,
          ValueContainer,
        }}
        value={getCurrentValue()}
        onChange={handleChange}
        isDisabled={isDisabled}
        noOptionsMessage={() => "No results found"}
        tabIndex={isDisabled ? -1 : 0} // Ensures disabled dropdown has no keyboard accessibility
        placeholder={placeholder}
        onMenuOpen={onMenuOpen}
        controlShouldRenderValue={variant !== "button"} // Control doesn't change placeholder to selected value
      />
    </FormField>
  );
};

export default DropdownWrapper;
