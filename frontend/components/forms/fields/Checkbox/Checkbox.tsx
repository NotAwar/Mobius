import React, { ReactNode, KeyboardEvent, useEffect, useRef } from "react";
import classnames from "classnames";
import { noop, pick } from "lodash";

import FormField from "components/forms/FormField";
import { IFormFieldProps } from "components/forms/FormField/FormField";
import TooltipWrapper from "components/TooltipWrapper";
import Icon from "components/Icon";

const baseClass = "mobius-checkbox";

export interface ICheckboxProps {
  children?: ReactNode;
  className?: string;
  /** readOnly displays a non-editable field */
  readOnly?: boolean;
  /** disabled displays a greyed out non-editable field */
  disabled?: boolean;
  name?: string;
  onChange?: any; // TODO: meant to be an event; figure out type for this
  onBlur?: (event: React.FocusEvent<HTMLDivElement>) => void;
  value?: boolean | null;
  wrapperClassName?: string;
  indeterminate?: boolean;
  parseTarget?: boolean;
  /** to display over the checkbox label */
  labelTooltipContent?: React.ReactNode;
  /** to display over the checkbox icon */
  iconTooltipContent?: React.ReactNode;
  isLeftLabel?: boolean;
  helpText?: React.ReactNode;
  /** Use in table action only
   * Do not use on forms as enter key reserved for submit */
  enableEnterToCheck?: boolean;
}

const Checkbox = (props: ICheckboxProps) => {
  const {
    children,
    className,
    readOnly = false,
    disabled = false,
    name,
    onChange = noop,
    onBlur = noop,
    value = false,
    wrapperClassName,
    indeterminate = false,
    parseTarget,
    labelTooltipContent,
    iconTooltipContent,
    isLeftLabel,
    helpText,
    enableEnterToCheck = false,
  } = props;

  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (inputRef.current) {
      inputRef.current.indeterminate = indeterminate;
    }
  }, [indeterminate]);

  const handleChange = (
    event: React.MouseEvent | React.KeyboardEvent
  ): void => {
    event.preventDefault();
    if (readOnly || disabled) return;

    // If indeterminate, set to true; otherwise, toggle the current value
    const newValue = indeterminate || !value;

    if (parseTarget) {
      onChange({ name, value: newValue });
    } else {
      onChange(newValue);
    }

    // Update the hidden input
    if (inputRef.current) {
      inputRef.current.checked = newValue;
    }
  };

  /** Manual implementation of spacebar toggling checkboxes (default behavior)
   * since we're using a custom div instead of a native checkbox
   * Enter key intended to toggle table checkboxes only */
  const handleKeyDown = (event: KeyboardEvent<HTMLDivElement>): void => {
    if (event.key === " " || (enableEnterToCheck && event.key === "Enter")) {
      handleChange(event);
    }
  };

  const checkBoxClass = classnames(
    { inverse: isLeftLabel },
    className,
    baseClass
  );

  const checkBoxLabelClass = classnames(checkBoxClass, {
    [`${baseClass}__label--read-only`]: readOnly || disabled,
    [`${baseClass}__label--disabled`]: disabled,
  });

  const formFieldProps = {
    ...pick(props, ["helpText", "label", "error", "name"]),
    className: wrapperClassName,
    type: "checkbox",
  } as IFormFieldProps;

  const getIconName = () => {
    if (indeterminate) return "checkbox-indeterminate";
    if (value) return "checkbox";
    return "checkbox-unchecked";
  };

  const renderIcon = () => {
    const icon = (
      <Icon
        name={getIconName()}
        className={`${baseClass}__icon ${baseClass}__icon--${getIconName()}`}
      />
    );
    if (iconTooltipContent) {
      return (
        <TooltipWrapper
          tipContent={iconTooltipContent}
          clickable={false}
          underline={false}
          showArrow
          position="right"
          tipOffset={8}
        >
          {icon}
        </TooltipWrapper>
      );
    }
    return icon;
  };

  return (
    <FormField {...formFieldProps}>
      <label htmlFor={name}>
        <input
          type="checkbox"
          ref={inputRef}
          name={name}
          checked={!!value}
          onChange={noop} // Empty onChange to avoid React warning
          disabled={disabled || readOnly}
          style={{ display: "none" }} // Hide the input
          id={name}
        />
        <div
          role="checkbox"
          aria-label={name}
          aria-checked={indeterminate ? "mixed" : value || undefined}
          aria-readonly={readOnly}
          aria-disabled={disabled}
          tabIndex={disabled ? -1 : 0}
          className={checkBoxLabelClass}
          onClick={handleChange}
          onKeyDown={handleKeyDown}
          onBlur={onBlur}
        >
          {renderIcon()}
          {labelTooltipContent ? (
            <span className={`${baseClass}__label-tooltip tooltip`}>
              <TooltipWrapper
                tipContent={labelTooltipContent}
                clickable={false} // Not block form behind tooltip
              >
                {children}
              </TooltipWrapper>
            </span>
          ) : (
            <span className={`${baseClass}__label`}>{children}</span>
          )}
        </div>
      </label>
    </FormField>
  );
};

export default Checkbox;
