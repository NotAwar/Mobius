// @ts-ignore
import validateQuery from "components/forms/validators/validate_query";

import {
  IMobiusMaintainedAppFormData,
  IFormValidation,
} from "./MobiusAppDetailsForm";

type IMessageFunc = (formData: IMobiusMaintainedAppFormData) => string;
type IValidationMessage = string | IMessageFunc;
type IFormValidationKey = keyof Omit<IFormValidation, "isValid">;

interface IValidation {
  name: string;
  isValid: (formData: IMobiusMaintainedAppFormData) => boolean;
  message?: IValidationMessage;
}

const FORM_VALIDATION_CONFIG: Record<
  IFormValidationKey,
  { validations: IValidation[] }
> = {
  preInstallQuery: {
    validations: [
      {
        name: "invalidQuery",
        isValid: (formData) => {
          const query = formData.preInstallQuery;
          return (
            query === undefined || query === "" || validateQuery(query).valid
          );
        },
        message: (formData) => validateQuery(formData.preInstallQuery).error,
      },
    ],
  },
  customTarget: {
    validations: [
      {
        name: "requiredLabelTargets",
        isValid: (formData) => {
          if (formData.targetType === "All hosts") return true;
          // there must be at least one label target selected
          return (
            Object.keys(formData.labelTargets).find(
              (key) => formData.labelTargets[key]
            ) !== undefined
          );
        },
      },
    ],
  },
};

const getErrorMessage = (
  formData: IMobiusMaintainedAppFormData,
  message?: IValidationMessage
) => {
  if (message === undefined || typeof message === "string") {
    return message;
  }
  return message(formData);
};

// eslint-disable-next-line import/prefer-default-export
export const generateFormValidation = (
  formData: IMobiusMaintainedAppFormData
) => {
  const formValidation: IFormValidation = {
    isValid: true,
  };

  Object.keys(FORM_VALIDATION_CONFIG).forEach((key) => {
    const objKey = key as IFormValidationKey;
    const failedValidation = FORM_VALIDATION_CONFIG[objKey].validations.find(
      (validation) => !validation.isValid(formData)
    );

    if (!failedValidation) {
      formValidation[objKey] = {
        isValid: true,
      };
    } else {
      formValidation.isValid = false;
      formValidation[objKey] = {
        isValid: false,
        message: getErrorMessage(formData, failedValidation.message),
      };
    }
  });

  return formValidation;
};
