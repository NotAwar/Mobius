import React from "react";
import { AxiosResponse } from "axios";
import { IApiError } from "interfaces/errors";
import { generateSecretErrMsg } from "pages/SoftwarePage/helpers";
import CustomLink from "components/CustomLink";

export const parseFile = async (file: File): Promise<[string, string]> => {
  // get the file name and extension
  const nameParts = file.name.split(".");
  const name = nameParts.slice(0, -1).join(".");
  const ext = nameParts.slice(-1)[0];

  switch (ext) {
    case "xml": {
      return [name, "Windows"];
    }
    case "mobileconfig": {
      return [name, "macOS, iOS, iPadOS"];
    }
    case "json": {
      return [name, "macOS, iOS, iPadOS"];
    }
    default: {
      throw new Error(`Invalid file type: ${ext}`);
    }
  }
};

export const DEFAULT_ERROR_MESSAGE =
  "Couldn't add configuration profile. Please try again.";

const generateUnsupportedVariableErrMsg = (errMsg: string) => {
  const regex = /\$[A-Z0-9_]+/;
  const varName = errMsg.match(regex);
  return varName
    ? `Couldn't add. Variable "${varName[0]}" doesn't exist.`
    : DEFAULT_ERROR_MESSAGE;
};

const generateLearnMoreErrMsg = (errMsg: string, learnMoreUrl: string) => {
  return (
    <>
      Couldn&apos;t add. {errMsg}{" "}
      <CustomLink
        url={learnMoreUrl}
        text="Learn more"
        variant="flash-message-link"
        newTab
      />
    </>
  );
};

/** We want to add some additional messageing to some of the error messages so
 * we add them in this function. Otherwise, we'll just return the error message from the
 * API.
 */
// eslint-disable-next-line import/prefer-default-export
export const getErrorMessage = (err: AxiosResponse<IApiError>) => {
  const apiReason = err?.data?.errors?.[0]?.reason;

  if (
    apiReason.includes(
      "The configuration profile can't include BitLocker settings."
    )
  ) {
    return (
      <span>
        Couldn&apos;t add. The configuration profile can&apos;t include
        BitLocker settings. To control these settings, go to{" "}
        <b>Disk encryption</b>.
      </span>
    );
  }

  if (
    apiReason.includes(
      "The configuration profile can't include FileVault settings."
    )
  ) {
    return (
      <span>
        Couldn&apos;t add. The configuration profile can&apos;t include
        FileVault settings. To control these settings, go to{" "}
        <b>Disk encryption</b>.
      </span>
    );
  }

  if (
    apiReason.includes(
      "The configuration profile can't include Windows update settings."
    )
  ) {
    return (
      <span>
        {apiReason} To control these settings, go to <b>OS updates</b>.
      </span>
    );
  }

  if (apiReason.includes("Secret variable")) {
    return generateSecretErrMsg(err);
  }

  if (
    apiReason.includes("Mobius variable") &&
    apiReason.includes("not supported in configuration profiles")
  ) {
    return generateUnsupportedVariableErrMsg(apiReason);
  }

  if (
    apiReason.includes(
      "can't be used if variables for SCEP URL and Challenge are not specified"
    )
  ) {
    return generateLearnMoreErrMsg(
      apiReason,
      "https://mobius-mdm.org/learn-more-about/certificate-authorities"
    );
  }

  if (
    apiReason.includes(
      "SCEP profile for custom SCEP certificate authority requires"
    )
  ) {
    return generateLearnMoreErrMsg(
      apiReason,
      "https://mobius-mdm.org/learn-more-about/custom-scep-configuration-profile"
    );
  }

  if (
    apiReason.includes(
      "SCEP profile for NDES certificate authority requires: $MOBIUS_VAR_NDES_SCEP_CHALLENGE"
    )
  ) {
    return generateLearnMoreErrMsg(
      apiReason,
      "https://mobius-mdm.org/learn-more-about/ndes-scep-configuration-profile"
    );
  }

  return `${apiReason}` || DEFAULT_ERROR_MESSAGE;
};
