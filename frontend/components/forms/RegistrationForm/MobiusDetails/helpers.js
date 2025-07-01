import { size } from "lodash";

import validUrl from "components/forms/validators/valid_url";

import INVALID_SERVER_URL_MESSAGE from "utilities/error_messages";

const validate = (formData) => {
  const errors = {};
  const { server_url: mobiusWebAddress } = formData;

  if (!mobiusWebAddress) {
    errors.server_url = "Mobius web address must be completed";
  } else if (
    !validUrl({
      url: mobiusWebAddress,
      protocols: ["http", "https"],
      allowLocalHost: true,
    })
  ) {
    errors.server_url = INVALID_SERVER_URL_MESSAGE;
  }

  const valid = !size(errors);

  return { valid, errors };
};

export default { validate };
