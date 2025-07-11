import React, { Component } from "react";
import PropTypes from "prop-types";

import Form from "components/forms/Form";
import formFieldInterface from "interfaces/form_field";
import Button from "components/buttons/Button";
import helpers from "components/forms/RegistrationForm/OrgDetails/helpers";
import InputField from "components/forms/fields/InputField";

const formFields = ["org_name", "org_logo_url"];
const { validate } = helpers;

class OrgDetails extends Component {
  static propTypes = {
    className: PropTypes.string,
    currentPage: PropTypes.bool,
    fields: PropTypes.shape({
      org_name: formFieldInterface.isRequired,
      org_logo_url: formFieldInterface.isRequired,
    }).isRequired,
    handleSubmit: PropTypes.func.isRequired,
  };

  componentDidUpdate(prevProps) {
    if (
      this.props.currentPage &&
      this.props.currentPage !== prevProps.currentPage
    ) {
      // Component has a transition duration of 300ms set in
      // RegistrationForm/_styles.scss. We need to wait 300ms before
      // calling .focus() to preserve smooth transition.
      setTimeout(() => {
        this.firstInput.input.focus();
      }, 300);
    }
  }

  render() {
    const { className, currentPage, fields, handleSubmit } = this.props;
    const tabIndex = currentPage ? 0 : -1;

    return (
      <form onSubmit={handleSubmit} className={className} autoComplete="off">
        <InputField
          {...fields.org_name}
          label="Organization name"
          tabIndex={tabIndex}
          ref={(input) => {
            this.firstInput = input;
          }}
        />
        <InputField
          {...fields.org_logo_url}
          label="Organization logo URL (optional)"
          tabIndex={tabIndex}
          helpText="Personalize Mobius with your brand.  For best results, use a square image at least 150px wide, like https://mobiusmdm.com/logo.png."
        />
        <Button type="submit" tabIndex={tabIndex} disabled={!currentPage}>
          Next
        </Button>
      </form>
    );
  }
}

export default Form(OrgDetails, {
  fields: formFields,
  validate,
});
