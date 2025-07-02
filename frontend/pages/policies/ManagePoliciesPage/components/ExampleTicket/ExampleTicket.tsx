import React, { useContext } from "react";

import { AppContext } from "context/app";

import { IIntegrationType } from "interfaces/integration";

import Card from "components/Card";
import PlaceholderImage from "../../../../../../assets/images/mobius-logo.png";

const baseClass = "example-ticket";

interface IExampleTicketProps {
  integrationType?: IIntegrationType;
}

const ExampleTicket = ({
  integrationType,
}: IExampleTicketProps): JSX.Element => {
  const { isPremiumTier } = useContext(AppContext);

  const screenshot =
    integrationType === "jira" ? (
      <img
        src={PlaceholderImage}
        alt="Jira example policy automation ticket"
        className={`${baseClass}__screenshot`}
      />
    ) : (
      <img
        src={PlaceholderImage}
        alt="Zendesk example policy automation ticket"
        className={`${baseClass}__screenshot`}
      />
    );

  return (
    <Card className={baseClass} color="grey">
      {screenshot}
    </Card>
  );
};

export default ExampleTicket;
