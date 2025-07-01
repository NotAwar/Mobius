import React, { useContext, useEffect } from "react";
import { InjectedRouter } from "react-router";

import { AppContext } from "context/app";
import PATHS from "router/paths";

import PortalNavigation from "components/PortalNavigation";
import AuthenticationFormWrapper from "components/AuthenticationFormWrapper";

const baseClass = "portal-page";

interface IPortalPageProps {
  router: InjectedRouter;
}

const PortalPage = ({ router }: IPortalPageProps): JSX.Element => {
  const { currentUser } = useContext(AppContext);

  useEffect(() => {
    // If user isn't logged in, redirect to login
    if (!currentUser) {
      router.push(PATHS.LOGIN);
    }
  }, [currentUser, router]);

  if (!currentUser) {
    return (
      <AuthenticationFormWrapper>
        <div>Redirecting to login...</div>
      </AuthenticationFormWrapper>
    );
  }

  return (
    <div className={baseClass}>
      <PortalNavigation router={router} />
    </div>
  );
};

export default PortalPage;
