import React from "react";

interface IAppProps {
  children: JSX.Element;
}

export const UnauthenticatedRoutes = ({ children }: IAppProps): JSX.Element => {
  if (window.location.hostname.includes(".sandbox.mobiusdm.com")) {
    window.location.href = "https://www.mobiusdm.com/try-mobius/login";
  }
  return <div>{children}</div>;
};

export default UnauthenticatedRoutes;
