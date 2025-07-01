import React from "react";

// @ts-ignore
import mobiusLogoText from "../../../assets/images/mobius-logo-text-white.png";

interface IAuthenticationFormWrapperProps {
  children: React.ReactNode;
}

const baseClass = "auth-form-wrapper";

const AuthenticationFormWrapper = ({
  children,
}: IAuthenticationFormWrapperProps) => (
  <div className={baseClass}>
    <img alt="Mobius" src={mobiusLogoText} className={`${baseClass}__logo`} />
    {children}
  </div>
);

export default AuthenticationFormWrapper;
