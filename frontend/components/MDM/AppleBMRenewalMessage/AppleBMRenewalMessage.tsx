import React from "react";

import InfoBanner from "components/InfoBanner";
import CustomLink from "components/CustomLink";

const baseClass = "apple-bm-renewal-message";

type IAppleBMRenewalMessageProps = {
  expired: boolean;
};

const AppleBMRenewalMessage = ({ expired }: IAppleBMRenewalMessageProps) => {
  return (
    <InfoBanner
      className={baseClass}
      color="yellow"
      cta={
        <CustomLink
          url="/settings/integrations/mdm/abm"
          text="Renew ABM"
          className={`${baseClass}`}
          variant="banner-link"
        />
      }
    >
      {expired ? (
        <>
          Your Apple Business Manager (ABM) server token has expired. macOS,
          iOS, and iPadOS hosts won’t automatically enroll to Mobius. Users with
          the admin role in Mobius can renew ABM.
        </>
      ) : (
        <>
          Your Apple Business Manager (ABM) server token is less than 30 days
          from expiration. If it expires, macOS, iOS, and iPadOS hosts won’t
          automatically enroll to Mobius. Users with the admin role in Mobius
          can renew ABM.
        </>
      )}
    </InfoBanner>
  );
};

export default AppleBMRenewalMessage;
