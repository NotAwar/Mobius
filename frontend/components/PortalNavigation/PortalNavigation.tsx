import React, { useContext } from "react";
import { useQuery } from "react-query";
import { InjectedRouter } from "react-router";

import { AppContext } from "context/app";
import PATHS from "router/paths";
import configAPI from "services/entities/config";

import Button from "components/buttons/Button";
import Icon from "components/Icon";

const baseClass = "portal-navigation";

interface IPortalNavigationProps {
  router: InjectedRouter;
}

const PortalNavigation = ({ router }: IPortalNavigationProps): JSX.Element => {
  const { currentUser } = useContext(AppContext);

  const { data: config } = useQuery("config", () => configAPI.loadAll(), {
    refetchOnWindowFocus: false,
    retry: false,
  });

  const handleInternalPortal = () => {
    router.push(PATHS.INTERNAL_PORTAL);
  };

  const handleUserPortal = () => {
    router.push(PATHS.USER_PORTAL);
  };

  const handleMainDashboard = () => {
    router.push(PATHS.DASHBOARD);
  };

  const isGlobalAdmin = currentUser?.global_role?.includes("admin");
  const isUserPortalEnabled = true; // Always enable user portal for now

  return (
    <div className={baseClass}>
      <div className={`${baseClass}__header`}>
        <h2>Mobius MDM Portals</h2>
        <p>Access different interfaces based on your role and needs</p>
      </div>

      <div className={`${baseClass}__portals`}>
        <div className={`${baseClass}__portal-card`}>
          <div className={`${baseClass}__portal-icon`}>
            <Icon name="policy" />
          </div>
          <div className={`${baseClass}__portal-content`}>
            <h3>Main Dashboard</h3>
            <p>
              Primary administrative interface for device management and
              monitoring
            </p>
            <div className={`${baseClass}__portal-features`}>
              <span>• Device inventory</span>
              <span>• Policy management</span>
              <span>• Software distribution</span>
              <span>• Reporting and analytics</span>
            </div>
          </div>
          <div className={`${baseClass}__portal-actions`}>
            <Button
              onClick={handleMainDashboard}
              variant="success"
              className={`${baseClass}__portal-button`}
            >
              Access Dashboard
            </Button>
          </div>
        </div>

        {isGlobalAdmin && (
          <div className={`${baseClass}__portal-card`}>
            <div className={`${baseClass}__portal-icon`}>
              <Icon name="settings" />
            </div>
            <div className={`${baseClass}__portal-content`}>
              <h3>Internal Admin Portal</h3>
              <p>Advanced system administration and configuration interface</p>
              <div className={`${baseClass}__portal-features`}>
                <span>• System health monitoring</span>
                <span>• User and team management</span>
                <span>• Ansible MDM configuration</span>
                <span>• System logs and audit trails</span>
              </div>
            </div>
            <div className={`${baseClass}__portal-actions`}>
              <Button
                onClick={handleInternalPortal}
                variant="brand"
                className={`${baseClass}__portal-button`}
              >
                Access Internal Portal
              </Button>
            </div>
          </div>
        )}

        {isUserPortalEnabled && (
          <div className={`${baseClass}__portal-card`}>
            <div className={`${baseClass}__portal-icon`}>
              <Icon name="user" />
            </div>
            <div className={`${baseClass}__portal-content`}>
              <h3>User Portal</h3>
              <p>
                Self-service interface for end users to manage their devices
              </p>
              <div className={`${baseClass}__portal-features`}>
                <span>• Device enrollment</span>
                <span>• Personal device status</span>
                <span>• Support requests</span>
                <span>• Profile management</span>
              </div>
            </div>
            <div className={`${baseClass}__portal-actions`}>
              <Button
                onClick={handleUserPortal}
                variant="secondary"
                className={`${baseClass}__portal-button`}
              >
                Access User Portal
              </Button>
            </div>
          </div>
        )}
      </div>

      <div className={`${baseClass}__info`}>
        <div className={`${baseClass}__info-section`}>
          <h4>Current User</h4>
          <p>
            <strong>{currentUser?.name}</strong> ({currentUser?.email})
          </p>
          <p>Role: {currentUser?.global_role || "User"}</p>
        </div>

        <div className={`${baseClass}__info-section`}>
          <h4>System Information</h4>
          <p>Mobius MDM v{config?.version || "Unknown"}</p>
          <p>Open Source Device Management Platform</p>
        </div>
      </div>
    </div>
  );
};

export default PortalNavigation;
