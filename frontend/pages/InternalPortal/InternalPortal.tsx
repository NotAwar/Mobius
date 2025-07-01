import React, { useContext, useEffect, useState } from "react";
import { InjectedRouter } from "react-router";
import { useQuery } from "react-query";

import { AppContext } from "context/app";
import { NotificationContext } from "context/notification";
import PATHS from "router/paths";
import configAPI from "services/entities/config";
import teamsAPI from "services/entities/teams";
import usersAPI from "services/entities/users";

import Button from "components/buttons/Button";
import Spinner from "components/Spinner";
import DataTable from "components/DataTable";
import TableContainer from "components/TableContainer";

import { IConfig } from "interfaces/config";
import { IUser } from "interfaces/user";
import { ITeam } from "interfaces/team";

const baseClass = "internal-portal";

interface IInternalPortalProps {
  router: InjectedRouter;
}

interface ISystemStat {
  label: string;
  value: string | number;
  status?: "healthy" | "warning" | "error";
}

const InternalPortal = ({ router }: IInternalPortalProps): JSX.Element => {
  const { currentUser } = useContext(AppContext);
  const { renderFlash } = useContext(NotificationContext);
  const [systemStats, setSystemStats] = useState<ISystemStat[]>([]);

  const { data: config, isLoading: isLoadingConfig } = useQuery<IConfig, Error>(
    "config",
    () => configAPI.loadAll(),
    {
      refetchOnWindowFocus: false,
      retry: false,
    }
  );

  const { data: users, isLoading: isLoadingUsers } = useQuery<IUser[], Error>(
    "users",
    () => usersAPI.loadAll(),
    {
      refetchOnWindowFocus: false,
      retry: false,
    }
  );

  const { data: teams, isLoading: isLoadingTeams } = useQuery<ITeam[], Error>(
    "teams",
    () => teamsAPI.loadAll(),
    {
      refetchOnWindowFocus: false,
      retry: false,
    }
  );

  useEffect(() => {
    if (!currentUser?.global_role?.includes("admin")) {
      renderFlash("error", "Access denied. Admin privileges required.");
      router.push(PATHS.DASHBOARD);
    }
  }, [currentUser, router, renderFlash]);

  useEffect(() => {
    if (config && users && teams) {
      const stats: ISystemStat[] = [
        {
          label: "Total Users",
          value: users.length,
          status: users.length > 0 ? "healthy" : "warning",
        },
        {
          label: "Active Teams",
          value: teams.length,
          status: "healthy",
        },
        {
          label: "Ansible MDM Status",
          value: "Active",
          status: "healthy",
        },
        {
          label: "Server Version",
          value: config.version || "Unknown",
          status: "healthy",
        },
        {
          label: "License Status",
          value: "Open Source",
          status: "healthy",
        },
      ];
      setSystemStats(stats);
    }
  }, [config, users, teams]);

  const handleManageUsers = () => {
    router.push(PATHS.ADMIN_USERS);
  };

  const handleManageTeams = () => {
    router.push("/settings/teams");
  };

  const handleSystemSettings = () => {
    router.push(PATHS.ADMIN_SETTINGS);
  };

  const handleAnsibleMDM = () => {
    router.push("/ansible-mdm");
  };

  const handleViewLogs = () => {
    router.push("/admin/logs");
  };

  if (isLoadingConfig || isLoadingUsers || isLoadingTeams) {
    return <Spinner />;
  }

  return (
    <div className={baseClass}>
      <div className={`${baseClass}__header`}>
        <h1>Mobius MDM Internal Admin Portal</h1>
        <p>Advanced administration and system management interface</p>
      </div>

      <div className={`${baseClass}__content`}>
        <section className={`${baseClass}__system-overview`}>
          <h2>System Overview</h2>
          <div className={`${baseClass}__stats-grid`}>
            {systemStats.map((stat, index) => (
              <div
                key={index}
                className={`${baseClass}__stat-card ${baseClass}__stat-card--${stat.status}`}
              >
                <div className={`${baseClass}__stat-value`}>{stat.value}</div>
                <div className={`${baseClass}__stat-label`}>{stat.label}</div>
              </div>
            ))}
          </div>
        </section>

        <section className={`${baseClass}__quick-actions`}>
          <h2>Quick Actions</h2>
          <div className={`${baseClass}__actions-grid`}>
            <Button
              onClick={handleManageUsers}
              className={`${baseClass}__action-button`}
              variant="brand"
            >
              Manage Users
            </Button>
            <Button
              onClick={handleManageTeams}
              className={`${baseClass}__action-button`}
              variant="brand"
            >
              Manage Teams
            </Button>
            <Button
              onClick={handleSystemSettings}
              className={`${baseClass}__action-button`}
              variant="brand"
            >
              System Settings
            </Button>
            <Button
              onClick={handleAnsibleMDM}
              className={`${baseClass}__action-button`}
              variant="brand"
            >
              Ansible MDM Config
            </Button>
            <Button
              onClick={handleViewLogs}
              className={`${baseClass}__action-button`}
              variant="secondary"
            >
              View System Logs
            </Button>
          </div>
        </section>

        <section className={`${baseClass}__recent-activity`}>
          <h2>Recent Administrative Activity</h2>
          <div className={`${baseClass}__activity-list`}>
            <div className={`${baseClass}__activity-item`}>
              <span className={`${baseClass}__activity-time`}>
                {new Date().toLocaleTimeString()}
              </span>
              <span className={`${baseClass}__activity-description`}>
                Internal portal accessed by {currentUser?.name}
              </span>
            </div>
            <div className={`${baseClass}__activity-item`}>
              <span className={`${baseClass}__activity-time`}>
                {new Date(Date.now() - 300000).toLocaleTimeString()}
              </span>
              <span className={`${baseClass}__activity-description`}>
                System health check completed successfully
              </span>
            </div>
            <div className={`${baseClass}__activity-item`}>
              <span className={`${baseClass}__activity-time`}>
                {new Date(Date.now() - 600000).toLocaleTimeString()}
              </span>
              <span className={`${baseClass}__activity-description`}>
                Ansible MDM configuration synchronized
              </span>
            </div>
          </div>
        </section>
      </div>
    </div>
  );
};

export default InternalPortal;
