import React, { useContext, useEffect, useState } from "react";
import { InjectedRouter } from "react-router";
import { useQuery } from "react-query";

import { AppContext } from "context/app";
import { NotificationContext } from "context/notification";
import PATHS from "router/paths";
import hostsAPI from "services/entities/hosts";
import usersAPI from "services/entities/users";

import Button from "components/buttons/Button";
import Spinner from "components/Spinner";
import Card from "components/Card";

import { IHost } from "interfaces/host";
import { IUser } from "interfaces/user";

const baseClass = "user-portal";

interface IUserPortalProps {
  router: InjectedRouter;
}

interface IDeviceInfo {
  hostname: string;
  platform: string;
  osVersion: string;
  lastSeen: string;
  status: "online" | "offline" | "pending";
  enrollmentStatus: "enrolled" | "pending" | "failed";
}

const UserPortal = ({ router }: IUserPortalProps): JSX.Element => {
  const { currentUser } = useContext(AppContext);
  const { renderFlash } = useContext(NotificationContext);
  const [userDevices, setUserDevices] = useState<IDeviceInfo[]>([]);
  const [enrollmentCode, setEnrollmentCode] = useState<string>("");

  const { data: hosts, isLoading: isLoadingHosts } = useQuery<IHost[], Error>(
    "user-hosts",
    () => hostsAPI.loadAll(),
    {
      refetchOnWindowFocus: false,
      retry: false,
    }
  );

  useEffect(() => {
    // Generate a unique enrollment code for this user
    const code = `${currentUser?.id}-${Date.now().toString(36)}`.toUpperCase();
    setEnrollmentCode(code);
  }, [currentUser]);

  useEffect(() => {
    if (hosts && currentUser) {
      // Filter hosts that belong to the current user
      const filteredHosts = hosts.filter(
        (host) => host.primary_email === currentUser.email
      );

      const deviceInfo: IDeviceInfo[] = filteredHosts.map((host) => ({
        hostname: host.hostname || "Unknown Device",
        platform: host.platform || "Unknown",
        osVersion: host.os_version || "Unknown",
        lastSeen: host.seen_time || "Never",
        status: host.status === "online" ? "online" : "offline",
        enrollmentStatus: "enrolled",
      }));

      setUserDevices(deviceInfo);
    }
  }, [hosts, currentUser]);

  const handleEnrollDevice = () => {
    renderFlash("success", "Device enrollment instructions have been generated!");
  };

  const handleDownloadCertificate = () => {
    renderFlash("success", "Certificate download initiated.");
  };

  const handleRequestSupport = () => {
    router.push("/support");
  };

  const handleViewProfile = () => {
    router.push(PATHS.ACCOUNT);
  };

  const getStatusBadge = (status: string) => {
    const statusClass = `${baseClass}__status-badge ${baseClass}__status-badge--${status}`;
    return <span className={statusClass}>{status.toUpperCase()}</span>;
  };

  if (isLoadingHosts) {
    return <Spinner />;
  }

  return (
    <div className={baseClass}>
      <div className={`${baseClass}__header`}>
        <h1>Welcome to Mobius MDM</h1>
        <p>Manage your devices and access IT resources</p>
        <div className={`${baseClass}__user-info`}>
          <span>Logged in as: <strong>{currentUser?.name}</strong></span>
          <Button
            onClick={handleViewProfile}
            variant="text-link"
            className={`${baseClass}__profile-link`}
          >
            View Profile
          </Button>
        </div>
      </div>

      <div className={`${baseClass}__content`}>
        <section className={`${baseClass}__my-devices`}>
          <h2>My Devices</h2>
          {userDevices.length > 0 ? (
            <div className={`${baseClass}__devices-grid`}>
              {userDevices.map((device, index) => (
                <Card key={index} className={`${baseClass}__device-card`}>
                  <div className={`${baseClass}__device-header`}>
                    <h3>{device.hostname}</h3>
                    {getStatusBadge(device.status)}
                  </div>
                  <div className={`${baseClass}__device-details`}>
                    <p><strong>Platform:</strong> {device.platform}</p>
                    <p><strong>OS Version:</strong> {device.osVersion}</p>
                    <p><strong>Last Seen:</strong> {new Date(device.lastSeen).toLocaleDateString()}</p>
                    <p><strong>Enrollment:</strong> {getStatusBadge(device.enrollmentStatus)}</p>
                  </div>
                </Card>
              ))}
            </div>
          ) : (
            <div className={`${baseClass}__no-devices`}>
              <p>No devices enrolled yet.</p>
              <p>Use the enrollment section below to add your first device.</p>
            </div>
          )}
        </section>

        <section className={`${baseClass}__enrollment`}>
          <h2>Enroll a New Device</h2>
          <Card className={`${baseClass}__enrollment-card`}>
            <div className={`${baseClass}__enrollment-content`}>
              <h3>Device Enrollment</h3>
              <p>Follow these steps to enroll your device with Mobius MDM:</p>
              
              <div className={`${baseClass}__enrollment-steps`}>
                <div className={`${baseClass}__step`}>
                  <span className={`${baseClass}__step-number`}>1</span>
                  <div className={`${baseClass}__step-content`}>
                    <h4>Download Enrollment Profile</h4>
                    <p>Download the configuration profile for your device type</p>
                    <div className={`${baseClass}__download-buttons`}>
                      <Button
                        onClick={handleDownloadCertificate}
                        variant="brand"
                        className={`${baseClass}__download-button`}
                      >
                        Download for macOS
                      </Button>
                      <Button
                        onClick={handleDownloadCertificate}
                        variant="brand"
                        className={`${baseClass}__download-button`}
                      >
                        Download for Windows
                      </Button>
                      <Button
                        onClick={handleDownloadCertificate}
                        variant="brand"
                        className={`${baseClass}__download-button`}
                      >
                        Download for Linux
                      </Button>
                    </div>
                  </div>
                </div>

                <div className={`${baseClass}__step`}>
                  <span className={`${baseClass}__step-number`}>2</span>
                  <div className={`${baseClass}__step-content`}>
                    <h4>Install Profile</h4>
                    <p>Install the downloaded profile on your device following the platform-specific instructions</p>
                  </div>
                </div>

                <div className={`${baseClass}__step`}>
                  <span className={`${baseClass}__step-number`}>3</span>
                  <div className={`${baseClass}__step-content`}>
                    <h4>Enrollment Code</h4>
                    <p>Use this code during device enrollment:</p>
                    <div className={`${baseClass}__enrollment-code`}>
                      <code>{enrollmentCode}</code>
                      <Button
                        onClick={() => navigator.clipboard.writeText(enrollmentCode)}
                        variant="text-link"
                        className={`${baseClass}__copy-button`}
                      >
                        Copy
                      </Button>
                    </div>
                  </div>
                </div>
              </div>

              <div className={`${baseClass}__enrollment-actions`}>
                <Button
                  onClick={handleEnrollDevice}
                  variant="brand"
                  className={`${baseClass}__enroll-button`}
                >
                  Generate Enrollment Instructions
                </Button>
              </div>
            </div>
          </Card>
        </section>

        <section className={`${baseClass}__support`}>
          <h2>Need Help?</h2>
          <Card className={`${baseClass}__support-card`}>
            <div className={`${baseClass}__support-content`}>
              <h3>Support & Resources</h3>
              <div className={`${baseClass}__support-options`}>
                <div className={`${baseClass}__support-option`}>
                  <h4>IT Support</h4>
                  <p>Contact your IT administrator for technical assistance</p>
                  <Button
                    onClick={handleRequestSupport}
                    variant="secondary"
                    className={`${baseClass}__support-button`}
                  >
                    Contact Support
                  </Button>
                </div>
                <div className={`${baseClass}__support-option`}>
                  <h4>Documentation</h4>
                  <p>Browse our user guides and troubleshooting documentation</p>
                  <Button
                    onClick={() => window.open("/docs/user-guide", "_blank")}
                    variant="secondary"
                    className={`${baseClass}__support-button`}
                  >
                    View Documentation
                  </Button>
                </div>
                <div className={`${baseClass}__support-option`}>
                  <h4>System Status</h4>
                  <p>Check the current status of Mobius MDM services</p>
                  <Button
                    onClick={() => window.open("/status", "_blank")}
                    variant="secondary"
                    className={`${baseClass}__support-button`}
                  >
                    View Status
                  </Button>
                </div>
              </div>
            </div>
          </Card>
        </section>
      </div>
    </div>
  );
};

export default UserPortal;
