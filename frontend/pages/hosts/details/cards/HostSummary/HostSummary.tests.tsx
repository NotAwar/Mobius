import React from "react";
import { screen, fireEvent } from "@testing-library/react";
import { createCustomRenderer } from "test/test-utils";

import createMockUser from "__mocks__/userMock";
import { createMockHostSummary } from "__mocks__/hostMock";

import { BootstrapPackageStatus } from "interfaces/mdm";
import HostSummary from "./HostSummary";

describe("Host Summary section", () => {
  describe("Issues data", () => {
    it("omit issues header if no issues", async () => {
      const render = createCustomRenderer({
        context: {
          app: {
            isPremiumTier: true,
            isGlobalAdmin: true,
            currentUser: createMockUser(),
          },
        },
      });
      const summaryData = createMockHostSummary({});

      render(<HostSummary summaryData={summaryData} />);

      expect(screen.queryByText("Issues")).not.toBeInTheDocument();
    });
  });

  describe("Team data", () => {
    it("renders the team name when present", () => {
      const render = createCustomRenderer({
        context: {
          app: {
            isPremiumTier: true,
            isGlobalAdmin: true,
            currentUser: createMockUser(),
          },
        },
      });
      const summaryData = createMockHostSummary({ team_name: "Engineering" });
      render(<HostSummary summaryData={summaryData} isPremiumTier />);
      expect(screen.getByText("Team").nextElementSibling).toHaveTextContent(
        "Engineering"
      );
    });

    it("renders 'No team' when team_name is '---'", () => {
      const render = createCustomRenderer({
        /* ...context... */
      });
      const summaryData = createMockHostSummary({ team_name: "---" });
      render(<HostSummary summaryData={summaryData} isPremiumTier />);
      expect(screen.getByText("No team")).toBeInTheDocument();
    });
  });

  describe("Disk encryption data", () => {
    it("renders 'On' for macOS when enabled", () => {
      const render = createCustomRenderer({
        context: {
          app: {
            isPremiumTier: true,
            isGlobalAdmin: true,
            currentUser: createMockUser(),
          },
        },
      });
      const summaryData = createMockHostSummary({
        platform: "darwin",
        disk_encryption_enabled: true,
      });
      render(<HostSummary summaryData={summaryData} />);
      expect(screen.getByText("Disk encryption")).toBeInTheDocument();
      expect(screen.getByText("On")).toBeInTheDocument();
    });

    it("renders 'Off' for Windows when disabled", () => {
      const render = createCustomRenderer({
        context: {
          app: {
            isPremiumTier: true,
            isGlobalAdmin: true,
            currentUser: createMockUser(),
          },
        },
      });
      const summaryData = createMockHostSummary({
        platform: "windows",
        disk_encryption_enabled: false,
      });
      render(<HostSummary summaryData={summaryData} />);
      expect(screen.getByText("Disk encryption")).toBeInTheDocument();
      expect(screen.getByText("Off")).toBeInTheDocument();
    });

    it("renders Chromebook message for Chrome platform", () => {
      const render = createCustomRenderer({
        context: {
          app: {
            isPremiumTier: true,
            isGlobalAdmin: true,
            currentUser: createMockUser(),
          },
        },
      });
      const summaryData = createMockHostSummary({ platform: "chrome" });
      render(<HostSummary summaryData={summaryData} />);
      expect(screen.getByText("Always on")).toBeInTheDocument();
    });
  });

  describe("Agent data", () => {
    it("with all info present, render Agent header with orbit_version and tooltip with all 3 data points", async () => {
      const render = createCustomRenderer({
        context: {
          app: {
            isPremiumTier: true,
            isGlobalAdmin: true,
            currentUser: createMockUser(),
          },
        },
      });
      const summaryData = createMockHostSummary();
      const orbitVersion = summaryData.orbit_version as string;
      const osqueryVersion = summaryData.osquery_version as string;
      const mobiusdVersion = summaryData.mobius_desktop_version as string;

      render(<HostSummary summaryData={summaryData} />);

      expect(screen.getByText("Agent")).toBeInTheDocument();

      await fireEvent.mouseEnter(
        screen.getByText(new RegExp(orbitVersion, "i"))
      );

      expect(
        screen.getByText(new RegExp(osqueryVersion, "i"))
      ).toBeInTheDocument();
      expect(
        screen.getByText(new RegExp(mobiusdVersion, "i"))
      ).toBeInTheDocument();
    });

    it("omit mobius desktop from tooltip if no mobius desktop version", async () => {
      const render = createCustomRenderer({
        context: {
          app: {
            isPremiumTier: true,
            isGlobalAdmin: true,
            currentUser: createMockUser(),
          },
        },
      });
      const summaryData = createMockHostSummary({
        mobius_desktop_version: null,
      });
      const orbitVersion = summaryData.orbit_version as string;
      const osqueryVersion = summaryData.osquery_version as string;

      render(<HostSummary summaryData={summaryData} />);

      expect(screen.getByText("Agent")).toBeInTheDocument();

      await fireEvent.mouseEnter(
        screen.getByText(new RegExp(orbitVersion, "i"))
      );

      expect(
        screen.getByText(new RegExp(osqueryVersion, "i"))
      ).toBeInTheDocument();
      expect(screen.queryByText(/Mobius desktop:/i)).not.toBeInTheDocument();
    });

    it("for Chromebooks, render Agent header with osquery_version that is the mobiusdaemon chrome version and no tooltip", async () => {
      const render = createCustomRenderer({
        context: {
          app: {
            isPremiumTier: true,
            isGlobalAdmin: true,
            currentUser: createMockUser(),
          },
        },
      });
      const summaryData = createMockHostSummary({
        platform: "chrome",
        osquery_version: "mobiusdaemon 1.2.0",
      });

      const mobiusdChromeVersion = summaryData.osquery_version as string;

      const { user } = render(<HostSummary summaryData={summaryData} />);

      expect(screen.getByText("Agent")).toBeInTheDocument();
      await user.hover(screen.getByText(new RegExp(mobiusdChromeVersion, "i")));
      expect(screen.queryByText("Osquery")).not.toBeInTheDocument();
    });
  });

  describe("iOS and iPadOS data", () => {
    it("for iOS, renders Team, Disk space, and Operating system data only", async () => {
      const render = createCustomRenderer({
        context: {
          app: {
            isPremiumTier: true,
            isGlobalAdmin: true,
            currentUser: createMockUser(),
          },
        },
      });

      const summaryData = createMockHostSummary({
        team_id: 2,
        team_name: "Mobile",
        platform: "ios",
        os_version: "iOS 14.7.1",
      });

      const teamName = summaryData.team_name as string;
      const diskSpaceAvailable = summaryData.gigs_disk_space_available as string;
      const osVersion = summaryData.os_version as string;

      render(<HostSummary summaryData={summaryData} isPremiumTier />);

      expect(screen.getByText("Team").nextElementSibling).toHaveTextContent(
        teamName
      );
      expect(
        screen.getByText("Disk space").nextElementSibling
      ).toHaveTextContent(`${diskSpaceAvailable} GB available`);
      expect(
        screen.getByText("Operating system").nextElementSibling
      ).toHaveTextContent(osVersion);

      expect(screen.queryByText("Status")).not.toBeInTheDocument();
      expect(screen.queryByText("Memory")).not.toBeInTheDocument();
      expect(screen.queryByText("Processor type")).not.toBeInTheDocument();
      expect(screen.queryByText("Agent")).not.toBeInTheDocument();
      expect(screen.queryByText("Osquery")).not.toBeInTheDocument();
    });
    it("for iPadOS, renders Team, Disk space, and Operating system data only", async () => {
      const render = createCustomRenderer({
        context: {
          app: {
            isPremiumTier: true,
            isGlobalAdmin: true,
            currentUser: createMockUser(),
          },
        },
      });

      const summaryData = createMockHostSummary({
        team_id: 2,
        team_name: "Mobile",
        platform: "ipados",
        os_version: "iPadOS 16.7.8",
      });

      const teamName = summaryData.team_name as string;
      const diskSpaceAvailable = summaryData.gigs_disk_space_available as string;
      const osVersion = summaryData.os_version as string;

      render(<HostSummary summaryData={summaryData} isPremiumTier />);

      expect(screen.getByText("Team").nextElementSibling).toHaveTextContent(
        teamName
      );
      expect(
        screen.getByText("Disk space").nextElementSibling
      ).toHaveTextContent(`${diskSpaceAvailable} GB available`);
      expect(
        screen.getByText("Operating system").nextElementSibling
      ).toHaveTextContent(osVersion);

      expect(screen.queryByText("Status")).not.toBeInTheDocument();
      expect(screen.queryByText("Memory")).not.toBeInTheDocument();
      expect(screen.queryByText("Processor type")).not.toBeInTheDocument();
      expect(screen.queryByText("Agent")).not.toBeInTheDocument();
      expect(screen.queryByText("Osquery")).not.toBeInTheDocument();
    });
  });

  describe("Maintenance window data", () => {
    it("renders maintenance window data with timezone", async () => {
      const render = createCustomRenderer({
        context: {
          app: {
            isPremiumTier: true,
            isGlobalAdmin: true,
            currentUser: createMockUser(),
          },
        },
      });

      const summaryData = createMockHostSummary({
        maintenance_window: {
          starts_at: "3025-06-24T20:48:14-03:00",
          timezone: "America/Argentina/Buenos_Aires",
        },
      });
      const prettyStartTime = /Jun 24 at 8:48 PM/;

      render(<HostSummary summaryData={summaryData} isPremiumTier />);

      expect(screen.getByText("Scheduled maintenance")).toBeInTheDocument();
      expect(screen.getByText(prettyStartTime)).toBeInTheDocument();
    });
  });

  describe("Bootstrap package data", () => {
    it("renders Bootstrap package indicator when status is present", () => {
      const toggleBootstrapPackageModal = jest.fn();
      const render = createCustomRenderer({
        context: {
          app: {
            isPremiumTier: true,
            isGlobalAdmin: true,
            currentUser: createMockUser(),
          },
        },
      });
      const summaryData = createMockHostSummary({ platform: "darwin" });
      const bootstrapPackageData = {
        status: "installed" as BootstrapPackageStatus,
      };
      render(
        <HostSummary
          summaryData={summaryData}
          bootstrapPackageData={bootstrapPackageData}
          toggleBootstrapPackageModal={toggleBootstrapPackageModal}
        />
      );
      expect(screen.getByText("Bootstrap package")).toBeInTheDocument();
    });
  });
});
