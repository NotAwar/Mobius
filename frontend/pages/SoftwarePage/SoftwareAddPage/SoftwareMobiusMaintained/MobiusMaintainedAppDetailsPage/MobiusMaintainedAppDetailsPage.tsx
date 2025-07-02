import React, { useContext, useState } from "react";
import { AxiosResponse } from "axios";
import { Location } from "history";
import { useQuery } from "react-query";
import { InjectedRouter } from "react-router";
import { useErrorHandler } from "react-error-boundary";

import PATHS from "router/paths";
import { getPathWithQueryParams } from "utilities/url";
import { DEFAULT_USE_QUERY_OPTIONS } from "utilities/constants";
import softwareAPI from "services/entities/software";
import labelsAPI, { getCustomLabels } from "services/entities/labels";
import { QueryContext } from "context/query";
import { AppContext } from "context/app";
import { NotificationContext } from "context/notification";
import { Platform, PLATFORM_DISPLAY_NAMES } from "interfaces/platform";
import { ILabelSummary } from "interfaces/label";
import useToggleSidePanel from "hooks/useToggleSidePanel";

import BackLink from "components/BackLink";
import MainContent from "components/MainContent";
import Spinner from "components/Spinner";
import DataError from "components/DataError";
import SidePanelContent from "components/SidePanelContent";
import QuerySidePanel from "components/side_panels/QuerySidePanel";
import PremiumFeatureMessage from "components/PremiumFeatureMessage";
import Card from "components/Card";
import SoftwareIcon from "pages/SoftwarePage/components/icons/SoftwareIcon";
import Button from "components/buttons/Button";
import Icon from "components/Icon";
import CategoriesEndUserExperienceModal from "pages/SoftwarePage/components/modals/CategoriesEndUserExperienceModal";

import MobiusAppDetailsForm from "./MobiusAppDetailsForm";
import { IMobiusMaintainedAppFormData } from "./MobiusAppDetailsForm/MobiusAppDetailsForm";

import AddMobiusAppSoftwareModal from "./AddMobiusAppSoftwareModal";
import MobiusAppDetailsModal from "./MobiusAppDetailsModal";

import { getErrorMessage } from "./helpers";

const DEFAULT_ERROR_MESSAGE = "Couldn't add. Please try again.";
const REQUEST_TIMEOUT_ERROR_MESSAGE =
  "Couldn't add. Request timeout. Please make sure your server and load balancer timeout is long enough.";

const baseClass = "mobius-maintained-app-details-page";

interface IMobiusAppSummaryProps {
  name: string;
  platform: string;
  version: string;
  onClickShowAppDetails: (event: MouseEvent) => void;
}

const MobiusAppSummary = ({
  name,
  platform,
  version,
  onClickShowAppDetails,
}: IMobiusAppSummaryProps) => {
  return (
    <Card
      className={`${baseClass}__mobius-app-summary`}
      borderRadiusSize="medium"
      color="grey"
    >
      <div className={`${baseClass}__mobius-app-summary--left`}>
        <SoftwareIcon name={name} size="medium" />
        <div className={`${baseClass}__mobius-app-summary--details`}>
          <div className={`${baseClass}__mobius-app-summary--title`}>
            {name}
          </div>
          <div className={`${baseClass}__mobius-app-summary--info`}>
            <div
              className={`${baseClass}__mobius-app-summary--details--platform`}
            >
              {PLATFORM_DISPLAY_NAMES[platform as Platform]}
            </div>
            &bull;
            <div
              className={`${baseClass}__mobius-app-summary--details--version`}
            >
              {version}
            </div>
          </div>
        </div>
      </div>
      <div className={`${baseClass}__mobius-app-summary--show-details`}>
        <Button variant="text-icon" onClick={onClickShowAppDetails}>
          <Icon name="info" /> Show details
        </Button>
      </div>
    </Card>
  );
};

export interface IMobiusMaintainedAppDetailsQueryParams {
  team_id?: string;
}

interface IMobiusMaintainedAppDetailsRouteParams {
  id: string;
}

interface IMobiusMaintainedAppDetailsPageProps {
  location: Location<IMobiusMaintainedAppDetailsQueryParams>;
  router: InjectedRouter;
  routeParams: IMobiusMaintainedAppDetailsRouteParams;
}

/** This type includes the editable form data as well as the mobius maintained
 * app id */
export type IAddMobiusMaintainedData = IMobiusMaintainedAppFormData & {
  appId: number;
};

const MobiusMaintainedAppDetailsPage = ({
  location,
  router,
  routeParams,
}: IMobiusMaintainedAppDetailsPageProps) => {
  const teamId = location.query.team_id;
  const appId = parseInt(routeParams.id, 10);
  if (isNaN(appId)) {
    router.push(PATHS.SOFTWARE_ADD_MOBIUS_MAINTAINED);
  }

  const { renderFlash } = useContext(NotificationContext);

  const handlePageError = useErrorHandler();
  const { isPremiumTier } = useContext(AppContext);

  const { selectedOsqueryTable, setSelectedOsqueryTable } = useContext(
    QueryContext
  );
  const { isSidePanelOpen, setSidePanelOpen } = useToggleSidePanel(false);
  const [
    showAddMobiusAppSoftwareModal,
    setShowAddMobiusAppSoftwareModal,
  ] = useState(false);
  const [showAppDetailsModal, setShowAppDetailsModal] = useState(false);
  const [
    showPreviewEndUserExperience,
    setShowPreviewEndUserExperience,
  ] = useState(false);

  const {
    data: mobiusApp,
    isLoading: isLoadingMobiusApp,
    isError: isErrorMobiusApp,
  } = useQuery(
    ["mobius-maintained-app", appId],
    () => softwareAPI.getMobiusMaintainedApp(appId, teamId),
    {
      ...DEFAULT_USE_QUERY_OPTIONS,
      enabled: isPremiumTier,
      retry: false,
      select: (res) => res.mobius_maintained_app,
      onError: (error) => handlePageError(error),
    }
  );

  const {
    data: labels,
    isLoading: isLoadingLabels,
    isError: isErrorLabels,
  } = useQuery<ILabelSummary[], Error>(
    ["custom_labels"],
    () => labelsAPI.summary().then((res) => getCustomLabels(res.labels)),

    {
      ...DEFAULT_USE_QUERY_OPTIONS,
      enabled: isPremiumTier,
      staleTime: 10000,
    }
  );

  const onOsqueryTableSelect = (tableName: string) => {
    setSelectedOsqueryTable(tableName);
  };

  const onClickShowAppDetails = () => {
    setShowAppDetailsModal(true);
  };

  const onClickPreviewEndUserExperience = () => {
    setShowPreviewEndUserExperience(!showPreviewEndUserExperience);
  };

  const backToAddSoftwareUrl = getPathWithQueryParams(
    PATHS.SOFTWARE_ADD_MOBIUS_MAINTAINED,
    { team_id: teamId }
  );

  const onCancel = () => {
    router.push(backToAddSoftwareUrl);
  };

  const onSubmit = async (formData: IMobiusMaintainedAppFormData) => {
    // this should not happen but we need to handle the type correctly
    if (!teamId) return;

    setShowAddMobiusAppSoftwareModal(true);

    try {
      const {
        software_title_id: softwareFmaTitleId,
      } = await softwareAPI.addMobiusMaintainedApp(parseInt(teamId, 10), {
        ...formData,
        appId,
      });

      router.push(
        getPathWithQueryParams(
          PATHS.SOFTWARE_TITLE_DETAILS(softwareFmaTitleId.toString()),
          {
            team_id: teamId,
          }
        )
      );

      renderFlash(
        "success",
        <>
          <b>{mobiusApp?.name}</b> successfully added.
        </>
      );
    } catch (error) {
      const ae = (typeof error === "object" ? error : {}) as AxiosResponse;

      const errorMessage = getErrorMessage(ae);

      if (
        ae.status === 408 ||
        errorMessage.includes("json decoder error") // 400 bad request when really slow
      ) {
        renderFlash("error", REQUEST_TIMEOUT_ERROR_MESSAGE);
      } else if (errorMessage) {
        renderFlash("error", errorMessage);
      } else {
        renderFlash("error", DEFAULT_ERROR_MESSAGE);
      }
    }

    setShowAddMobiusAppSoftwareModal(false);
  };

  const renderContent = () => {
    if (!isPremiumTier) {
      return <PremiumFeatureMessage />;
    }

    if (isLoadingMobiusApp || isLoadingLabels) {
      return <Spinner />;
    }

    if (isErrorMobiusApp || isErrorLabels) {
      return <DataError verticalPaddingSize="pad-xxxlarge" />;
    }

    if (mobiusApp) {
      return (
        <>
          <BackLink
            text="Back to add software"
            path={backToAddSoftwareUrl}
            className={`${baseClass}__back-to-add-software`}
          />
          <h1>{mobiusApp.name}</h1>
          <div className={`${baseClass}__page-content`}>
            <MobiusAppSummary
              name={mobiusApp.name}
              platform={mobiusApp.platform}
              version={mobiusApp.version}
              onClickShowAppDetails={onClickShowAppDetails}
            />
            <MobiusAppDetailsForm
              labels={labels || []}
              categories={mobiusApp.categories}
              name={mobiusApp.name}
              showSchemaButton={!isSidePanelOpen}
              defaultInstallScript={mobiusApp.install_script}
              defaultPostInstallScript={mobiusApp.post_install_script}
              defaultUninstallScript={mobiusApp.uninstall_script}
              teamId={teamId}
              onClickShowSchema={() => setSidePanelOpen(true)}
              onCancel={onCancel}
              onSubmit={onSubmit}
              softwareTitleId={mobiusApp.software_title_id}
              onClickPreviewEndUserExperience={onClickPreviewEndUserExperience}
            />
          </div>
          {showPreviewEndUserExperience && (
            <CategoriesEndUserExperienceModal
              onCancel={onClickPreviewEndUserExperience}
            />
          )}
        </>
      );
    }

    return null;
  };

  return (
    <>
      <MainContent className={baseClass}>
        <>{renderContent()}</>
      </MainContent>
      {isPremiumTier && mobiusApp && isSidePanelOpen && (
        <SidePanelContent className={`${baseClass}__side-panel`}>
          <QuerySidePanel
            key="query-side-panel"
            onOsqueryTableSelect={onOsqueryTableSelect}
            selectedOsqueryTable={selectedOsqueryTable}
            onClose={() => setSidePanelOpen(false)}
          />
        </SidePanelContent>
      )}
      {showAddMobiusAppSoftwareModal && <AddMobiusAppSoftwareModal />}
      {showAppDetailsModal && mobiusApp && (
        <MobiusAppDetailsModal
          name={mobiusApp.name}
          platform={mobiusApp.platform}
          version={mobiusApp.version}
          slug={mobiusApp.slug}
          url={mobiusApp.url}
          onCancel={() => setShowAppDetailsModal(false)}
        />
      )}
    </>
  );
};

export default MobiusMaintainedAppDetailsPage;
