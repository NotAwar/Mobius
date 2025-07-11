import React, { useContext, useState, useEffect } from "react";
import { InjectedRouter } from "react-router";
import { useQuery } from "react-query";
import paths from "router/paths";
import classnames from "classnames";

import { ILabelSummary } from "interfaces/label";
import {
  IAppStoreApp,
  ISoftwarePackage,
  isSoftwarePackage,
} from "interfaces/software";
import mdmAppleAPI from "services/entities/mdm_apple";

import { NotificationContext } from "context/notification";
import softwareAPI, {
  MAX_FILE_SIZE_BYTES,
  MAX_FILE_SIZE_MB,
} from "services/entities/software";
import labelsAPI, { getCustomLabels } from "services/entities/labels";

import { DEFAULT_USE_QUERY_OPTIONS } from "utilities/constants";
import deepDifference from "utilities/deep_difference";
import { getFileDetails } from "utilities/file/fileUtils";
import { getPathWithQueryParams, QueryParams } from "utilities/url";

import Modal from "components/Modal";
import FileProgressModal from "components/FileProgressModal";
import CategoriesEndUserExperienceModal from "pages/SoftwarePage/components/modals/CategoriesEndUserExperienceModal";

import PackageForm from "pages/SoftwarePage/components/forms/PackageForm";
import { IPackageFormData } from "pages/SoftwarePage/components/forms/PackageForm/PackageForm";
import SoftwareVppForm from "pages/SoftwarePage/components/forms/SoftwareVppForm";
import { ISoftwareVppFormData } from "pages/SoftwarePage/components/forms/SoftwareVppForm/SoftwareVppForm";
import {
  generateSelectedLabels,
  getCustomTarget,
  getInstallType,
  getTargetType,
} from "pages/SoftwarePage/helpers";

import { getErrorMessage } from "./helpers";
import ConfirmSaveChangesModal from "../ConfirmSaveChangesModal";

const baseClass = "edit-software-modal";

// Install type used on add but not edit
export type IEditPackageFormData = Omit<IPackageFormData, "installType">;

interface IEditSoftwareModalProps {
  softwareId: number;
  teamId: number;
  software: ISoftwarePackage | IAppStoreApp;
  refetchSoftwareTitle: () => void;
  onExit: () => void;
  installerType: "package" | "vpp";
  router: InjectedRouter;
  gitOpsModeEnabled?: boolean;
  openViewYamlModal: () => void;
}

const EditSoftwareModal = ({
  softwareId,
  teamId,
  software,
  onExit,
  refetchSoftwareTitle,
  installerType,
  router,
  gitOpsModeEnabled = false,
  openViewYamlModal,
}: IEditSoftwareModalProps) => {
  const { renderFlash } = useContext(NotificationContext);

  const [editSoftwareModalClasses, setEditSoftwareModalClasses] = useState(
    baseClass
  );
  const [isUpdatingSoftware, setIsUpdatingSoftware] = useState(false);
  const [
    showConfirmSaveChangesModal,
    setShowConfirmSaveChangesModal,
  ] = useState(false);
  const [
    showPreviewEndUserExperienceModal,
    setShowPreviewEndUserExperienceModal,
  ] = useState(false);

  const [
    pendingPackageUpdates,
    setPendingPackageUpdates,
  ] = useState<IEditPackageFormData>({
    software: null,
    installScript: "",
    selfService: false,
    automaticInstall: false,
    targetType: "",
    customTarget: "",
    labelTargets: {},
    categories: [],
  });
  const [
    pendingVppUpdates,
    setPendingVppUpdates,
  ] = useState<ISoftwareVppFormData>({
    selfService: false,
    automaticInstall: false,
    targetType: "",
    customTarget: "",
    labelTargets: {},
    categories: [],
  });
  const [uploadProgress, setUploadProgress] = useState(0);

  const { data: labels } = useQuery<ILabelSummary[], Error>(
    ["custom_labels"],
    () => labelsAPI.summary().then((res) => getCustomLabels(res.labels)),
    {
      ...DEFAULT_USE_QUERY_OPTIONS,
    }
  );

  // Work around to not lose Edit Software modal data when Save changes modal opens
  // by using CSS to hide Edit Software modal when Save changes modal is open
  useEffect(() => {
    setEditSoftwareModalClasses(
      classnames(baseClass, {
        [`${baseClass}--hidden`]:
          showConfirmSaveChangesModal ||
          showPreviewEndUserExperienceModal ||
          (!!pendingPackageUpdates.software && isUpdatingSoftware),
      })
    );
  }, [
    showConfirmSaveChangesModal,
    showPreviewEndUserExperienceModal,
    pendingPackageUpdates.software,
    isUpdatingSoftware,
  ]);

  useEffect(() => {
    const beforeUnloadHandler = (e: BeforeUnloadEvent) => {
      e.preventDefault();
      // Next line with e.returnValue is included for legacy support
      // e.g.Chrome / Edge < 119
      e.returnValue = true;
    };

    // set up event listener to prevent user from leaving page while uploading
    if (isUpdatingSoftware) {
      addEventListener("beforeunload", beforeUnloadHandler);
    } else {
      removeEventListener("beforeunload", beforeUnloadHandler);
    }

    // clean up event listener and timeout on component unmount
    return () => {
      removeEventListener("beforeunload", beforeUnloadHandler);
    };
  }, [isUpdatingSoftware]);

  const toggleConfirmSaveChangesModal = () => {
    setShowConfirmSaveChangesModal(!showConfirmSaveChangesModal);
  };

  const togglePreviewEndUserExperienceModal = () => {
    setShowPreviewEndUserExperienceModal(!showPreviewEndUserExperienceModal);
  };

  // Edit package API call
  const onEditPackage = async (formData: IEditPackageFormData) => {
    setIsUpdatingSoftware(true);

    if (formData.software && formData.software.size > MAX_FILE_SIZE_BYTES) {
      renderFlash(
        "error",
        `Couldn't edit software. The maximum file size is ${MAX_FILE_SIZE_MB} MB.`
      );
      setIsUpdatingSoftware(false);
      return;
    }

    try {
      await softwareAPI.editSoftwarePackage({
        data: formData,
        orignalPackage: software as ISoftwarePackage,
        softwareId,
        teamId,
        onUploadProgress: (progressEvent) => {
          const progress = progressEvent.progress || 0;
          // for large uploads it seems to take a bit for the server to finalize its response so we'll keep the
          // progress bar at 97% until the server response is received
          setUploadProgress(Math.max(progress - 0.03, 0.01));
        },
      });

      if (
        isSoftwarePackage(software) &&
        software.title_id &&
        gitOpsModeEnabled
      ) {
        // No longer flash message, we open YAML modal if editing with gitOpsModeEnabled
        openViewYamlModal();
      } else {
        renderFlash(
          "success",
          <>
            Successfully edited <b>{formData.software?.name}</b>.
            {formData.selfService
              ? " The end user can install from Mobius Desktop."
              : ""}
          </>
        );
      }
      refetchSoftwareTitle();
      onExit();
    } catch (e) {
      renderFlash("error", getErrorMessage(e, software as IAppStoreApp));
    }
    setIsUpdatingSoftware(false);
  };

  const isOnlySelfServiceUpdated = (updates: Record<string, any>) => {
    return Object.keys(updates).length === 1 && "selfService" in updates;
  };

  const onClickSavePackage = (formData: IPackageFormData) => {
    const softwarePackage = software as ISoftwarePackage;

    const currentData = {
      software: null,
      installScript: softwarePackage.install_script || "",
      preInstallQuery: softwarePackage.pre_install_query || "",
      postInstallScript: softwarePackage.post_install_script || "",
      uninstallScript: softwarePackage.uninstall_script || "",
      selfService: softwarePackage.self_service || false,
      installType: getInstallType(softwarePackage),
      targetType: getTargetType(softwarePackage),
      customTarget: getCustomTarget(softwarePackage),
      labelTargets: generateSelectedLabels(softwarePackage),
    };

    setPendingPackageUpdates(formData);

    const updates = deepDifference(formData, currentData);

    if (isOnlySelfServiceUpdated(updates)) {
      onEditPackage(formData);
    } else {
      setShowConfirmSaveChangesModal(true);
    }
  };

  // Edit VPP API call
  const onEditVpp = async (formData: ISoftwareVppFormData) => {
    setIsUpdatingSoftware(true);

    try {
      await mdmAppleAPI.editVppApp(softwareId, teamId, formData);

      renderFlash(
        "success",
        <>
          Successfully edited <b>{software.name}</b>.
          {formData.selfService
            ? " The end user can install from Mobius Desktop."
            : ""}
        </>
      );
      onExit();
      refetchSoftwareTitle();
    } catch (e) {
      renderFlash("error", getErrorMessage(e, software as IAppStoreApp));
    }
    setIsUpdatingSoftware(false);
  };

  const onClickSaveVpp = async (formData: ISoftwareVppFormData) => {
    const currentData = {
      selfService: software.self_service || false,
      automaticInstall: software.automatic_install || false,
      targetType: getTargetType(software),
      customTarget: getCustomTarget(software),
      labelTargets: generateSelectedLabels(software),
    };

    setPendingVppUpdates(formData);

    const updates = deepDifference(formData, currentData);

    if (isOnlySelfServiceUpdated(updates)) {
      onEditVpp(formData);
    } else {
      setShowConfirmSaveChangesModal(true);
    }
  };

  const onClickConfirmChanges = () => {
    if (installerType === "package") {
      onEditPackage(pendingPackageUpdates);
    } else {
      onEditVpp(pendingVppUpdates);
    }
  };

  const renderForm = () => {
    if (installerType === "package") {
      const softwarePackage = software as ISoftwarePackage;
      return (
        <PackageForm
          labels={labels || []}
          className={`${baseClass}__package-form`}
          isEditingSoftware
          onCancel={onExit}
          onSubmit={onClickSavePackage}
          onClickPreviewEndUserExperience={togglePreviewEndUserExperienceModal}
          defaultSoftware={software}
          defaultInstallScript={softwarePackage.install_script}
          defaultPreInstallQuery={softwarePackage.pre_install_query}
          defaultPostInstallScript={softwarePackage.post_install_script}
          defaultUninstallScript={softwarePackage.uninstall_script}
          defaultSelfService={softwarePackage.self_service}
          defaultCategories={softwarePackage.categories}
        />
      );
    }

    return (
      <SoftwareVppForm
        labels={labels || []}
        softwareVppForEdit={software as IAppStoreApp}
        onSubmit={onClickSaveVpp}
        onCancel={onExit}
        isLoading={isUpdatingSoftware}
        onClickPreviewEndUserExperience={togglePreviewEndUserExperienceModal}
      />
    );
  };

  return (
    <>
      <Modal
        className={editSoftwareModalClasses}
        title="Edit software"
        onExit={onExit}
        width="large"
      >
        {renderForm()}
      </Modal>
      {showConfirmSaveChangesModal && (
        <ConfirmSaveChangesModal
          onClose={toggleConfirmSaveChangesModal}
          softwareInstallerName={software?.name}
          installerType={installerType}
          onSaveChanges={onClickConfirmChanges}
        />
      )}
      {showPreviewEndUserExperienceModal && (
        <CategoriesEndUserExperienceModal
          onCancel={togglePreviewEndUserExperienceModal}
        />
      )}
      {!!pendingPackageUpdates.software && isUpdatingSoftware && (
        <FileProgressModal
          fileDetails={getFileDetails(pendingPackageUpdates.software)}
          fileProgress={uploadProgress}
        />
      )}
    </>
  );
};

export default EditSoftwareModal;
