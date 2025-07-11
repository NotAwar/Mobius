import React, {
  FormEvent,
  useState,
  useEffect,
  useContext,
  useRef,
} from "react";
import { Link } from "react-router";
import PATHS from "router/paths";

import { PRIMO_TOOLTIP } from "utilities/constants";

import { NotificationContext } from "context/notification";
import { AppContext } from "context/app";

import { ITeam } from "interfaces/team";
import { IUserFormErrors, UserRole } from "interfaces/user";
import { IFormField } from "interfaces/form_field";

import { SingleValue } from "react-select-5";
import Button from "components/buttons/Button";
import DropdownWrapper from "components/forms/fields/DropdownWrapper";
import { CustomOptionType } from "components/forms/fields/DropdownWrapper/DropdownWrapper";
import ModalFooter from "components/ModalFooter";
import validatePresence from "components/forms/validators/validate_presence";
import validEmail from "components/forms/validators/valid_email";
// @ts-ignore
import validPassword from "components/forms/validators/valid_password";
// @ts-ignore
import InputField from "components/forms/fields/InputField";
import Checkbox from "components/forms/fields/Checkbox";
import Radio from "components/forms/fields/Radio";
import InfoBanner from "components/InfoBanner/InfoBanner";
import CustomLink from "components/CustomLink";
import TooltipWrapper from "components/TooltipWrapper";
import SelectedTeamsForm from "../SelectedTeamsForm/SelectedTeamsForm";
import SelectRoleForm from "../SelectRoleForm/SelectRoleForm";
import { roleOptions } from "../../helpers/userManagementHelpers";

const baseClass = "user-form";

export enum NewUserType {
  AdminInvited = "ADMIN_INVITED",
  AdminCreated = "ADMIN_CREATED",
}

enum UserTeamType {
  GlobalUser = "GLOBAL_USER",
  AssignTeams = "ASSIGN_TEAMS",
}

export interface IUserFormData {
  email: string;
  name: string;
  newUserType?: NewUserType | null;
  password?: string | null;
  new_password?: string | null; // if a new password is being set for an existing user, the API expects `new_password` rather than `password`
  sso_enabled: boolean;
  mfa_enabled?: boolean;
  global_role: UserRole | null;
  teams: ITeam[];
  currentUserId?: number;
  invited_by?: number;
  role?: UserRole;
}

interface IUserFormProps {
  availableTeams: ITeam[];
  onCancel: () => void;
  onSubmit: (formData: IUserFormData) => void;
  defaultName?: string;
  defaultEmail?: string;
  currentUserId?: number;
  currentTeam?: ITeam;
  isModifiedByGlobalAdmin?: boolean | false;
  defaultGlobalRole?: UserRole | null;
  defaultTeamRole?: UserRole;
  defaultTeams?: ITeam[];
  isPremiumTier: boolean;
  smtpConfigured?: boolean;
  sesConfigured?: boolean;
  canUseSso: boolean; // corresponds to whether SSO is enabled for the organization
  isSsoEnabled?: boolean; // corresponds to whether SSO is enabled for the individual user
  isMfaEnabled?: boolean; // corresponds to whether MFA is enabled for the individual user
  isApiOnly?: boolean;
  isNewUser?: boolean;
  isInvitePending?: boolean;
  ancestorErrors: IUserFormErrors;
  isUpdatingUsers?: boolean;
}

const validate = (
  formData: IUserFormData,
  canUseSso: boolean,
  isNewUser: boolean,
  isSsoEnabled: boolean,
  initiallyPasswordAuth: boolean
) => {
  const newErrors: IUserFormErrors = {};

  const { name, email, newUserType, sso_enabled, password } = formData;

  if (!validatePresence(name)) {
    newErrors.name = "Name field must be completed";
  }
  if (!validatePresence(email)) {
    newErrors.email = "Email field must be completed";
  } else if (!validEmail(email)) {
    newErrors.email = `${email} is not a valid email`;
  }

  const isNewAdminCreatedUserWithoutSSO =
    isNewUser && newUserType === NewUserType.AdminCreated && !sso_enabled;

  // force to password auth if SSO is disabled globally but was enabled on the form
  const isExistingUserForcedToPasswordAuth = !canUseSso && isSsoEnabled;

  // password required when creating a user with SSO disabled and when changing a user from SSO to
  // password authentication, though not when inviting a user
  if (
    isNewAdminCreatedUserWithoutSSO ||
    isExistingUserForcedToPasswordAuth ||
    (!initiallyPasswordAuth && !sso_enabled)
  ) {
    if (password !== null && !validPassword(password)) {
      newErrors.password = "Password must meet the criteria below";
    }
    if (!validatePresence(password)) {
      newErrors.password = "Password field must be completed";
    }
  }

  return newErrors;
};

const UserForm = ({
  availableTeams,
  onCancel,
  onSubmit,
  defaultName,
  defaultEmail,
  currentUserId,
  currentTeam,
  isModifiedByGlobalAdmin,
  defaultGlobalRole,
  defaultTeamRole,
  defaultTeams,
  isPremiumTier,
  smtpConfigured,
  sesConfigured,
  canUseSso,
  isSsoEnabled,
  isMfaEnabled,
  isApiOnly,
  isNewUser = false,
  isInvitePending,
  ancestorErrors,
  isUpdatingUsers,
}: IUserFormProps): JSX.Element => {
  // For scrollable modal
  const [isTopScrolling, setIsTopScrolling] = useState(false);
  const topDivRef = useRef<HTMLDivElement>(null);
  const checkScroll = () => {
    if (topDivRef.current) {
      const isScrolling =
        topDivRef.current.scrollHeight > topDivRef.current.clientHeight;
      setIsTopScrolling(isScrolling);
    }
  };

  const { renderFlash } = useContext(NotificationContext);
  const { config } = useContext(AppContext);
  const priMode = config?.partnerships?.enable_primo;

  const [formErrors, setFormErrors] = useState<IUserFormErrors>({});
  const [formData, setFormData] = useState<IUserFormData>({
    email: defaultEmail || "",
    name: defaultName || "",
    newUserType: isNewUser ? NewUserType.AdminCreated : null,
    password: "",
    sso_enabled: isSsoEnabled || false,
    mfa_enabled: isMfaEnabled || false,
    global_role: defaultGlobalRole || null,
    teams: defaultTeams || [],
    currentUserId,
  });

  const isGlobalUser = formData.global_role !== null;

  // watch for population from context, set state
  useEffect(() => {
    if (priMode) {
      setFormData((prevFormData) => ({
        ...prevFormData,
        global_role: "observer",
        teams: [],
      }));
    }
  }, [priMode]);

  const initiallyPasswordAuth = !isSsoEnabled;

  useEffect(() => {
    setFormErrors((curErrs) => ({ ...curErrs, ...ancestorErrors }));
  }, [ancestorErrors]);

  useEffect(() => {
    // If SSO is globally disabled but user previously signed in via SSO,
    // require password is automatically selected on first render
    if (!canUseSso && !isNewUser && isSsoEnabled) {
      setFormData({ ...formData, sso_enabled: false });
    }
  }, []);

  // For scrollable modal (re-rerun when formData changes)
  useEffect(() => {
    checkScroll();
    window.addEventListener("resize", checkScroll);
    return () => window.removeEventListener("resize", checkScroll);
  }, [formData]);

  const onInputChange = ({ name, value }: IFormField) => {
    const newFormData = { ...formData, [name]: value };
    setFormData(newFormData);
    const newErrs = validate(
      newFormData,
      canUseSso,
      isNewUser,
      !!isSsoEnabled,
      initiallyPasswordAuth
    );
    // only set errors that are updates of existing errors
    // new errors are only set onBlur or submit
    const errsToSet: Record<string, string> = {};
    Object.keys(formErrors).forEach((k) => {
      // @ts-ignore
      if (newErrs[k]) {
        // @ts-ignore
        errsToSet[k] = newErrs[k];
      }
    });
    setFormErrors(errsToSet);
  };

  const onInputBlur = () => {
    setFormErrors(
      validate(
        formData,
        canUseSso,
        isNewUser,
        !!isSsoEnabled,
        initiallyPasswordAuth
      )
    );
  };

  // Used to show entire dropdown when a dropdown menu is open in scrollable component of a modal
  // menuPortalTarget solution not used as scrolling is weird
  const scrollToFitDropdownMenu = () => {
    if (topDivRef?.current) {
      setTimeout(() => {
        if (topDivRef.current) {
          topDivRef.current.scrollTop =
            topDivRef.current.scrollHeight - topDivRef.current.clientHeight;
        }
      }, 50); // Delay needed for scrollHeight to update first
    }
  };

  const onRadioChange = (formField: string): ((evt: string) => void) => {
    // TODO - make these work similarly to onInputChange
    return (value: string) => {
      setFormErrors({
        ...formErrors,
        [formField]: null,
      });
      setFormData({
        ...formData,
        [formField]: value,
      });
    };
  };

  const onIsGlobalUserChange = (value: string): void => {
    setFormData({
      ...formData,
      global_role: value === UserTeamType.GlobalUser ? "observer" : null,
    });
  };

  const onGlobalUserRoleChange = (value: UserRole): void => {
    setFormData({
      ...formData,
      global_role: value,
    });
  };

  const onSsoChange = (value: boolean): void => {
    const newFormData = { ...formData, sso_enabled: value };
    setFormData(newFormData);
    if (value) {
      // clears password error when enabling sso, allowing submission even if password is invalid
      setFormErrors(
        validate(
          newFormData,
          canUseSso,
          isNewUser,
          !!isSsoEnabled,
          initiallyPasswordAuth
        )
      );
    }
  };

  const onSelectedTeamChange = (teams: ITeam[]): void => {
    setFormData({
      ...formData,
      teams,
    });
  };

  const onTeamRoleChange = (teams: ITeam[]): void => {
    setFormData({
      ...formData,
      teams,
    });
  };

  // UserForm component can be used to add a new user or edit an existing user so submitData will be assembled accordingly
  const addSubmitData = (): IUserFormData => {
    const submitData = formData;

    if (!isNewUser && !isInvitePending) {
      // if a new password is being set for an existing user, the API expects `new_password` rather than `password`
      submitData.new_password = formData.password;
      submitData.password = null;
      delete submitData.newUserType; // this field will not be submitted when form is used to edit an existing user
      // if an existing user is converted to sso, the API expects `new_password` to be null
      if (formData.sso_enabled) {
        submitData.new_password = null;
        submitData.mfa_enabled = false; // Edge case a user sets mfa, and then sets sso, we need to remove mfa
      }
    }

    if (
      submitData.sso_enabled ||
      formData.newUserType === NewUserType.AdminInvited
    ) {
      submitData.password = null; // this field will not be submitted with the form
    }

    return isGlobalUser
      ? { ...submitData, global_role: formData.global_role, teams: [] }
      : { ...submitData, global_role: null, teams: formData.teams };
  };

  const onFormSubmit = (evt: FormEvent): void => {
    evt.preventDefault();

    // separate from `validate` function as it uses `renderFlash` hook, incompatible with pure
    // `validate` function
    if (!formData.global_role && !formData.teams.length) {
      renderFlash("error", `Please select at least one team for this user.`);
      return;
    }
    const errs = validate(
      formData,
      canUseSso,
      isNewUser,
      !!isSsoEnabled,
      initiallyPasswordAuth
    );
    if (Object.keys(errs).length > 0) {
      setFormErrors(errs);
      return;
    }
    onSubmit(addSubmitData());
  };

  const renderGlobalRoleForm = (): JSX.Element => {
    return (
      <>
        {isPremiumTier && (
          <InfoBanner className={`${baseClass}__user-permissions-info`}>
            <p>
              Global users can manage or observe all users, entities, and
              settings in Mobius.
            </p>
            <CustomLink
              url="https://mobius-mdm.org/docs/using-mobius/permissions#user-permissions"
              text="Learn more about user permissions"
              newTab
            />
          </InfoBanner>
        )}
        <DropdownWrapper
          label="Role"
          name="Role"
          className={`${baseClass}__global-role-dropdown`}
          options={roleOptions({ isPremiumTier, isApiOnly })}
          value={formData.global_role || "Observer"}
          onChange={(selectedOption: SingleValue<CustomOptionType>) => {
            if (selectedOption) {
              onGlobalUserRoleChange(selectedOption.value as UserRole);
            }
          }}
          isSearchable={false}
          onMenuOpen={scrollToFitDropdownMenu}
        />
      </>
    );
  };

  const renderNoTeamsMessage = (): JSX.Element => {
    return (
      <div>
        <p>
          <strong>You have no teams.</strong>
        </p>
        <p>
          Expecting to see teams? Try again in a few seconds as the system
          catches up or&nbsp;
          <Link
            className={`${baseClass}__create-team-link`}
            to={PATHS.ADMIN_TEAMS}
          >
            create a team
          </Link>
          .
        </p>
      </div>
    );
  };

  const renderTeamsForm = (): JSX.Element => {
    return (
      <>
        {!!availableTeams.length &&
          (isModifiedByGlobalAdmin ? (
            <>
              <InfoBanner className={`${baseClass}__user-permissions-info`}>
                <p>
                  Users can manage or observe team-specific users, entities, and
                  settings in Mobius.
                </p>
                <CustomLink
                  url="https://mobius-mdm.org/docs/using-mobius/permissions#team-member-permissions"
                  text="Learn more about user permissions"
                  newTab
                />
              </InfoBanner>
              <SelectedTeamsForm
                availableTeams={availableTeams}
                usersCurrentTeams={formData.teams}
                onFormChange={onSelectedTeamChange}
                isApiOnly={isApiOnly}
                onMenuOpen={scrollToFitDropdownMenu}
              />
            </>
          ) : (
            <SelectRoleForm
              currentTeam={currentTeam || formData.teams[0]}
              teams={formData.teams}
              defaultTeamRole={defaultTeamRole || "Observer"}
              onFormChange={onTeamRoleChange}
              isApiOnly={isApiOnly}
              onMenuOpen={scrollToFitDropdownMenu}
            />
          ))}
        {!availableTeams.length && renderNoTeamsMessage()}
      </>
    );
  };

  if (!isPremiumTier && !isGlobalUser) {
    console.log(
      `Note: Mobius Free UI does not have teams options.\n
        User ${formData.name} is already assigned to a team and cannot be reassigned without access to Mobius Pro UI.`
    );
  }

  const renderAccountSection = () => (
    <div className="form-field">
      {isModifiedByGlobalAdmin ? (
        <>
          <div className="form-field__label">Account</div>
          <Radio
            className={`${baseClass}__radio-input`}
            label="Create user"
            id="create-user"
            checked={formData.newUserType !== NewUserType.AdminInvited}
            value={NewUserType.AdminCreated}
            name="new-user-type"
            onChange={onRadioChange("newUserType")}
          />
          <Radio
            className={`${baseClass}__radio-input`}
            label="Invite user"
            id="invite-user"
            disabled={!(smtpConfigured || sesConfigured)}
            checked={formData.newUserType === NewUserType.AdminInvited}
            value={NewUserType.AdminInvited}
            name="new-user-type"
            onChange={onRadioChange("newUserType")}
            tooltip={
              smtpConfigured || sesConfigured ? (
                ""
              ) : (
                <>
                  The &quot;Invite user&quot; feature requires that SMTP or SES
                  is configured in order to send invitation emails.
                  <br />
                  <br />
                  SMTP can be configured in Settings &gt; Organization settings.
                </>
              )
            }
          />
        </>
      ) : (
        <input
          type="hidden"
          id="create-user"
          value={NewUserType.AdminCreated}
          name="new-user-type"
        />
      )}
    </div>
  );

  const renderNameAndEmailSection = () => (
    <>
      <InputField
        label="Full name"
        autofocus
        error={formErrors.name}
        name="name"
        onChange={onInputChange}
        onBlur={onInputBlur}
        placeholder="Full name"
        value={formData.name || ""}
        inputOptions={{
          maxLength: "80",
        }}
        ignore1password
        parseTarget
      />
      <InputField
        label="Email"
        error={formErrors.email}
        name="email"
        onChange={onInputChange}
        onBlur={onInputBlur}
        parseTarget
        placeholder="Email"
        value={formData.email || ""}
        readOnly={!isNewUser && !(smtpConfigured || sesConfigured)}
        tooltip={
          <>
            Editing an email address requires that SMTP or SES is configured in
            order to send a validation email.
            <br />
            <br />
            Users with Admin role can configure SMTP in{" "}
            <strong>Settings &gt; Organization settings</strong>.
          </>
        }
      />
    </>
  );

  const renderAuthenticationSection = () => (
    <div className="form-field">
      <div className="form-field__label">Authentication</div>
      <Radio
        className={`${baseClass}__radio-input`}
        label={
          canUseSso ? (
            "Single sign-on"
          ) : (
            <TooltipWrapper
              tipContent={
                <>
                  SSO is not enabled in organization settings.
                  <br />
                  User must sign in with a password.
                </>
              }
            >
              Single sign-on
            </TooltipWrapper>
          )
        }
        id="single-sign-on-authentication"
        checked={!!formData.sso_enabled}
        value="true"
        name="authentication-type"
        onChange={() => onSsoChange(true)}
        disabled={!canUseSso}
      />
      <Radio
        className={`${baseClass}__radio-input`}
        label="Password"
        id="password-authentication"
        // allow the user to change auth back to password if they only changed the form to SSO in
        // the current session, that is, in the db, the user is still password authenticated
        checked={!formData.sso_enabled}
        value="false"
        name="authentication-type"
        onChange={() => onSsoChange(false)}
      />
    </div>
  );

  const renderPasswordSection = () => (
    <div className={`${baseClass}__${isNewUser ? "" : "edit-"}password`}>
      <InputField
        label="Password"
        error={formErrors.password}
        name="password"
        onChange={onInputChange}
        onBlur={onInputBlur}
        parseTarget
        placeholder={isNewUser ? "Password" : "••••••••"}
        value={formData.password || ""}
        type="password"
        helpText="12-48 characters, with at least 1 number (e.g. 0 - 9) and 1 symbol (e.g. &*#)."
        blockAutoComplete
        tooltip={
          isNewUser ? (
            <>
              This password is temporary. This user will be asked to set a new
              password after logging in to the Mobius UI.
              <br />
              <br />
              This user will not be asked to set a new password after logging in
              to MobiusCLI or the Mobius API.
            </>
          ) : undefined
        }
      />
    </div>
  );

  // 2fa option shows on premium tier or if previously set to true before downgrading to free
  const renderTwoFactorAuthenticationOption = () => (
    <div className="form-field">
      {/* Renders missing password heading when inviting a user */}
      {formData.newUserType === NewUserType.AdminInvited && (
        <div className="form-field__label">Password</div>
      )}
      <Checkbox
        name="mfa_enabled"
        onChange={onInputChange}
        onBlur={onInputBlur}
        value={formData.mfa_enabled}
        wrapperClassName={`${baseClass}__2fa`}
        helpText="User will be asked to authenticate with a magic link that will be sent to their email."
        disabled={!smtpConfigured && !sesConfigured}
        parseTarget
      >
        {smtpConfigured || sesConfigured ? (
          "Enable two-factor authentication (email)"
        ) : (
          <TooltipWrapper
            tipContent={
              <>
                This feature requires that SMTP or SES is configured in order to
                send authentication emails.
                <br />
                <br />
                SMTP can be configured in Settings &gt; Organization settings.
              </>
            }
          >
            Enable two-factor authentication (email)
          </TooltipWrapper>
        )}
      </Checkbox>
    </div>
  );

  const renderGlobalAdminOptions = () => {
    if (priMode) {
      return (
        <TooltipWrapper
          tipContent={PRIMO_TOOLTIP}
          tipOffset={20}
          position="right"
          showArrow
          underline={false}
        >
          <Radio
            className={`${baseClass}__radio-input`}
            label="Global user"
            id="global-user"
            checked={isGlobalUser}
            value={UserTeamType.GlobalUser}
            name="user-team-type"
            onChange={onIsGlobalUserChange}
            disabled
          />
          <Radio
            className={`${baseClass}__radio-input`}
            label="Assign team(s)"
            id="assign-teams"
            checked={!isGlobalUser}
            value={UserTeamType.AssignTeams}
            name="user-team-type"
            onChange={onIsGlobalUserChange}
            disabled
          />
        </TooltipWrapper>
      );
    }
    return (
      <>
        <Radio
          className={`${baseClass}__radio-input`}
          label="Global user"
          id="global-user"
          checked={isGlobalUser}
          value={UserTeamType.GlobalUser}
          name="user-team-type"
          onChange={onIsGlobalUserChange}
        />
        <Radio
          className={`${baseClass}__radio-input`}
          label="Assign team(s)"
          id="assign-teams"
          checked={!isGlobalUser}
          value={UserTeamType.AssignTeams}
          name="user-team-type"
          onChange={onIsGlobalUserChange}
          disabled={!availableTeams.length}
        />
      </>
    );
  };

  const renderPremiumRoleOptions = () => (
    <>
      <div className="form-field team-field">
        <div className="form-field__label">Team</div>
        {isModifiedByGlobalAdmin ? (
          renderGlobalAdminOptions()
        ) : (
          <>{currentTeam ? currentTeam.name : ""}</>
        )}
      </div>
      {isGlobalUser ? renderGlobalRoleForm() : renderTeamsForm()}
    </>
  );

  const renderScrollableContent = () => {
    return (
      <div className={baseClass} ref={topDivRef}>
        <form autoComplete="off">
          {isNewUser && renderAccountSection()}
          {renderNameAndEmailSection()}
          {renderAuthenticationSection()}
          {((isNewUser && formData.newUserType !== NewUserType.AdminInvited) ||
            (!isNewUser && !isInvitePending)) &&
            !formData.sso_enabled &&
            renderPasswordSection()}
          {(isPremiumTier || isMfaEnabled) &&
            !formData.sso_enabled &&
            renderTwoFactorAuthenticationOption()}
          {isPremiumTier ? renderPremiumRoleOptions() : renderGlobalRoleForm()}
        </form>
      </div>
    );
  };

  const renderFooter = () => (
    <ModalFooter
      isTopScrolling={isTopScrolling}
      primaryButtons={
        <>
          <Button onClick={onCancel} variant="inverse">
            Cancel
          </Button>
          <Button
            type="submit"
            onClick={onFormSubmit}
            className={`${isNewUser ? "add" : "save"}-loading
          `}
            isLoading={isUpdatingUsers}
            disabled={Object.keys(formErrors).length > 0}
          >
            {isNewUser ? "Add" : "Save"}
          </Button>
        </>
      }
    />
  );

  return (
    <>
      {renderScrollableContent()}
      {renderFooter()}
    </>
  );
};

export default UserForm;
