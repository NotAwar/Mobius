import React from "react";
import { Link } from "react-router";

import PATHS from "router/paths";

import { SUPPORT_LINK } from "utilities/constants";
import Button from "components/buttons/Button";
// @ts-ignore
import mobiusLogoText from "../../../../assets/images/mobius-logo-text-white.png";
// @ts-ignore
import backgroundImg from "../../../../assets/images/500.svg";
import githubLogo from "../../../../assets/images/github-mark-white-24x24@2x.png";
import slackLogo from "../../../../assets/images/logo-slack-24x24@2x.png";

const baseClass = "mobius-500";

const Mobius500 = () => (
  <div className={baseClass}>
    <header className="primary-header">
      <Link to={PATHS.DASHBOARD}>
        <img
          className="primary-header__logo"
          src={mobiusLogoText}
          alt="Mobius logo"
        />
      </Link>
    </header>
    <img
      className="background-image"
      src={backgroundImg}
      alt="500 background"
    />
    <main>
      <h1>
        <span>500:</span> Oh, something went wrong.
      </h1>
      <p>Please file an issue if you believe this is a bug.</p>
      <div className={`${baseClass}__button-wrapper`}>
        <a href={SUPPORT_LINK} target="_blank" rel="noopener noreferrer">
          <Button variant="unstyled" className={`${baseClass}__slack-btn`}>
            <>
              <img src={slackLogo} alt="Slack icon" />
              Get help on Slack
            </>
          </Button>
        </a>
        <a
          href="https://github.com/mobiusdm/mobius/issues/new?assignees=&labels=bug%2C%3Areproduce&template=bug-report.md&title="
          target="_blank"
          rel="noopener noreferrer"
        >
          <Button>
            <>
              <img src={githubLogo} alt="Github icon" />
              File an issue
            </>
          </Button>
        </a>
      </div>
    </main>
  </div>
);

export default Mobius500;
