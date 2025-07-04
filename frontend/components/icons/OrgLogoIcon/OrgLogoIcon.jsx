import React, { Component } from "react";
import PropTypes from "prop-types";
import classnames from "classnames";

import mobiusAvatar from "../../../../assets/images/icon-avatar-default-dark-24x24@2x.png";

const baseClass = "org-logo-icon";

class OrgLogoIcon extends Component {
  static propTypes = {
    className: PropTypes.string,
    src: PropTypes.string.isRequired,
  };

  static defaultProps = {
    src: mobiusAvatar,
  };

  constructor(props) {
    super(props);

    this.state = { imageSrc: mobiusAvatar };
  }

  componentWillMount() {
    const { src } = this.props;

    this.setState({ imageSrc: src });

    return false;
  }

  componentWillReceiveProps(nextProps) {
    const { src } = nextProps;
    const { unchangedSourceProp } = this;

    if (unchangedSourceProp(nextProps)) {
      return false;
    }

    this.setState({ imageSrc: src });

    return false;
  }

  shouldComponentUpdate(nextProps) {
    const { imageSrc } = this.state;
    const { unchangedSourceProp } = this;

    if (unchangedSourceProp(nextProps) && imageSrc === mobiusAvatar) {
      return false;
    }

    return true;
  }

  onError = () => {
    this.setState({ imageSrc: mobiusAvatar });

    return false;
  };

  unchangedSourceProp = (nextProps) => {
    const { src: nextSrcProp } = nextProps;
    const { src } = this.props;

    return src === nextSrcProp;
  };

  render() {
    const { className } = this.props;
    const { imageSrc } = this.state;
    const { onError } = this;

    const classNames =
      imageSrc === mobiusAvatar
        ? classnames(baseClass, className, "default-mobius-logo")
        : classnames(baseClass, className);

    return (
      <img
        alt="Organization Logo"
        className={classNames}
        onError={onError}
        src={imageSrc}
      />
    );
  }
}

export default OrgLogoIcon;
