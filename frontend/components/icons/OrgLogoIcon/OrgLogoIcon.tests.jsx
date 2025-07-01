import React from "react";
import { render, screen } from "@testing-library/react";

import mobiusAvatar from "../../../../assets/images/mobius-avatar-24x24@2x.png";
import OrgLogoIcon from "./OrgLogoIcon";

describe("OrgLogoIcon - component", () => {
  it("renders the Mobius Logo by default", () => {
    render(<OrgLogoIcon />);

    // expect(component.state("imageSrc")).toEqual(mobiusAvatar);
    expect(screen.getByRole("img")).toHaveAttribute("src", mobiusAvatar);
  });

  it("renders the image source when it is valid", () => {
    render(<OrgLogoIcon src="/assets/images/avatar.svg" />);

    expect(screen.getByRole("img")).toHaveAttribute(
      "src",
      "/assets/images/avatar.svg"
    );
  });
});
