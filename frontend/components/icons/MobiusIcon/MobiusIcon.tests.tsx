import React from "react";
import { render } from "@testing-library/react";

import MobiusIcon from "./MobiusIcon";

describe("MobiusIcon - component", () => {
  it("renders", () => {
    const { container } = render(<MobiusIcon name="success-check" />);
    expect(
      container.querySelector(".mobiusicon-success-check")
    ).toBeInTheDocument();
  });
});
