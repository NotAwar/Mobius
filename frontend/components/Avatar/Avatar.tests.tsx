import React from "react";
import { render, screen } from "@testing-library/react";

import Avatar from "./Avatar";

describe("Avatar - component", () => {
  it("renders the user gravatar if provided", () => {
    render(
      <Avatar user={{ gravatar_url: "https://example.com/avatar.png" }} />
    );

    const avatar = screen.getByAltText("User avatar");
    expect(avatar).toBeVisible();
    expect(avatar).toHaveAttribute("src", "https://example.com/avatar.png");
  });

  it("renders the mobius avatar if useMobiusAvatar is `true`", () => {
    render(<Avatar useMobiusAvatar user={{}} />);
    expect(screen.getByTestId("mobius-avatar")).toBeVisible();
  });
});
