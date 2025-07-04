import React from "react";
import { screen } from "@testing-library/react";
import { noop } from "lodash";
import { createCustomRenderer } from "test/test-utils";

import MobiusAppDetailsModal from "./MobiusAppDetailsModal";

describe("MobiusAppDetailsModal", () => {
  const defaultProps = {
    name: "Test App",
    platform: "darwin",
    version: "1.0.0",
    url: "https://example.com/app",
    slug: "test-app/darwin",
    onCancel: noop,
  };

  it("renders modal with correct title", () => {
    const render = createCustomRenderer();

    render(<MobiusAppDetailsModal {...defaultProps} />);

    const modalTitle = screen.getByText("Software details");
    expect(modalTitle).toBeInTheDocument();
  });

  it("displays correct app details", () => {
    const render = createCustomRenderer();

    render(<MobiusAppDetailsModal {...defaultProps} />);

    expect(screen.getByText("Name")).toBeInTheDocument();
    expect(screen.getByText("Test App")).toBeInTheDocument();
    expect(screen.getByText("Platform")).toBeInTheDocument();
    expect(screen.getByText("macOS")).toBeInTheDocument();
    expect(screen.getByText("Version")).toBeInTheDocument();
    expect(screen.getByText("1.0.0")).toBeInTheDocument();
    expect(screen.getByText("Mobius-maintained app slug")).toBeInTheDocument();
    expect(screen.getByText("test-app/darwin")).toBeInTheDocument();
    expect(screen.getByText("URL")).toBeInTheDocument();
    expect(
      screen.getAllByText("https://example.com/app").length
    ).toBeGreaterThan(0); // Tooltip renders text twice causing use of toBeInTheDocument to fail
  });

  it("does not render URL or slug field when respective props are not provided", () => {
    const render = createCustomRenderer();
    const propsWithoutUrl = {
      ...defaultProps,
      url: undefined,
      slug: undefined,
    };

    render(<MobiusAppDetailsModal {...propsWithoutUrl} />);

    expect(screen.queryByText("URL")).not.toBeInTheDocument();
    expect(screen.queryByText(/slug/i)).not.toBeInTheDocument();
  });
});
