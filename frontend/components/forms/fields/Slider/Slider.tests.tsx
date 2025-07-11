import React from "react";
import { render, fireEvent, screen } from "@testing-library/react";
import Slider from "./Slider";

describe("Slider Component", () => {
  const defaultProps = {
    onChange: jest.fn(),
    value: false,
    inactiveText: "Off",
    activeText: "On",
  };

  it("renders correctly with default props", () => {
    render(<Slider {...defaultProps} />);
    expect(screen.getByText("Off")).toBeInTheDocument();
    expect(screen.getByRole("switch")).toHaveClass("mobius-slider");
  });

  it("renders active state correctly", () => {
    render(<Slider {...defaultProps} value />);
    expect(screen.getByText("On")).toBeInTheDocument();
    expect(screen.getByRole("switch")).toHaveClass("mobius-slider--active");
  });

  it("calls onChange when clicked", () => {
    render(<Slider {...defaultProps} />);
    fireEvent.click(screen.getByRole("switch"));
    expect(defaultProps.onChange).toHaveBeenCalledTimes(1);
  });
});
