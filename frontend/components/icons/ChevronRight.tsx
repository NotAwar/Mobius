import React from "react";
import { COLORS, Colors } from "styles/var/colors";
import { ICON_SIZES, IconSizes } from "styles/var/icon_sizes";

interface IChevronProps {
  color?: Colors;
  size?: IconSizes;
}

const ChevronRight = ({
  color = "core-mobius-black",
  size = "medium",
}: IChevronProps) => {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width={ICON_SIZES[size]}
      height={ICON_SIZES[size]}
      fill="none"
      viewBox="0 0 16 16"
    >
      <path
        stroke={COLORS[color]}
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth="2"
        d="M6 4l4 4-4 4"
      />
    </svg>
  );
};

export default ChevronRight;
