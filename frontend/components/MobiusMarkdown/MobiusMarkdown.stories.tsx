import { Meta, StoryObj } from "@storybook/react";

import MobiusMarkdown from "./MobiusMarkdown";

const TestMarkdown = `
# Test Markdown

## This is a heading

### This is a subheading

#### This is a subsubheading


---
**bold**

*italic*

[test link](https://www.mobiusdm.com)

- test list item 1
- test list item 2
- test list item 3

> test blockquote

\`code text\`
`;

const meta: Meta<typeof MobiusMarkdown> = {
  title: "Components/MobiusMarkdown",
  component: MobiusMarkdown,
  args: { markdown: TestMarkdown },
};

export default meta;

type Story = StoryObj<typeof MobiusMarkdown>;

export const Basic: Story = {};
