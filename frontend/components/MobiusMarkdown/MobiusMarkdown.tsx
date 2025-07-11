import React from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import classnames from "classnames";
import { IAceEditor } from "react-ace/lib/types";
import { noop } from "lodash";

import SQLEditor from "components/SQLEditor";
import CustomLink from "components/CustomLink";

interface IMobiusMarkdownProps {
  markdown: string;
  className?: string;
  name?: string;
}

const baseClass = "mobius-markdown";

/** This will give us sensible defaults for how we render markdown across the mobius application.
 * NOTE: can be extended later to take custom components, but dont need that at the moment.
 */
const MobiusMarkdown = ({
  markdown,
  className,
  name,
}: IMobiusMarkdownProps) => {
  const classNames = classnames(baseClass, className);

  return (
    <ReactMarkdown
      className={classNames}
      // enables some more markdown features such as direct urls and strikethroughts.
      // more info here: https://github.com/remarkjs/remark-gfm
      remarkPlugins={[remarkGfm]}
      components={{
        a: ({ href = "", children }) => {
          return <CustomLink text={String(children)} url={href} newTab />;
        },

        // Overrides code display to use SQLEditor with Readonly overrides.
        code: ({ inline, children, ...props }) => {
          const onEditorBlur = (editor?: IAceEditor) => {
            editor && editor.clearSelection();
          };

          const onEditorLoad = (editor: IAceEditor) => {
            editor.setOptions({
              indentedSoftWrap: false, // removes automatic indentation when wrapping
            });

            // removes focus UI styling
            editor.renderer.visualizeFocus = noop;
          };

          // Dont render the mobius ace code block for simple inline code blocks.
          // e.g. `x = 1`
          if (inline) {
            return <code {...props}>{children}</code>;
          }

          // full code blocks we want to use Mobius Ace.
          // e.g. ```SELECT * FROM USERS```
          return (
            <SQLEditor
              wrapperClassName={`${baseClass}__ace-display`}
              value={String(children).replace(/\n/, "")}
              showGutter={false}
              onBlur={onEditorBlur}
              onLoad={onEditorLoad}
              style={{ border: "none" }}
              wrapEnabled
              readOnly
              name={name}
            />
          );
        },
      }}
    >
      {markdown}
    </ReactMarkdown>
  );
};

export default MobiusMarkdown;
