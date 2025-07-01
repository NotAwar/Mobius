import React from "react";

import MobiusMarkdown from "components/MobiusMarkdown";

interface IQueryTableExampleProps {
  example: string;
}

const baseClass = "query-table-example";

const QueryTableExample = ({ example }: IQueryTableExampleProps) => {
  return (
    <div className={baseClass}>
      <h3>Example</h3>
      <MobiusMarkdown markdown={example} name="query-table-example" />
    </div>
  );
};

export default QueryTableExample;
