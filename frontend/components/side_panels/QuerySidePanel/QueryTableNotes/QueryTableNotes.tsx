import React from "react";

import MobiusMarkdown from "components/MobiusMarkdown";

interface IQueryTableNotesProps {
  notes: string;
}

const baseClass = "query-table-notes";

const QueryTableNotes = ({ notes }: IQueryTableNotesProps) => {
  return (
    <div className={baseClass}>
      <h3>Notes</h3>
      <MobiusMarkdown
        markdown={notes}
        className={`${baseClass}__notes-markdown`}
      />
    </div>
  );
};

export default QueryTableNotes;
