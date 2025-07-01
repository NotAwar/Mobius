package mobiuscli

import (
	"encoding/json"
	"io"
	"os"
	"sort"

	"github.com/notawar/mobius/v4/server/mobius"
	"github.com/gosuri/uilive"
	"github.com/olekukonko/tablewriter"
)

type outputWriter interface {
	WriteResult(res mobius.DistributedQueryResult) error
}

type resultOutput struct {
	HostIdentifier string              `json:"host"`
	Rows           []map[string]string `json:"rows"`
	Error          *string             `json:"error,omitempty"`
}

type jsonWriter struct {
	w io.Writer
}

func newJsonWriter(w io.Writer) *jsonWriter {
	if w == nil {
		w = os.Stdout
	}
	return &jsonWriter{w: w}
}

func (w *jsonWriter) WriteResult(res mobius.DistributedQueryResult) error {
	out := resultOutput{
		HostIdentifier: res.Host.Hostname,
		Rows:           res.Rows,
		Error:          res.Error,
	}
	return json.NewEncoder(w.w).Encode(out)
}

type prettyWriter struct {
	results []mobius.DistributedQueryResult
	columns map[string]bool
	writer  *uilive.Writer
}

func newPrettyWriter() *prettyWriter {
	return &prettyWriter{
		columns: make(map[string]bool),
		writer:  uilive.New(),
	}
}

func (w *prettyWriter) WriteResult(res mobius.DistributedQueryResult) error {
	w.results = append(w.results, res)

	// Recompute columns
	for _, row := range res.Rows {
		delete(row, "host_hostname")
		delete(row, "host_display_name")
		for col := range row {
			w.columns[col] = true
		}
	}

	columns := []string{}
	for col := range w.columns {
		columns = append(columns, col)
	}
	sort.Strings(columns)

	table := tablewriter.NewWriter(w.writer.Newline())
	table.SetRowLine(true)
	table.SetHeader(append([]string{"hostname"}, columns...))

	// Extract columns from the results in the appropriate order
	for _, res := range w.results {
		for _, row := range res.Rows {
			cols := []string{res.Host.Hostname}
			for _, col := range columns {
				cols = append(cols, row[col])
			}
			table.Append(cols)
		}
	}
	table.Render()

	// Actually write the output
	w.writer.Flush()

	return nil
}
