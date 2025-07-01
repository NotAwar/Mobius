package ctxerr

import (
	"context"
	"encoding/json"

	"github.com/notawar/mobius/v4/server/mobius"
)

type ErrorAgg struct {
	Count    int             `json:"count"`
	Loc      []string        `json:"loc"`
	Metadata json.RawMessage `json:"metadata,omitempty"`
}

// Aggregate retrieves all errors in the store and returns an aggregated,
// json-formatted summary containing:
// - The number of occurrences of each error
// - A reduced stack trace used for debugging the error
// - Additional metadata present for vital errors
func Aggregate(ctx context.Context) (json.RawMessage, error) {
	const maxTraceLen = 3
	empty := json.RawMessage("[]")

	storedErrs, err := Retrieve(ctx)
	if err != nil {
		return empty, Wrap(ctx, err, "retrieve on aggregation")
	}

	aggs := make([]ErrorAgg, len(storedErrs))
	for i, stored := range storedErrs {
		var ferr []mobiusErrorJSON
		if err = json.Unmarshal(stored.Chain, &ferr); err != nil {
			return empty, Wrap(ctx, err, "unmarshal on aggregation")
		}

		stack := aggregateStack(ferr, maxTraceLen)
		meta := getVitalMetadata(ferr)
		aggs[i] = ErrorAgg{stored.Count, stack, meta}
	}

	return json.Marshal(aggs)
}

// aggregateStack creates a single stack trace by joining all the stack traces in
// an error chain
func aggregateStack(chain []mobiusErrorJSON, maxStack int) []string {
	stack := make([]string, maxStack)
	stackIdx := 0

out:
	for _, e := range chain {
		for _, m := range e.Stack {
			if stackIdx >= maxStack {
				break out
			}

			stack[stackIdx] = m
			stackIdx++
		}
	}

	return stack[:stackIdx]
}

func getVitalMetadata(chain []mobiusErrorJSON) json.RawMessage {
	for _, e := range chain {
		if len(e.Data) > 0 {
			// Currently, only vital mobiusdaemon errors contain metadata.
			// Note: vital errors should not contain any sensitive info
			var mobiusdErr mobius.MobiusdError
			var err error
			if err = json.Unmarshal(e.Data, &mobiusdErr); err != nil || !mobiusdErr.Vital {
				continue
			}
			export := map[string]interface{}{
				"error_source":          mobiusdErr.ErrorSource,
				"error_source_version":  mobiusdErr.ErrorSourceVersion,
				"error_message":         mobiusdErr.ErrorMessage,
				"error_additional_info": mobiusdErr.ErrorAdditionalInfo,
			}
			var meta json.RawMessage
			if meta, err = json.Marshal(export); err != nil {
				return nil
			}
			return meta
		}
	}
	return nil
}
