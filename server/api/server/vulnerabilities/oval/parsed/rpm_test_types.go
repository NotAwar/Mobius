package oval_parsed

import (
	"github.com/notawar/mobius/mobius-server/server/mobius"
	oval_input "github.com/notawar/mobius/mobius-server/server/vulnerabilities/oval/input"
)

// Minimal stub definitions for RPM parsed types to fix build issues
// These are placeholders for the actual OVAL parsed type definitions

type ObjectMatchType string
type StateMatchType string
type OperatorType string

type RpmInfoTest struct {
	ID            string
	Comment       string
	ObjectMatch   ObjectMatchType
	StateMatch    StateMatchType
	StateOperator OperatorType
	InputTest     oval_input.RpmInfoTest
}

// Eval is a stub method that returns empty results
func (r *RpmInfoTest) Eval(software []mobius.Software) ([]mobius.Software, error) {
	// Return empty slice as this is a stub implementation
	return []mobius.Software{}, nil
}

type RpmVerifyFileTest struct {
	ID            string
	Comment       string
	ObjectMatch   ObjectMatchType
	StateMatch    StateMatchType
	StateOperator OperatorType
}

// Eval is a stub method that returns false
func (r *RpmVerifyFileTest) Eval(ver mobius.OSVersion) (bool, error) {
	// Return false as this is a stub implementation
	return false, nil
}
