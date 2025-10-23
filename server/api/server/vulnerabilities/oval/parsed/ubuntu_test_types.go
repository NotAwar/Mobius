package oval_parsed

import (
	"github.com/notawar/mobius/mobius-server/server/mobius"
	oval_input "github.com/notawar/mobius/mobius-server/server/vulnerabilities/oval/input"
)

// Minimal stub definitions for Ubuntu/Debian parsed types to fix build issues
// These are placeholders for the actual OVAL parsed type definitions

type DpkgInfoTest struct {
	ID            string
	Comment       string
	ObjectMatch   ObjectMatchType
	StateMatch    StateMatchType
	StateOperator OperatorType
	InputTest     oval_input.DpkgInfoTest
}

// Eval is a stub method that returns empty results
func (d *DpkgInfoTest) Eval(software []mobius.Software) ([]mobius.Software, error) {
	// Return empty slice as this is a stub implementation
	return []mobius.Software{}, nil
}

type UnixUnameTest struct {
	ID      string
	Comment string
}

// Eval is a stub method that returns false
func (u *UnixUnameTest) Eval(version string) (bool, error) {
	// Return false as this is a stub implementation
	return false, nil
}
