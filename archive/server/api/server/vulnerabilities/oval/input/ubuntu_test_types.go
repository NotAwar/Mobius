package oval_input

// Minimal stub definitions for Ubuntu/Debian test types to fix build issues
// These are placeholders for the actual OVAL test type definitions

type DpkgInfoState struct {
	Name      string
	Version   string
	Arch      string
	EvrString string
}

type DpkgInfoTest struct {
	ID       string
	StateRef string
}

type DpkgInfoTestXML struct {
	ID             string `xml:"id,attr"`
	Comment        string `xml:"comment,attr"`
	CheckExistence string `xml:"check_existence,attr"`
	Check          string `xml:"check,attr"`
	StateOperator  string `xml:"state_operator,attr"`
}

type UnixUnameTestXML struct {
	ID      string `xml:"id,attr"`
	Comment string `xml:"comment,attr"`
}

type VariableTestXML struct {
	ID      string `xml:"id,attr"`
	Comment string `xml:"comment,attr"`
}
