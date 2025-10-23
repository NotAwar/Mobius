package oval_input

// Minimal stub definitions for RPM test types to fix build issues
// These are placeholders for the actual OVAL test type definitions

type RpmInfoState struct {
	Name    string
	Version string
	Release string
	Arch    string
}

type RpmInfoTest struct {
	ID       string
	StateRef string
}

type RpmVerifyFileTestXML struct {
	ID             string `xml:"id,attr"`
	Comment        string `xml:"comment,attr"`
	CheckExistence string `xml:"check_existence,attr"`
	Check          string `xml:"check,attr"`
	StateOperator  string `xml:"state_operator,attr"`
}

type RpmInfoTestXML struct {
	ID             string `xml:"id,attr"`
	Comment        string `xml:"comment,attr"`
	CheckExistence string `xml:"check_existence,attr"`
	Check          string `xml:"check,attr"`
	StateOperator  string `xml:"state_operator,attr"`
}

type ObjectName struct {
	Value  string `xml:",chardata"`
	VarRef string `xml:"var_ref,attr"`
}

type PackageInfoTestObjectXML struct {
	ID      string     `xml:"id,attr"`
	Comment string     `xml:"comment,attr"`
	Name    ObjectName `xml:"name"`
}
