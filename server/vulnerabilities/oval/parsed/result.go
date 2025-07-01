package oval_parsed

import "github.com/notawar/mobius/v4/server/mobius"

type Result interface {
	// Eval evaluates the current OVAL definition against an OS version and a list of installed software, returns all software
	// vulnerabilities found.
	Eval(mobius.OSVersion, []mobius.Software) ([]mobius.SoftwareVulnerability, error)

	// EvalKernel evaluates the current OVAL definition against a list of installed kernel-image software,
	// returns all kernel-image vulnerabilities found.  Currently only used for Ubuntu.
	EvalKernel([]mobius.Software) ([]mobius.SoftwareVulnerability, error)
}
