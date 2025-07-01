package oval_parsed

import (
	"github.com/notawar/mobius/v4/server/mobius"
)

type RhelResult struct {
	Definitions        []Definition
	RpmInfoTests       map[int]*RpmInfoTest
	RpmVerifyFileTests map[int]*RpmVerifyFileTest
}

// NewRhelResult is the result of parsing an OVAL file that targets a Rhel based distro.
func NewRhelResult() *RhelResult {
	return &RhelResult{
		RpmInfoTests:       make(map[int]*RpmInfoTest),
		RpmVerifyFileTests: make(map[int]*RpmVerifyFileTest),
	}
}

func (r RhelResult) Eval(ver mobius.OSVersion, software []mobius.Software) ([]mobius.SoftwareVulnerability, error) {
	// Rpm Info Test Id => Matching software
	pkgTstResults := make(map[int][]mobius.Software)
	for i, t := range r.RpmInfoTests {
		rEval, err := t.Eval(software)
		if err != nil {
			return nil, err
		}
		pkgTstResults[i] = rEval
	}

	// Evaluate RpmVerifyFileTests, which are used to make assertions against the installed OS
	OSTstResults := make(map[int]bool)
	for i, t := range r.RpmVerifyFileTests {
		rEval, err := t.Eval(ver)
		if err != nil {
			return nil, err
		}
		OSTstResults[i] = rEval
	}

	vuln := make([]mobius.SoftwareVulnerability, 0)
	for _, d := range r.Definitions {
		if !d.Eval(OSTstResults, pkgTstResults) {
			continue
		}

		for _, tId := range d.CollectTestIds() {
			for _, software := range pkgTstResults[tId] {
				for _, v := range d.CveVulnerabilities() {
					vuln = append(vuln, mobius.SoftwareVulnerability{
						SoftwareID: software.ID,
						CVE:        v,
					})
				}
			}
		}
	}

	return vuln, nil
}

// EvalUname is not implemented for Rhel based distros
func (r RhelResult) EvalKernel(software []mobius.Software) ([]mobius.SoftwareVulnerability, error) {
	return nil, nil
}
