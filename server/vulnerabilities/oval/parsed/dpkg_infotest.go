package oval_parsed

import (
	"github.com/notawar/mobius/server/mobius"
	"github.com/notawar/mobius/server/vulnerabilities/utils"
)

// DpkgInfoTest encapsulates a Dpkg info test.
// see https://oval.mitre.org/language/version5.10.1/ovaldefinition/documentation/linux-definitions-schema.html#dpkginfo_test
type DpkgInfoTest struct {
	Objects       []string
	States        []ObjectStateEvrString
	StateOperator OperatorType
	ObjectMatch   ObjectMatchType
	StateMatch    StateMatchType
}

// Eval evaluates the given dpkg info test against a host's installed packages.
// If test evaluates to true, returns all Software involved with the test match, otherwise will
// return nil.
func (t *DpkgInfoTest) Eval(packages []mobius.Software) ([]mobius.Software, error) {
	if len(packages) == 0 {
		return nil, nil
	}

	no, ns, m, err := t.matches(packages)
	if err != nil {
		return nil, err
	}

	oMatches := t.ObjectMatch.Eval(no, len(t.Objects))
	sMatches := t.StateMatch.Eval(no, ns)

	if oMatches && sMatches {
		return m, nil
	}
	return nil, nil
}

// Returns:
//
//	nObjects: How many items in the set defined by the OVAL Object set exists in the system.
//	nStates: How many items in the set defined by the OVAL Object set satisfy the state requirements.
//	Slice with software matching both the object and state criteria.
func (t *DpkgInfoTest) matches(software []mobius.Software) (int, int, []mobius.Software, error) {
	var nObjects int
	var nState int
	var matches []mobius.Software

	for _, p := range software {
		for _, o := range t.Objects {
			if p.Name == o {
				nObjects++

				r := make([]bool, 0)
				for _, s := range t.States {
					evalR, err := s.Eval(p.Version, utils.Rpmvercmp, false)
					if err != nil {
						return 0, 0, nil, err
					}
					r = append(r, evalR)
				}
				if t.StateOperator.Eval(r...) {
					matches = append(matches, p)
					nState++
				}
			}
		}
	}

	return nObjects, nState, matches, nil
}
