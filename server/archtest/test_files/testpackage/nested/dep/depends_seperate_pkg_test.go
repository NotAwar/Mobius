package dep_test

import (
	"testing"

	"github.com/notawar/mobius/server/archtest/test_files/testfiledeps/testpkgdependency"
)

func Test(t *testing.T) {
	testpkgdependency.OohNoBadCode()
}
