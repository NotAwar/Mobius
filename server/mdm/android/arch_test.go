package android_test

import (
	"regexp"
	"testing"

	"github.com/notawar/mobius/server/archtest"
)

// TestAllAndroidPackageDependencies checks that android packages are not dependent on other Mobius packages
// to maintain decoupling and modularity.
// If coupling is necessary, it should be done in the main server/mobius, server/service, or other package.
func TestAllAndroidPackageDependencies(t *testing.T) {
	t.Parallel()
	archtest.NewPackageTest(t, "github.com/notawar/mobius/server/mdm/android...").
		OnlyInclude(regexp.MustCompile(`^github\.com/mobiusmdm/`)).
		WithTests().
		IgnoreXTests("github.com/notawar/mobius/server/mobius"). // ignore mobius_test package
		IgnorePackages(
			"github.com/notawar/mobius/server/datastore/mysql/common_mysql...",
			"github.com/notawar/mobius/server/service/externalsvc", // dependency on Jira and Zendesk
			"github.com/notawar/mobius/server/service/middleware/auth",
			"github.com/notawar/mobius/server/service/middleware/authzcheck",
			"github.com/notawar/mobius/server/service/middleware/endpoint_utils",
			"github.com/notawar/mobius/server/service/middleware/log",
			"github.com/notawar/mobius/server/service/middleware/ratelimit",
		).
		ShouldNotDependOn(
			"github.com/notawar/mobius/server/service...",
			"github.com/notawar/mobius/server/datastore...",
		)
}

// TestAndroidPackageDependencies checks that android package is NOT dependent on ANY other Mobius packages
// to maintain decoupling and modularity. This package should only contain basic structs and interfaces.
// If coupling is necessary, it should be done in the main server/mobius or another package.
func TestAndroidPackageDependencies(t *testing.T) {
	t.Parallel()
	archtest.NewPackageTest(t, "github.com/notawar/mobius/server/mdm/android").
		OnlyInclude(regexp.MustCompile(`^github\.com/mobiusmdm/`)).
		ShouldNotDependOn("github.com/notawar/mobius/...")
}
