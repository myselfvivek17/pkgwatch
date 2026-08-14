package scriptguard

import (
	"context"
	"errors"
	"testing"
)

// The one function here that deliberately executes third-party code is the last
// place to hand an unchecked string to a command line.
//
// npm reads a leading dash as a flag, not a package, so `allow-scripts
// --some-flag` would pass an option through to a program whose whole job in
// this codebase is running install scripts. The name is validated and passed
// after `--`; both, because either alone is one mistake away from the other
// being load-bearing.
func TestARgumentLikeNamesAreRefused(t *testing.T) {
	refuse := []string{
		"--ignore-scripts=true",
		"-g",
		"--prefix=/tmp/evil",
		"pkg;rm -rf /",
		"pkg name",
		"../../etc/passwd",
		"UPPER",
		"",
	}
	for _, name := range refuse {
		if _, err := Run(context.Background(), t.TempDir(), name); !errors.Is(err, ErrBadPackageName) {
			t.Errorf("Run(%q) error = %v, want %v", name, err, ErrBadPackageName)
		}
	}
}

// And the names npm actually uses still work. A validator that rejected scoped
// packages would refuse most of what needs an allowance.
func TestRealPackageNamesPassValidation(t *testing.T) {
	for _, name := range []string{
		"esbuild", "sharp", "@ctrl/tinycolor", "node-gyp", "core-js", "@github/keytar", "re2",
	} {
		if !npmName.MatchString(name) {
			t.Errorf("%q is a real npm package name and was refused", name)
		}
	}
}
