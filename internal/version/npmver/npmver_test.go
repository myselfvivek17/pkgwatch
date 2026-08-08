package npmver

import "testing"

func TestParseAcceptsRegistryVersions(t *testing.T) {
	tests := []struct{ in, want string }{
		{"1.0.0", "1.0.0"},
		{"v1.0.0", "1.0.0"}, // tags carry a leading v
		{" 1.0.0 ", "1.0.0"},
		{"0.0.1", "0.0.1"},
		{"1.0.0-beta.1", "1.0.0-beta.1"},
		{"1.0.0-rc.1", "1.0.0-rc.1"},
		{"1.0.0+build.5", "1.0.0+build.5"},
		{"1.0.0-alpha+001", "1.0.0-alpha+001"},
		{"4.17.20", "4.17.20"},
		{"3.4.1", "3.4.1"},
	}

	for _, tt := range tests {
		v, err := Parse(tt.in)
		if err != nil {
			t.Errorf("Parse(%q): %v", tt.in, err)
			continue
		}
		if got := v.String(); got != tt.want {
			t.Errorf("Parse(%q).String() = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestParseRejectsNonSemver(t *testing.T) {
	// npm registry versions are strict semver. Accepting partials silently
	// invents a patch number, which is how a bound quietly shifts.
	for _, in := range []string{"", "1", "1.0", "not-a-version", "1.0.0.0", "^1.0.0", ">=1.0.0"} {
		if v, err := Parse(in); err == nil {
			t.Errorf("Parse(%q) = %v, want an error", in, v)
		}
	}
}

func TestOrdering(t *testing.T) {
	tests := []struct{ lo, hi string }{
		{"1.0.0", "1.0.1"},
		{"1.0.9", "1.0.10"}, // numeric, not lexical
		{"1.9.0", "1.10.0"},
		{"0.9.0", "1.0.0"},

		// A prerelease sorts before its own release. This is the case that
		// decides whether 1.0.0-beta.1 falls inside a range introduced at
		// 1.0.0 — it must not.
		{"1.0.0-beta.1", "1.0.0"},
		{"1.0.0-alpha", "1.0.0-beta"},
		{"1.0.0-alpha.1", "1.0.0-alpha.2"},
		{"1.0.0-alpha.9", "1.0.0-alpha.10"}, // numeric identifiers compare numerically
		{"1.0.0-alpha", "1.0.0-alpha.1"},    // fewer fields sorts first
		{"1.0.0-rc.1", "1.0.0"},
	}

	for _, tt := range tests {
		a, err := Parse(tt.lo)
		if err != nil {
			t.Fatalf("Parse(%q): %v", tt.lo, err)
		}
		b, err := Parse(tt.hi)
		if err != nil {
			t.Fatalf("Parse(%q): %v", tt.hi, err)
		}
		if got := Compare(a, b); got >= 0 {
			t.Errorf("Compare(%q, %q) = %d, want < 0", tt.lo, tt.hi, got)
		}
		if got := Compare(b, a); got <= 0 {
			t.Errorf("Compare(%q, %q) = %d, want > 0", tt.hi, tt.lo, got)
		}
	}
}

// Build metadata is not part of precedence: 1.0.0+a and 1.0.0+b are the same
// version. An advisory bound written with build metadata must still match.
func TestBuildMetadataIsIgnoredInOrdering(t *testing.T) {
	for _, pair := range [][2]string{
		{"1.0.0+build.1", "1.0.0+build.2"},
		{"1.0.0", "1.0.0+build.1"},
		{"1.0.0-alpha+a", "1.0.0-alpha+b"},
	} {
		a, err := Parse(pair[0])
		if err != nil {
			t.Fatal(err)
		}
		b, err := Parse(pair[1])
		if err != nil {
			t.Fatal(err)
		}
		if got := Compare(a, b); got != 0 {
			t.Errorf("Compare(%q, %q) = %d, want 0", pair[0], pair[1], got)
		}
	}
}

func TestIsPrerelease(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"1.0.0", false},
		{"1.0.0+build", false},
		{"1.0.0-beta.1", true},
		{"1.0.0-0", true},
	}

	for _, tt := range tests {
		v, err := Parse(tt.in)
		if err != nil {
			t.Fatalf("Parse(%q): %v", tt.in, err)
		}
		if got := v.IsPrerelease(); got != tt.want {
			t.Errorf("Parse(%q).IsPrerelease() = %v, want %v", tt.in, got, tt.want)
		}
	}
}
