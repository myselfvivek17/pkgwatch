package apk

import "testing"

// The rules that make apk's ordering unlike every other ecosystem's. Each was
// read off `apk version -t` inside Alpine rather than from documentation.
func TestCompare(t *testing.T) {
	tests := []struct {
		name   string
		lo, hi string
	}{
		{"numeric", "1.0", "1.1"},
		{"numeric not lexical", "1.0.2", "1.0.10"},
		{"major", "0.9", "1.0"},

		// More components is greater. Trailing zeros are significant here,
		// unlike PEP 440 where 1.0 and 1.0.0 are the same version.
		{"more components wins", "1.0", "1.0.0"},
		{"and again", "1.0.0", "1.0.0.0"},

		// A component with a leading zero is compared as a fraction, so 1.01
		// sorts below 1.1 rather than above it.
		{"leading zero is a fraction", "1.01", "1.1"},
		{"longer fraction", "1.010", "1.10"},

		// Numeric components are compared before the letter, so more numbers
		// beats a letter suffix.
		{"numbers before letter", "1.0a", "1.0.1"},
		{"letter raises", "1.0", "1.0a"},
		{"letters in order", "1.0a", "1.0b"},

		// Pre-release suffixes sort below the bare version; post-release
		// suffixes sort above it. Getting this backwards would treat every
		// Alpine release candidate as newer than its release.
		{"alpha", "1.0_alpha1", "1.0"},
		{"beta", "1.0_beta1", "1.0"},
		{"pre", "1.0_pre1", "1.0"},
		{"rc", "1.0_rc1", "1.0"},
		{"alpha before beta", "1.0_alpha1", "1.0_beta1"},
		{"rc is the last pre", "1.0_rc1", "1.0_cvs1"},
		{"cvs is a post-release", "1.0", "1.0_cvs1"},
		{"p is a post-release", "1.0", "1.0_p1"},
		{"post-release order", "1.0_cvs1", "1.0_p1"},
		{"suffix numbers", "1.0_alpha1", "1.0_alpha2"},

		// An absent suffix number sorts below zero, not equal to it.
		{"absent suffix number", "1.0_p", "1.0_p0"},
		{"absent then numbered", "1.0_alpha", "1.0_alpha1"},

		// The package revision is compared last, and an absent one is lowest.
		{"absent revision", "1.0", "1.0-r0"},
		{"revision order", "1.0-r1", "1.0-r2"},
		{"revision numeric", "1.0-r2", "1.0-r10"},
		{"suffix outranks revision", "1.0_rc1-r1", "1.0-r0"},

		{"real alpine versions", "1.1.1f-r0", "3.0.2-r1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
		})
	}
}

func TestEqual(t *testing.T) {
	for _, pair := range [][2]string{
		{"1.0", "1.0"},
		{"1.0-r1", "1.0-r1"},
		{"1.0_rc1", "1.0_rc1"},
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

func TestParseRejectsInvalid(t *testing.T) {
	// apk itself refuses these; accepting them would mean inventing an ordering
	// no Alpine tool agrees with.
	for _, in := range []string{
		"",
		"abc",     // must start with a digit
		"1.0zz",   // only a single letter is allowed
		"1.0_xyz", // unknown suffix
		"1.0-",    // empty revision
		"1.0-r",   // revision with no number
		"1.0-x1",  // revision must be rN
		"1..0",    // empty component
		"1.0 ",    // whitespace
	} {
		if v, err := Parse(in); err == nil {
			t.Errorf("Parse(%q) = %+v, want an error", in, v)
		}
	}
}

func TestString(t *testing.T) {
	for _, in := range []string{"1.0", "1.0.1-r2", "1.0_rc1", "1.0a", "1.2.3_beta_p1-r4"} {
		v, err := Parse(in)
		if err != nil {
			t.Fatalf("Parse(%q): %v", in, err)
		}
		if got := v.String(); got != in {
			t.Errorf("Parse(%q).String() = %q", in, got)
		}
	}
}
