package pep440

import "testing"

// The canonical ordering example from PEP 440 itself. If the parser gets any
// piece of the sort key wrong — epoch, release padding, pre/post/dev
// precedence, local segments — some adjacent pair here stops being ordered.
var pep440CanonicalOrder = []string{
	"1.dev0",
	"1.0.dev456",
	"1.0a1",
	"1.0a2.dev456",
	"1.0a12.dev456",
	"1.0a12",
	"1.0b1.dev456",
	"1.0b2",
	"1.0b2.post345.dev456",
	"1.0b2.post345",
	"1.0rc1.dev456",
	"1.0rc1",
	"1.0",
	"1.0+abc.5",
	"1.0+abc.7",
	"1.0+5",
	"1.0.post456.dev34",
	"1.0.post456",
	"1.1.dev1",
}

func TestCanonicalOrdering(t *testing.T) {
	for i := 0; i < len(pep440CanonicalOrder)-1; i++ {
		lo, hi := pep440CanonicalOrder[i], pep440CanonicalOrder[i+1]

		a, err := Parse(lo)
		if err != nil {
			t.Fatalf("Parse(%q): %v", lo, err)
		}
		b, err := Parse(hi)
		if err != nil {
			t.Fatalf("Parse(%q): %v", hi, err)
		}

		if got := Compare(a, b); got >= 0 {
			t.Errorf("Compare(%q, %q) = %d, want < 0", lo, hi, got)
		}
		if got := Compare(b, a); got <= 0 {
			t.Errorf("Compare(%q, %q) = %d, want > 0", hi, lo, got)
		}
	}
}

func TestNormalization(t *testing.T) {
	tests := []struct{ in, want string }{
		// Case, whitespace and the tolerated "v" prefix.
		{"1.0", "1.0"},
		{" 1.0 ", "1.0"},
		{"v1.0", "1.0"},
		{"1.0A1", "1.0a1"},

		// Leading zeros are not significant.
		{"01.0", "1.0"},
		{"1.0.007", "1.0.7"},

		// Pre-release spellings all fold to a, b, rc.
		{"1.0alpha1", "1.0a1"},
		{"1.0beta2", "1.0b2"},
		{"1.0c3", "1.0rc3"},
		{"1.0pre4", "1.0rc4"},
		{"1.0preview5", "1.0rc5"},
		{"1.0-a.1", "1.0a1"},
		{"1.0_b_2", "1.0b2"},
		{"1.0a", "1.0a0"}, // implicit zero
		// Valid PEP 440 despite looking like the npm spelling: the pre-release
		// separator is optional, so this is 1.0.0b0 and not a parse error.
		{"1.0.0-beta", "1.0.0b0"},

		// Post-release spellings.
		{"1.0.post1", "1.0.post1"},
		{"1.0-1", "1.0.post1"},
		{"1.0-post1", "1.0.post1"},
		{"1.0.rev2", "1.0.post2"},
		{"1.0.r3", "1.0.post3"},
		{"1.0.post", "1.0.post0"},

		// Dev releases.
		{"1.0.dev1", "1.0.dev1"},
		{"1.0dev", "1.0.dev0"},
		{"1.0-dev-2", "1.0.dev2"},

		// Epochs.
		{"1!2.0", "1!2.0"},
		{"0!1.0", "1.0"}, // epoch 0 is the default and is not printed

		// Local versions lowercase and use "." as the separator.
		{"1.0+UBUNTU-1", "1.0+ubuntu.1"},
		{"1.0+abc_5", "1.0+abc.5"},

		// Everything at once.
		{"1!1.0alpha1.post2.dev3+Local_1", "1!1.0a1.post2.dev3+local.1"},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			v, err := Parse(tt.in)
			if err != nil {
				t.Fatalf("Parse(%q): %v", tt.in, err)
			}
			if got := v.String(); got != tt.want {
				t.Errorf("Parse(%q).String() = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// Zero padding: trailing zero components are not significant, so 1.0 and 1.0.0
// are the same version. Getting this wrong silently misses advisories whose
// bound is written with a different number of components than the installed
// version reports.
func TestEqualityAcrossRepresentations(t *testing.T) {
	equal := [][2]string{
		{"1.0", "1.0.0"},
		{"1.0", "1.0.0.0"},
		{"1", "1.0"},
		{"1.0", "0!1.0"},
		{"1.0alpha1", "1.0a1"},
		{"1.0-1", "1.0.post1"},
		{"1.0+FOO", "1.0+foo"},
	}

	for _, pair := range equal {
		a, err := Parse(pair[0])
		if err != nil {
			t.Fatalf("Parse(%q): %v", pair[0], err)
		}
		b, err := Parse(pair[1])
		if err != nil {
			t.Fatalf("Parse(%q): %v", pair[1], err)
		}
		if got := Compare(a, b); got != 0 {
			t.Errorf("Compare(%q, %q) = %d, want 0", pair[0], pair[1], got)
		}
	}
}

// An epoch beats everything to its left. A parser that ignores epochs reads
// 1!1.0 as older than 2.0 and matches the wrong side of every bound.
func TestEpochDominatesRelease(t *testing.T) {
	older, err := Parse("2.0")
	if err != nil {
		t.Fatal(err)
	}
	newer, err := Parse("1!1.0")
	if err != nil {
		t.Fatal(err)
	}
	if Compare(older, newer) >= 0 {
		t.Errorf("2.0 should sort before 1!1.0")
	}
}

// Numeric local segments outrank alphabetic ones regardless of value.
func TestLocalSegmentOrdering(t *testing.T) {
	tests := []struct {
		lo, hi string
	}{
		{"1.0+abc.7", "1.0+5"}, // numeric beats alphabetic
		{"1.0+1", "1.0+2"},     // numeric compares numerically
		{"1.0+abc", "1.0+abd"}, // alphabetic compares lexically
		{"1.0", "1.0+local"},   // any local beats none
		{"1.0+1", "1.0+1.1"},   // longer wins when the prefix ties
		{"1.0+9", "1.0+10"},    // not string ordering
		{"1.0+abc.1", "1.0+abc.2"},
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
	}
}

// A release with no pre/post/dev outranks all of its own pre-releases and dev
// releases, and is outranked by its post-releases.
func TestReleaseVersusPreAndPost(t *testing.T) {
	tests := []struct{ lo, hi string }{
		{"1.0.dev1", "1.0a1"},
		{"1.0a1", "1.0b1"},
		{"1.0b1", "1.0rc1"},
		{"1.0rc1", "1.0"},
		{"1.0", "1.0.post1"},
		{"1.0.post1", "1.0.post2"},
		{"1.0.post1.dev1", "1.0.post1"},
		{"1.0a1.dev1", "1.0a1"},
		{"1.0", "1.0.1"},
		{"1.9", "1.10"}, // numeric, not lexical
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
	}
}

func TestIsPrerelease(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"1.0", false},
		{"1.0.post1", false},
		{"1.0a1", true},
		{"1.0b1", true},
		{"1.0rc1", true},
		{"1.0.dev1", true},
		{"1.0.post1.dev1", true},
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

func TestParseRejectsInvalid(t *testing.T) {
	invalid := []string{
		"",
		"not-a-version",
		"1.0.0+",     // empty local
		"1.-1",       // negative
		"1!",         // epoch with no release
		"1.0.post1a", // trailing junk
		"1.0 .0",     // internal whitespace
		"~1.0",       // a specifier, not a version
		"1.0+foo!",   // illegal character in local
	}

	for _, in := range invalid {
		if v, err := Parse(in); err == nil {
			t.Errorf("Parse(%q) = %v, want an error", in, v)
		}
	}
}
