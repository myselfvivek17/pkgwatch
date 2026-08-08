package dpkg

import "testing"

func TestParse(t *testing.T) {
	tests := []struct {
		in       string
		epoch    int
		upstream string
		revision string
	}{
		{"1.0", 0, "1.0", ""},
		{"1.0-1", 0, "1.0", "1"},
		{"1:1.0-1", 1, "1.0", "1"},
		{"2:7.4.052-1ubuntu3", 2, "7.4.052", "1ubuntu3"},
		// The revision is split at the LAST hyphen, so hyphens inside the
		// upstream version stay there.
		{"1.0-beta-3", 0, "1.0-beta", "3"},
		{"1:2.4.52-1ubuntu4.6", 1, "2.4.52", "1ubuntu4.6"},
		{"0:1.0", 0, "1.0", ""},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			v, err := Parse(tt.in)
			if err != nil {
				t.Fatalf("Parse(%q): %v", tt.in, err)
			}
			if v.epoch != tt.epoch || v.upstream != tt.upstream || v.revision != tt.revision {
				t.Errorf("Parse(%q) = {epoch:%d upstream:%q revision:%q}, want {%d %q %q}",
					tt.in, v.epoch, v.upstream, v.revision, tt.epoch, tt.upstream, tt.revision)
			}
		})
	}
}

func TestParseRejectsInvalid(t *testing.T) {
	for _, in := range []string{
		"",
		"1:",     // epoch with no version
		"a:1.0",  // non-numeric epoch
		"-1",     // upstream must start with a digit
		"1.0 -1", // whitespace
		"1.0-1-", // empty revision
		"1.0\n",  // control character
	} {
		if v, err := Parse(in); err == nil {
			t.Errorf("Parse(%q) = %+v, want an error", in, v)
		}
	}
}

// The ordering rules that make dpkg's algorithm unlike every other ecosystem's.
func TestCompare(t *testing.T) {
	tests := []struct {
		name   string
		lo, hi string
	}{
		{"simple", "1.0", "1.1"},
		{"patch", "1.0.0", "1.0.1"},
		{"numeric not lexical", "1.9", "1.10"},
		{"revision", "1.0-1", "1.0-2"},
		{"revision numeric", "1.0-9", "1.0-10"},
		{"absent revision is lowest", "1.0", "1.0-1"},

		// Epoch dominates everything to its right. Without it, 1:1.0 reads as
		// older than 2.0 and every bound on an epoch-bearing package is wrong.
		{"epoch beats upstream", "2.0", "1:1.0"},
		{"epoch ordering", "1:1.0", "2:1.0"},

		// The tilde sorts before everything, including the end of the string.
		// This is how Debian expresses pre-releases: 1.0~rc1 precedes 1.0.
		{"tilde precedes empty", "1.0~", "1.0"},
		{"tilde precedes anything", "1.0~rc1", "1.0"},
		{"double tilde", "1.0~~", "1.0~"},
		{"tilde vs letter", "1.0~a", "1.0a"},
		{"debian prerelease", "1.0~beta1", "1.0"},
		{"tilde in revision", "1.0-1~bpo1", "1.0-1"},

		// Letters sort before every non-letter, which is not ASCII order.
		{"letter before plus", "1.0a", "1.0+"},
		{"letters in ascii order", "1.0a", "1.0b"},
		{"uppercase before lowercase", "1.0A", "1.0a"},

		// A shorter string is smaller when the prefix ties.
		{"prefix", "1.0", "1.0.1"},
		{"ubuntu revisions", "1:2.4.52-1ubuntu4.5", "1:2.4.52-1ubuntu4.6"},
		{"real openssl", "1.1.1f-1ubuntu2.16", "3.0.2-0ubuntu1.10"},
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
	// Leading zeros in a numeric run are not significant — a genuine dpkg
	// quirk, and one that decides whether a bound written 1.09 catches 1.9.
	equal := [][2]string{
		{"1.0", "1.0"},
		{"1.0", "0:1.0"},
		{"1.0", "1.0-0"},
		{"1.09", "1.9"},
		{"1.0-01", "1.0-1"},
		{"1.007", "1.7"},
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

func TestString(t *testing.T) {
	// Round-tripping must preserve the version exactly: it is shown to the user
	// and compared against what dpkg itself reports.
	for _, in := range []string{"1.0", "1.0-1", "1:1.0-1", "2:7.4.052-1ubuntu3", "1.0~rc1-2"} {
		v, err := Parse(in)
		if err != nil {
			t.Fatalf("Parse(%q): %v", in, err)
		}
		if got := v.String(); got != in {
			t.Errorf("Parse(%q).String() = %q", in, got)
		}
	}
}
