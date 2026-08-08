// Package dpkg parses and orders Debian and Ubuntu package versions.
//
// The algorithm is specified in deb-version(7) and is unlike every other
// ecosystem's in two ways that matter: '~' sorts before the end of a string
// (which is how Debian spells a pre-release), and letters sort before all
// non-letters rather than in ASCII order. Getting either wrong silently
// mismatches every advisory bound on a package that uses them.
package dpkg

import (
	"fmt"
	"strconv"
	"strings"
)

// Version is a parsed Debian version: [epoch:]upstream[-revision].
type Version struct {
	epoch    int
	upstream string
	revision string
}

// Parse reads a Debian version string.
func Parse(s string) (Version, error) {
	if s == "" {
		return Version{}, fmt.Errorf("dpkg: empty version")
	}
	for _, r := range s {
		if r <= ' ' || r > '~' {
			return Version{}, fmt.Errorf("dpkg: %q contains an invalid character", s)
		}
	}

	v := Version{}
	rest := s

	// The epoch, if present, is everything before the first colon.
	if colon := strings.IndexByte(rest, ':'); colon >= 0 {
		epoch, err := strconv.Atoi(rest[:colon])
		if err != nil || epoch < 0 {
			return Version{}, fmt.Errorf("dpkg: %q has a non-numeric epoch", s)
		}
		v.epoch = epoch
		rest = rest[colon+1:]
	}

	// The revision is everything after the LAST hyphen, so hyphens inside the
	// upstream version stay where they are.
	if hyphen := strings.LastIndexByte(rest, '-'); hyphen >= 0 {
		v.upstream = rest[:hyphen]
		v.revision = rest[hyphen+1:]
		if v.revision == "" {
			return Version{}, fmt.Errorf("dpkg: %q has an empty revision", s)
		}
	} else {
		v.upstream = rest
	}

	if v.upstream == "" {
		return Version{}, fmt.Errorf("dpkg: %q has no upstream version", s)
	}
	if !isDigit(v.upstream[0]) {
		return Version{}, fmt.Errorf("dpkg: upstream version in %q must start with a digit", s)
	}

	return v, nil
}

// String renders the version exactly as it was written, so it can be compared
// against what dpkg itself reports.
func (v Version) String() string {
	var b strings.Builder
	if v.epoch != 0 {
		fmt.Fprintf(&b, "%d:", v.epoch)
	}
	b.WriteString(v.upstream)
	if v.revision != "" {
		b.WriteByte('-')
		b.WriteString(v.revision)
	}
	return b.String()
}

// Compare returns -1, 0 or +1 as a sorts before, equal to, or after b.
func Compare(a, b Version) int {
	if c := cmpInt(a.epoch, b.epoch); c != 0 {
		return c
	}
	if c := compareFragment(a.upstream, b.upstream); c != 0 {
		return c
	}
	// An absent revision compares equal to "0": both reduce to an empty
	// non-digit run followed by a numeric run worth zero.
	return compareFragment(a.revision, b.revision)
}

func (v Version) Less(other Version) bool  { return Compare(v, other) < 0 }
func (v Version) Equal(other Version) bool { return Compare(v, other) == 0 }

// compareFragment implements deb-version(7)'s comparison of one component:
// alternating runs of non-digits and digits, non-digits by the modified
// ordering below and digits numerically.
func compareFragment(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		// Non-digit run.
		for (i < len(a) && !isDigit(a[i])) || (j < len(b) && !isDigit(b[j])) {
			ac, bc := 0, 0
			if i < len(a) {
				ac = order(a[i])
			}
			if j < len(b) {
				bc = order(b[j])
			}
			if ac != bc {
				return cmpInt(ac, bc)
			}
			i++
			j++
		}

		// Numeric run. Leading zeros are not significant, so the runs are
		// compared as numbers: 1.09 and 1.9 are the same version.
		for i < len(a) && a[i] == '0' {
			i++
		}
		for j < len(b) && b[j] == '0' {
			j++
		}

		digitsA, digitsB := 0, 0
		for i+digitsA < len(a) && isDigit(a[i+digitsA]) {
			digitsA++
		}
		for j+digitsB < len(b) && isDigit(b[j+digitsB]) {
			digitsB++
		}
		if digitsA != digitsB {
			// More digits after stripping leading zeros means a larger number.
			return cmpInt(digitsA, digitsB)
		}
		if c := strings.Compare(a[i:i+digitsA], b[j:j+digitsB]); c != 0 {
			return c
		}
		i += digitsA
		j += digitsB
	}
	return 0
}

// order is deb-version(7)'s modified character ordering:
//
//	'~' sorts before everything, including the end of the string
//	the end of the string sorts before any character
//	letters sort before all other characters
//
// The tilde rule is what makes 1.0~rc1 precede 1.0; the letter rule is what
// makes 1.0a precede 1.0+ even though '+' is lower in ASCII.
func order(c byte) int {
	switch {
	case isDigit(c):
		return 0
	case isAlpha(c):
		return int(c)
	case c == '~':
		return -1
	default:
		return int(c) + 256
	}
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}
