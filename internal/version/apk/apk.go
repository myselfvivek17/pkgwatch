// Package apk parses and orders Alpine Linux package versions.
//
// The grammar is:
//
//	number{.number}...[letter][_suffix[number]]...[-r revision]
//
// Three rules are easy to get wrong and were read off `apk version -t` rather
// than from documentation: trailing components are significant (1.0 < 1.0.0,
// unlike PEP 440), a component with a leading zero is compared as a fraction
// (1.01 < 1.1), and an absent suffix number sorts below zero (1.0_p < 1.0_p0).
package apk

import (
	"fmt"
	"strconv"
	"strings"
)

// suffixOrder is apk's suffix table. Everything below the empty string is a
// pre-release and sorts under the bare version; everything above is a
// post-release and sorts over it. Reversing this would make every Alpine
// release candidate look newer than its release.
var suffixOrder = []string{"alpha", "beta", "pre", "rc", "", "cvs", "svn", "git", "hg", "p"}

// noSuffixRank is the index of "" — the rank a version with no suffix carries.
const noSuffixRank = 4

// Version is a parsed Alpine version.
type Version struct {
	// numbers keeps the raw text of each component, because whether a
	// component is compared numerically or as a fraction depends on its
	// leading zero.
	numbers  []string
	letter   byte // 0 when absent
	suffixes []suffix
	revision int // -1 when absent
	raw      string
}

type suffix struct {
	rank int
	num  int // -1 when the suffix carries no number
}

// Parse reads an Alpine version string.
func Parse(s string) (Version, error) {
	if s == "" {
		return Version{}, fmt.Errorf("apk: empty version")
	}
	v := Version{revision: -1, raw: s}
	rest := s

	// Revision: -rN, always last.
	if idx := strings.LastIndex(rest, "-"); idx >= 0 {
		tail := rest[idx+1:]
		if !strings.HasPrefix(tail, "r") {
			return Version{}, fmt.Errorf("apk: %q has a trailing -%s, expected -rN", s, tail)
		}
		n, err := strconv.Atoi(tail[1:])
		if err != nil || n < 0 {
			return Version{}, fmt.Errorf("apk: %q has an invalid revision", s)
		}
		v.revision = n
		rest = rest[:idx]
	}

	// Suffixes: _name[number], repeatable.
	for {
		idx := strings.LastIndex(rest, "_")
		if idx < 0 {
			break
		}
		token := rest[idx+1:]

		name := token
		num := -1
		for i := 0; i < len(token); i++ {
			if isDigit(token[i]) {
				name = token[:i]
				n, err := strconv.Atoi(token[i:])
				if err != nil {
					return Version{}, fmt.Errorf("apk: %q has an invalid suffix number", s)
				}
				num = n
				break
			}
		}

		rank := suffixRank(name)
		if rank < 0 {
			return Version{}, fmt.Errorf("apk: %q has an unknown suffix %q", s, name)
		}
		// Suffixes were consumed right to left; prepend to restore order.
		v.suffixes = append([]suffix{{rank: rank, num: num}}, v.suffixes...)
		rest = rest[:idx]
	}

	// A single optional letter follows the numbers.
	if rest != "" && isAlpha(rest[len(rest)-1]) {
		v.letter = rest[len(rest)-1]
		rest = rest[:len(rest)-1]
		if rest != "" && isAlpha(rest[len(rest)-1]) {
			return Version{}, fmt.Errorf("apk: %q has more than one letter", s)
		}
	}

	// What remains is the dotted numeric part.
	if rest == "" {
		return Version{}, fmt.Errorf("apk: %q has no numeric part", s)
	}
	for _, part := range strings.Split(rest, ".") {
		if part == "" {
			return Version{}, fmt.Errorf("apk: %q has an empty component", s)
		}
		for i := 0; i < len(part); i++ {
			if !isDigit(part[i]) {
				return Version{}, fmt.Errorf("apk: %q has a non-numeric component %q", s, part)
			}
		}
		v.numbers = append(v.numbers, part)
	}

	return v, nil
}

func suffixRank(name string) int {
	if name == "" {
		return -1 // a bare "_" is not a suffix
	}
	for i, candidate := range suffixOrder {
		if candidate != "" && candidate == name {
			return i
		}
	}
	return -1
}

// String returns the version as written.
func (v Version) String() string { return v.raw }

// Compare returns -1, 0 or +1 as a sorts before, equal to, or after b.
func Compare(a, b Version) int {
	if c := compareNumbers(a.numbers, b.numbers); c != 0 {
		return c
	}
	if c := cmpInt(int(a.letter), int(b.letter)); c != 0 {
		return c
	}
	if c := compareSuffixes(a.suffixes, b.suffixes); c != 0 {
		return c
	}
	return cmpInt(a.revision, b.revision)
}

func (v Version) Less(other Version) bool  { return Compare(v, other) < 0 }
func (v Version) Equal(other Version) bool { return Compare(v, other) == 0 }

// compareNumbers compares the dotted components. The first is always numeric;
// any later component with a leading zero is a fraction and compares as text,
// which is why 1.01 sorts below 1.1.
func compareNumbers(a, b []string) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if i > 0 && (strings.HasPrefix(a[i], "0") || strings.HasPrefix(b[i], "0")) {
			if c := strings.Compare(a[i], b[i]); c != 0 {
				return c
			}
			continue
		}
		if c := cmpInt(atoi(a[i]), atoi(b[i])); c != 0 {
			return c
		}
	}
	// A version with more components is greater; trailing zeros are significant.
	return cmpInt(len(a), len(b))
}

// compareSuffixes walks both suffix lists, treating a missing entry as the
// no-suffix rank so a bare version sits between pre-releases and post-releases.
func compareSuffixes(a, b []suffix) int {
	for i := 0; i < len(a) || i < len(b); i++ {
		x := suffix{rank: noSuffixRank, num: -1}
		y := x
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if c := cmpInt(x.rank, y.rank); c != 0 {
			return c
		}
		if c := cmpInt(x.num, y.num); c != 0 {
			return c
		}
	}
	return 0
}

func atoi(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
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
