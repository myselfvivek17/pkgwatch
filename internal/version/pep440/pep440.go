// Package pep440 parses and orders Python package versions.
//
// This is hand-written because no Go library handles the whole of PEP 440 —
// epochs, post-releases, dev releases and local versions — correctly, and both
// false positives and false negatives in version matching are silent. It is the
// most correctness-critical code in pkgwatch; change it only with the test
// table in hand.
//
// Reference: https://peps.python.org/pep-0440/
package pep440

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// The canonical PEP 440 grammar, anchored and case-insensitive.
//
// Alternation order matters: Go's regexp is leftmost-first, so the longer
// spellings must come before their prefixes or "alpha" matches as "a" and the
// rest becomes trailing junk.
var versionRE = regexp.MustCompile(`^(?i)` +
	`v?` +
	`(?:(?P<epoch>[0-9]+)!)?` +
	`(?P<release>[0-9]+(?:\.[0-9]+)*)` +
	`(?:[-_.]?(?P<preL>alpha|beta|preview|pre|a|b|c|rc)[-_.]?(?P<preN>[0-9]+)?)?` +
	`(?:` +
	`(?:-(?P<postN1>[0-9]+))` +
	`|` +
	`(?:[-_.]?(?P<postL>post|rev|r)[-_.]?(?P<postN2>[0-9]+)?)` +
	`)?` +
	`(?:[-_.]?(?P<devL>dev)[-_.]?(?P<devN>[0-9]+)?)?` +
	`(?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?` +
	`$`)

// Pre-release kinds, in sort order.
const (
	preAlpha = iota
	preBeta
	preRC
)

// Version is a parsed, normalized PEP 440 version.
type Version struct {
	epoch   int
	release []int

	hasPre  bool
	preKind int
	preNum  int

	hasPost bool
	postNum int

	hasDev bool
	devNum int

	local []localSegment
}

// localSegment is one dot-separated piece of a local version. Numeric segments
// sort above alphabetic ones regardless of value.
type localSegment struct {
	num     int
	str     string
	numeric bool
}

// Parse reads a PEP 440 version string. Surrounding whitespace and a leading
// "v" are tolerated; anything else outside the grammar is an error.
func Parse(s string) (Version, error) {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return Version{}, fmt.Errorf("pep440: empty version")
	}

	m := versionRE.FindStringSubmatch(trimmed)
	if m == nil {
		return Version{}, fmt.Errorf("pep440: %q is not a valid version", s)
	}
	group := func(name string) string { return m[versionRE.SubexpIndex(name)] }

	v := Version{}

	if e := group("epoch"); e != "" {
		n, err := strconv.Atoi(e)
		if err != nil {
			return Version{}, fmt.Errorf("pep440: epoch in %q: %w", s, err)
		}
		v.epoch = n
	}

	for _, part := range strings.Split(group("release"), ".") {
		n, err := strconv.Atoi(part)
		if err != nil {
			return Version{}, fmt.Errorf("pep440: release segment %q in %q: %w", part, s, err)
		}
		v.release = append(v.release, n)
	}

	if l := group("preL"); l != "" {
		v.hasPre = true
		switch strings.ToLower(l) {
		case "a", "alpha":
			v.preKind = preAlpha
		case "b", "beta":
			v.preKind = preBeta
		default: // c, rc, pre, preview
			v.preKind = preRC
		}
		v.preNum = atoiOrZero(group("preN"))
	}

	// Two spellings reach the same place: the implicit "-N" form and an
	// explicit post/rev/r label.
	if n1 := group("postN1"); n1 != "" {
		v.hasPost = true
		v.postNum = atoiOrZero(n1)
	} else if group("postL") != "" {
		v.hasPost = true
		v.postNum = atoiOrZero(group("postN2"))
	}

	if group("devL") != "" {
		v.hasDev = true
		v.devNum = atoiOrZero(group("devN"))
	}

	if l := group("local"); l != "" {
		for _, seg := range strings.FieldsFunc(strings.ToLower(l), func(r rune) bool {
			return r == '.' || r == '-' || r == '_'
		}) {
			if n, err := strconv.Atoi(seg); err == nil {
				v.local = append(v.local, localSegment{num: n, numeric: true})
			} else {
				v.local = append(v.local, localSegment{str: seg})
			}
		}
	}

	return v, nil
}

func atoiOrZero(s string) int {
	if s == "" {
		return 0
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
}

// IsPrerelease reports whether this version is a pre-release or a dev release.
// Post-releases are not pre-releases.
func (v Version) IsPrerelease() bool { return v.hasPre || v.hasDev }

// String renders the normalized form.
func (v Version) String() string {
	var b strings.Builder

	if v.epoch != 0 {
		fmt.Fprintf(&b, "%d!", v.epoch)
	}

	for i, n := range v.release {
		if i > 0 {
			b.WriteByte('.')
		}
		b.WriteString(strconv.Itoa(n))
	}

	if v.hasPre {
		b.WriteString([...]string{"a", "b", "rc"}[v.preKind])
		b.WriteString(strconv.Itoa(v.preNum))
	}
	if v.hasPost {
		fmt.Fprintf(&b, ".post%d", v.postNum)
	}
	if v.hasDev {
		fmt.Fprintf(&b, ".dev%d", v.devNum)
	}

	if len(v.local) > 0 {
		b.WriteByte('+')
		for i, seg := range v.local {
			if i > 0 {
				b.WriteByte('.')
			}
			if seg.numeric {
				b.WriteString(strconv.Itoa(seg.num))
			} else {
				b.WriteString(seg.str)
			}
		}
	}

	return b.String()
}

// Compare returns -1, 0 or +1 as a sorts before, equal to, or after b.
func Compare(a, b Version) int {
	if c := cmpInt(a.epoch, b.epoch); c != 0 {
		return c
	}
	if c := compareRelease(a.release, b.release); c != 0 {
		return c
	}
	if c := comparePre(a, b); c != 0 {
		return c
	}
	// No post-release sorts before any post-release.
	if c := cmpPresence(a.hasPost, b.hasPost, a.postNum, b.postNum, false); c != 0 {
		return c
	}
	// A dev release sorts before the version it leads up to, so *having* dev
	// is the lesser state — the opposite of post.
	if c := cmpPresence(a.hasDev, b.hasDev, a.devNum, b.devNum, true); c != 0 {
		return c
	}
	return compareLocal(a.local, b.local)
}

// Less reports whether v sorts before other.
func (v Version) Less(other Version) bool { return Compare(v, other) < 0 }

// Equal reports whether two versions are the same release, ignoring how they
// were spelled: 1.0 and 1.0.0 are equal.
func (v Version) Equal(other Version) bool { return Compare(v, other) == 0 }

// compareRelease treats trailing zeros as insignificant, so 1.0 == 1.0.0, and
// pads the shorter side with zeros.
func compareRelease(a, b []int) int {
	a, b = trimTrailingZeros(a), trimTrailingZeros(b)
	for i := 0; i < len(a) || i < len(b); i++ {
		if c := cmpInt(at(a, i), at(b, i)); c != 0 {
			return c
		}
	}
	return 0
}

func trimTrailingZeros(xs []int) []int {
	end := len(xs)
	for end > 0 && xs[end-1] == 0 {
		end--
	}
	return xs[:end]
}

func at(xs []int, i int) int {
	if i < len(xs) {
		return xs[i]
	}
	return 0
}

// comparePre ranks the three states a version can be in relative to its own
// release: a dev release with no pre-release part comes first, then
// pre-releases, then the release itself (and any post-release of it).
func comparePre(a, b Version) int {
	ra, rb := preRank(a), preRank(b)
	if ra != rb {
		return cmpInt(ra, rb)
	}
	if ra != 0 { // neither side carries a pre-release part
		return 0
	}
	if c := cmpInt(a.preKind, b.preKind); c != 0 {
		return c
	}
	return cmpInt(a.preNum, b.preNum)
}

func preRank(v Version) int {
	switch {
	case !v.hasPre && !v.hasPost && v.hasDev:
		return -1 // 1.0.dev1 precedes 1.0a1
	case !v.hasPre:
		return 1 // 1.0 and 1.0.post1 follow every 1.0aN
	default:
		return 0
	}
}

// cmpPresence compares an optional numeric component. absentIsGreater says
// which way the missing case sorts: dev-absent is greater, post-absent is less.
func cmpPresence(aHas, bHas bool, aNum, bNum int, absentIsGreater bool) int {
	if aHas && bHas {
		return cmpInt(aNum, bNum)
	}
	if !aHas && !bHas {
		return 0
	}
	missingIsA := !aHas
	if missingIsA == absentIsGreater {
		return 1
	}
	return -1
}

// compareLocal implements PEP 440's local version ordering: no local version
// sorts before any local version, numeric segments outrank alphabetic ones, and
// otherwise segments compare pairwise with the longer list winning a tie.
func compareLocal(a, b []localSegment) int {
	if len(a) == 0 || len(b) == 0 {
		return cmpInt(len(a), len(b))
	}
	for i := 0; i < len(a) && i < len(b); i++ {
		x, y := a[i], b[i]
		switch {
		case x.numeric && y.numeric:
			if c := cmpInt(x.num, y.num); c != 0 {
				return c
			}
		case x.numeric != y.numeric:
			if x.numeric {
				return 1
			}
			return -1
		default:
			if c := strings.Compare(x.str, y.str); c != 0 {
				return c
			}
		}
	}
	return cmpInt(len(a), len(b))
}

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
