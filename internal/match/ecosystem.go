package match

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/Masterminds/semver/v3"

	"github.com/myselfvivek17/pkgwatch/internal/version/apk"
	"github.com/myselfvivek17/pkgwatch/internal/version/dpkg"
	"github.com/myselfvivek17/pkgwatch/internal/version/npmver"
	"github.com/myselfvivek17/pkgwatch/internal/version/pep440"
)

// Ecosystem identifiers, spelled as OSV spells them.
const (
	EcosystemNPM    = "npm"
	EcosystemPyPI   = "PyPI"
	EcosystemDebian = "Debian"
	EcosystemUbuntu = "Ubuntu"
	EcosystemAlpine = "Alpine"
	EcosystemGo     = "Go"
	EcosystemCrates = "crates.io"
)

// comparator returns -1, 0 or +1 comparing two version strings.
type comparator func(a, b string) (int, error)

// ops is everything an ecosystem needs: how to order its versions and how to
// fold its package names for lookup.
type ops struct {
	compare   comparator
	normalize func(string) string
}

// registry maps an ecosystem to its behaviour. Adding an ecosystem here is the
// only thing needed to start matching it — and an ecosystem absent from this
// map is refused loudly rather than guessed at, because a confident wrong
// answer about whether you are exposed is worse than "cannot evaluate".
var registry = map[string]ops{
	EcosystemNPM: {
		// npm names are case-sensitive; folding them would match a different
		// package than the one installed.
		compare: comparatorFrom(npmver.Parse, npmver.Compare),
	},
	EcosystemPyPI: {
		compare:   comparatorFrom(pep440.Parse, pep440.Compare),
		normalize: normalizePEP503,
	},
	EcosystemDebian: {
		compare:   comparatorFrom(dpkg.Parse, dpkg.Compare),
		normalize: strings.ToLower,
	},
	EcosystemUbuntu: {
		compare:   comparatorFrom(dpkg.Parse, dpkg.Compare),
		normalize: strings.ToLower,
	},
	EcosystemAlpine: {
		compare:   comparatorFrom(apk.Parse, apk.Compare),
		normalize: strings.ToLower,
	},
	EcosystemGo: {
		compare: compareGo,
		// Module paths are case-sensitive, and the case-encoding rules for the
		// module cache do not apply to advisory lookups.
	},
	EcosystemCrates: {
		compare: compareSemver,
		// crates.io treats - and _ as distinct but reserves both spellings, so
		// folding is safe and catches advisories filed under either.
		normalize: func(s string) string { return strings.ReplaceAll(strings.ToLower(s), "_", "-") },
	},
}

// comparatorFrom adapts a package's Parse/Compare pair into a comparator.
func comparatorFrom[V any](parse func(string) (V, error), compare func(V, V) int) comparator {
	return func(a, b string) (int, error) {
		av, err := parse(a)
		if err != nil {
			return 0, err
		}
		bv, err := parse(b)
		if err != nil {
			return 0, err
		}
		return compare(av, bv), nil
	}
}

// compareSemver handles ecosystems that use plain semver.
func compareSemver(a, b string) (int, error) {
	av, err := semver.NewVersion(strings.TrimSpace(a))
	if err != nil {
		return 0, fmt.Errorf("semver: %q: %w", a, err)
	}
	bv, err := semver.NewVersion(strings.TrimSpace(b))
	if err != nil {
		return 0, fmt.Errorf("semver: %q: %w", b, err)
	}
	return av.Compare(bv), nil
}

// compareGo strips the leading "v" every Go version carries and the
// "+incompatible" marker the module system appends to pre-modules majors,
// neither of which affects ordering.
func compareGo(a, b string) (int, error) {
	return compareSemver(cleanGoVersion(a), cleanGoVersion(b))
}

func cleanGoVersion(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "v")
	return strings.TrimSuffix(s, "+incompatible")
}

// pep503Separators collapses the runs PEP 503 treats as equivalent.
var pep503Separators = regexp.MustCompile(`[-_.]+`)

func normalizePEP503(name string) string {
	return pep503Separators.ReplaceAllString(strings.ToLower(name), "-")
}

// BaseEcosystem strips the release qualifier OSV appends to distribution
// ecosystems — "Debian:12", "Alpine:v3.19", "Ubuntu:22.04:LTS".
//
// The qualifier is kept everywhere else: a Debian 11 advisory and a Debian 12
// advisory for the same package carry different fixed versions, so collapsing
// them would match against the wrong distribution's bounds. Only the choice of
// comparator and name folding is release-independent.
func BaseEcosystem(ecosystem string) string {
	base, _, _ := strings.Cut(ecosystem, ":")
	return base
}

// Supported reports whether pkgwatch can evaluate versions in this ecosystem.
func Supported(ecosystem string) bool {
	_, ok := registry[BaseEcosystem(ecosystem)]
	return ok
}

// SupportedEcosystems lists what can be matched, for error messages and docs.
func SupportedEcosystems() []string {
	out := make([]string, 0, len(registry))
	for name := range registry {
		out = append(out, name)
	}
	return out
}

// NormalizeName folds a package name to the form used for lookups.
func NormalizeName(ecosystem, name string) string {
	if op, ok := registry[BaseEcosystem(ecosystem)]; ok && op.normalize != nil {
		return op.normalize(name)
	}
	return name
}

func comparatorFor(ecosystem string) (comparator, error) {
	op, ok := registry[BaseEcosystem(ecosystem)]
	if !ok {
		return nil, fmt.Errorf("match: no version comparator for ecosystem %q", ecosystem)
	}
	return op.compare, nil
}
