// Package match decides whether an installed package is affected by an
// advisory, and how much that should worry you.
package match

import (
	"time"
)

// Advisory kinds. Malware and vulnerabilities are different products: one is
// an active attack, the other is a latent weakness.
const (
	KindVulnerability = "vulnerability"
	KindMalware       = "malware"
)

// Package scopes.
const (
	ScopeGlobal    = "global"
	ScopeProject   = "project"
	ScopeVenv      = "venv"
	ScopeSystem    = "system"
	ScopeContainer = "container"
)

// Finding tiers, most severe first.
const (
	TierCritical = "critical"
	TierHigh     = "high"
	TierMedium   = "medium"
	TierLow      = "low"
)

// staleAfter is how long a project dependency can go unseen before its score is
// discounted — an old lockfile in a directory you have not touched in months is
// not the same risk as something on your PATH.
const staleAfter = 90 * 24 * time.Hour

// Range is one affected interval. Introduced is inclusive, Fixed is exclusive,
// LastAffected is inclusive. Empty fields are unbounded on that side.
type Range struct {
	Introduced   string
	Fixed        string
	LastAffected string
}

// Advisory is the subset of an OSV record pkgwatch needs. The upstream
// raw_json is deliberately absent: it is the bulk of the corpus size and
// nothing reads it.
type Advisory struct {
	ID           string
	Kind         string
	Ecosystem    string
	PackageName  string
	Summary      string
	SeverityCVSS *float64 // nil when upstream gave no score
	Withdrawn    bool
	Versions     []string // exact hits — the fast path
	Ranges       []Range

	Source    string // osv | ossf-malicious-packages
	Published time.Time
	Modified  time.Time
}

// Package is an installed package as the inventory sees it.
type Package struct {
	Ecosystem  string
	Name       string
	Version    string
	Scope      string
	HasScripts bool
	LastSeen   time.Time
}

// Affects reports whether pkg falls inside adv.
//
// Exact versions are checked first: every malware record names specific
// versions, and a string comparison beats parsing. Ranges are evaluated only if
// no exact version hits.
func Affects(adv Advisory, pkg Package) (bool, error) {
	// A withdrawn advisory was retracted upstream. It must never fire.
	if adv.Withdrawn {
		return false, nil
	}

	cmp, err := comparatorFor(adv.Ecosystem)
	if err != nil {
		return false, err
	}

	for _, v := range adv.Versions {
		if v == pkg.Version {
			return true, nil
		}
		// Fall back to a semantic comparison so 1.0 and 1.0.0 still match.
		if eq, err := cmp(pkg.Version, v); err == nil && eq == 0 {
			return true, nil
		}
	}

	// One unparseable bound must not discard the whole advisory. Real feeds carry
	// them: PYSEC records for requests give an introduced bound of "2.23.0-py2.7",
	// which is not a PEP 440 version, and abandoning the record on the first
	// error silently dropped every other interval in it — a false negative
	// several times larger than the one bad bound deserves.
	//
	// The error is still returned when nothing matched, so the caller can say
	// coverage was incomplete rather than report a clean result.
	var firstErr error
	for _, r := range adv.Ranges {
		in, err := inRange(cmp, pkg.Version, r)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if in {
			return true, nil
		}
	}
	return false, firstErr
}

// inRange evaluates one interval: introduced <= v, and v < fixed, and
// v <= last_affected, for whichever bounds are present.
func inRange(cmp comparator, version string, r Range) (bool, error) {
	// OSV writes "0" for "affected since the beginning of time". It is not a
	// parseable version in every ecosystem, so treat it as unbounded.
	if r.Introduced != "" && r.Introduced != "0" {
		c, err := cmp(version, r.Introduced)
		if err != nil {
			return false, err
		}
		if c < 0 {
			return false, nil
		}
	}

	if r.Fixed != "" {
		c, err := cmp(version, r.Fixed)
		if err != nil {
			return false, err
		}
		if c >= 0 {
			return false, nil
		}
	}

	if r.LastAffected != "" {
		c, err := cmp(version, r.LastAffected)
		if err != nil {
			return false, err
		}
		if c > 0 {
			return false, nil
		}
	}

	// An interval with no bounds at all still means "affected" — that is how an
	// unfixed advisory covering every version is expressed.
	return true, nil
}

// Score rates a finding, and returns the tier it lands in.
func Score(adv Advisory, pkg Package, now time.Time) (float64, string) {
	score := 5.0 // no upstream score is not the same as harmless
	if adv.SeverityCVSS != nil {
		score = *adv.SeverityCVSS
	}

	if adv.Kind == KindMalware {
		score *= 4.0
	}
	if pkg.Scope == ScopeGlobal {
		score *= 1.5
	}
	if pkg.HasScripts {
		score *= 1.5
	}
	if pkg.Scope == ScopeProject && now.Sub(pkg.LastSeen) > staleAfter {
		score *= 0.4
	}

	return score, tierFor(adv, score)
}

// tierFor floors malware at critical regardless of score. Active malware and a
// latent CVE must not share a scale.
func tierFor(adv Advisory, score float64) string {
	switch {
	case adv.Kind == KindMalware, score >= 9:
		return TierCritical
	case score >= 7:
		return TierHigh
	case score >= 4:
		return TierMedium
	default:
		return TierLow
	}
}
