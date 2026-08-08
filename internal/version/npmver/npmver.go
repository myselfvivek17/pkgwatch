// Package npmver parses and orders npm registry versions.
//
// A thin layer over Masterminds/semver that pins the two behaviours advisory
// matching depends on: registry versions must be strict semver, and a
// prerelease must sort below its own release so 1.0.0-beta.1 never falls inside
// a range introduced at 1.0.0.
package npmver

import (
	"fmt"
	"strings"

	"github.com/Masterminds/semver/v3"
)

// Version is a parsed npm version.
type Version struct {
	v *semver.Version
	// raw keeps the string as published so the UI can echo exactly what npm
	// installed, build metadata and all.
	raw string
}

// Parse reads a strict semver version. A leading "v" and surrounding
// whitespace are tolerated because tags and lockfiles carry them; partial
// versions like "1.0" are rejected, since accepting them would silently invent
// a patch number and shift an advisory bound.
func Parse(s string) (Version, error) {
	trimmed := strings.TrimSpace(s)
	trimmed = strings.TrimPrefix(trimmed, "v")
	if trimmed == "" {
		return Version{}, fmt.Errorf("npmver: empty version")
	}

	v, err := semver.StrictNewVersion(trimmed)
	if err != nil {
		return Version{}, fmt.Errorf("npmver: %q is not a valid version: %w", s, err)
	}
	return Version{v: v, raw: trimmed}, nil
}

// String returns the version as published.
func (v Version) String() string { return v.raw }

// IsPrerelease reports whether this version carries a prerelease identifier.
// Build metadata alone does not make a prerelease.
func (v Version) IsPrerelease() bool { return v.v != nil && v.v.Prerelease() != "" }

// Compare returns -1, 0 or +1 as a sorts before, equal to, or after b.
// Build metadata is not part of precedence, so 1.0.0+a and 1.0.0+b are equal.
func Compare(a, b Version) int { return a.v.Compare(b.v) }

// Less reports whether v sorts before other.
func (v Version) Less(other Version) bool { return Compare(v, other) < 0 }

// Equal reports whether two versions have the same precedence.
func (v Version) Equal(other Version) bool { return Compare(v, other) == 0 }
