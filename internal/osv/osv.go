// Package osv reads OSV advisory records into pkgwatch's advisory shape.
//
// Only the fields pkgwatch actually uses are kept. The upstream raw JSON is
// deliberately discarded: it is the bulk of the corpus size, and the dashboard
// only ever shows a summary, a severity and a set of ranges.
package osv

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/myselfvivek17/pkgwatch/internal/cvss"
	"github.com/myselfvivek17/pkgwatch/internal/match"
)

// Record is the subset of the OSV schema we read.
// Reference: https://ossf.github.io/osv-schema/
type Record struct {
	ID        string     `json:"id"`
	Summary   string     `json:"summary"`
	Details   string     `json:"details"`
	Published *time.Time `json:"published"`
	Modified  *time.Time `json:"modified"`
	Withdrawn *time.Time `json:"withdrawn"`
	Aliases   []string   `json:"aliases"`

	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`

	Affected []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
			PURL      string `json:"purl"`
		} `json:"package"`

		Versions []string `json:"versions"`

		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced   string `json:"introduced"`
				Fixed        string `json:"fixed"`
				LastAffected string `json:"last_affected"`
				Limit        string `json:"limit"`
			} `json:"events"`
		} `json:"ranges"`

		DatabaseSpecific json.RawMessage `json:"database_specific"`
	} `json:"affected"`

	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
}

// Whether an ecosystem can be imported is decided by match's comparator
// registry: storing rows nothing can compare reads as "no advisories" rather
// than "cannot evaluate", which is the wrong way to be wrong.

// ParseRecord reads one OSV JSON document and returns one advisory per affected
// package — lookups are per (ecosystem, name), so splitting here keeps them a
// single indexed query.
func ParseRecord(data []byte) ([]match.Advisory, error) {
	var rec Record
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, fmt.Errorf("osv: parse record: %w", err)
	}
	if rec.ID == "" {
		return nil, fmt.Errorf("osv: record has no id")
	}
	return rec.Advisories(), nil
}

// Advisories converts a parsed record.
func (rec Record) Advisories() []match.Advisory {
	kind := match.KindVulnerability
	source := "osv"
	// OSV gives malware its own ID space. That prefix is the signal: a MAL-
	// record is an active attack, not a latent weakness, and the scorer floors
	// it at critical.
	if strings.HasPrefix(rec.ID, "MAL-") {
		kind = match.KindMalware
		source = "ossf-malicious-packages"
	}

	severity := rec.severityScore()
	summary := rec.Summary
	if summary == "" {
		summary = firstLine(rec.Details)
	}

	var out []match.Advisory
	for _, affected := range rec.Affected {
		// Keep the release qualifier ("Debian:12", "Alpine:v3.19"): the same
		// package has different fixed versions per release, so collapsing them
		// would match against the wrong distribution's bounds.
		ecosystem := affected.Package.Ecosystem
		if !match.Supported(ecosystem) {
			continue
		}

		adv := match.Advisory{
			ID:           rec.ID,
			Kind:         kind,
			Source:       source,
			Ecosystem:    ecosystem,
			PackageName:  affected.Package.Name,
			Summary:      summary,
			SeverityCVSS: severity,
			Withdrawn:    rec.Withdrawn != nil,
			Versions:     affected.Versions,
		}
		if rec.Published != nil {
			adv.Published = *rec.Published
		}
		if rec.Modified != nil {
			adv.Modified = *rec.Modified
		}

		for _, r := range affected.Ranges {
			// GIT ranges carry commit hashes, not versions. Keeping them would
			// feed unparseable strings to the version comparator.
			if r.Type != "SEMVER" && r.Type != "ECOSYSTEM" {
				continue
			}
			adv.Ranges = append(adv.Ranges, eventsToIntervals(r.Events)...)
		}

		// For a vulnerability, the enumerated version list is the expanded form
		// of the ranges, so storing both duplicates what the range already
		// says. Debian enumerates exhaustively across four releases: dropping
		// the redundant copies takes ~7M rows and 160MB out of a bundle every
		// agent downloads.
		//
		// Malware keeps its enumeration even when a range is present. A range
		// spanning a non-contiguous set would mark clean versions in the gap as
		// malicious, and "this package is malware" is the one verdict that must
		// never be reached by inference. Malware enumerations are small anyway.
		if len(adv.Ranges) > 0 && kind != match.KindMalware {
			adv.Versions = nil
		}

		out = append(out, adv)
	}
	return out
}

// eventsToIntervals folds OSV's event stream into closed intervals. Events are
// ordered: "introduced" opens an interval, "fixed" or "last_affected" closes
// it. An interval left open at the end is an unfixed advisory and is kept —
// dropping it would report a live vulnerability as harmless.
func eventsToIntervals(events []struct {
	Introduced   string `json:"introduced"`
	Fixed        string `json:"fixed"`
	LastAffected string `json:"last_affected"`
	Limit        string `json:"limit"`
}) []match.Range {
	var out []match.Range
	var current *match.Range

	for _, ev := range events {
		switch {
		case ev.Introduced != "":
			if current != nil {
				out = append(out, *current)
			}
			current = &match.Range{Introduced: ev.Introduced}

		case ev.Fixed != "":
			if current == nil {
				current = &match.Range{Introduced: "0"}
			}
			current.Fixed = ev.Fixed
			out = append(out, *current)
			current = nil

		case ev.LastAffected != "":
			if current == nil {
				current = &match.Range{Introduced: "0"}
			}
			current.LastAffected = ev.LastAffected
			out = append(out, *current)
			current = nil
		}
		// "limit" bounds the range for GIT types only; ignored here.
	}

	if current != nil {
		out = append(out, *current)
	}
	return out
}

// severityScore prefers a real CVSS vector and falls back to the qualitative
// rating. Returning nil means genuinely unscored, which the scorer treats as
// 5.0 rather than as harmless.
func (rec Record) severityScore() *float64 {
	for _, s := range rec.Severity {
		if !strings.HasPrefix(s.Type, "CVSS_V3") && !strings.HasPrefix(s.Type, "CVSS_V4") {
			continue
		}
		if score, err := cvss.BaseScore(s.Score); err == nil {
			return &score
		}
	}
	if score, ok := cvss.FromQualitative(rec.DatabaseSpecific.Severity); ok {
		return &score
	}
	return nil
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
	if len(line) > 300 {
		return line[:300]
	}
	return line
}
