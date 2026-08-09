// Package watch matches the installed inventory against the advisory bundle.
//
// This is the retroactive half of pkgwatch. The gate protects you at the moment
// you install something; the watcher answers the other question — the package
// you installed six months ago that only became known-bad this morning. It runs
// after every scan and after every bundle sync, because those are the two
// events that can change the answer.
package watch

import (
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	"github.com/myselfvivek17/pkgwatch/internal/match"
	"github.com/myselfvivek17/pkgwatch/internal/repo"
)

// Report is what one pass found.
type Report struct {
	Examined int
	New      int
	Resolved int

	// Baseline is set on the first pass a machine ever runs. Pre-existing
	// low and medium findings are recorded acknowledged rather than announced.
	Baseline     bool
	Acknowledged int

	// Uncovered names ecosystems the inventory contains and the bundle does not.
	// Those packages were not evaluated, which is not the same as finding
	// nothing wrong with them.
	Uncovered []string

	// Unevaluated counts packages whose version no comparator could read.
	Unevaluated int
}

// Run matches every installed package against the bundle and records findings.
//
// bundle describes what the attached advisory database actually covers, so an
// ecosystem it does not carry is reported as unexamined rather than clean.
func Run(handle *sql.DB, store repo.Agent, bundle repo.BundleInfo, now time.Time) (Report, error) {
	var report Report

	if !bundle.Attached {
		return report, fmt.Errorf("no advisory bundle installed — nothing can be matched; run `pkgwatch sync`")
	}

	packages, err := store.PresentPackages()
	if err != nil {
		return report, err
	}

	known, err := store.HasFindings()
	if err != nil {
		return report, err
	}
	report.Baseline = !known

	uncovered := map[string]bool{}
	var findings []repo.Finding

	for _, pkg := range packages {
		if len(bundle.Ecosystems) > 0 && !bundle.Covers(pkg.Ecosystem) {
			// Zero rows and "we never looked" are the same query result and
			// opposite answers. Count it, do not score it.
			uncovered[match.BaseEcosystem(pkg.Ecosystem)] = true
			continue
		}
		report.Examined++

		advisories, err := repo.LookupAdvisories(handle, pkg.Ecosystem, pkg.Name)
		if err != nil {
			return report, fmt.Errorf("look up %s: %w", pkg.Name, err)
		}

		for _, adv := range advisories {
			affected, err := match.Affects(adv, pkg)
			if err != nil {
				// One version this build cannot parse is a gap in coverage, not
				// a clean result. Say so and carry on.
				slog.Debug("watch: could not evaluate advisory",
					"advisory", adv.ID, "package", pkg.Name, "error", err)
				report.Unevaluated++
				continue
			}
			if !affected {
				continue
			}

			score, tier := match.Score(adv, pkg, now)
			findings = append(findings, repo.Finding{
				PURL:       match.PURL(pkg.Ecosystem, pkg.Name, pkg.Version),
				AdvisoryID: adv.ID,
				Score:      score,
				Tier:       tier,
				State:      stateFor(report.Baseline, adv, tier),
			})
		}
	}

	for ecosystem := range uncovered {
		report.Uncovered = append(report.Uncovered, ecosystem)
	}

	added, err := store.RecordFindings(findings, now)
	if err != nil {
		return report, err
	}
	report.New = added

	for _, finding := range findings {
		if finding.State == repo.StateAcknowledged {
			report.Acknowledged++
		}
	}

	if report.Resolved, err = store.ResolveFindingsForGonePackages(now); err != nil {
		return report, err
	}
	return report, nil
}

// stateFor decides whether a finding is announced or filed quietly.
//
// On a machine's first pass, low and medium findings are recorded as already
// acknowledged. They are real, and they are also six-year-old dev dependencies
// that were never news — announcing several hundred of them at once is exactly
// how a person learns to ignore this tool's notifications.
//
// Critical and high are always announced, baseline or not, and malware is never
// quietly filed regardless of what it scored. A machine that has been carrying
// a compromised package since before pkgwatch was installed is the single most
// important thing a first run can tell you.
func stateFor(baseline bool, adv match.Advisory, tier string) string {
	if !baseline || adv.Kind == match.KindMalware {
		return repo.StateNew
	}
	switch tier {
	case match.TierCritical, match.TierHigh:
		return repo.StateNew
	default:
		return repo.StateAcknowledged
	}
}
