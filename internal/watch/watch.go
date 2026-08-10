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
	"sort"
	"time"

	"github.com/myselfvivek17/pkgwatch/internal/match"
	"github.com/myselfvivek17/pkgwatch/internal/repo"
)

// Report is what one pass found.
type Report struct {
	Examined int
	New      int
	Resolved int

	// Reopened counts findings that had been closed and are open again because
	// the package is installed once more.
	Reopened int

	// Unignored counts findings whose ignore window expired on this pass.
	Unignored int

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
			//
			// Named in full, not collapsed to the base. Coverage is per release:
			// a bundle can carry Ubuntu:24.04:LTS and not Ubuntu:22.04:LTS, and
			// saying "no advisories for Ubuntu" while 1,830 Ubuntu packages were
			// just examined is false in the direction that gets ignored.
			uncovered[pkg.Ecosystem] = true
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
	sort.Strings(report.Uncovered)

	added, err := store.RecordFindings(findings, now)
	if err != nil {
		return report, err
	}
	report.New = added

	// A timeline row per announced finding, and none for the quiet ones. The
	// state was already decided above by stateFor, so reusing it keeps the
	// timeline and the notification telling the same story — a baseline pass
	// that files 900 findings quietly must not then post 900 timeline rows.
	recordFindingEvents(store, findings, now)

	for _, finding := range findings {
		if finding.State == repo.StateAcknowledged {
			report.Acknowledged++
		}
	}

	if report.Resolved, err = store.ResolveFindingsForGonePackages(now); err != nil {
		return report, err
	}
	// After closing, reopen: a package can come back — a stopped container
	// started again, a package reinstalled — and RecordFindings above would have
	// silently absorbed it, since the finding row already exists in the fixed
	// state. Ordering matters only in that both run every pass.
	if report.Reopened, err = store.ReopenFindingsForPresentPackages(); err != nil {
		return report, err
	}

	// An ignore with an expiry that nothing enforces is a permanent ignore with
	// extra steps. This runs on every pass so "hide it for a week" comes back
	// after a week without anyone having to remember.
	if report.Unignored, err = store.ExpireIgnores(now); err != nil {
		return report, err
	}
	return report, nil
}

// recordFindingEvents posts one timeline row per announced finding.
//
// Only findings RecordFindings actually inserted deserve a row, but it reports
// a count rather than which ones — so this re-reads state from the finding it
// just tried to record. A duplicate insert leaves the stored state alone, and
// the event would be a second announcement of old news; checking the row's
// detected_at against this pass is what tells them apart.
//
// Event recording never fails the pass. The finding is already stored, and
// losing a timeline row is not worth discarding a scan over.
func recordFindingEvents(store repo.Agent, findings []repo.Finding, now time.Time) {
	for _, finding := range findings {
		if finding.State != repo.StateNew {
			continue
		}
		// Compared in whole seconds: detected_at is stored as a Unix timestamp,
		// so an equality test against a time.Time carrying nanoseconds would
		// never match and no finding would ever get a timeline row.
		fresh, err := store.FindingFirstSeen(finding.PURL, finding.AdvisoryID)
		if err != nil || fresh.Unix() != now.Unix() {
			continue
		}
		if err := store.RecordEvent(repo.EventFindingNew, finding.Tier,
			finding.PURL, finding.AdvisoryID, map[string]any{
				"score": finding.Score,
			}, now); err != nil {
			slog.Warn("watch: could not record finding event", "purl", finding.PURL, "error", err)
		}
	}
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
