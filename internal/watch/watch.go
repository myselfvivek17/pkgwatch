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

	// Rescored counts findings whose score or tier changed, because the policy
	// or the package's install context did.
	Rescored int

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
				State:      stateFor(report.Baseline, adv, score),
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

	// Findings already on file keep the score they were first given, so a
	// change in policy or in a package's context would otherwise never reach
	// them — and every machine that has ever scanned already has findings.
	if report.Rescored, err = store.RescoreFindings(findings); err != nil {
		return report, err
	}

	for _, finding := range findings {
		if finding.State == repo.StateAcknowledged {
			report.Acknowledged++
		}
	}

	closed, err := store.ResolveFindingsForGonePackages(now)
	if err != nil {
		return report, err
	}
	report.Resolved = len(closed)
	// After closing, reopen: a package can come back — a stopped container
	// started again, a package reinstalled — and RecordFindings above would have
	// silently absorbed it, since the finding row already exists in the fixed
	// state. Ordering matters only in that both run every pass.
	reopened, err := store.ReopenFindingsForPresentPackages()
	if err != nil {
		return report, err
	}
	report.Reopened = len(reopened)

	// Both transitions get a timeline row. Neither had one before, so a machine
	// whose findings dropped from 116 to 18 overnight showed the new number and
	// no account of where the other 98 went — and the reopen direction matters
	// more, because that is a vulnerability coming back into view during a pass
	// nobody was watching.
	recordChangeEvent(store, repo.EventFindingFixed, closed, now)
	recordChangeEvent(store, repo.EventFindingBack, reopened, now)

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

// recordChangeEvent posts one summary row for a batch of state changes.
//
// Deliberately one row per pass rather than one per finding. Stopping two
// containers retired 322 packages at once; 322 timeline rows saying the same
// thing would bury the day they landed on, and the design's timeline is meant
// to be read. The count and the per-tier breakdown are the facts worth having,
// and the findings page is where the individual rows already live.
//
// Filed under the worst tier present, so a critical returning gets the critical
// row treatment rather than being averaged away by fifty lows alongside it.
func recordChangeEvent(store repo.Agent, kind string, changes []repo.FindingChange, now time.Time) {
	if len(changes) == 0 {
		return
	}
	detail := map[string]any{"count": len(changes)}
	for tier, n := range repo.TierCounts(changes) {
		detail[tier] = n
	}
	if err := store.RecordEvent(kind, repo.WorstTier(changes), "", "", detail, now); err != nil {
		slog.Warn("watch: could not record finding change event", "kind", kind, "error", err)
	}
}

// stateFor decides whether a finding is announced or filed quietly.
//
// On a machine's first pass, quiet findings are recorded as already
// acknowledged. They are real, and they are also six-year-old dev dependencies
// that were never news — announcing several hundred of them at once is exactly
// how a person learns to ignore this tool's notifications.
//
// Deliberately keyed on the contextual score rather than the tier. Whether
// something is worth interrupting a person about is a triage question, and
// triage is exactly where install context belongs: a 7.2 in a dependency nobody
// has touched in eight months is not day-one news, while the same advisory in a
// globally installed package with lifecycle scripts is. The tier answers a
// different question — how bad the advisory is — and letting it drive
// announcements would have made a first scan noisier the moment tiers started
// following advisory severity instead of install context.
//
// Malware is never quietly filed regardless of score. A machine that has been
// carrying a compromised package since before pkgwatch was installed is the
// single most important thing a first run can tell you.
func stateFor(baseline bool, adv match.Advisory, score float64) string {
	if !baseline || adv.Kind == match.KindMalware {
		return repo.StateNew
	}
	if score >= announceAbove {
		return repo.StateNew
	}
	return repo.StateAcknowledged
}

// announceAbove is the score at or above which a finding is announced rather
// than filed quietly — the high threshold from §5.2, applied to the contextual
// score.
const announceAbove = repo.AnnounceAbove
