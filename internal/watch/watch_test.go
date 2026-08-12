package watch_test

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/myselfvivek17/pkgwatch/internal/bundle"
	"github.com/myselfvivek17/pkgwatch/internal/db"
	"github.com/myselfvivek17/pkgwatch/internal/match"
	"github.com/myselfvivek17/pkgwatch/internal/osv"
	"github.com/myselfvivek17/pkgwatch/internal/repo"
	"github.com/myselfvivek17/pkgwatch/internal/watch"
)

// newWatched builds an agent database with the real OSV fixtures attached:
// a high-severity lodash CVE and the @ctrl/tinycolor malware record.
func newWatched(t *testing.T) (*sql.DB, repo.Agent, repo.BundleInfo) {
	t.Helper()

	var advisories []match.Advisory
	for _, name := range []string{"GHSA-35jh-r3h4-6jhm", "MAL-2025-47141"} {
		raw, err := os.ReadFile(filepath.Join("..", "osv", "testdata", name+".json"))
		if err != nil {
			t.Fatalf("read fixture: %v", err)
		}
		parsed, err := osv.ParseRecord(raw)
		if err != nil {
			t.Fatalf("parse fixture: %v", err)
		}
		advisories = append(advisories, parsed...)
	}

	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "advisories.db")
	if _, err := bundle.Build(bundlePath, "20260808", bundle.ScopeAll, advisories, time.Now()); err != nil {
		t.Fatalf("build bundle: %v", err)
	}

	handle, err := db.Open(filepath.Join(dir, "agent.db"), db.SchemaAgent)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { handle.Close() })

	attached, err := db.AttachAdvisories(handle, bundlePath)
	if err != nil || !attached {
		t.Fatalf("attach: %v", err)
	}
	info, err := repo.Bundle(handle, true)
	if err != nil {
		t.Fatal(err)
	}
	return handle, repo.Agent{DB: handle}, info
}

func installed(store repo.Agent, t *testing.T, rows ...repo.PackageRow) {
	t.Helper()
	if _, _, err := store.UpsertPackages(rows, time.Now()); err != nil {
		t.Fatal(err)
	}
}

func pkgRow(purl, ecosystem, name, version, scope string) repo.PackageRow {
	return repo.PackageRow{
		PURL: purl, Ecosystem: ecosystem, Name: name, Version: version,
		Scope: scope, InstallDir: "/app/node_modules/" + name,
	}
}

// The retroactive case: a package installed long before anyone knew it was bad.
func TestWatchFindsAffectedInstalledPackage(t *testing.T) {
	handle, store, info := newWatched(t)
	installed(store, t,
		pkgRow("pkg:npm/lodash@4.17.20", "npm", "lodash", "4.17.20", match.ScopeProject),
		pkgRow("pkg:npm/lodash@4.17.21", "npm", "lodash", "4.17.21", match.ScopeProject))

	report, err := watch.Run(handle, store, info, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if report.Examined != 2 {
		t.Errorf("Examined = %d, want 2", report.Examined)
	}
	if report.New != 1 {
		t.Fatalf("New = %d, want 1 — only 4.17.20 is affected", report.New)
	}

	findings, err := store.OpenFindings(true, repo.FindingFilter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].PURL != "pkg:npm/lodash@4.17.20" {
		t.Fatalf("findings = %+v", findings)
	}
	if findings[0].AdvisoryID != "GHSA-35jh-r3h4-6jhm" {
		t.Errorf("AdvisoryID = %q", findings[0].AdvisoryID)
	}
}

// The watcher runs after every scan and every sync. A finding that re-notified
// on each pass would train the user to ignore it.
func TestWatchIsIdempotent(t *testing.T) {
	handle, store, info := newWatched(t)
	installed(store, t, pkgRow("pkg:npm/lodash@4.17.20", "npm", "lodash", "4.17.20", match.ScopeProject))

	first, err := watch.Run(handle, store, info, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	second, err := watch.Run(handle, store, info, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	if first.New != 1 {
		t.Fatalf("first pass New = %d, want 1", first.New)
	}
	if second.New != 0 {
		t.Errorf("second pass New = %d, want 0 — alert once", second.New)
	}
}

// Day one on an existing machine is hundreds of findings about years-old
// dependencies. Announcing all of them is how notifications get switched off.
func TestBaselineFilesLowAndMediumQuietly(t *testing.T) {
	handle, store, info := newWatched(t)

	// A project-scope install with no scripts scores 7.2 → high, so drop it
	// below the threshold using the staleness discount: a project dependency
	// untouched for months is not the same risk (§5.2).
	stale := repo.PackageRow{
		PURL: "pkg:npm/lodash@4.17.20", Ecosystem: "npm", Name: "lodash",
		Version: "4.17.20", Scope: match.ScopeProject, InstallDir: "/old/lodash",
	}
	installed(store, t, stale)
	if _, err := store.DB.Exec(
		"UPDATE packages SET last_seen = ? WHERE purl = ?",
		time.Now().Add(-200*24*time.Hour).Unix(), stale.PURL); err != nil {
		t.Fatal(err)
	}

	report, err := watch.Run(handle, store, info, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !report.Baseline {
		t.Fatal("a machine with no findings on file is a baseline run")
	}
	if report.Acknowledged != 1 {
		t.Fatalf("Acknowledged = %d, want the stale medium finding filed quietly", report.Acknowledged)
	}

	// Filed, not hidden: it must still be listed.
	open, err := store.OpenFindings(true, repo.FindingFilter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(open) != 1 || open[0].State != repo.StateAcknowledged {
		t.Errorf("findings = %+v, want one acknowledged", open)
	}
}

// Malware is never filed quietly. A machine that has been carrying a
// compromised package since before pkgwatch was installed is the single most
// important thing a first run can say.
func TestBaselineStillAnnouncesMalware(t *testing.T) {
	handle, store, info := newWatched(t)
	installed(store, t, pkgRow("pkg:npm/%40ctrl/tinycolor@4.1.2", "npm",
		"@ctrl/tinycolor", "4.1.2", match.ScopeProject))

	report, err := watch.Run(handle, store, info, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !report.Baseline {
		t.Fatal("expected a baseline run")
	}
	if report.Acknowledged != 0 {
		t.Errorf("malware was filed quietly on the baseline pass")
	}

	open, err := store.OpenFindings(true, repo.FindingFilter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(open) != 1 || open[0].State != repo.StateNew {
		t.Fatalf("findings = %+v, want one announced", open)
	}
	if open[0].Tier != match.TierCritical {
		t.Errorf("Tier = %q, want critical", open[0].Tier)
	}
}

// Uninstalling is a fix. Leaving the finding open keeps a machine looking dirty
// for something it no longer has.
func TestUninstallClosesFinding(t *testing.T) {
	handle, store, info := newWatched(t)
	installed(store, t, pkgRow("pkg:npm/lodash@4.17.20", "npm", "lodash", "4.17.20", match.ScopeProject))

	if _, err := watch.Run(handle, store, info, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkGone([]string{"pkg:npm/lodash@4.17.20"}, time.Now()); err != nil {
		t.Fatal(err)
	}

	report, err := watch.Run(handle, store, info, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if report.Resolved != 1 {
		t.Errorf("Resolved = %d, want 1", report.Resolved)
	}
	open, err := store.OpenFindings(true, repo.FindingFilter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(open) != 0 {
		t.Errorf("findings still open for an uninstalled package: %+v", open)
	}
}

// --fixable has to filter before the limit, not after. Malware outscores the
// lodash CVE and sorts above it, so a post-limit filter over the worst N would
// return nothing here — the one finding that can actually be acted on, hidden
// behind a higher-scoring one that cannot.
func TestFixableFiltersBeforeTheLimit(t *testing.T) {
	handle, store, info := newWatched(t)
	installed(store, t,
		pkgRow("pkg:npm/%40ctrl/tinycolor@4.1.2", "npm", "@ctrl/tinycolor", "4.1.2", match.ScopeProject),
		pkgRow("pkg:npm/lodash@4.17.20", "npm", "lodash", "4.17.20", match.ScopeProject))

	if _, err := watch.Run(handle, store, info, time.Now()); err != nil {
		t.Fatal(err)
	}

	worst, err := store.OpenFindings(true, repo.FindingFilter{Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(worst) != 1 || worst[0].PURL != "pkg:npm/%40ctrl/tinycolor@4.1.2" {
		t.Fatalf("expected malware to sort first, got %+v", worst)
	}

	fixable, err := store.OpenFindings(true, repo.FindingFilter{Limit: 1, FixableOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(fixable) != 1 || fixable[0].PURL != "pkg:npm/lodash@4.17.20" {
		t.Fatalf("fixable = %+v, want the lodash finding", fixable)
	}
	if fixable[0].FixedIn != "4.17.21" {
		t.Errorf("FixedIn = %q, want 4.17.21", fixable[0].FixedIn)
	}
}

// An ecosystem the bundle does not carry returns zero rows for every lookup,
// which is the same query result as "nothing wrong".
func TestUncoveredEcosystemIsReportedNotScored(t *testing.T) {
	handle, store, info := newWatched(t)
	installed(store, t,
		pkgRow("pkg:npm/lodash@4.17.20", "npm", "lodash", "4.17.20", match.ScopeProject),
		pkgRow("pkg:pypi/requests@2.19.1", "PyPI", "requests", "2.19.1", match.ScopeSystem))

	report, err := watch.Run(handle, store, info, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if report.Examined != 1 {
		t.Errorf("Examined = %d, want only the npm package", report.Examined)
	}
	if len(report.Uncovered) != 1 || report.Uncovered[0] != match.EcosystemPyPI {
		t.Errorf("Uncovered = %v, want PyPI named as unexamined", report.Uncovered)
	}
}

func TestWatchWithoutBundleIsAnError(t *testing.T) {
	handle, store, _ := newWatched(t)
	if _, err := watch.Run(handle, store, repo.BundleInfo{}, time.Now()); err == nil {
		t.Error("matching with no bundle must fail loudly, not report a clean machine")
	}
}

// Closing a finding must not be permanent. RecordFindings is INSERT OR IGNORE,
// so a row left in the fixed state absorbs every later attempt to record the
// same finding — a package that comes back would never be reported again. Two
// stopped containers hid 322 findings this way.
func TestReturningPackageReopensFinding(t *testing.T) {
	handle, store, info := newWatched(t)
	lodash := pkgRow("pkg:npm/lodash@4.17.20", "npm", "lodash", "4.17.20", match.ScopeProject)
	installed(store, t, lodash)

	if _, err := watch.Run(handle, store, info, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkGone([]string{lodash.PURL}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := watch.Run(handle, store, info, time.Now()); err != nil {
		t.Fatal(err)
	}

	// The package is seen again — a stopped container started, or a reinstall.
	installed(store, t, lodash)
	report, err := watch.Run(handle, store, info, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if report.New != 0 {
		t.Errorf("New = %d — the finding row already exists, it is reopened not re-added", report.New)
	}
	if report.Reopened != 1 {
		t.Errorf("Reopened = %d, want 1", report.Reopened)
	}

	open, err := store.OpenFindings(true, repo.FindingFilter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(open) != 1 || open[0].PURL != lodash.PURL {
		t.Fatalf("findings = %+v, want the lodash finding open again", open)
	}
	if open[0].State != repo.StateNew {
		t.Errorf("State = %q, want new — it is news again", open[0].State)
	}
}

// Closing and reopening happen during an unattended pass, so the timeline is
// the only place either is ever visible. Without a row, a machine whose
// findings dropped overnight shows the new number and no account of the change.
func TestCloseAndReopenReachTheTimeline(t *testing.T) {
	handle, store, info := newWatched(t)
	lodash := pkgRow("pkg:npm/lodash@4.17.20", "npm", "lodash", "4.17.20", match.ScopeProject)
	installed(store, t, lodash)

	if _, err := watch.Run(handle, store, info, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkGone([]string{lodash.PURL}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := watch.Run(handle, store, info, time.Now()); err != nil {
		t.Fatal(err)
	}
	installed(store, t, lodash)
	if _, err := watch.Run(handle, store, info, time.Now()); err != nil {
		t.Fatal(err)
	}

	events, err := store.Events(repo.EventFilter{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]repo.Event{}
	for _, e := range events {
		kinds[e.Kind] = e
	}

	fixed, ok := kinds[repo.EventFindingFixed]
	if !ok {
		t.Fatal("no finding_fixed event — the close left no trace on the timeline")
	}
	if fixed.Detail["count"] != "1" {
		t.Errorf("fixed count = %q, want 1", fixed.Detail["count"])
	}

	back, ok := kinds[repo.EventFindingBack]
	if !ok {
		t.Fatal("no finding_reopened event — a vulnerability came back in silence")
	}
	// Filed under the tier of what actually returned, so a critical coming back
	// gets the critical row treatment rather than a neutral one.
	if back.Severity != "high" {
		t.Errorf("reopened severity = %q, want high (the lodash advisory's tier)", back.Severity)
	}
	if back.Routine() {
		t.Error("a returning vulnerability must not render as routine machinery")
	}
}

// An ignored finding was a decision about the package, not about whether it
// happened to be installed that week.
func TestReopenLeavesIgnoredAlone(t *testing.T) {
	handle, store, info := newWatched(t)
	lodash := pkgRow("pkg:npm/lodash@4.17.20", "npm", "lodash", "4.17.20", match.ScopeProject)
	installed(store, t, lodash)
	if _, err := watch.Run(handle, store, info, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := handle.Exec("UPDATE findings SET state = ?", repo.StateIgnored); err != nil {
		t.Fatal(err)
	}

	report, err := watch.Run(handle, store, info, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if report.Reopened != 0 {
		t.Errorf("Reopened = %d, want 0 — ignored stays ignored", report.Reopened)
	}
}

// Reopening must not promote a finding that was deliberately filed quietly.
// Otherwise stopping and starting a container turns every low and medium
// finding it holds into an announcement — the "hundreds of alerts at once"
// failure that baseline mode exists to prevent, arriving by a side door.
func TestReopenKeepsQuietFindingsQuiet(t *testing.T) {
	handle, store, info := newWatched(t)
	stale := repo.PackageRow{
		PURL: "pkg:npm/lodash@4.17.20", Ecosystem: "npm", Name: "lodash",
		Version: "4.17.20", Scope: match.ScopeProject, InstallDir: "/old/lodash",
	}
	installed(store, t, stale)
	// Stale enough to score medium, so the baseline pass files it acknowledged.
	if _, err := store.DB.Exec("UPDATE packages SET last_seen = ? WHERE purl = ?",
		time.Now().Add(-200*24*time.Hour).Unix(), stale.PURL); err != nil {
		t.Fatal(err)
	}

	report, err := watch.Run(handle, store, info, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if report.Acknowledged != 1 {
		t.Fatalf("Acknowledged = %d, want the medium finding filed quietly", report.Acknowledged)
	}

	// Gone, then back — a stopped container starting again.
	if err := store.MarkGone([]string{stale.PURL}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := watch.Run(handle, store, info, time.Now()); err != nil {
		t.Fatal(err)
	}
	installed(store, t, stale)
	// Re-recording a package moves last_seen forward, which would make it no
	// longer stale and legitimately rescore it upward. Keep it stale, since the
	// case under test is a container coming back, not a dependency being
	// actively used again.
	if _, err := store.DB.Exec("UPDATE packages SET last_seen = ? WHERE purl = ?",
		time.Now().Add(-200*24*time.Hour).Unix(), stale.PURL); err != nil {
		t.Fatal(err)
	}
	if _, err := watch.Run(handle, store, info, time.Now()); err != nil {
		t.Fatal(err)
	}

	open, err := store.OpenFindings(true, repo.FindingFilter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(open) != 1 {
		t.Fatalf("findings = %+v, want one", open)
	}
	if open[0].State != repo.StateAcknowledged {
		t.Errorf("State = %q, want acknowledged — a restart is not news", open[0].State)
	}
}

// Reopening runs on every pass. If it flapped, the same findings would reopen
// forever and notify every six hours.
func TestReopenIsIdempotent(t *testing.T) {
	handle, store, info := newWatched(t)
	lodash := pkgRow("pkg:npm/lodash@4.17.20", "npm", "lodash", "4.17.20", match.ScopeProject)
	installed(store, t, lodash)

	for i := 0; i < 3; i++ {
		report, err := watch.Run(handle, store, info, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if report.Reopened != 0 {
			t.Fatalf("pass %d reopened %d — nothing was ever closed", i, report.Reopened)
		}
	}
}

// A finding's score and tier are written once, by INSERT OR IGNORE. If nothing
// updates them, changing the tier policy does nothing on any machine that has
// ever scanned — which is every machine that matters.
func TestPolicyChangeReachesExistingFindings(t *testing.T) {
	handle, store, info := newWatched(t)
	// Global scope with lifecycle scripts: 7.2 base, 16.2 after multipliers.
	pkg := repo.PackageRow{
		PURL: "pkg:npm/lodash@4.17.20", Ecosystem: "npm", Name: "lodash",
		Version: "4.17.20", Scope: match.ScopeGlobal, HasScripts: true,
		InstallDir: "/usr/lib/node_modules/lodash",
	}
	installed(store, t, pkg)

	if _, err := watch.Run(handle, store, info, time.Now()); err != nil {
		t.Fatal(err)
	}
	open, err := store.OpenFindings(true, repo.FindingFilter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(open) != 1 {
		t.Fatalf("findings = %+v", open)
	}
	if open[0].Tier != match.TierHigh {
		t.Fatalf("tier = %q, want high — the advisory rates this 7.2", open[0].Tier)
	}

	// Someone turns the old behaviour back on.
	match.PromoteTiers = true
	defer func() { match.PromoteTiers = false }()

	report, err := watch.Run(handle, store, info, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if report.Rescored != 1 {
		t.Errorf("Rescored = %d, want 1 — the stored finding still carries the old tier", report.Rescored)
	}

	open, err = store.OpenFindings(true, repo.FindingFilter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if open[0].Tier != match.TierCritical {
		t.Errorf("tier = %q, want critical after the policy change", open[0].Tier)
	}
	// Rescoring must not disturb triage state: how bad something is and whether
	// someone has dealt with it are different questions.
	if open[0].State != repo.StateNew {
		t.Errorf("State = %q — rescoring changed triage state", open[0].State)
	}
}
