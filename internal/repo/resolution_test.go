package repo_test

import (
	"testing"
	"time"

	"github.com/myselfvivek17/pkgwatch/internal/repo"
)

// findingState reads one finding's state directly, including the states
// OpenFindings filters out — the question here is what the row says, not what
// the dashboard chooses to show.
func findingState(t *testing.T, store repo.Agent, purl string) string {
	t.Helper()
	var state string
	if err := store.DB.QueryRow(
		"SELECT state FROM findings WHERE purl = ?", purl).Scan(&state); err != nil {
		t.Fatal(err)
	}
	return state
}

// Removing a package by hand closes its findings, and putting it back reopens
// them.
//
// Both halves matter. Closing is what stops a machine looking dirty for
// something it no longer has; reopening is what stops the close being
// permanent, since RecordFindings is INSERT OR IGNORE and a row sitting in
// 'fixed' would absorb every later attempt to record the same finding.
func TestRemovingAPackageByHandResolvesItAndReinstallingBringsItBack(t *testing.T) {
	store := newAgentDB(t)
	const purl = "pkg:npm/lodash@4.17.20"
	at := time.Now()

	if _, _, err := store.UpsertPackages([]repo.PackageRow{
		row(purl, "lodash", "4.17.20", "/app/node_modules/lodash"),
	}, at); err != nil {
		t.Fatal(err)
	}
	seedFinding(t, store, purl, "GHSA-x", "critical", 9.8)

	// The package is deleted by hand, so the next scan does not see it.
	if err := store.MarkGone([]string{purl}, at.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	closed, err := store.ResolveFindingsForGonePackages(at.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(closed) != 1 {
		t.Fatalf("closed %d findings after the package was removed, want 1", len(closed))
	}
	if got := findingState(t, store, purl); got != repo.StateFixed {
		t.Errorf("state = %q after a manual removal, want %q", got, repo.StateFixed)
	}

	// And it is reinstalled.
	if _, _, err := store.UpsertPackages([]repo.PackageRow{
		row(purl, "lodash", "4.17.20", "/app/node_modules/lodash"),
	}, at.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	reopened, err := store.ReopenFindingsForPresentPackages()
	if err != nil {
		t.Fatal(err)
	}
	if len(reopened) != 1 {
		t.Fatalf("reopened %d findings after the package came back, want 1", len(reopened))
	}
	if got := findingState(t, store, purl); got != repo.StateNew {
		t.Errorf("state = %q after reinstalling, want %q — a critical must not stay closed", got, repo.StateNew)
	}
}

// Restoring a quarantined package puts its finding back in play.
//
// This is the gap the state machine had: quarantine moves a finding to
// 'quarantined', and nothing moved it back. Restore before the next scan and
// the row stayed 'quarantined' for good — still counted as open, but labelled
// as boxed up while the package was sitting back on disk. A badge that claims
// the malware is contained when it is not is the reassuring direction to be
// wrong in, which is the one this tool may not fail in.
func TestRestoringAQuarantinedPackageReopensItsFinding(t *testing.T) {
	store := newAgentDB(t)
	const purl = "pkg:npm/%40ctrl/tinycolor@4.1.2"
	at := time.Now()

	if _, _, err := store.UpsertPackages([]repo.PackageRow{
		row(purl, "@ctrl/tinycolor", "4.1.2", "/app/node_modules/@ctrl/tinycolor"),
	}, at); err != nil {
		t.Fatal(err)
	}
	seedFinding(t, store, purl, "MAL-2025-47141", "critical", 10)

	if _, err := store.MarkFindingsQuarantined(purl, at); err != nil {
		t.Fatal(err)
	}
	if got := findingState(t, store, purl); got != repo.StateQuarantined {
		t.Fatalf("state = %q after quarantine, want %q", got, repo.StateQuarantined)
	}

	// Restored before any scan ran, which is the ordinary case: the button is
	// right there on the page that lists it.
	if _, err := store.ReopenFindingsForRestored(purl); err != nil {
		t.Fatal(err)
	}
	if got := findingState(t, store, purl); got != repo.StateNew {
		t.Errorf("state = %q after a restore, want %q — the package is back on disk", got, repo.StateNew)
	}
}

// The same repair reaches a package restored by any other route, because the
// scan converges on what is actually present rather than on what it was told.
func TestAScanReopensAQuarantinedFindingWhosePackageIsBack(t *testing.T) {
	store := newAgentDB(t)
	const purl = "pkg:npm/zwitch@2.0.4"
	at := time.Now()

	if _, _, err := store.UpsertPackages([]repo.PackageRow{
		row(purl, "zwitch", "2.0.4", "/app/node_modules/zwitch"),
	}, at); err != nil {
		t.Fatal(err)
	}
	seedFinding(t, store, purl, "MAL-1", "critical", 10)
	if _, err := store.MarkFindingsQuarantined(purl, at); err != nil {
		t.Fatal(err)
	}

	// Somebody unpacked the archive by hand. The scan sees the files, and that
	// is the only thing it should be trusting.
	reopened, err := store.ReopenFindingsForPresentPackages()
	if err != nil {
		t.Fatal(err)
	}
	if len(reopened) != 1 {
		t.Fatalf("reopened %d, want the quarantined finding whose package is present", len(reopened))
	}
	if got := findingState(t, store, purl); got != repo.StateNew {
		t.Errorf("state = %q, want %q", got, repo.StateNew)
	}
}

// An ignored finding is not touched by any of this. That was a decision about
// a package, not about whether it happened to be installed this week.
func TestIgnoredFindingsSurviveRemovalAndRestore(t *testing.T) {
	store := newAgentDB(t)
	const purl = "pkg:npm/chalk@5.0.0"
	at := time.Now()

	if _, _, err := store.UpsertPackages([]repo.PackageRow{
		row(purl, "chalk", "5.0.0", "/app/node_modules/chalk"),
	}, at); err != nil {
		t.Fatal(err)
	}
	seedFinding(t, store, purl, "GHSA-y", "low", 2)
	if err := store.IgnoreFinding(purl, "GHSA-y", "accepted", at.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}

	if err := store.MarkGone([]string{purl}, at.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ResolveFindingsForGonePackages(at.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if got := findingState(t, store, purl); got != repo.StateIgnored {
		t.Errorf("state = %q, want the ignore to survive a removal", got)
	}
}
