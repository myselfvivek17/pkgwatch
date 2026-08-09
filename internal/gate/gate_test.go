package gate_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/myselfvivek17/pkgwatch/internal/bundle"
	"github.com/myselfvivek17/pkgwatch/internal/config"
	"github.com/myselfvivek17/pkgwatch/internal/db"
	"github.com/myselfvivek17/pkgwatch/internal/gate"
	"github.com/myselfvivek17/pkgwatch/internal/match"
	"github.com/myselfvivek17/pkgwatch/internal/osv"
	"github.com/myselfvivek17/pkgwatch/internal/repo"
)

// fixtures are the same real OSV records the matcher is tested against:
// a high-severity lodash CVE and the @ctrl/tinycolor supply-chain compromise.
var fixtures = []string{"GHSA-35jh-r3h4-6jhm", "MAL-2025-47141"}

// newGate builds a gate over a real compiled bundle. withBundle=false leaves it
// with nothing to evaluate against, which is the fresh-machine case.
func newGate(t *testing.T, withBundle bool) *gate.Gate {
	t.Helper()
	return newGateWith(t, withBundle)
}

// newGateWith adds advisories the OSV fixtures do not cover — used where a test
// needs an ecosystem no real fixture is on file for.
func newGateWith(t *testing.T, withBundle bool, extra ...match.Advisory) *gate.Gate {
	t.Helper()

	dir := t.TempDir()
	handle, err := db.Open(filepath.Join(dir, "agent.db"), db.SchemaAgent)
	if err != nil {
		t.Fatalf("open agent db: %v", err)
	}
	t.Cleanup(func() { handle.Close() })

	attached := false
	if withBundle {
		var advisories []match.Advisory
		for _, name := range fixtures {
			raw, err := os.ReadFile(filepath.Join("..", "osv", "testdata", name+".json"))
			if err != nil {
				t.Fatalf("read fixture %s: %v", name, err)
			}
			parsed, err := osv.ParseRecord(raw)
			if err != nil {
				t.Fatalf("parse %s: %v", name, err)
			}
			advisories = append(advisories, parsed...)
		}
		advisories = append(advisories, extra...)

		bundlePath := filepath.Join(dir, "advisories.db")
		if _, err := bundle.Build(bundlePath, "20260808", advisories, time.Now()); err != nil {
			t.Fatalf("build bundle: %v", err)
		}
		if attached, err = db.AttachAdvisories(handle, bundlePath); err != nil || !attached {
			t.Fatalf("attach bundle: attached=%v err=%v", attached, err)
		}
	}

	cfg := config.Default()
	return gate.New(handle, cfg, attached)
}

func TestBlocksVulnerableVersion(t *testing.T) {
	g := newGate(t, true)

	verdict := g.Evaluate(gate.Request{Ecosystem: match.EcosystemNPM, Name: "lodash", Version: "4.17.20"})
	if !verdict.Blocked {
		t.Fatalf("lodash 4.17.20 should be blocked, got %+v", verdict)
	}
	if verdict.AdvisoryID != "GHSA-35jh-r3h4-6jhm" {
		t.Errorf("AdvisoryID = %q", verdict.AdvisoryID)
	}
	if verdict.FixedIn != "4.17.21" {
		t.Errorf("FixedIn = %q, want 4.17.21 — the user needs to be told where to go", verdict.FixedIn)
	}
	if verdict.Degraded {
		t.Error("a verdict from a working bundle must not be marked degraded")
	}
}

func TestAllowsFixedVersion(t *testing.T) {
	g := newGate(t, true)

	verdict := g.Evaluate(gate.Request{Ecosystem: match.EcosystemNPM, Name: "lodash", Version: "4.17.21"})
	if verdict.Blocked {
		t.Fatalf("lodash 4.17.21 is fixed and must install, got %+v", verdict)
	}
}

// Malware blocks whatever the configured threshold is. Setting block_tier to
// critical-only is a legitimate choice for CVEs; it must not become a way to
// let known-malicious packages through.
func TestMalwareBlocksBelowThreshold(t *testing.T) {
	g := newGate(t, true)
	g.BlockTier = match.TierCritical

	verdict := g.Evaluate(gate.Request{
		Ecosystem: match.EcosystemNPM, Name: "@ctrl/tinycolor", Version: "4.1.2",
	})
	if !verdict.Blocked {
		t.Fatalf("malware must block, got %+v", verdict)
	}
	if verdict.Reason != gate.ReasonMalware {
		t.Errorf("Reason = %q, want malware", verdict.Reason)
	}
	if verdict.FixedIn != "" {
		t.Errorf("FixedIn = %q — malware is not fixed by upgrading, and saying so is worse than saying nothing",
			verdict.FixedIn)
	}
}

// The default threshold is high. A medium finding is real but not grounds to
// stop an install, or nobody keeps the gate switched on.
func TestBlockTierIsRespected(t *testing.T) {
	g := newGate(t, true)
	g.BlockTier = match.TierCritical

	verdict := g.Evaluate(gate.Request{Ecosystem: match.EcosystemNPM, Name: "lodash", Version: "4.17.20"})
	if verdict.Blocked {
		t.Errorf("a high finding must not block when block_tier is critical, got %+v", verdict)
	}
	if verdict.AdvisoryID == "" {
		t.Error("the advisory should still be reported even when it does not block")
	}
}

// A machine that has never synced must not look like a clean machine.
func TestNoBundleIsDegradedNotClean(t *testing.T) {
	g := newGate(t, false)

	verdict := g.Evaluate(gate.Request{
		Ecosystem: match.EcosystemNPM, Name: "@ctrl/tinycolor", Version: "4.1.2",
	})
	if verdict.Blocked {
		t.Error("with no bundle the gate has nothing to judge against and must fail open")
	}
	if !verdict.Degraded {
		t.Fatal("an unevaluated request must be marked degraded, not returned as clean")
	}

	// Failing open silently is the failure mode this whole design is against.
	var kind string
	if err := g.DB.QueryRow(
		"SELECT kind FROM events ORDER BY id DESC LIMIT 1").Scan(&kind); err != nil {
		t.Fatalf("no event recorded for a degraded evaluation: %v", err)
	}
	if kind != repo.EventGateDegraded {
		t.Errorf("event kind = %q, want %q", kind, repo.EventGateDegraded)
	}
}

// A bundle built without an ecosystem's feed returns zero rows for every
// package in it, which is the same query result as "nothing wrong". This was a
// live gap: a bundle with 496,740 records and no PyPI feed at all answered
// "no advisories" for every Python package on the machine.
func TestUncoveredEcosystemIsDegradedNotClean(t *testing.T) {
	g := newGate(t, true)
	g.Covered = []string{match.EcosystemNPM} // as if the PyPI feed was never fetched

	verdict := g.Evaluate(gate.Request{
		Ecosystem: match.EcosystemPyPI, Name: "requests", Version: "2.19.1",
	})
	if !verdict.Degraded {
		t.Fatal("a package in an uncovered ecosystem must read as unknown, not clean")
	}
	if verdict.Blocked {
		t.Error("unknown is not grounds to block — the gate fails open")
	}

	var detail string
	if err := g.DB.QueryRow(
		"SELECT detail_json FROM events WHERE kind = ? ORDER BY id DESC LIMIT 1",
		repo.EventGateDegraded).Scan(&detail); err != nil {
		t.Fatalf("no degraded event recorded: %v", err)
	}
	if !strings.Contains(detail, "PyPI") {
		t.Errorf("the event should name the missing ecosystem, got %s", detail)
	}
}

func TestCoveredEcosystemIsEvaluatedNormally(t *testing.T) {
	g := newGate(t, true)
	g.Covered = []string{match.EcosystemNPM}

	verdict := g.Evaluate(gate.Request{Ecosystem: match.EcosystemNPM, Name: "lodash", Version: "4.17.20"})
	if verdict.Degraded {
		t.Fatal("npm is covered and must be evaluated")
	}
	if !verdict.Blocked {
		t.Error("lodash 4.17.20 should still block")
	}
}

func TestBlockRecordsDecisionAndEvent(t *testing.T) {
	g := newGate(t, true)
	const session = "deadbeefdeadbeef"

	if err := g.Repo.StartSession(session, match.EcosystemNPM, ".", "npm i lodash", "interactive", time.Now()); err != nil {
		t.Fatal(err)
	}
	g.Evaluate(gate.Request{
		SessionID: session, Ecosystem: match.EcosystemNPM, Name: "lodash", Version: "4.17.20",
	})

	decisions, err := g.Repo.SessionDecisions(session)
	if err != nil {
		t.Fatal(err)
	}
	if len(decisions) != 1 {
		t.Fatalf("got %d recorded decisions, want 1", len(decisions))
	}
	if decisions[0].Decision != repo.DecisionBlocked {
		t.Errorf("Decision = %q", decisions[0].Decision)
	}
	if decisions[0].PURL != "pkg:npm/lodash@4.17.20" {
		t.Errorf("PURL = %q", decisions[0].PURL)
	}

	var kind string
	if err := g.DB.QueryRow("SELECT kind FROM events ORDER BY id DESC LIMIT 1").Scan(&kind); err != nil {
		t.Fatal(err)
	}
	if kind != repo.EventInstallBlocked {
		t.Errorf("event kind = %q, want %q", kind, repo.EventInstallBlocked)
	}
}

// Filtering a version out of a listing and refusing to hand over a download are
// different events, and conflating them buries the one line that matters under
// a hundred that do not: an ordinary `npm install lodash` withholds well over a
// hundred long-abandoned versions nobody asked for.
func TestWithheldIsNotReportedAsBlocked(t *testing.T) {
	g := newGate(t, true)
	const session = "3333333333333333"

	if err := g.Repo.StartSession(session, match.EcosystemNPM, ".", "npm i lodash", "interactive", time.Now()); err != nil {
		t.Fatal(err)
	}

	for _, version := range []string{"4.17.19", "4.17.20"} {
		g.Evaluate(gate.Request{
			SessionID: session, Ecosystem: match.EcosystemNPM, Name: "lodash",
			Version: version, Point: gate.PointResolve,
		})
	}
	g.Evaluate(gate.Request{
		SessionID: session, Ecosystem: match.EcosystemNPM, Name: "lodash",
		Version: "4.17.20", Point: gate.PointDownload,
	})

	reported, err := g.Repo.SessionDecisions(session)
	if err != nil {
		t.Fatal(err)
	}
	if len(reported) != 1 {
		t.Fatalf("the report should carry only the refused download, got %d rows", len(reported))
	}

	withheld, err := g.Repo.SessionWithheld(session)
	if err != nil {
		t.Fatal(err)
	}
	if len(withheld) != 1 {
		t.Fatalf("withheld versions should group to one package, got %d", len(withheld))
	}
	if withheld[0].PURLBase != "pkg:npm/lodash" {
		t.Errorf("PURLBase = %q, want pkg:npm/lodash", withheld[0].PURLBase)
	}
	if withheld[0].Count != 2 {
		t.Errorf("Count = %d, want 2", withheld[0].Count)
	}

	// One summary event per filtered package, not one per version — otherwise a
	// single install floods the timeline.
	var events int
	if err := g.DB.QueryRow("SELECT COUNT(*) FROM events WHERE kind = ?",
		repo.EventInstallBlocked).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != 1 {
		t.Errorf("got %d install_blocked events, want 1 — withheld versions must not raise them", events)
	}
}

// A package-level override covers every version of that package for the run.
// The user's real decision is "I accept this package's advisories for this
// install"; there is no way to know which of a hundred filtered versions the
// resolver would have picked.
func TestPackageLevelOverrideCoversEveryVersion(t *testing.T) {
	g := newGate(t, true)
	const session = "4444444444444444"

	if err := g.Repo.StartSession(session, match.EcosystemNPM, ".", "npm i lodash", "interactive", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := g.Repo.ApproveInSession(session, "pkg:npm/lodash", time.Now()); err != nil {
		t.Fatal(err)
	}

	for _, version := range []string{"4.17.19", "4.17.20"} {
		verdict := g.Evaluate(gate.Request{
			SessionID: session, Ecosystem: match.EcosystemNPM, Name: "lodash",
			Version: version, Point: gate.PointResolve,
		})
		if verdict.Blocked {
			t.Errorf("lodash %s should be allowed by the package-level override", version)
		}
	}

	// It must not spill onto a different package.
	verdict := g.Evaluate(gate.Request{
		SessionID: session, Ecosystem: match.EcosystemNPM,
		Name: "@ctrl/tinycolor", Version: "4.1.2", Point: gate.PointDownload,
	})
	if !verdict.Blocked {
		t.Error("an override for lodash must not cover a different package")
	}
}

// An override is a local, deliberate loosening — the only direction loosening
// is allowed to travel. It must apply to the session that granted it and to no
// other.
func TestOverrideAppliesOnlyToItsSession(t *testing.T) {
	g := newGate(t, true)
	const approved, other = "1111111111111111", "2222222222222222"

	for _, id := range []string{approved, other} {
		if err := g.Repo.StartSession(id, match.EcosystemNPM, ".", "npm i lodash", "interactive", time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	if err := g.Repo.ApproveInSession(approved, "pkg:npm/lodash@4.17.20", time.Now()); err != nil {
		t.Fatal(err)
	}

	req := gate.Request{Ecosystem: match.EcosystemNPM, Name: "lodash", Version: "4.17.20"}

	req.SessionID = approved
	if verdict := g.Evaluate(req); verdict.Blocked {
		t.Error("the approving session must be allowed through")
	}

	req.SessionID = other
	if verdict := g.Evaluate(req); !verdict.Blocked {
		t.Error("an override must not leak into another install session")
	}
}

// Advisories lag attacks. A version published minutes ago with nothing on file
// is the signal that matters most during the window a compromise lives in — but
// it is a warning, not a block: every legitimate release is brand new once.
func TestCooldownWarnsWithoutBlocking(t *testing.T) {
	g := newGate(t, true)
	g.Cooldown = 24 * time.Hour

	verdict := g.Evaluate(gate.Request{
		Ecosystem: match.EcosystemNPM,
		Name:      "some-fresh-package",
		Version:   "1.0.0",
		Published: time.Now().Add(-10 * time.Minute),
	})
	if verdict.Blocked {
		t.Error("cooldown must not block — every release is new once")
	}
	if !verdict.Warn || verdict.Reason != gate.ReasonCooldown {
		t.Errorf("expected a cooldown warning, got %+v", verdict)
	}
}

func TestCooldownIgnoresOldReleases(t *testing.T) {
	g := newGate(t, true)
	g.Cooldown = 24 * time.Hour

	verdict := g.Evaluate(gate.Request{
		Ecosystem: match.EcosystemNPM, Name: "some-old-package", Version: "1.0.0",
		Published: time.Now().Add(-30 * 24 * time.Hour),
	})
	if verdict.Warn || verdict.Reason != "" {
		t.Errorf("a month-old release is not inside a 24h cooldown: %+v", verdict)
	}
}

// A version string no comparator can parse must not take the install down.
func TestUnparseableVersionFailsOpen(t *testing.T) {
	g := newGate(t, true)

	verdict := g.Evaluate(gate.Request{
		Ecosystem: match.EcosystemNPM, Name: "lodash", Version: "not-a-version",
	})
	if verdict.Blocked {
		t.Errorf("an unparseable version must not block, got %+v", verdict)
	}
}

func TestPURL(t *testing.T) {
	cases := []struct{ ecosystem, name, version, want string }{
		{match.EcosystemNPM, "lodash", "4.17.20", "pkg:npm/lodash@4.17.20"},
		{match.EcosystemNPM, "@ctrl/tinycolor", "4.1.2", "pkg:npm/%40ctrl/tinycolor@4.1.2"},
		// PyPI names normalize per PEP 503, so Django and django are one package.
		{match.EcosystemPyPI, "Zope.Interface", "5.4.0", "pkg:pypi/zope-interface@5.4.0"},
	}
	for _, tc := range cases {
		if got := match.PURL(tc.ecosystem, tc.name, tc.version); got != tc.want {
			t.Errorf("PURL(%q, %q) = %q, want %q", tc.ecosystem, tc.name, got, tc.want)
		}
	}
}
