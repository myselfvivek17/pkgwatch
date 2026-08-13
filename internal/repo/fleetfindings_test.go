package repo_test

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
)

// A hub that has been given a bundle can answer the question its findings page
// exists to answer: what fixes this. Before the bundle it could only list the
// problem.
//
// The uncovered row is the half that matters more. The hub's bundle carries npm
// records only, and the fleet also reports Debian findings — those must come
// back marked unknown, not as "no fix published", and --fixable must not quietly
// present them as unfixable.
func hubWithNPMBundle(t *testing.T) repo.Hub {
	t.Helper()

	var advisories []match.Advisory
	for _, name := range []string{"GHSA-35jh-r3h4-6jhm", "MAL-2025-47141"} {
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

	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "advisories.db")
	if _, err := bundle.Build(bundlePath, "20260808", match.EcosystemNPM, advisories, time.Now()); err != nil {
		t.Fatalf("build bundle: %v", err)
	}

	handle, err := db.Open(filepath.Join(dir, "hub.db"), db.SchemaHub)
	if err != nil {
		t.Fatalf("open hub db: %v", err)
	}
	t.Cleanup(func() { handle.Close() })

	attached, err := db.AttachAdvisories(handle, bundlePath)
	if err != nil || !attached {
		t.Fatalf("attach bundle: attached=%v err=%v", attached, err)
	}
	return repo.Hub{DB: handle}
}

func seedDevice(t *testing.T, handle *sql.DB, id, hostname string) {
	t.Helper()
	_, err := handle.Exec(`INSERT INTO devices
		(id, pubkey, token_hash, hostname, os, arch, status, enrolled_at)
		VALUES (?,?,?,?,?,?,?,?)`,
		id, []byte("key"), "hash", hostname, "linux", "amd64", repo.DeviceStatusApproved, time.Now().Unix())
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}
}

func TestFleetFindingsCarryFixVersionsFromTheHubsBundle(t *testing.T) {
	hub := hubWithNPMBundle(t)
	seedDevice(t, hub.DB, "AAAA-BBBB", "laptop")

	now := time.Now()
	_, err := hub.ReplaceFindings("AAAA-BBBB", []repo.FleetFinding{
		{PURL: "pkg:npm/lodash@4.17.20", AdvisoryID: "GHSA-35jh-r3h4-6jhm",
			Tier: match.TierHigh, Score: 7.4, State: repo.StateNew, DetectedAt: now},
		{PURL: "pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1?distro=ubuntu-22.04", AdvisoryID: "CVE-2024-0001",
			Tier: match.TierCritical, Score: 9.1, State: repo.StateNew, DetectedAt: now},
	}, now)
	if err != nil {
		t.Fatalf("seed findings: %v", err)
	}

	rows, err := hub.FleetFindings(true, repo.FindingFilter{})
	if err != nil {
		t.Fatalf("fleet findings: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d findings, want 2", len(rows))
	}

	byPURL := map[string]repo.Finding{}
	for _, row := range rows {
		byPURL[row.PURL] = row
	}

	lodash := byPURL["pkg:npm/lodash@4.17.20"]
	if lodash.FixedIn == "" {
		t.Error("the hub holds the advisory that fixes lodash and reported no fix version")
	}
	if lodash.FixUnknown {
		t.Error("lodash is in the bundle, so its fix is known")
	}
	if lodash.Summary == "" || lodash.BaseCVSS == nil {
		t.Errorf("summary %q cvss %v — both come from the same bundle row as the fix",
			lodash.Summary, lodash.BaseCVSS)
	}
	if lodash.Machine != "laptop" {
		t.Errorf("machine = %q, want laptop", lodash.Machine)
	}

	// The npm-only bundle knows nothing about Ubuntu. Saying "none yet" here
	// would be inventing an answer about a critical.
	ubuntu := byPURL["pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1?distro=ubuntu-22.04"]
	if !ubuntu.FixUnknown {
		t.Error("a finding the bundle does not cover was reported as known")
	}
	if ubuntu.FixedIn != "" {
		t.Errorf("fix %q claimed for a package the bundle never saw", ubuntu.FixedIn)
	}

	// --fixable is the list you act on. An unknown must not appear in it, and
	// must not be counted against the fleet as unfixable either.
	fixable, err := hub.FleetFindings(true, repo.FindingFilter{FixableOnly: true})
	if err != nil {
		t.Fatalf("fixable: %v", err)
	}
	if len(fixable) != 1 || fixable[0].PURL != "pkg:npm/lodash@4.17.20" {
		t.Fatalf("fixable list = %+v, want lodash alone", fixable)
	}
}

// Without a bundle the fixable filter has nothing to judge against. Returning
// every open finding would claim each one is fixable; returning them silently
// under the filter is the inversion this project keeps fixing.
func TestFleetFindingsRefuseToGuessFixabilityWithoutABundle(t *testing.T) {
	handle, err := db.Open(filepath.Join(t.TempDir(), "hub.db"), db.SchemaHub)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()

	hub := repo.Hub{DB: handle}
	seedDevice(t, handle, "CCCC-DDDD", "server")
	now := time.Now()
	if _, err := hub.ReplaceFindings("CCCC-DDDD", []repo.FleetFinding{
		{PURL: "pkg:npm/lodash@4.17.20", AdvisoryID: "GHSA-35jh-r3h4-6jhm",
			Tier: match.TierHigh, Score: 7.4, State: repo.StateNew, DetectedAt: now},
	}, now); err != nil {
		t.Fatal(err)
	}

	all, err := hub.FleetFindings(false, repo.FindingFilter{})
	if err != nil {
		t.Fatalf("unattached listing: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("got %d findings without a bundle, want the recorded 1", len(all))
	}
	if all[0].FixedIn != "" {
		t.Error("a fix version appeared with no bundle to read it from")
	}

	fixable, err := hub.FleetFindings(false, repo.FindingFilter{FixableOnly: true})
	if err != nil {
		t.Fatalf("unattached fixable: %v", err)
	}
	if len(fixable) != 0 {
		t.Errorf("got %d fixable findings with no bundle to judge fixability", len(fixable))
	}
}
