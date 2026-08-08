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

// buildTestBundle compiles the real OSV fixtures into a bundle and attaches it
// to a fresh agent database — the same path a synced bundle takes.
func buildTestBundle(t *testing.T) *sql.DB {
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
	manifest, err := bundle.Build(bundlePath, "20260808", advisories, time.Now())
	if err != nil {
		t.Fatalf("build bundle: %v", err)
	}
	if manifest.RecordCount != len(advisories) {
		t.Fatalf("manifest counts %d records, wrote %d", manifest.RecordCount, len(advisories))
	}

	handle, err := db.Open(filepath.Join(dir, "agent.db"), db.SchemaAgent)
	if err != nil {
		t.Fatalf("open agent db: %v", err)
	}
	t.Cleanup(func() { handle.Close() })

	attached, err := db.AttachAdvisories(handle, bundlePath)
	if err != nil || !attached {
		t.Fatalf("attach bundle: attached=%v err=%v", attached, err)
	}
	return handle
}

// The acceptance criterion, end to end: build a bundle from real OSV records,
// attach it, look the package up, and match the installed version.
func TestLookupAndMatchLodash(t *testing.T) {
	handle := buildTestBundle(t)

	advisories, err := repo.LookupAdvisories(handle, match.EcosystemNPM, "lodash")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if len(advisories) != 1 {
		t.Fatalf("got %d advisories for lodash, want 1", len(advisories))
	}

	adv := advisories[0]
	if adv.ID != "GHSA-35jh-r3h4-6jhm" {
		t.Errorf("ID = %q", adv.ID)
	}
	if adv.SeverityCVSS == nil || *adv.SeverityCVSS != 7.2 {
		t.Errorf("severity did not survive the round trip: %v", adv.SeverityCVSS)
	}

	affected, err := match.Affects(adv, match.Package{
		Ecosystem: match.EcosystemNPM, Name: "lodash", Version: "4.17.20",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !affected {
		t.Error("lodash 4.17.20 should be affected")
	}

	// The fix landed in 4.17.21, so that version must come back clean.
	affected, err = match.Affects(adv, match.Package{
		Ecosystem: match.EcosystemNPM, Name: "lodash", Version: "4.17.21",
	})
	if err != nil {
		t.Fatal(err)
	}
	if affected {
		t.Error("lodash 4.17.21 is fixed and must not match")
	}
}

func TestLookupAndMatchMalware(t *testing.T) {
	handle := buildTestBundle(t)

	advisories, err := repo.LookupAdvisories(handle, match.EcosystemNPM, "@ctrl/tinycolor")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if len(advisories) != 1 {
		t.Fatalf("got %d advisories, want 1", len(advisories))
	}

	adv := advisories[0]
	if adv.Kind != match.KindMalware {
		t.Errorf("Kind = %q, want malware", adv.Kind)
	}

	affected, err := match.Affects(adv, match.Package{
		Ecosystem: match.EcosystemNPM, Name: "@ctrl/tinycolor", Version: "4.1.2",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !affected {
		t.Fatal("@ctrl/tinycolor 4.1.2 should match the malware record")
	}

	_, tier := match.Score(adv, match.Package{Scope: match.ScopeProject, LastSeen: time.Now()}, time.Now())
	if tier != match.TierCritical {
		t.Errorf("tier = %q, want critical", tier)
	}
}

// One GHSA covering four npm packages must land as four separately addressable
// rows — the spec's id-only primary key would have collapsed them into one.
func TestSiblingPackagesAreAddressableSeparately(t *testing.T) {
	handle := buildTestBundle(t)

	for _, name := range []string{"lodash", "lodash-es", "lodash.template", "lodash-template"} {
		advisories, err := repo.LookupAdvisories(handle, match.EcosystemNPM, name)
		if err != nil {
			t.Fatalf("lookup %s: %v", name, err)
		}
		if len(advisories) != 1 {
			t.Errorf("%s: got %d advisories, want 1", name, len(advisories))
		}
	}
}

// npm names are case-sensitive, so a lookup for the wrong case must miss
// rather than quietly match a different package.
func TestLookupIsCaseSensitiveForNPM(t *testing.T) {
	handle := buildTestBundle(t)

	advisories, err := repo.LookupAdvisories(handle, match.EcosystemNPM, "Lodash")
	if err != nil {
		t.Fatal(err)
	}
	if len(advisories) != 0 {
		t.Errorf(`lookup for "Lodash" returned %d advisories; npm names are case-sensitive`, len(advisories))
	}
}

func TestLookupUnknownPackageIsEmpty(t *testing.T) {
	handle := buildTestBundle(t)

	advisories, err := repo.LookupAdvisories(handle, match.EcosystemNPM, "definitely-not-a-package")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if len(advisories) != 0 {
		t.Errorf("got %d advisories for an unknown package", len(advisories))
	}
}
