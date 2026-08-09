package repo_test

import (
	"testing"
	"time"

	"github.com/myselfvivek17/pkgwatch/internal/repo"
)

func row(purl, name, version, dir string) repo.PackageRow {
	return repo.PackageRow{
		PURL: purl, Ecosystem: "npm", Name: name, Version: version,
		InstallDir: dir, Scope: "project",
	}
}

// Upgrading in place leaves a directory that still exists but now holds a
// different version. A filesystem check alone would keep calling the old
// version installed, and the machine would carry a finding for something
// replaced months ago.
func TestMarkSupersededRetiresReplacedVersions(t *testing.T) {
	store := newAgentDB(t)
	first := time.Now().Add(-time.Hour)

	if _, _, err := store.UpsertPackages([]repo.PackageRow{
		row("pkg:npm/lodash@4.17.20", "lodash", "4.17.20", "/app/node_modules/lodash"),
		row("pkg:npm/chalk@5.0.0", "chalk", "5.0.0", "/app/node_modules/chalk"),
	}, first); err != nil {
		t.Fatal(err)
	}

	// A later scan finds a new version in the same directory.
	second := time.Now()
	if _, _, err := store.UpsertPackages([]repo.PackageRow{
		row("pkg:npm/lodash@4.17.21", "lodash", "4.17.21", "/app/node_modules/lodash"),
		row("pkg:npm/chalk@5.0.0", "chalk", "5.0.0", "/app/node_modules/chalk"),
	}, second); err != nil {
		t.Fatal(err)
	}

	retired, err := store.MarkSuperseded(second)
	if err != nil {
		t.Fatal(err)
	}
	if retired != 1 {
		t.Fatalf("retired %d rows, want just the replaced lodash", retired)
	}

	present, err := store.Present()
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range present {
		if item.PURL == "pkg:npm/lodash@4.17.20" {
			t.Error("the replaced version is still being treated as installed")
		}
	}
	if len(present) != 2 {
		t.Errorf("present = %d, want lodash 4.17.21 and chalk", len(present))
	}

	// The row itself survives. The timeline has to be able to say this machine
	// was carrying 4.17.20 when the advisory landed.
	total := count(t, store.DB, "SELECT COUNT(*) FROM packages")
	if total != 3 {
		t.Errorf("packages = %d, want 3 — retiring is not deleting", total)
	}
}

func TestMarkGoneAndReinstall(t *testing.T) {
	store := newAgentDB(t)
	now := time.Now()

	if _, _, err := store.UpsertPackages([]repo.PackageRow{
		row("pkg:npm/lodash@4.17.21", "lodash", "4.17.21", "/app/node_modules/lodash"),
	}, now); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkGone([]string{"pkg:npm/lodash@4.17.21"}, now); err != nil {
		t.Fatal(err)
	}

	present, _, err := store.PresentCount()
	if err != nil {
		t.Fatal(err)
	}
	if present != 0 {
		t.Fatalf("present = %d after the package was removed", present)
	}

	// Reinstalling must bring it back, or the watcher would never look at it
	// again.
	if _, _, err := store.UpsertPackages([]repo.PackageRow{
		row("pkg:npm/lodash@4.17.21", "lodash", "4.17.21", "/app/node_modules/lodash"),
	}, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	present, historical, err := store.PresentCount()
	if err != nil {
		t.Fatal(err)
	}
	if present != 1 || historical != 0 {
		t.Errorf("present=%d historical=%d, want a reinstall to restore the row", present, historical)
	}
}

// A scan of one project must not conclude that everything else was
// uninstalled, so nothing is retired just for being absent from this scan.
func TestPartialScanDoesNotRetireUntouchedPackages(t *testing.T) {
	store := newAgentDB(t)
	first := time.Now().Add(-time.Hour)

	if _, _, err := store.UpsertPackages([]repo.PackageRow{
		row("pkg:npm/lodash@4.17.21", "lodash", "4.17.21", "/global/node_modules/lodash"),
		row("pkg:npm/chalk@5.0.0", "chalk", "5.0.0", "/projectA/node_modules/chalk"),
	}, first); err != nil {
		t.Fatal(err)
	}

	// A later scan covering only project B.
	second := time.Now()
	if _, _, err := store.UpsertPackages([]repo.PackageRow{
		row("pkg:npm/ms@2.0.0", "ms", "2.0.0", "/projectB/node_modules/ms"),
	}, second); err != nil {
		t.Fatal(err)
	}
	if _, err := store.MarkSuperseded(second); err != nil {
		t.Fatal(err)
	}

	present, _, err := store.PresentCount()
	if err != nil {
		t.Fatal(err)
	}
	if present != 3 {
		t.Errorf("present = %d, want 3 — a partial scan says nothing about what it did not look at", present)
	}
}
