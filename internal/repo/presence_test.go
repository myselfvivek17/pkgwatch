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

// A bundle holding one distribution release does not answer for another.
//
// This is the finer-grained version of the PyPI gap, and it bit for real: a
// bundle carrying only Ubuntu:24.04:LTS recorded its coverage as "Ubuntu", so a
// machine running Ubuntu:24.04 was reported as examined, every lookup returned
// no rows, and 1,830 packages read as clean.
func TestCoverageIsMatchedPerRelease(t *testing.T) {
	info := repo.BundleInfo{
		Attached:   true,
		Ecosystems: []string{"Alpine:v3.24", "Debian:12", "Ubuntu:24.04:LTS", "npm"},
	}

	for _, covered := range []string{"Debian:12", "Alpine:v3.24", "Ubuntu:24.04:LTS", "npm"} {
		if !info.Covers(covered) {
			t.Errorf("Covers(%q) = false, but the bundle carries it", covered)
		}
	}
	for _, missing := range []string{"Debian:13", "Alpine:v3.22", "Ubuntu:24.04", "Ubuntu:22.04:LTS", "PyPI"} {
		if info.Covers(missing) {
			t.Errorf("Covers(%q) = true — the bundle has no records for it, and saying otherwise "+
				"turns an empty lookup into a clean result", missing)
		}
	}

	bases := info.CoveredBases()
	if len(bases) != 4 {
		t.Errorf("CoveredBases() = %v, want one entry per distinct ecosystem", bases)
	}
}

// The audit has to tell an upgrade, a rename and a disappearance apart, because
// only the third means the collector lost a row — and a lost row closes that
// package's findings. Matching on ecosystem would call the rename a
// disappearance, which is what a real Ubuntu:24.04 -> Ubuntu:24.04:LTS change
// did to 1,830 host packages that had never moved.
func TestRetiredPackagesDistinguishesRenameFromLoss(t *testing.T) {
	store := newAgentDB(t)
	first := time.Now().Add(-time.Hour)

	upgraded := row("pkg:npm/lodash@4.17.20", "lodash", "4.17.20", "/app/node_modules/lodash")
	renamed := row("pkg:deb/ubuntu/curl@8.5.0?distro=ubuntu-24.04", "curl", "8.5.0", "/var/lib/dpkg/status")
	renamed.Ecosystem = "Ubuntu:24.04"
	vanished := row("pkg:npm/chalk@5.0.0", "chalk", "5.0.0", "/app/node_modules/chalk")

	if _, _, err := store.UpsertPackages([]repo.PackageRow{upgraded, renamed, vanished}, first); err != nil {
		t.Fatal(err)
	}

	// lodash upgrades in place; curl keeps its version but its ecosystem
	// identifier changes; chalk is simply not seen again.
	second := time.Now()
	newLodash := row("pkg:npm/lodash@4.17.21", "lodash", "4.17.21", "/app/node_modules/lodash")
	newCurl := row("pkg:deb/ubuntu/curl@8.5.0?distro=ubuntu-24.04:LTS", "curl", "8.5.0", "/var/lib/dpkg/status")
	newCurl.Ecosystem = "Ubuntu:24.04:LTS"
	if _, _, err := store.UpsertPackages([]repo.PackageRow{newLodash, newCurl}, second); err != nil {
		t.Fatal(err)
	}
	if _, err := store.MarkSuperseded(second); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkGone([]string{"pkg:npm/chalk@5.0.0",
		"pkg:deb/ubuntu/curl@8.5.0?distro=ubuntu-24.04"}, second); err != nil {
		t.Fatal(err)
	}

	retired, err := store.RetiredPackages(50)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]repo.PackageRow{}
	for _, pkg := range retired {
		got[pkg.Name] = pkg
	}
	if len(got) != 3 {
		t.Fatalf("retired = %+v, want lodash, curl and chalk", retired)
	}

	if got["lodash"].ReplacedBy != "4.17.21" || got["lodash"].ReplacedEcosystem != "npm" {
		t.Errorf("upgrade: ReplacedBy = %q in %q, want 4.17.21 in npm",
			got["lodash"].ReplacedBy, got["lodash"].ReplacedEcosystem)
	}
	if got["curl"].ReplacedBy != "8.5.0" || got["curl"].ReplacedEcosystem != "Ubuntu:24.04:LTS" {
		t.Errorf("rename: ReplacedBy = %q in %q, want 8.5.0 in Ubuntu:24.04:LTS",
			got["curl"].ReplacedBy, got["curl"].ReplacedEcosystem)
	}
	if got["chalk"].ReplacedBy != "" {
		t.Errorf("loss: ReplacedBy = %q, want empty — nothing replaced it",
			got["chalk"].ReplacedBy)
	}
}
