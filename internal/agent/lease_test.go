package agent

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/myselfvivek17/pkgwatch/internal/bundle"
	"github.com/myselfvivek17/pkgwatch/internal/db"
	"github.com/myselfvivek17/pkgwatch/internal/match"
	"github.com/myselfvivek17/pkgwatch/internal/repo"
)

// writeBundle puts an advisory database at path, replacing whatever is there.
func writeBundle(t *testing.T, path string, names ...string) {
	t.Helper()
	advisories := make([]match.Advisory, 0, len(names))
	for _, name := range names {
		advisories = append(advisories, match.Advisory{
			ID: "GHSA-" + name, Kind: "vuln", Source: "test",
			Ecosystem: match.EcosystemNPM, PackageName: name,
			Ranges:    []match.Range{{Introduced: "0", Fixed: "9.9.9"}},
			Published: time.Now(), Modified: time.Now(),
		})
	}
	if _, err := bundle.Build(path, "20260813", match.EcosystemNPM, advisories, time.Now()); err != nil {
		t.Fatalf("build bundle at %s: %v", path, err)
	}
}

// The whole reason this type exists: a reader in this process holds the merged
// database open, and on Windows that makes replacing the file impossible. The
// lease stands its readers down for the swap and brings them back, so the file
// can be replaced while the daemon is running — which is what moves bundle
// updates off the "remember to run it by hand" list.
func TestASwapReplacesTheBundleUnderALiveReader(t *testing.T) {
	dir := t.TempDir()
	advisoryPath := filepath.Join(dir, "advisories.db")
	writeBundle(t, advisoryPath, "lodash")

	handle, err := db.Open(filepath.Join(dir, "agent.db"), db.SchemaAgent)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	attached, err := db.AttachAdvisories(handle, advisoryPath)
	if err != nil || !attached {
		t.Fatalf("attach: attached=%v err=%v", attached, err)
	}

	lease := NewLease(advisoryPath)
	lease.Register(handle)

	// A live read, the way the gate and the dashboard read.
	if found, err := repo.LookupAdvisories(handle, match.EcosystemNPM, "lodash"); err != nil {
		t.Fatal(err)
	} else if len(found) != 1 {
		t.Fatalf("before the swap: %d advisories for lodash, want 1", len(found))
	}

	// The swap writes a different bundle over the same path. Without the lease
	// this is the call that fails on Windows with "used by another process".
	if err := lease.Swap(func() error {
		writeBundle(t, advisoryPath, "lodash", "express")
		return nil
	}); err != nil {
		t.Fatalf("swap: %v", err)
	}

	// Reattached, and reading the new file rather than the replaced one.
	found, err := repo.LookupAdvisories(handle, match.EcosystemNPM, "express")
	if err != nil {
		t.Fatalf("after the swap the handle cannot query advisories: %v", err)
	}
	if len(found) != 1 {
		t.Errorf("after the swap: %d advisories for express, want 1 — the handle is still "+
			"reading the bundle that was replaced", len(found))
	}
}

// A swap that fails must still leave every reader attached. A handle left
// detached answers every lookup with no advisories at all, which is the shape
// of "nothing found" that reads as "nothing wrong".
func TestAFailedSwapLeavesReadersAttached(t *testing.T) {
	dir := t.TempDir()
	advisoryPath := filepath.Join(dir, "advisories.db")
	writeBundle(t, advisoryPath, "lodash")

	handle, err := db.Open(filepath.Join(dir, "agent.db"), db.SchemaAgent)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	if _, err := db.AttachAdvisories(handle, advisoryPath); err != nil {
		t.Fatal(err)
	}

	lease := NewLease(advisoryPath)
	lease.Register(handle)

	boom := errTest("the download failed halfway")
	if err := lease.Swap(func() error { return boom }); err != boom {
		t.Fatalf("swap returned %v, want the replace error to travel out intact", err)
	}

	found, err := repo.LookupAdvisories(handle, match.EcosystemNPM, "lodash")
	if err != nil {
		t.Fatalf("reader is detached after a failed swap: %v", err)
	}
	if len(found) != 1 {
		t.Errorf("%d advisories after a failed swap, want the previous bundle intact", len(found))
	}
}

type errTest string

func (e errTest) Error() string { return string(e) }
