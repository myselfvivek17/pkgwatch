package db

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestOpenAppliesSchemaAndIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.db")

	handle, err := Open(path, SchemaAgent)
	if err != nil {
		t.Fatalf("first open: %v", err)
	}

	for _, table := range []string{"packages", "findings", "install_sessions", "events", "hub_state"} {
		var name string
		err := handle.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&name)
		if err != nil {
			t.Errorf("table %s missing after migration: %v", table, err)
		}
	}
	var first int
	if err := handle.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&first); err != nil {
		t.Fatal(err)
	}
	if first == 0 {
		t.Fatal("no migrations were applied")
	}
	handle.Close()

	// Re-opening must not re-apply anything. Asserted as a stable count rather
	// than a fixed number: the property is idempotency, and pinning the number
	// means every new migration breaks a test that has nothing to do with it.
	handle, err = Open(path, SchemaAgent)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer handle.Close()

	var second int
	if err := handle.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&second); err != nil {
		t.Fatal(err)
	}
	if second != first {
		t.Errorf("schema_migrations went from %d to %d rows on reopen", first, second)
	}
}

func TestOpenHubSchema(t *testing.T) {
	handle, err := Open(filepath.Join(t.TempDir(), "hub.db"), SchemaHub)
	if err != nil {
		t.Fatalf("open hub: %v", err)
	}
	defer handle.Close()

	var name string
	if err := handle.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='devices'").Scan(&name); err != nil {
		t.Errorf("devices table missing: %v", err)
	}
}

// A fresh machine has no advisory bundle. That must be an ordinary state, not
// an error — the agent still gates and still records without one.
func TestAttachAdvisoriesMissingBundleIsNotAnError(t *testing.T) {
	dir := t.TempDir()
	handle, err := Open(filepath.Join(dir, "agent.db"), SchemaAgent)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()

	attached, err := AttachAdvisories(handle, filepath.Join(dir, "advisories.db"))
	if err != nil {
		t.Fatalf("missing bundle returned an error: %v", err)
	}
	if attached {
		t.Error("reported a bundle attached when none exists")
	}
}

func TestAttachAdvisoriesReadsBundle(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "advisories.db")

	bundle, err := Open(bundlePath, SchemaAgent) // any schema; we only need a file
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bundle.Exec(`CREATE TABLE bundle_meta (k TEXT PRIMARY KEY, v TEXT);
		INSERT INTO bundle_meta VALUES ('version','20260808')`); err != nil {
		t.Fatal(err)
	}
	bundle.Close()

	handle, err := Open(filepath.Join(dir, "agent.db"), SchemaAgent)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()

	attached, err := AttachAdvisories(handle, bundlePath)
	if err != nil || !attached {
		t.Fatalf("attach: attached=%v err=%v", attached, err)
	}

	var version string
	if err := handle.QueryRow("SELECT v FROM adv.bundle_meta WHERE k='version'").Scan(&version); err != nil {
		t.Fatalf("read through attached bundle: %v", err)
	}
	if version != "20260808" {
		t.Errorf("version = %q, want 20260808", version)
	}

	// The bundle must be attached read-only. Without this assertion the test
	// passes on the writable fallback path too, and the guarantee whose whole
	// point is preventing a stray write from corrupting the bundle mid-swap
	// would be silently absent.
	if _, err := handle.Exec("INSERT INTO adv.bundle_meta VALUES ('tamper','1')"); err == nil {
		t.Error("wrote through the advisory schema — bundle is not attached read-only")
	}

	// Detach must free the file so a bundle update can swap it (§3.2).
	if err := DetachAdvisories(handle); err != nil {
		t.Errorf("detach: %v", err)
	}
}

// A bundle arrives as a whole-file swap, so a layout change has nothing else to
// catch it: the failure mode without this gate is a raw "no such column" from
// inside the matcher, or zero rows, which reads as "no advisories" rather than
// "cannot evaluate".
func TestCheckAdvisorySchema(t *testing.T) {
	tests := []struct {
		name      string
		declared  string // "" means the bundle records no schema at all
		want      string
		wantError bool
	}{
		{"matching", "3", "3", false},
		{"older bundle, newer binary", "2", "3", true},
		{"newer bundle, older binary", "4", "3", true},
		{"bundle predates schema versioning", "", "3", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			bundlePath := filepath.Join(dir, "advisories.db")

			bundleDB, err := Open(bundlePath, SchemaAgent)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := bundleDB.Exec(`CREATE TABLE bundle_meta (k TEXT PRIMARY KEY, v TEXT)`); err != nil {
				t.Fatal(err)
			}
			if tt.declared != "" {
				if _, err := bundleDB.Exec("INSERT INTO bundle_meta VALUES ('schema', ?)", tt.declared); err != nil {
					t.Fatal(err)
				}
			}
			bundleDB.Close()

			handle, err := Open(filepath.Join(dir, "agent.db"), SchemaAgent)
			if err != nil {
				t.Fatal(err)
			}
			defer handle.Close()

			if _, err := AttachAdvisories(handle, bundlePath); err != nil {
				t.Fatal(err)
			}

			err = CheckAdvisorySchema(handle, tt.want)
			if tt.wantError {
				if err == nil {
					t.Fatalf("schema %q should not be accepted by a build reading %q", tt.declared, tt.want)
				}
				var mismatch ErrSchemaMismatch
				if !errors.As(err, &mismatch) {
					t.Errorf("error should be an ErrSchemaMismatch, got %T: %v", err, err)
				}
				return
			}
			if err != nil {
				t.Errorf("schema %q should be accepted: %v", tt.declared, err)
			}
		})
	}
}
