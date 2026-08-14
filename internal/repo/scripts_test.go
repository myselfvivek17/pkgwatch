package repo_test

import (
	"testing"
	"time"

	"github.com/myselfvivek17/pkgwatch/internal/repo"
)

// An allowance is a decision, and withdrawing it must not erase that it was
// made. "Never allowed" and "allowed, then withdrawn" are different answers to
// the same question, and only the second one has somebody behind it.
func TestARevokedAllowanceIsRememberedNotDeleted(t *testing.T) {
	store := newAgentDB(t)
	at := time.Now()

	if err := store.AllowScripts("pkg:npm/esbuild", repo.ApprovedViaCLI, "native binary", at); err != nil {
		t.Fatal(err)
	}
	ok, err := store.ScriptsAllowed("pkg:npm/esbuild")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("an allowed package is not allowed")
	}

	if err := store.RevokeScripts("pkg:npm/esbuild", at.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if ok, err = store.ScriptsAllowed("pkg:npm/esbuild"); err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("a revoked package may still run scripts")
	}

	list, err := store.ScriptAllowlist()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("allowlist has %d rows, want the revoked one still on file", len(list))
	}
	if list[0].Active() || list[0].RevokedAt.IsZero() {
		t.Error("the revocation was not recorded")
	}
	// The original decision date survives, so how long this was trusted is
	// still answerable.
	if list[0].AllowedAt.Unix() != at.Unix() {
		t.Error("revoking lost the original approved_at")
	}
}

// Re-allowing something previously withdrawn is the current decision winning,
// without pretending the earlier one never happened.
func TestReAllowingClearsTheRevocation(t *testing.T) {
	store := newAgentDB(t)
	at := time.Now()

	for _, step := range []func() error{
		func() error { return store.AllowScripts("pkg:npm/sharp", repo.ApprovedViaCLI, "", at) },
		func() error { return store.RevokeScripts("pkg:npm/sharp", at.Add(time.Hour)) },
		func() error {
			return store.AllowScripts("pkg:npm/sharp", repo.ApprovedViaCLI, "needed again", at.Add(2*time.Hour))
		},
	} {
		if err := step(); err != nil {
			t.Fatal(err)
		}
	}

	ok, err := store.ScriptsAllowed("pkg:npm/sharp")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("re-allowing did not take effect")
	}
	list, err := store.ScriptAllowlist()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Note != "needed again" {
		t.Errorf("allowlist = %+v, want one row carrying the newer reason", list)
	}
	if list[0].AllowedAt.Unix() != at.Unix() {
		t.Error("re-allowing moved approved_at; how long this was trusted is now unanswerable")
	}
}

// The guard's real cost is the packages that will come up unbuilt, and that
// list has to be per package rather than per version: allowing a package and
// then upgrading it must not silently re-block the build.
func TestPackagesWithScriptsAreListedOncePerName(t *testing.T) {
	store := newAgentDB(t)
	at := time.Now()

	rows := []repo.PackageRow{
		withScripts(row("pkg:npm/esbuild@0.20.0", "esbuild", "0.20.0", "/app/node_modules/esbuild")),
		withScripts(row("pkg:npm/esbuild@0.21.0", "esbuild", "0.21.0", "/other/node_modules/esbuild")),
		row("pkg:npm/lodash@4.17.21", "lodash", "4.17.21", "/app/node_modules/lodash"),
	}
	if _, _, err := store.UpsertPackages(rows, at); err != nil {
		t.Fatal(err)
	}

	names, err := store.PackagesWithScripts("npm")
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 1 || names[0] != "esbuild" {
		t.Errorf("packages with scripts = %v, want esbuild once", names)
	}
}

func withScripts(r repo.PackageRow) repo.PackageRow {
	r.HasScripts = true
	return r
}
