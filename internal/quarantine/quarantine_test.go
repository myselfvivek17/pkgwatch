package quarantine

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// tree builds a small package directory: nested files, an executable, and a
// symlink where npm puts one.
func tree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()

	mustWrite(t, filepath.Join(root, "package.json"), `{"name":"thing","version":"1.0.0"}`, 0o644)
	mustWrite(t, filepath.Join(root, "lib", "index.js"), "module.exports = 1\n", 0o644)
	mustWrite(t, filepath.Join(root, "bin", "thing"), "#!/bin/sh\necho hi\n", 0o755)

	if runtime.GOOS != "windows" {
		if err := os.Symlink("../bin/thing", filepath.Join(root, "lib", "thing")); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func mustWrite(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

// The acceptance criterion for this feature: what comes back is what was taken,
// checked rather than asserted. Everything else here is about the cases where
// that is not true.
func TestARestoredTreeIsIdenticalToTheOneTakenAway(t *testing.T) {
	origin := tree(t)
	store := t.TempDir()

	archive, err := Pack(origin, store, "abc123")
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	if archive.Files < 3 {
		t.Errorf("packed %d files, want at least the three written", archive.Files)
	}

	// The package is deleted, exactly as quarantine does it.
	if err := os.RemoveAll(origin); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(origin); !os.IsNotExist(err) {
		t.Fatal("the origin is still there after removal")
	}

	restored, err := Unpack(archive.Path, origin)
	if err != nil {
		t.Fatalf("unpack: %v", err)
	}
	if restored != archive.Digest {
		t.Errorf("digest after restore = %s, want %s — what came back is not what was taken",
			restored, archive.Digest)
	}

	// And the files really are there, not merely hashed to the same value.
	if content, err := os.ReadFile(filepath.Join(origin, "lib", "index.js")); err != nil {
		t.Fatal(err)
	} else if string(content) != "module.exports = 1\n" {
		t.Errorf("restored content = %q", content)
	}
}

// A file changed while in quarantine must not restore silently. The digest is
// the only thing standing between "restored" and "some files are back".
func TestATamperedArchiveIsCaughtByTheDigest(t *testing.T) {
	origin := tree(t)
	store := t.TempDir()

	archive, err := Pack(origin, store, "abc123")
	if err != nil {
		t.Fatal(err)
	}

	// Unpack somewhere else, change one byte, and hash that tree: this is what a
	// restore would produce from an archive somebody edited.
	scratch := filepath.Join(t.TempDir(), "out")
	if _, err := Unpack(archive.Path, scratch); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(scratch, "lib", "index.js"), "module.exports = 666\n", 0o644)

	after, err := Digest(scratch)
	if err != nil {
		t.Fatal(err)
	}
	if after == archive.Digest {
		t.Error("a changed file produced the same digest — the check is not checking anything")
	}
}

// The executable bit changes what a file does, so it is part of the digest.
func TestTheExecutableBitIsPartOfTheDigest(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod is not meaningful on Windows")
	}
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "run.sh"), "echo hi\n", 0o755)

	before, err := Digest(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "run.sh"), 0o644); err != nil {
		t.Fatal(err)
	}
	after, err := Digest(root)
	if err != nil {
		t.Fatal(err)
	}
	if before == after {
		t.Error("dropping the executable bit did not change the digest")
	}
}

// An archive is a file on disk in a directory a person can reach. An extractor
// that trusts its entries is how a tarball writes outside the directory it was
// asked to fill.
//
// The assertion is containment, not refusal, because those are the same thing
// only on Windows. A backslash is a path separator there and an ordinary
// filename character on Unix, so `..\escape.txt` is a traversal on one platform
// and a legally-named file on the other — and safeJoin is right to accept it on
// Unix, where it lands inside the directory. Asserting the refusal instead is
// what made this pass on Windows and fail in Linux CI.
//
// Refusing backslashes everywhere would square that, and would also break the
// promise restore exists for: Pack would archive a Unix file named `foo\bar`
// that restore then would not put back.
func TestAnArchiveCannotWriteOutsideTheRestoreDirectory(t *testing.T) {
	hostile := []string{
		"../escape.txt",
		"../../../../etc/passwd",
		"/etc/passwd",
		"sub/../../escape.txt",
		`..\escape.txt`,
		`..\..\escape.txt`,
		`C:\Windows\system32\drivers\etc\hosts`,
		"",
		".",
		"..",
	}

	for _, name := range hostile {
		dir := t.TempDir()
		got, err := safeJoin(dir, name)
		if err != nil {
			continue // refused outright, which is always an acceptable answer
		}

		// Accepted, so it must be inside the directory. Resolved on both sides
		// because a temp dir can be a symlink (/var on macOS), and comparing an
		// unresolved prefix would call a contained path an escape.
		realDir, err := filepath.EvalSymlinks(dir)
		if err != nil {
			t.Fatal(err)
		}
		rel, err := filepath.Rel(realDir, got)
		if err != nil {
			t.Errorf("entry %q was accepted as %q, which is not under %q", name, got, realDir)
			continue
		}
		if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			t.Errorf("entry %q escaped: %q is outside %q", name, got, realDir)
		}
	}
}

// The separator-specific half, where the platform decides the answer.
func TestBackslashIsATraversalOnlyOnWindows(t *testing.T) {
	_, err := safeJoin(t.TempDir(), `..\escape.txt`)

	if runtime.GOOS == "windows" {
		if err == nil {
			t.Error(`..\escape.txt was accepted on Windows, where \ is a path separator`)
		}
		return
	}
	if err != nil {
		t.Errorf(`..\escape.txt was refused on %s, where \ is an ordinary filename `+
			`character — Pack can produce that name, so restore has to accept it: %v`,
			runtime.GOOS, err)
	}
}

// System and container packages are refused, and the refusal says why in terms
// of what would actually happen.
func TestSystemAndContainerPackagesAreRefused(t *testing.T) {
	if CanQuarantine("system") || CanQuarantine("container") {
		t.Fatal("a scope that cannot be quarantined is reported as quarantinable")
	}
	for _, scope := range []string{"global", "project", "venv"} {
		if !CanQuarantine(scope) {
			t.Errorf("%s should be quarantinable", scope)
		}
	}

	err := ErrScope{Scope: "system", PURL: "pkg:deb/ubuntu/openssl@3.0.2", Path: "/var/lib/dpkg/status"}
	if got := err.Error(); got == "" || !contains(got, "/var/lib/dpkg/status") {
		t.Errorf("refusal = %q, want it to name the path it would have destroyed", got)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) &&
		(haystack == needle || len(needle) == 0 ||
			indexOf(haystack, needle) >= 0)
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
