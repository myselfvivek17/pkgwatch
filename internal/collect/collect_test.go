package collect_test

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/myselfvivek17/pkgwatch/internal/collect"
	"github.com/myselfvivek17/pkgwatch/internal/match"
)

// write creates a file and every directory above it.
func write(t *testing.T, path, content string) {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// byPURL indexes a result so assertions do not depend on walk order.
func byPURL(result collect.Result) map[string]collect.Package {
	out := make(map[string]collect.Package, len(result.Packages))
	for _, pkg := range result.Packages {
		out[pkg.PURL()] = pkg
	}
	return out
}

func TestNPMCollectsScopedNestedAndScripted(t *testing.T) {
	root := filepath.Join(t.TempDir(), "node_modules")

	write(t, filepath.Join(root, "lodash", "package.json"),
		`{"name":"lodash","version":"4.17.21"}`)

	// Scoped packages live one level deeper, under the scope directory.
	write(t, filepath.Join(root, "@ctrl", "tinycolor", "package.json"),
		`{"name":"@ctrl/tinycolor","version":"4.1.2"}`)

	// A lifecycle script is the mechanism nearly every npm supply-chain attack
	// uses, so it has to be recorded.
	write(t, filepath.Join(root, "esbuild", "package.json"),
		`{"name":"esbuild","version":"0.20.0","scripts":{"postinstall":"node install.js"}}`)

	// npm hoists what it can; a version conflict leaves a copy nested under its
	// parent, and that copy is just as installed as any other.
	write(t, filepath.Join(root, "esbuild", "node_modules", "ms", "package.json"),
		`{"name":"ms","version":"2.0.0"}`)

	// Not a package. npm leaves these behind and they must not be counted as
	// unreadable.
	if err := os.MkdirAll(filepath.Join(root, ".bin"), 0o755); err != nil {
		t.Fatal(err)
	}

	result := collect.NPM(root, match.ScopeProject, nil)
	found := byPURL(result)

	for _, want := range []string{
		"pkg:npm/lodash@4.17.21",
		"pkg:npm/%40ctrl/tinycolor@4.1.2",
		"pkg:npm/esbuild@0.20.0",
		"pkg:npm/ms@2.0.0",
	} {
		if _, ok := found[want]; !ok {
			t.Errorf("missing %s; found %v", want, keys(found))
		}
	}
	if len(found) != 4 {
		t.Errorf("found %d packages, want 4: %v", len(found), keys(found))
	}
	if !found["pkg:npm/esbuild@0.20.0"].HasScripts {
		t.Error("esbuild has a postinstall script and must be recorded as such")
	}
	if found["pkg:npm/lodash@4.17.21"].HasScripts {
		t.Error("lodash has no lifecycle script")
	}
	if result.Skipped != 0 {
		t.Errorf("Skipped = %d; .bin is not a package and must not count as unreadable", result.Skipped)
	}
}

// A package.json that exists but cannot be understood is a gap in coverage and
// has to be counted, not swallowed.
func TestNPMCountsUnreadableManifests(t *testing.T) {
	root := filepath.Join(t.TempDir(), "node_modules")
	write(t, filepath.Join(root, "broken", "package.json"), `{not json`)
	write(t, filepath.Join(root, "nameless", "package.json"), `{"version":"1.0.0"}`)

	result := collect.NPM(root, match.ScopeProject, nil)
	if len(result.Packages) != 0 {
		t.Errorf("got %d packages from unusable manifests", len(result.Packages))
	}
	if result.Skipped != 2 {
		t.Errorf("Skipped = %d, want 2", result.Skipped)
	}
}

func TestNPMMissingRootIsNotAnError(t *testing.T) {
	result := collect.NPM(filepath.Join(t.TempDir(), "nope"), match.ScopeProject, nil)
	if len(result.Packages) != 0 || result.Skipped != 0 {
		t.Errorf("a machine with no node_modules is normal: %+v", result)
	}
}

func TestPythonReadsBothMetadataLayouts(t *testing.T) {
	site := t.TempDir()

	// PEP 376, what pip writes today. The body after the blank line is the long
	// description and can be a megabyte of README — it must not be parsed as
	// headers.
	write(t, filepath.Join(site, "requests-2.31.0.dist-info", "METADATA"),
		"Metadata-Version: 2.1\nName: requests\nVersion: 2.31.0\n"+
			"Summary: Python HTTP for Humans.\n\nName: NOT-THIS\nVersion: 9.9.9\n")

	// What setuptools left behind, still present in older environments — which
	// are the ones most likely to be carrying something unpatched.
	write(t, filepath.Join(site, "legacy_pkg.egg-info", "PKG-INFO"),
		"Metadata-Version: 1.0\nName: legacy-pkg\nVersion: 0.4.2\n")

	// Not distribution metadata.
	if err := os.MkdirAll(filepath.Join(site, "requests"), 0o755); err != nil {
		t.Fatal(err)
	}

	result := collect.Python(site, match.ScopeSystem, nil)
	found := byPURL(result)

	if pkg, ok := found["pkg:pypi/requests@2.31.0"]; !ok {
		t.Errorf("requests not found: %v", keys(found))
	} else if pkg.Scope != match.ScopeSystem {
		t.Errorf("Scope = %q", pkg.Scope)
	}
	// PEP 503 folds the name, which is what makes the advisory lookup match.
	if _, ok := found["pkg:pypi/legacy-pkg@0.4.2"]; !ok {
		t.Errorf("egg-info package not found: %v", keys(found))
	}
	if len(found) != 2 {
		t.Errorf("found %d, want 2: %v", len(found), keys(found))
	}
}

// The scan skips directories whose mtime matches what was recorded, which is
// what turns a multi-second scan into a sub-second one.
func TestKnownMTimeSkipsUnchangedDirectories(t *testing.T) {
	root := filepath.Join(t.TempDir(), "node_modules")
	write(t, filepath.Join(root, "lodash", "package.json"),
		`{"name":"lodash","version":"4.17.21"}`)

	first := collect.NPM(root, match.ScopeProject, nil)
	if len(first.Packages) != 1 {
		t.Fatalf("first scan found %d packages", len(first.Packages))
	}

	known := collect.Known{first.Packages[0].InstallDir: first.Packages[0].DirMTime}
	second := collect.NPM(root, match.ScopeProject, known)

	if len(second.Packages) != 0 {
		t.Errorf("unchanged package was re-read: %+v", second.Packages)
	}
	if second.Unchanged != 1 {
		t.Errorf("Unchanged = %d, want 1", second.Unchanged)
	}
}

func TestFindRootsStopsAtNodeModulesAndVenvs(t *testing.T) {
	project := t.TempDir()

	write(t, filepath.Join(project, "app", "node_modules", "lodash", "package.json"), `{}`)
	// A nested node_modules belongs to the package above it; the npm collector
	// recurses, so the walk must not report it separately.
	write(t, filepath.Join(project, "app", "node_modules", "lodash", "node_modules", "x", "package.json"), `{}`)

	// PEP 405 makes pyvenv.cfg the marker, and the conventional name starts with
	// a dot — so this has to be recognised before the dot-directory rule.
	write(t, filepath.Join(project, ".venv", "pyvenv.cfg"), "home = /usr\n")

	// .git is usually most of the files on disk and holds nothing installable.
	write(t, filepath.Join(project, ".git", "objects", "ab", "cdef"), "x")

	roots := collect.FindRoots(project)

	if len(roots.NodeModules) != 1 {
		t.Errorf("NodeModules = %v, want exactly the outer one", roots.NodeModules)
	}
	if len(roots.Venvs) != 1 {
		t.Errorf("Venvs = %v, want the dot-prefixed virtualenv", roots.Venvs)
	}
}

func TestIsVirtualenv(t *testing.T) {
	dir := t.TempDir()
	if collect.IsVirtualenv(dir) {
		t.Error("an empty directory is not a virtualenv")
	}
	write(t, filepath.Join(dir, "pyvenv.cfg"), "home = /usr\n")
	if !collect.IsVirtualenv(dir) {
		t.Error("pyvenv.cfg is the PEP 405 marker")
	}
}

func keys(m map[string]collect.Package) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
