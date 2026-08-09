// Package collect finds what is already installed on this machine.
//
// The gate only ever sees a package at the moment you install it. Everything
// that was here before pkgwatch, and everything installed while it was not
// running, is invisible until something walks the disk and says so — which is
// what this package does.
//
// Two rules shape the collectors.
//
// Nothing here executes anything it finds. Python metadata is parsed straight
// out of `*.dist-info/METADATA` rather than by asking each interpreter, because
// asking means running that interpreter — which on a machine that may already
// be compromised is precisely the thing not to do, and is slow besides.
//
// Nothing here deletes. A package that has been uninstalled keeps its row: the
// timeline needs to be able to say "you had this when the advisory landed", and
// a row removed on the day of uninstall takes that answer with it.
package collect

import (
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/myselfvivek17/pkgwatch/internal/match"
)

// Package is one installed thing, as found on disk.
type Package struct {
	Ecosystem  string
	Name       string
	Version    string
	Scope      string // global | project | venv | system | container
	InstallDir string
	HasScripts bool

	// DirMTime is the modification time of InstallDir, kept so the next scan can
	// skip parsing anything that has not changed.
	DirMTime int64
}

// PURL is how this package is named everywhere else in pkgwatch.
func (p Package) PURL() string { return match.PURL(p.Ecosystem, p.Name, p.Version) }

// Result is what one scan found.
type Result struct {
	Packages []Package

	// Skipped counts directories that looked like packages but could not be
	// read. Reported rather than swallowed: a scan that quietly covers less of
	// the disk than you think reads as a clean machine.
	Skipped int

	// Unchanged counts packages skipped because their directory mtime matched
	// what the last scan recorded.
	Unchanged int

	// Gone counts inventory rows retired because the package is no longer
	// installed. Filled in by the caller, which is what reconciles against the
	// filesystem.
	Gone int

	// Copies counts installs collapsed into a row that already existed — the
	// same version present in more than one place. Filled in by the caller that
	// does the collapsing, since the inventory's key is what decides it.
	Copies int
}

func (r *Result) add(pkgs ...Package) { r.Packages = append(r.Packages, pkgs...) }

// Merge folds another result in.
func (r *Result) Merge(other Result) {
	r.Packages = append(r.Packages, other.Packages...)
	r.Skipped += other.Skipped
	r.Unchanged += other.Unchanged
	r.Copies += other.Copies
}

// Known is the mtime of every install directory the last scan recorded, keyed
// by directory. A scan consults it to avoid re-reading metadata that cannot
// have changed.
type Known map[string]int64

// unchanged reports whether dir can be skipped, given its current mtime.
func (k Known) unchanged(dir string, mtime int64) bool {
	if k == nil {
		return false
	}
	previous, seen := k[dir]
	return seen && previous == mtime && mtime != 0
}

func dirMTime(dir string) int64 {
	info, err := os.Stat(dir)
	if err != nil {
		return 0
	}
	return info.ModTime().Unix()
}

// Now is overridable in tests.
var Now = time.Now

// walkLimit bounds how deep a project scan descends looking for dependency
// directories.
//
// ponytail: a depth cap rather than a cleverer heuristic. Project trees are
// shallow and the pathological case — pointing a scan at a home directory — is
// what actually needs bounding. Raise it if a real layout is missed.
const walkLimit = 8

// Roots are the dependency directories one project tree contains.
type Roots struct {
	NodeModules []string
	Venvs       []string
}

// FindRoots walks a project tree once and reports every node_modules and every
// virtualenv under it.
//
// One walk rather than one per ecosystem: the walk is the expensive part, and a
// project tree with a node_modules in it is mostly node_modules.
func FindRoots(root string) Roots {
	var found Roots

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// An unreadable directory is not a reason to abandon the scan. Most
			// of these on Windows are junctions into protected system state.
			return fs.SkipDir
		}
		if !d.IsDir() {
			return nil
		}

		// Checked before the dot-directory rule below, because the conventional
		// name for a virtualenv is .venv.
		if IsVirtualenv(path) {
			found.Venvs = append(found.Venvs, path)
			return fs.SkipDir
		}

		name := d.Name()
		if name == "node_modules" {
			// Do not descend: nested node_modules belong to the packages inside
			// this one, and the npm collector already recurses into them.
			found.NodeModules = append(found.NodeModules, path)
			return fs.SkipDir
		}
		// Skipping dot-directories keeps .git out of the walk, which on a large
		// repository is most of the files on disk.
		if len(name) > 1 && name[0] == '.' {
			return fs.SkipDir
		}
		if depthBelow(root, path) >= walkLimit {
			return fs.SkipDir
		}
		return nil
	})
	if err != nil {
		slog.Warn("collect: walk ended early", "root", root, "error", err)
	}
	return found
}

func depthBelow(root, path string) int {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return 0
	}
	if rel == "." {
		return 0
	}
	depth := 1
	for _, r := range rel {
		if r == filepath.Separator || r == '/' {
			depth++
		}
	}
	return depth
}
