package collect

import (
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/myselfvivek17/pkgwatch/internal/match"
)

// Everything scans the machine-wide installs plus each project tree given.
//
// Machine-wide is scanned unconditionally because it is small, bounded and the
// highest-risk scope: a globally installed package is on your PATH, which is
// why it carries a score multiplier (§5.2).
//
// Project trees are only scanned where asked. There is no safe default for
// "where do this person's projects live", and walking a home directory to guess
// would be slow enough that nobody would run it twice.
func Everything(projectRoots []string, known Known) Result {
	var out Result
	out.Merge(Global(known))

	for _, root := range projectRoots {
		out.Merge(Project(root, known))
	}
	return out
}

// Global scans installs that are not tied to any project: the npm global root
// and the site-packages of every interpreter on PATH.
func Global(known Known) Result {
	var out Result

	if root := NPMGlobalRoot(); root != "" {
		slog.Debug("collect: npm global root", "path", root)
		out.Merge(NPM(root, match.ScopeGlobal, known))
	}

	for _, sitePackages := range SystemSitePackages() {
		slog.Debug("collect: site-packages", "path", sitePackages)
		out.Merge(Python(sitePackages, match.ScopeSystem, known))
	}
	return out
}

// Project scans one project tree.
func Project(root string, known Known) Result {
	var out Result

	roots := FindRoots(root)
	for _, dir := range roots.NodeModules {
		out.Merge(NPM(dir, match.ScopeProject, known))
	}
	for _, venv := range roots.Venvs {
		for _, sitePackages := range SitePackages(venv) {
			out.Merge(Python(sitePackages, match.ScopeVenv, known))
		}
	}
	return out
}

// SystemSitePackages locates the site-packages of the Python installations on
// PATH.
//
// The interpreter is located, never run. Its prefix is derived from where the
// executable sits — the directory itself on Windows, its parent on POSIX, where
// binaries live in <prefix>/bin.
func SystemSitePackages() []string {
	seen := map[string]bool{}
	var found []string

	for _, name := range pythonExecutables() {
		path, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		// Resolve symlinks so /usr/bin/python3 and /usr/local/bin/python3
		// pointing at the same install are not scanned twice.
		if resolved, err := filepath.EvalSymlinks(path); err == nil {
			path = resolved
		}

		prefix := filepath.Dir(path)
		if runtime.GOOS != "windows" {
			prefix = filepath.Dir(prefix) // .../bin/python3 → ...
		}

		for _, sitePackages := range SitePackages(prefix) {
			if !seen[sitePackages] {
				seen[sitePackages] = true
				found = append(found, sitePackages)
			}
		}
	}

	// On Windows, pip installs into a per-user directory that is not under any
	// interpreter prefix, and it is where most things actually land.
	for _, extra := range userSitePackages() {
		if isDir(extra) && !seen[extra] {
			seen[extra] = true
			found = append(found, extra)
		}
	}
	return found
}

func pythonExecutables() []string {
	if runtime.GOOS == "windows" {
		return []string{"python", "python3", "py"}
	}
	return []string{"python3", "python"}
}

// userSitePackages covers the per-user install location, which is separate from
// any interpreter prefix and is where `pip install --user` lands.
func userSitePackages() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}

	if runtime.GOOS == "windows" {
		roaming := os.Getenv("APPDATA")
		if roaming == "" {
			return nil
		}
		// %APPDATA%\Python\PythonXY\site-packages — the version is in the
		// directory name, so enumerate rather than guess it.
		var found []string
		base := filepath.Join(roaming, "Python")
		entries, err := os.ReadDir(base)
		if err != nil {
			return nil
		}
		for _, entry := range entries {
			if entry.IsDir() {
				found = append(found, filepath.Join(base, entry.Name(), "site-packages"))
			}
		}
		return found
	}

	if runtime.GOOS == "darwin" {
		return globSitePackages(filepath.Join(home, "Library", "Python"))
	}
	return globSitePackages(filepath.Join(home, ".local", "lib"))
}

// globSitePackages returns <base>/<anything>/{site-packages,lib/python*/site-packages}.
func globSitePackages(base string) []string {
	entries, err := os.ReadDir(base)
	if err != nil {
		return nil
	}

	var found []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		direct := filepath.Join(base, entry.Name(), "site-packages")
		if isDir(direct) {
			found = append(found, direct)
		}
		found = append(found, SitePackages(filepath.Join(base, entry.Name()))...)
	}
	return found
}
