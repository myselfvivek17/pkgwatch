package collect

import (
	"bufio"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/myselfvivek17/pkgwatch/internal/match"
)

// Python reads installed distributions out of a site-packages directory.
//
// The metadata files are parsed directly. The alternative — running each
// interpreter and asking importlib — means executing a Python that may be the
// very thing under suspicion, once per environment, and a machine with a dozen
// virtualenvs would spend most of a scan starting interpreters.
//
// Both metadata layouts are read. `*.dist-info/METADATA` is what pip writes
// today (PEP 376); `*.egg-info/PKG-INFO` is what setuptools left behind and is
// still present in older environments, which are exactly the ones most likely to
// be carrying something unpatched.
func Python(sitePackages, scope string, known Known) Result {
	var out Result

	entries, err := os.ReadDir(sitePackages)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("collect: cannot read site-packages", "path", sitePackages, "error", err)
			out.Skipped++
		}
		return out
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		var metadataFile string
		switch {
		case strings.HasSuffix(entry.Name(), ".dist-info"):
			metadataFile = "METADATA"
		case strings.HasSuffix(entry.Name(), ".egg-info"):
			metadataFile = "PKG-INFO"
		default:
			continue
		}

		dir := filepath.Join(sitePackages, entry.Name())
		mtime := dirMTime(dir)
		if known.unchanged(dir, mtime) {
			out.Unchanged++
			continue
		}

		name, version, err := readPythonMetadata(filepath.Join(dir, metadataFile))
		if err != nil || name == "" || version == "" {
			out.Skipped++
			continue
		}

		out.add(Package{
			Ecosystem:  match.EcosystemPyPI,
			Name:       name,
			Version:    version,
			Scope:      scope,
			InstallDir: dir,
			// Python has no install-time script hook comparable to npm's: a
			// wheel is data, and setup.py only runs when building from source.
			// Recording false here is a statement, not a default.
			HasScripts: false,
			DirMTime:   mtime,
		})
	}
	return out
}

// readPythonMetadata pulls Name and Version out of an RFC 822-style metadata
// file, reading only the header block.
//
// The body after the first blank line is the package's long description, which
// can be a megabyte of README and contains nothing worth having.
func readPythonMetadata(path string) (name, version string, err error) {
	file, err := os.Open(path)
	if err != nil {
		return "", "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			break // end of headers
		}
		key, value, found := strings.Cut(line, ":")
		if !found {
			continue // a folded continuation line
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "name":
			name = strings.TrimSpace(value)
		case "version":
			version = strings.TrimSpace(value)
		}
		if name != "" && version != "" {
			break
		}
	}
	return name, version, scanner.Err()
}

// SitePackages finds the site-packages directories under a Python installation
// or virtualenv root.
//
// Derived from the layout rather than from asking the interpreter, for the same
// reason the metadata is: this must not execute anything.
//
//	Windows   <prefix>/Lib/site-packages
//	POSIX     <prefix>/lib/pythonX.Y/site-packages
func SitePackages(prefix string) []string {
	if runtime.GOOS == "windows" {
		candidate := filepath.Join(prefix, "Lib", "site-packages")
		if isDir(candidate) {
			return []string{candidate}
		}
		return nil
	}

	libDir := filepath.Join(prefix, "lib")
	entries, err := os.ReadDir(libDir)
	if err != nil {
		return nil
	}

	var found []string
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "python") {
			continue
		}
		candidate := filepath.Join(libDir, entry.Name(), "site-packages")
		if isDir(candidate) {
			found = append(found, candidate)
		}
	}
	return found
}

// IsVirtualenv reports whether dir is a virtualenv root. PEP 405 makes
// pyvenv.cfg the marker, and virtualenv writes one too.
func IsVirtualenv(dir string) bool {
	info, err := os.Stat(filepath.Join(dir, "pyvenv.cfg"))
	return err == nil && !info.IsDir()
}
