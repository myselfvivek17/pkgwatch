package collect

import (
	"log/slog"
	"os"

	"github.com/myselfvivek17/pkgwatch/internal/match"
)

// SystemDistro reads the packages installed on this machine itself.
//
// The Docker collector reads what is inside containers; without this, the host
// running them is the one machine nobody looks at. That is backwards: on a
// server the host is where the exposed services and the SSH daemon live, and
// its openssl is the one an attacker reaches first.
//
// Same files as the container collector, read off the local filesystem rather
// than out of a tar stream, and parsed by the same code. Nothing is executed:
// `dpkg-query` and `apk info` would both be a subprocess, and the database they
// read is right there.
func SystemDistro(known Known) Result {
	var out Result

	release, err := os.ReadFile("/etc/os-release")
	if err != nil {
		// Not a Linux machine, or one whose distribution does not say so.
		return out
	}

	ecosystem, dbPath := ecosystemFromOSRelease(release)
	if ecosystem == "" {
		slog.Debug("collect: host distribution is not one pkgwatch matches")
		return out
	}

	info, err := os.Stat(dbPath)
	if err != nil {
		return out
	}
	mtime := info.ModTime().Unix()

	// Deliberately not skipped on an unchanged mtime, unlike the npm and Python
	// collectors. The whole machine's packages come from this one file, so the
	// saving is a single read of about a megabyte — and the cost of caching it
	// was real: when the Ubuntu ecosystem string gained its :LTS suffix, every
	// host kept its old rows because the file had not been touched, and the fix
	// silently did nothing. A cache keyed on a timestamp cannot notice that the
	// code reading it changed.
	raw, err := os.ReadFile(dbPath)
	if err != nil {
		slog.Warn("collect: cannot read the host package database", "path", dbPath, "error", err)
		out.Skipped++
		return out
	}

	var parsed []distroPackage
	if dbPath == "/lib/apk/db/installed" {
		parsed = parseAPKInstalled(raw)
	} else {
		parsed = parseDpkgStatus(raw)
	}

	for _, item := range parsed {
		out.add(Package{
			Ecosystem: ecosystem,
			Name:      item.name,
			Version:   item.version,
			Scope:     match.ScopeSystem,
			// Every host package shares the database it came from, which is
			// deliberate: it exists, so the presence check keeps them, and a
			// package removed between scans is retired by the same rule that
			// retires a version replaced in place.
			InstallDir: dbPath,
			DirMTime:   mtime,
		})
	}
	return out
}
