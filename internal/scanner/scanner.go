// Package scanner runs one full inventory pass: collect, reconcile, prune, match.
//
// It exists so the command and the daemon do the same thing. A scheduled scan
// that diverged from `pkgwatch scan` would mean the unattended path — the one
// nobody watches — is the one nobody tests.
package scanner

import (
	"database/sql"
	"fmt"
	"os"
	"time"

	"github.com/myselfvivek17/pkgwatch/internal/collect"
	"github.com/myselfvivek17/pkgwatch/internal/config"
	"github.com/myselfvivek17/pkgwatch/internal/match"
	"github.com/myselfvivek17/pkgwatch/internal/repo"
	"github.com/myselfvivek17/pkgwatch/internal/watch"
)

// Outcome is everything one pass did.
type Outcome struct {
	collect.Result

	Inserted int
	Updated  int
	Pruned   repo.Pruned
	Watch    watch.Report
	Matched  bool // false when there is no bundle to match against
	Elapsed  time.Duration
}

// Run collects the inventory, reconciles what is no longer installed, applies
// retention, and matches everything against the bundle.
func Run(handle *sql.DB, store repo.Agent, bundleInfo repo.BundleInfo,
	cfg config.Config, projectRoots []string, full bool) (Outcome, error) {

	var out Outcome
	started := time.Now()

	var known collect.Known
	if !full {
		mtimes, err := store.KnownMTimes()
		if err != nil {
			return out, fmt.Errorf("read previous scan state: %w", err)
		}
		known = mtimes
	}

	out.Result = collect.Everything(projectRoots, known)

	rows, copies := collapse(out.Result.Packages)
	out.Result.Copies = copies

	scanAt := time.Now()
	inserted, updated, err := store.UpsertPackages(rows, scanAt)
	if err != nil {
		return out, fmt.Errorf("record inventory: %w", err)
	}
	out.Inserted, out.Updated = inserted, updated

	if out.Result.Gone, err = reconcile(store, scanAt, out.Result.ContainersScanned); err != nil {
		return out, err
	}

	if out.Pruned, err = store.Prune(
		time.Duration(cfg.Agent.HistoryDays)*24*time.Hour, cfg.Agent.HubURL != "", scanAt); err != nil {
		return out, fmt.Errorf("apply retention: %w", err)
	}

	if bundleInfo.Attached {
		if out.Watch, err = watch.Run(handle, store, bundleInfo, scanAt); err != nil {
			return out, err
		}
		out.Matched = true
	}

	out.Elapsed = time.Since(started)
	return out, nil
}

// collapse folds duplicate installs into one row each.
//
// The inventory is keyed by purl, so the same version installed in five places
// is one row — counting the copies as five inserts would report a machine as
// carrying far more than it does.
func collapse(packages []collect.Package) ([]repo.PackageRow, int) {
	rows := make([]repo.PackageRow, 0, len(packages))
	seen := make(map[string]int, len(packages))
	copies := 0

	for _, pkg := range packages {
		purl := pkg.PURL()
		if index, dup := seen[purl]; dup {
			copies++
			// Widest scope wins: a package that is also installed globally is on
			// your PATH, and that is the fact that decides its score.
			if scopeRank(pkg.Scope) > scopeRank(rows[index].Scope) {
				rows[index].Scope = pkg.Scope
				rows[index].InstallDir = pkg.InstallDir
				rows[index].DirMTime = pkg.DirMTime
			}
			rows[index].HasScripts = rows[index].HasScripts || pkg.HasScripts
			continue
		}
		seen[purl] = len(rows)
		rows = append(rows, repo.PackageRow{
			PURL:       purl,
			Ecosystem:  pkg.Ecosystem,
			Name:       pkg.Name,
			Version:    pkg.Version,
			InstallDir: pkg.InstallDir,
			Scope:      pkg.Scope,
			HasScripts: pkg.HasScripts,
			DirMTime:   pkg.DirMTime,
		})
	}
	return rows, copies
}

// reconcile retires inventory rows for packages that are no longer installed.
//
// Two ways a package stops being installed, and both have to be caught: its
// directory disappears, or it is upgraded in place, leaving a directory that
// still exists but now holds a different version. Nothing is deleted either
// way — the timeline still has to answer what this machine was carrying when an
// advisory landed.
func reconcile(store repo.Agent, scanAt time.Time, containersScanned bool) (int, error) {
	superseded, err := store.MarkSuperseded(scanAt)
	if err != nil {
		return 0, fmt.Errorf("retire replaced packages: %w", err)
	}

	present, err := store.Present()
	if err != nil {
		return 0, err
	}

	var missing []string
	for _, item := range present {
		if item.InstallDir == "" {
			continue
		}
		// A package inside a container has no path on this filesystem, so the
		// only evidence is whether this scan found it — and that is only usable
		// when the Docker collector reached the engine. An engine that was down
		// for one scan must not make every container look emptied.
		if item.Scope == match.ScopeContainer {
			if containersScanned && item.LastSeen < scanAt.Unix() {
				missing = append(missing, item.PURL)
			}
			continue
		}
		if _, err := os.Stat(item.InstallDir); os.IsNotExist(err) {
			missing = append(missing, item.PURL)
		}
	}
	if err := store.MarkGone(missing, scanAt); err != nil {
		return 0, fmt.Errorf("retire uninstalled packages: %w", err)
	}
	return superseded + len(missing), nil
}

// scopeRank orders scopes by how much a finding in them matters (§5.2).
func scopeRank(scope string) int {
	switch scope {
	case match.ScopeGlobal:
		return 4
	case match.ScopeSystem:
		return 3
	case match.ScopeVenv:
		return 2
	default:
		return 1
	}
}
