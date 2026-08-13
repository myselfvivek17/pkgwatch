package agent

import (
	"context"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/myselfvivek17/pkgwatch/internal/config"
	"github.com/myselfvivek17/pkgwatch/internal/db"
	"github.com/myselfvivek17/pkgwatch/internal/repo"
	"github.com/myselfvivek17/pkgwatch/internal/scanner"
)

// startupDelay lets the daemon finish binding its ports before the first scan.
//
// A scan is cheap but not free, and a machine that has just booted is usually
// busy. Being ready to gate an install matters more in that first minute than
// being current about an advisory.
const startupDelay = 30 * time.Second

// runPeriodicScans re-scans and re-matches on an interval until ctx ends.
//
// This is what makes the retroactive half of pkgwatch work at all. The gate
// protects an install as it happens; everything already on the machine is only
// re-examined by a pass nobody triggered, and a tool that requires you to
// remember to run it is a tool that answers questions you already thought to
// ask.
func runPeriodicScans(ctx context.Context, cfg config.Config, lease *Lease) {
	interval := time.Duration(cfg.Agent.ScanIntervalHours) * time.Hour
	if interval <= 0 {
		slog.Info("periodic scanning disabled (scan_interval_hours = 0)")
		return
	}

	roots, err := absolutePaths(cfg.Agent.ScanPaths)
	if err != nil {
		slog.Error("scan_paths is unusable, scanning machine-wide only", "error", err)
		roots = nil
	}
	slog.Info("periodic scanning enabled", "every", interval, "project_roots", len(roots))

	select {
	case <-time.After(startupDelay):
	case <-ctx.Done():
		return
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		// A scan opens its own handle and attaches the advisory database for as
		// long as it runs, so it is a reader like any other: a bundle swap waits
		// for it rather than pulling the file out from under it. Scans take
		// seconds and updates come hours apart, so the wait is theoretical.
		lease.Read(func() error {
			scanOnce(cfg, roots)
			return nil
		})
		select {
		case <-ticker.C:
		case <-ctx.Done():
			return
		}
	}
}

// scanOnce runs one pass on its own database handle.
//
// Its own handle, not the dashboard's or the gate's: a scan writes for as long
// as it takes to walk the disk, and db.Open pins each handle to a single
// connection. Sharing one would mean an install waiting on an inventory pass.
func scanOnce(cfg config.Config, roots []string) {
	handle, err := db.Open(cfg.AgentDBPath(), db.SchemaAgent)
	if err != nil {
		slog.Error("scheduled scan could not open the database", "error", err)
		return
	}
	defer handle.Close()

	attached, err := db.AttachAdvisories(handle, cfg.AdvisoryDBPath())
	if err != nil {
		slog.Warn("scheduled scan: advisory bundle unusable", "error", err)
		attached = false
	}
	bundleInfo, err := repo.Bundle(handle, attached)
	if err != nil {
		slog.Warn("scheduled scan: advisory metadata unreadable", "error", err)
		bundleInfo = repo.BundleInfo{}
	}

	store := repo.Agent{DB: handle}
	outcome, err := scanner.Run(handle, store, bundleInfo, cfg, roots, false)
	if err != nil {
		slog.Error("scheduled scan failed", "error", err)
		return
	}

	// Logged at info even when nothing changed. A scheduled task that is running
	// and finding nothing looks exactly like one that stopped running a month
	// ago, and the whole point of this is that nobody is watching.
	slog.Info("scheduled scan complete",
		"elapsed", outcome.Elapsed.Round(time.Millisecond),
		"new", outcome.Inserted, "seen_again", outcome.Updated,
		"retired", outcome.Gone, "matched", outcome.Matched,
		"new_findings", outcome.Watch.New, "resolved", outcome.Watch.Resolved)

	if !outcome.Matched {
		slog.Warn("scheduled scan recorded an inventory but matched nothing — no advisory bundle")
	}
	if len(outcome.Watch.Uncovered) > 0 {
		slog.Warn("scheduled scan left packages unexamined — the bundle carries no advisories for them",
			"ecosystems", outcome.Watch.Uncovered)
	}
	if outcome.Watch.New > 0 {
		slog.Warn("new findings recorded", "count", outcome.Watch.New)
	}
}

func absolutePaths(paths []string) ([]string, error) {
	out := make([]string, 0, len(paths))
	for _, path := range paths {
		absolute, err := filepath.Abs(path)
		if err != nil {
			return nil, err
		}
		out = append(out, absolute)
	}
	return out, nil
}
