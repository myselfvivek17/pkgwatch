package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/myselfvivek17/pkgwatch/internal/bundlesync"
	"github.com/myselfvivek17/pkgwatch/internal/config"
	"github.com/myselfvivek17/pkgwatch/internal/db"
	"github.com/myselfvivek17/pkgwatch/internal/repo"
	"github.com/myselfvivek17/pkgwatch/internal/watch"
)

// bundleStartupDelay lets the gates bind before the first bundle check. Being
// ready to block an install matters more in the first minute than being current
// about an advisory published overnight.
const bundleStartupDelay = 2 * time.Minute

// runBundleUpdates keeps this machine's advisories current, on a schedule.
//
// Without it advisories only move when somebody remembers to type `pkgwatch
// sync`, and a watchdog matching against a corpus that stopped ageing looks
// exactly like a quiet week — the same failure as an agent that has stopped
// running, with none of the symptoms. It runs in the daemon rather than as
// another scheduled task because the daemon is the process holding the merged
// database open: it is the only one that can stand its own readers down and
// replace the file underneath them.
func runBundleUpdates(ctx context.Context, cfg config.Config, lease *Lease) {
	interval := time.Duration(cfg.Agent.BundleIntervalHours) * time.Hour
	if interval <= 0 {
		slog.Info("automatic bundle updates disabled (bundle_interval_hours = 0)")
		return
	}
	slog.Info("automatic bundle updates enabled", "every", interval)

	select {
	case <-time.After(bundleStartupDelay):
	case <-ctx.Done():
		return
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		updateBundlesOnce(cfg, lease)
		select {
		case <-ticker.C:
		case <-ctx.Done():
			return
		}
	}
}

// updateBundlesOnce pulls from the hub, swaps the merged database and re-matches.
func updateBundlesOnce(cfg config.Config, lease *Lease) {
	handle, err := db.Open(cfg.AgentDBPath(), db.SchemaAgent)
	if err != nil {
		slog.Error("bundle update could not open the database", "error", err)
		return
	}
	store := repo.Agent{DB: handle}
	client, err := HubClient(store)
	handle.Close()
	if err != nil {
		slog.Error("bundle update could not load the pairing", "error", err)
		return
	}

	report, err := bundlesync.FromHub(cfg, client, bundlesync.Options{Swap: lease.Swap})
	if errors.Is(err, bundlesync.ErrNoHub) {
		// The normal state for a machine that runs on its own. Said once at
		// debug rather than every six hours at warning.
		slog.Debug("no hub paired, so no bundles to pull")
		return
	}
	if err != nil {
		// A hub that is down is ordinary and costs the agent nothing; a bundle
		// that is refused is not. Both are worth a line, because the alternative
		// is an agent whose advisories quietly stopped moving.
		slog.Warn("bundle update failed, advisories are unchanged", "error", err)
		return
	}

	// Said before the early return, because the case it describes is exactly the
	// one where nothing was installed: an ecosystem this machine runs that no
	// bundle in the fleet covers is unexamined everywhere, and "bundles already
	// current" is the most misleading possible line to end on.
	if len(report.Unavailable) > 0 {
		slog.Warn("NO BUNDLE ANYWHERE for these, so packages from them are unexamined rather than clean",
			"ecosystems", strings.Join(report.Unavailable, ", "))
	}

	if !report.Rebuilt {
		slog.Info("bundles already current", "offered", report.Offered, "skipped", len(report.Skipped))
		return
	}

	slog.Info("advisories updated",
		"installed", report.Installed, "records", report.Merged.RecordCount,
		"covers", strings.Join(report.Covers, ", "))
	if len(report.NotRelayed) > 0 {
		// A scope the hub does not carry stays frozen at whatever this machine
		// last had, and every other line here reads as "updated".
		slog.Warn("NOT RELAYED by the hub, these scopes are unchanged",
			"scopes", strings.Join(report.NotRelayed, ", "))
	}

	rematch(cfg, report)
}

// rematch runs the watcher against the bundle that just landed.
//
// A new bundle is one of only two things that can change what is true about a
// package already installed, the other being a scan. Skipping this would mean
// an advisory published this morning sits on disk until the next scan hours
// later — the bundle arrived and nothing looked at it.
func rematch(cfg config.Config, report bundlesync.Report) {
	st, err := Open(cfg)
	if err != nil {
		slog.Error("could not reopen after a bundle update", "error", err)
		return
	}
	defer st.Close()

	now := time.Now()
	if err := st.Repo.RecordEvent(repo.EventFeedSync, "", "", "", map[string]any{
		"bundle":  st.Bundle.Version,
		"records": fmt.Sprint(st.Bundle.RecordCount),
		"covers":  strings.Join(st.Bundle.CoveredScopes(), ", "),
		"source":  "hub relay",
	}, now); err != nil {
		slog.Warn("could not record the bundle update", "error", err)
	}

	if !st.BundleAttached {
		slog.Error("advisories were updated but the merged database will not attach — nothing was matched")
		return
	}
	watched, err := watch.Run(st.DB, st.Repo, st.Bundle, now)
	if err != nil {
		slog.Error("could not match against the new bundle", "error", err)
		return
	}
	slog.Info("matched against the new bundle",
		"examined", watched.Examined, "new_findings", watched.New,
		"resolved", watched.Resolved, "reopened", watched.Reopened)
	if len(watched.Uncovered) > 0 {
		slog.Warn("NOT EXAMINED: the bundle carries no advisories for these",
			"ecosystems", strings.Join(watched.Uncovered, ", "))
	}
}
