package gate

import (
	"database/sql"
	"log/slog"
	"time"

	"github.com/myselfvivek17/pkgwatch/internal/bundle"
	"github.com/myselfvivek17/pkgwatch/internal/config"
	"github.com/myselfvivek17/pkgwatch/internal/db"
	"github.com/myselfvivek17/pkgwatch/internal/repo"
)

// Open builds a gate on its own database handle.
//
// A missing or unreadable bundle is not an error here. It leaves the gate
// degraded, which every request then records — a machine that has never synced
// must not silently look like a machine with nothing wrong.
func Open(cfg config.Config) (*Gate, error) {
	handle, err := db.Open(cfg.AgentDBPath(), db.SchemaAgent)
	if err != nil {
		return nil, err
	}

	attached, err := db.AttachAdvisories(handle, cfg.AdvisoryDBPath())
	if err != nil {
		slog.Warn("gate: advisory bundle present but unusable", "error", err)
		attached = false
	}
	if attached {
		if err := db.CheckAdvisorySchema(handle, bundle.SchemaVersion); err != nil {
			slog.Warn("gate: advisory bundle ignored", "error", err)
			attached = false
		}
	}

	g := New(handle, cfg, attached)
	if info, err := repo.Bundle(handle, attached); err == nil {
		g.Covered = info.Ecosystems
	}
	return g, nil
}

// New wires a gate over an already-open handle, for callers that have one.
// Callers that know the bundle's coverage should set Covered.
func New(handle *sql.DB, cfg config.Config, bundleAttached bool) *Gate {
	return &Gate{
		DB:             handle,
		Repo:           repo.Agent{DB: handle},
		BundleAttached: bundleAttached,
		BlockTier:      cfg.Agent.BlockTier,
		Cooldown:       time.Duration(cfg.Agent.CooldownHours) * time.Hour,
	}
}
