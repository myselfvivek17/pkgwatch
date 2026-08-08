// Package agent runs the local watchdog: registry gates, inventory, and the
// machine-local dashboard.
//
// The agent never depends on the hub. Hub down, hub unreachable, hub never
// configured — everything here still works (§0, hard rule 1).
package agent

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/myselfvivek17/pkgwatch/internal/buildinfo"
	"github.com/myselfvivek17/pkgwatch/internal/config"
	"github.com/myselfvivek17/pkgwatch/internal/daemon"
	"github.com/myselfvivek17/pkgwatch/internal/db"
	"github.com/myselfvivek17/pkgwatch/internal/repo"
	"github.com/myselfvivek17/pkgwatch/internal/web"
)

// State is an opened agent database plus whatever the advisory bundle told us.
type State struct {
	DB              *sql.DB
	Repo            repo.Agent
	BundleAttached  bool
	Bundle          repo.BundleInfo
	Paired          bool
	HubURL          string
	Hostname        string
	AdvisoryDBPath  string
	warnBundleError error
}

// Open prepares the agent's local state. A missing advisory bundle is normal on
// a fresh machine and must not be fatal.
func Open(cfg config.Config) (*State, error) {
	handle, err := db.Open(cfg.AgentDBPath(), db.SchemaAgent)
	if err != nil {
		return nil, err
	}

	st := &State{
		DB:             handle,
		Repo:           repo.Agent{DB: handle},
		Hostname:       hostname(),
		AdvisoryDBPath: cfg.AdvisoryDBPath(),
	}

	attached, err := db.AttachAdvisories(handle, cfg.AdvisoryDBPath())
	if err != nil {
		// A bundle that exists but will not attach is worth surfacing, but the
		// agent still gates and still records — degraded, not dead.
		st.warnBundleError = err
		slog.Warn("advisory bundle present but unusable", "error", err)
	}
	st.BundleAttached = attached

	if info, err := repo.Bundle(handle, attached); err == nil {
		st.Bundle = info
	} else {
		st.warnBundleError = err
		st.BundleAttached = false
		slog.Warn("advisory bundle metadata unreadable", "error", err)
	}

	token, err := st.Repo.HubState("token")
	if err != nil {
		handle.Close()
		return nil, fmt.Errorf("read pairing state: %w", err)
	}
	st.Paired = token != ""
	if st.HubURL, err = st.Repo.HubState("hub_url"); err != nil {
		handle.Close()
		return nil, fmt.Errorf("read hub url: %w", err)
	}
	if st.HubURL == "" {
		st.HubURL = cfg.Agent.HubURL
	}

	return st, nil
}

func (s *State) Close() error { return s.DB.Close() }

// BundleWarning reports a bundle that exists but could not be used, or nil.
func (s *State) BundleWarning() error { return s.warnBundleError }

// Run serves the agent's local dashboard.
//
// The gate proxies (:4873 / :4874), inventory scanning and hub sync are not
// built yet; this is the M0/M0.5 surface only.
func Run(ctx context.Context, cfg config.Config) error {
	st, err := Open(cfg)
	if err != nil {
		return err
	}
	defer st.Close()

	srv, err := web.New(web.ModeAgent, st.Hostname)
	if err != nil {
		return err
	}
	srv.Paired = st.Paired
	srv.HubLabel = st.HubURL

	started := time.Now()
	listenLabel := ""

	srv.Overview = func() (web.OverviewData, error) {
		counts, err := st.Repo.FindingCounts()
		if err != nil {
			return web.OverviewData{}, err
		}
		packages, err := st.Repo.PackageCount()
		if err != nil {
			return web.OverviewData{}, err
		}
		return web.OverviewData{
			Mode:     "agent",
			Version:  buildinfo.Version,
			Commit:   buildinfo.Commit,
			DataDir:  cfg.DataDir,
			Listen:   listenLabel,
			Packages: packages,
			Bundle:   st.Bundle,
			Findings: counts,
		}, nil
	}

	router := chi.NewRouter()
	router.Get("/health", daemon.HealthHandler("agent", started, func() (bool, string) {
		return st.DB.PingContext(ctx) == nil, st.Bundle.Version
	}))
	srv.Routes(router)

	ln, err := daemon.Listen(cfg.Agent.Bind, cfg.Agent.DashboardPort, config.DashboardPortAlt)
	if err != nil {
		return err
	}
	listenLabel = ln.Addr().String()
	slog.Info("agent dashboard listening", "addr", listenLabel, "hostname", st.Hostname)

	return daemon.Serve(ctx, &http.Server{
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
	}, ln)
}

func hostname() string {
	name, err := os.Hostname()
	if err != nil || name == "" {
		return "unknown-host"
	}
	return name
}
