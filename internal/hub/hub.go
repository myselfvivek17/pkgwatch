// Package hub aggregates events and findings from paired agents and serves the
// fleet dashboard.
//
// The hub is a convenience, never a dependency: killing it must leave every
// agent fully functional (§0, hard rule 1).
package hub

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net"
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

// ErrAuthRequired is returned when the hub is asked to bind a non-loopback
// address without a configured password.
var ErrAuthRequired = errors.New(
	"hub bind is not loopback but no password is configured: set hub.password_hash in the config " +
		"(the dashboard approves package installs and deletes files — unauthenticated on a LAN it is a " +
		"remote code execution primitive)")

type State struct {
	DB       *sql.DB
	Repo     repo.Hub
	Hostname string
}

func Open(cfg config.Config) (*State, error) {
	handle, err := db.Open(cfg.HubDBPath(), db.SchemaHub)
	if err != nil {
		return nil, err
	}
	return &State{DB: handle, Repo: repo.Hub{DB: handle}, Hostname: hostname()}, nil
}

func (s *State) Close() error { return s.DB.Close() }

// CheckBind enforces §8: a hub reachable from the network must have auth.
func CheckBind(cfg config.Config) error {
	if isLoopback(cfg.Hub.Bind) {
		return nil
	}
	if cfg.Hub.PasswordHash == "" {
		return ErrAuthRequired
	}
	return nil
}

func isLoopback(bind string) bool {
	if bind == "" || bind == "localhost" {
		return true
	}
	ip := net.ParseIP(bind)
	return ip != nil && ip.IsLoopback()
}

// Run serves the fleet dashboard.
//
// Pairing, the sync API and bundle relay are not built yet; this is the
// M0/M0.5 surface only.
func Run(ctx context.Context, cfg config.Config) error {
	if err := CheckBind(cfg); err != nil {
		return err
	}

	st, err := Open(cfg)
	if err != nil {
		return err
	}
	defer st.Close()

	srv, err := web.New(web.ModeHub, st.Hostname)
	if err != nil {
		return err
	}

	// CheckBind above refuses to start a routable hub without a password. That
	// is only worth anything if something then verifies it on every request —
	// this is that. A loopback hub with no password configured runs open, the
	// same as the agent's own dashboard.
	if cfg.Hub.PasswordHash != "" {
		key, err := st.Repo.SessionKey()
		if err != nil {
			return err
		}
		srv.Auth = &web.Auth{PasswordHash: cfg.Hub.PasswordHash, Key: key}
	}

	started := time.Now()
	listenLabel := ""

	srv.Overview = func() (web.OverviewData, error) {
		devices, err := st.Repo.DeviceCounts()
		if err != nil {
			return web.OverviewData{}, err
		}
		return web.OverviewData{
			Mode:    "hub",
			Version: buildinfo.Version,
			Commit:  buildinfo.Commit,
			DataDir: cfg.DataDir,
			Listen:  listenLabel,
			Devices: devices["approved"],
			// The hub has no advisory bundle of its own until relay is built;
			// reporting "none" is honest, and better than inventing a version.
			Findings: map[string]int{},
		}, nil
	}

	router := chi.NewRouter()
	router.Get("/health", daemon.HealthHandler("hub", started, func() (bool, string) {
		return st.DB.PingContext(ctx) == nil, ""
	}))
	srv.Routes(router)

	ln, err := daemon.Listen(cfg.Hub.Bind, cfg.Hub.Port)
	if err != nil {
		return fmt.Errorf("hub listen: %w", err)
	}
	listenLabel = ln.Addr().String()
	slog.Info("hub dashboard listening", "addr", listenLabel, "hostname", st.Hostname)

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
