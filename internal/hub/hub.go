// Package hub aggregates events and findings from paired agents and serves the
// fleet dashboard.
//
// The hub is a convenience, never a dependency: killing it must leave every
// agent fully functional (§0, hard rule 1).
package hub

import (
	"context"
	"crypto/tls"
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
	"github.com/myselfvivek17/pkgwatch/internal/bundle"
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

	// BundleAttached and Bundle describe the advisory bundle this hub holds, if
	// any. A hub does not need one to aggregate — findings arrive already scored
	// — but without one it cannot say what fixes them, which is the first thing
	// anyone looking at a critical actually wants. A hub with no bundle is a
	// normal state, not an error, and it says so rather than rendering blanks.
	BundleAttached bool
	Bundle         repo.BundleInfo
}

func Open(cfg config.Config) (*State, error) {
	handle, err := db.Open(cfg.HubDBPath(), db.SchemaHub)
	if err != nil {
		return nil, err
	}
	st := &State{DB: handle, Repo: repo.Hub{DB: handle}, Hostname: hostname()}

	// Same tolerance as the agent: a missing bundle is ordinary, and a bundle
	// this build cannot read is worse than none — queries would fail inside the
	// lookup or quietly return nothing. Degraded, never dead.
	attached, err := db.AttachAdvisories(handle, cfg.AdvisoryDBPath())
	if err != nil {
		slog.Warn("advisory bundle present but unusable", "error", err)
	}
	if attached {
		if err := db.CheckAdvisorySchema(handle, bundle.SchemaVersion); err != nil {
			attached = false
			slog.Warn("advisory bundle ignored", "error", err)
		}
	}
	if attached {
		if info, err := repo.Bundle(handle, true); err == nil {
			st.Bundle = info
		} else {
			attached = false
			slog.Warn("advisory bundle metadata unreadable", "error", err)
		}
	}
	st.BundleAttached = attached

	return st, nil
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
			Bundle:  st.Bundle,
			// Fleet-wide tier counts belong to the machine cards, which carry
			// their own; an empty map here means the overview does not repeat
			// them, not that there are none.
			Findings: map[string]int{},
		}, nil
	}

	srv.Devices = st.Repo.Devices
	srv.DeviceFindings = st.Repo.FleetFindingCounts
	srv.SetDeviceStatus = func(id, status string) error {
		return st.Repo.SetDeviceStatus(id, status, time.Now())
	}
	srv.SearchPackages = func(query string) ([]repo.FleetSearchHit, error) {
		return st.Repo.SearchPackages(query, 200)
	}
	srv.InventoryCoverage = st.Repo.InventoryCoverage

	// Fleet events, so the hub's timeline is every machine's rather than none.
	srv.Events = st.Repo.FleetEvents
	srv.OldestEvent = st.Repo.OldestFleetEventAt

	// Findings across the fleet, read-only. With a bundle attached the fix and
	// CVSS columns are real; without one the page says they are unknown rather
	// than rendering them blank, which would read as "no fix exists".
	//
	// Acknowledge and Ignore stay nil deliberately. The agent is authoritative
	// for its own findings (§3.3) and sync is outbound-only, so there is no
	// channel to write a decision back down — buttons here would do nothing.
	srv.Findings = func(f repo.FindingFilter) ([]repo.Finding, bool, error) {
		rows, err := st.Repo.FleetFindings(st.BundleAttached, f)
		return rows, st.BundleAttached, err
	}

	router := chi.NewRouter()
	router.Get("/health", daemon.HealthHandler("hub", started, func() (bool, string) {
		return st.DB.PingContext(ctx) == nil, st.Bundle.Version
	}))
	// Agents authenticate with a device token and a signature, not the hub
	// password, so the API sits outside the dashboard's session guard.
	st.API(router, time.Now)
	srv.Routes(router)

	ln, err := daemon.Listen(cfg.Hub.Bind, cfg.Hub.Port)
	if err != nil {
		return fmt.Errorf("hub listen: %w", err)
	}
	listenLabel = ln.Addr().String()

	scheme := "http"
	if cfg.Hub.TLSEnabled() {
		cert, err := LoadOrCreateCert(cfg)
		if err != nil {
			return err
		}
		ln = tls.NewListener(ln, TLSConfig(cert))
		scheme = "https"

		// Printed at every start, not just the first. This is the string a
		// person compares when pairing an agent, and having to go find a
		// command to print it is how the comparison gets skipped.
		slog.Info("hub certificate", "fingerprint", Fingerprint(cert.Certificate[0]))
	} else {
		// Said plainly. The dashboard password crosses the network in a
		// plaintext form POST with this off, to a listener the whole LAN can
		// reach — and nothing else about the hub looks any different.
		slog.Warn("TLS is OFF — the dashboard password will cross the network in the clear; " +
			"remove `tls = false` from the [hub] config to turn it back on")
	}

	slog.Info("hub dashboard listening",
		"url", scheme+"://"+listenLabel, "hostname", st.Hostname)

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
