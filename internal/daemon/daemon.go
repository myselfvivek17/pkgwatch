// Package daemon holds the pieces the agent and hub HTTP servers share.
package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/myselfvivek17/pkgwatch/internal/buildinfo"
)

// Health is the payload of /health.
//
// Not in the build spec, but required by this machine's standing rule that
// anything expected to stay up exposes a health endpoint — that is what the
// Scheduled Task and the systemd unit watch.
type Health struct {
	OK            bool   `json:"ok"`
	Mode          string `json:"mode"`
	Version       string `json:"version"`
	Commit        string `json:"commit"`
	DB            string `json:"db"`
	BundleVersion string `json:"bundle_version"`
	UptimeSeconds int64  `json:"uptime_seconds"`
}

// HealthHandler reports liveness. probe supplies the two facts that can change
// at runtime: whether the database still answers, and the current bundle version.
func HealthHandler(mode string, started time.Time, probe func() (dbOK bool, bundleVersion string)) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		dbOK, bundle := probe()
		if bundle == "" {
			bundle = "none"
		}
		h := Health{
			OK:            dbOK,
			Mode:          mode,
			Version:       buildinfo.Version,
			Commit:        buildinfo.Commit,
			DB:            statusWord(dbOK),
			BundleVersion: bundle,
			UptimeSeconds: int64(time.Since(started).Seconds()),
		}
		w.Header().Set("Content-Type", "application/json")
		if !dbOK {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		json.NewEncoder(w).Encode(h)
	}
}

func statusWord(ok bool) string {
	if ok {
		return "ok"
	}
	return "unreachable"
}

// Listen binds the first available port from prefer. The hub's dashboard and an
// agent's local dashboard both default to 4875; when they are co-resident the
// agent falls back to 4877. Detect and log — do not crash on a port conflict (§2).
func Listen(bind string, prefer ...int) (net.Listener, error) {
	var lastErr error
	for i, port := range prefer {
		addr := net.JoinHostPort(bind, strconv.Itoa(port))
		ln, err := net.Listen("tcp", addr)
		if err == nil {
			if i > 0 {
				slog.Warn("preferred port unavailable, using fallback",
					"wanted", prefer[0], "using", port)
			}
			return ln, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("bind %s on ports %v: %w", bind, prefer, lastErr)
}

// Serve runs srv on ln until ctx is cancelled, then shuts down gracefully.
func Serve(ctx context.Context, srv *http.Server, ln net.Listener) error {
	errCh := make(chan error, 1)
	go func() {
		err := srv.Serve(ln)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errCh <- err
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown: %w", err)
		}
		return <-errCh
	}
}
