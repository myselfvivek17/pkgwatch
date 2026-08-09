package agent

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/myselfvivek17/pkgwatch/internal/config"
	"github.com/myselfvivek17/pkgwatch/internal/gate"
)

// serveGates binds the npm and PyPI proxies on their configured ports.
//
// gate.Open gives them their own database handle rather than sharing the
// dashboard's. Each handle is pinned to a single connection (ATTACH is
// per-connection state), so sharing would serialise every packument lookup
// behind whatever the dashboard happens to be querying — an install would stall
// because someone opened a web page.
//
// A port already in use is logged and skipped, not fatal. Losing one gate is a
// degraded agent; a dead agent gates nothing at all.
func serveGates(ctx context.Context, cfg config.Config) (func(), error) {
	g, err := gate.Open(cfg)
	if err != nil {
		return nil, err
	}

	npmGate := &gate.NPM{Gate: g}
	if cfg.Agent.NPMUpstream != "" {
		if npmGate.Upstream, err = gate.ParseUpstream(cfg.Agent.NPMUpstream); err != nil {
			g.DB.Close()
			return nil, err
		}
	}
	pypiGate := &gate.PyPI{Gate: g}
	if cfg.Agent.PyPIUpstream != "" {
		if pypiGate.Upstream, err = gate.ParseUpstream(cfg.Agent.PyPIUpstream); err != nil {
			g.DB.Close()
			return nil, err
		}
	}

	var servers []*http.Server
	bind := func(label string, port int, handler http.Handler, onAddr func(string)) {
		listener, err := net.Listen("tcp", net.JoinHostPort(cfg.Agent.Bind, strconv.Itoa(port)))
		if err != nil {
			slog.Error("gate not started — port unavailable",
				"gate", label, "port", port, "error", err)
			return
		}
		if onAddr != nil {
			onAddr("http://" + listener.Addr().String())
		}
		srv := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second}
		servers = append(servers, srv)
		slog.Info("gate listening", "gate", label, "addr", listener.Addr().String())
		go srv.Serve(listener)
	}

	// SelfURL comes from the bound address so packument tarball links point back
	// here. Without the rewrite npm fetches tarballs straight from the upstream
	// registry and the lockfile interception point never fires.
	bind("npm", cfg.Agent.NPMPort, npmGate.Handler(), func(addr string) { npmGate.SelfURL = addr })
	bind("pypi", cfg.Agent.PyPIPort, pypiGate.Handler(), nil)

	return func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for _, srv := range servers {
			srv.Shutdown(shutdownCtx)
		}
		g.DB.Close()
	}, nil
}
