package gate

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
)

// ParseUpstream validates a configured registry URL. A malformed one must fail
// at startup: silently falling back to the public registry would mean a private
// index quietly stops being consulted.
func ParseUpstream(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("upstream registry %q is not a URL: %w", raw, err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("upstream registry %q needs a scheme and host", raw)
	}
	return parsed, nil
}

// Proxies is a running pair of registry gates and the URLs to point a package
// manager at.
type Proxies struct {
	NPMURL  string
	PyPIURL string

	servers []*http.Server
}

// StartEphemeral binds both gates on loopback ports the kernel picks.
//
// This is how `pkgwatch npm` runs: its own proxy, on its own port, for one
// install. That makes session attribution exact without npm having to carry a
// session identifier it has no way to send — and it means the wrapper works
// whether or not the agent daemon is running, which matters when there is no
// service manager set up yet.
func StartEphemeral(g *Gate, sessionID string, npmUpstream, pypiUpstream string) (*Proxies, error) {
	npmListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("bind npm gate: %w", err)
	}
	pypiListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		npmListener.Close()
		return nil, fmt.Errorf("bind pypi gate: %w", err)
	}

	p := &Proxies{
		NPMURL:  "http://" + npmListener.Addr().String(),
		PyPIURL: "http://" + pypiListener.Addr().String(),
	}

	npmGate := &NPM{Gate: g, SessionID: sessionID, SelfURL: p.NPMURL}
	if npmUpstream != "" {
		if npmGate.Upstream, err = ParseUpstream(npmUpstream); err != nil {
			return nil, err
		}
	}
	pypiGate := &PyPI{Gate: g, SessionID: sessionID}
	if pypiUpstream != "" {
		if pypiGate.Upstream, err = ParseUpstream(pypiUpstream); err != nil {
			return nil, err
		}
	}

	p.serve(npmGate.Handler(), npmListener)
	p.serve(pypiGate.Handler(), pypiListener)
	return p, nil
}

func (p *Proxies) serve(handler http.Handler, listener net.Listener) {
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	p.servers = append(p.servers, srv)
	go srv.Serve(listener)
}

// Close stops both gates.
func (p *Proxies) Close() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for _, srv := range p.servers {
		srv.Shutdown(ctx)
	}
}
