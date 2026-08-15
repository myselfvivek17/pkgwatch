package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Every response carries the headers, including static assets and the login
// page.
//
// Headers that only cover the pages somebody remembered are the ones that turn
// out not to cover the page that mattered, so this asserts on a page, an asset
// and the unauthenticated login screen rather than on one route.
func TestEveryResponseCarriesSecurityHeaders(t *testing.T) {
	_, h := newTestServer(t, ModeAgent)

	for _, path := range []string{"/", "/static/app.css", "/design"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))

		for header, want := range map[string]string{
			"X-Frame-Options":        "DENY",
			"X-Content-Type-Options": "nosniff",
			"Referrer-Policy":        "no-referrer",
		} {
			if got := rec.Header().Get(header); got != want {
				t.Errorf("%s: %s = %q, want %q", path, header, got, want)
			}
		}
		if csp := rec.Header().Get("Content-Security-Policy"); csp == "" {
			t.Errorf("%s: no Content-Security-Policy", path)
		}
	}
}

// The policy that closes the live hole: the agent dashboard has no login, so a
// page you happen to visit could otherwise frame it and trick you into
// clicking "restore" on a quarantined package.
func TestTheDashboardRefusesToBeFramed(t *testing.T) {
	_, h := newTestServer(t, ModeAgent)
	csp := get(t, h, "/").Header().Get("Content-Security-Policy")

	if !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("CSP does not forbid framing: %s", csp)
	}
	// script-src must not have re-acquired 'unsafe-inline'. The anti-flash
	// theme script was moved to a file so this could stay strict, and a future
	// inline script would quietly undo that.
	if strings.Contains(csp, "script-src 'self' 'unsafe-inline'") {
		t.Error("script-src allows inline script again — inline script is most of what CSP is for")
	}
}

// HSTS is deliberately absent. The hub serves a self-signed certificate
// trusted by fingerprint comparison, and HSTS would turn the browser's
// "proceed anyway" into a wall with no way through, for a year, on a LAN
// address that may later belong to something else.
func TestNoStrictTransportSecurity(t *testing.T) {
	_, h := newTestServer(t, ModeAgent)
	if got := get(t, h, "/").Header().Get("Strict-Transport-Security"); got != "" {
		t.Errorf("Strict-Transport-Security = %q; a self-signed hub must stay reachable", got)
	}
}
