package web

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"net/url"
)

// csrfField is the hidden input every state-changing form carries.
const csrfField = "csrf"

// newCSRFToken returns the per-process token embedded in forms.
//
// Per process rather than per session, because the agent's dashboard has no
// sessions at all and the hub's would leave the agent unprotected. It is
// regenerated on every start, so a form left open across a restart is refused
// and reloads — the same behaviour as an expired session, and cheaper than
// persisting a secret that guards nothing once the page is gone.
func newCSRFToken() string {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		// crypto/rand does not fail in practice, and a guessable token here
		// would be worse than no dashboard at all.
		panic("pkgwatch: no entropy for a CSRF token: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

// sameSite rejects state-changing requests that did not come from this page.
//
// The dashboard binds to 127.0.0.1, which stops other machines reaching it and
// does nothing about the browser already running on this one. Any web page you
// visit can POST a form to http://127.0.0.1:4875/ — it cannot read the response,
// but it does not need to in order to ignore a finding. So a page that changes
// state has to check where the request came from.
//
// Two checks, because either header can be absent:
//
//   - Sec-Fetch-Site is set by every current browser and cannot be forged by
//     page script. Anything other than same-origin is refused outright.
//   - Origin is the fallback for a browser that does not send Sec-Fetch-Site.
//     A cross-site form POST carries the attacker's origin, which will not match.
//
// A request with neither header is allowed: that is curl or a script the user
// ran themselves, which already has far more direct access to the database than
// this endpoint offers. The header pair exists to constrain browsers, and only
// browsers send them.
func sameSite(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "same-origin", "none":
		// "none" is a user-initiated navigation — typing the URL, a bookmark.
	case "":
		// Fall through to the Origin check.
	default:
		return false
	}

	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	parsed, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return parsed.Host == r.Host
}

// guard wraps a state-changing handler.
//
// Two checks, and the token is the one that does not depend on the browser
// volunteering anything. The header pair above is stopped by a client that
// simply omits both — a privacy extension that strips Origin, an old embedded
// WebView that never learned Sec-Fetch-Site — and the agent's dashboard has no
// session to fall back on, so that would be the whole defence gone.
//
// The token works without a session because CSRF's constraint is not secrecy,
// it is that an attacker cannot READ a same-origin response. A value this
// process generated, embedded in the page, is unavailable to any page that did
// not come from here.
func (s *Server) guard(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !sameSite(r) {
			http.Error(w, "refused: this request did not come from the dashboard",
				http.StatusForbidden)
			return
		}
		if !s.validCSRF(r) {
			// Fails closed, which also means a form that forgets the hidden
			// field breaks loudly on the first click rather than quietly
			// becoming the one unprotected endpoint.
			http.Error(w, "refused: this form is stale — reload the page and try again",
				http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// validCSRF checks the token a form posted back.
func (s *Server) validCSRF(r *http.Request) bool {
	got := r.PostFormValue(csrfField)
	if got == "" {
		got = r.Header.Get("X-CSRF-Token")
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(s.csrf)) == 1
}
