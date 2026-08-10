package web

import (
	"net/http"
	"net/url"
)

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
func guard(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !sameSite(r) {
			http.Error(w, "refused: this request did not come from the dashboard",
				http.StatusForbidden)
			return
		}
		next(w, r)
	}
}
