package web

import "net/http"

// contentSecurityPolicy is what the dashboards are allowed to load.
//
// Everything comes from this origin. There is no CDN, no analytics, no web
// font, and no third-party anything — a supply-chain tool that pulled a script
// from someone else's server would be an argument against itself — so the
// policy can be this narrow without breaking a single page.
//
// script-src has no 'unsafe-inline'. The one inline script this used to carry
// (the anti-flash theme setter) moved to /static/theme-init.js precisely so
// this line could stay strict, since inline script is most of what CSP exists
// to stop.
//
// style-src does allow 'unsafe-inline', and that is a real, named concession:
// the progress bars and the sparkline set width and height from the data, and
// the design page paints swatches from token values. Inline *style* cannot
// execute, so the exposure is CSS injection rather than script execution, and
// every one of those attributes is written by a Go template that escapes what
// goes into it. The alternative was a per-request nonce on every element that
// carries a computed dimension.
//
// frame-ancestors 'none' is the one that closes a live hole rather than a
// theoretical one: the agent dashboard has no login at all, so a page you
// happen to visit could frame it and trick you into clicking "restore" on a
// quarantined package. object-src and base-uri are set because their defaults
// are permissive and nothing here needs them.
const contentSecurityPolicy = "default-src 'self'; " +
	"script-src 'self'; " +
	"style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data:; " +
	"font-src 'self'; " +
	"connect-src 'self'; " +
	"object-src 'none'; " +
	"frame-ancestors 'none'; " +
	"base-uri 'self'; " +
	"form-action 'self'"

// secureHeaders sets the response headers every dashboard page needs.
//
// Deliberately NOT Strict-Transport-Security. The hub serves a certificate it
// generated itself, trusted because a person compared its fingerprint at
// pairing rather than because a CA vouched for it. HSTS would turn the
// browser's "proceed anyway" interstitial into a wall with no way through, and
// lock the host out of plain HTTP for a year — on a LAN address that may later
// belong to something else entirely. The pinning that protects agents happens
// in the sync client, where it does not depend on a browser.
func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", contentSecurityPolicy)

		// Belt and braces with frame-ancestors: an older browser that ignores
		// the CSP directive still honours this one.
		h.Set("X-Frame-Options", "DENY")

		// Stops a browser deciding a response is something more interesting
		// than what it was labelled.
		h.Set("X-Content-Type-Options", "nosniff")

		// A dashboard URL names a package or an advisory, which is a detail
		// about this machine that has no business travelling in a Referer.
		h.Set("Referrer-Policy", "no-referrer")

		// Nothing here needs a camera, a microphone or a location.
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), interest-cohort=()")

		next.ServeHTTP(w, r)
	})
}
