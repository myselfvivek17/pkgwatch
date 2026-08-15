package web

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/myselfvivek17/pkgwatch/internal/secret"
)

// SessionCookie is the hub dashboard's session. Named rather than inlined
// because logout has to clear exactly what login set.
const SessionCookie = "pkgwatch_hub"

// SessionTTL is how long a hub login lasts.
const SessionTTL = 7 * 24 * time.Hour

// Auth guards the hub dashboard.
//
// The hub binds 0.0.0.0 and this UI approves devices, revokes their tokens and
// lists every package on every machine in the fleet. Startup already refuses a
// non-loopback bind without a password (§8) — that check is only worth
// anything if something then verifies the password on each request, which is
// what this does.
//
// Key is the session signing key and is NOT derived from PasswordHash. Two
// secrets that collapse into one are a forger's key: anyone who learned the
// password could mint session cookies without logging in.
type Auth struct {
	PasswordHash string
	Key          []byte
	TTL          time.Duration

	// Now is overridable so expiry is testable without sleeping.
	Now func() time.Time
}

func (a *Auth) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func (a *Auth) ttl() time.Duration {
	if a.TTL > 0 {
		return a.TTL
	}
	return SessionTTL
}

var b64 = base64.RawURLEncoding

// issue mints a session token good until now+ttl.
func (a *Auth) issue() string {
	payload := strconv.FormatInt(a.now().Add(a.ttl()).Unix(), 10)
	return payload + "." + b64.EncodeToString(a.sign(payload))
}

func (a *Auth) sign(payload string) []byte {
	mac := hmac.New(sha256.New, a.Key)
	mac.Write([]byte(payload))
	return mac.Sum(nil)
}

// valid reports whether token is one this hub issued and has not expired.
func (a *Auth) valid(token string) bool {
	payload, sig, found := strings.Cut(token, ".")
	if !found {
		return false
	}
	raw, err := b64.DecodeString(sig)
	if err != nil || !hmac.Equal(raw, a.sign(payload)) {
		return false
	}
	exp, err := strconv.ParseInt(payload, 10, 64)
	return err == nil && a.now().Unix() < exp
}

// SignedIn reports whether r carries a live session.
func (a *Auth) SignedIn(r *http.Request) bool {
	cookie, err := r.Cookie(SessionCookie)
	return err == nil && a.valid(cookie.Value)
}

// Require wraps a handler so only a signed-in browser reaches it.
//
// A GET redirects to the login form; anything else gets a plain 401. A POST
// answered with an HTML login page looks to a script like a successful write.
func (a *Auth) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.SignedIn(r) {
			next.ServeHTTP(w, r)
			return
		}
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		http.Error(w, "not signed in", http.StatusUnauthorized)
	})
}

// setSession writes the session cookie.
//
// HttpOnly so page script cannot read a week-long credential, and
// SameSite=Strict so it does not ride along on a cross-site request at all —
// which is the same protection guard() gives the agent's writes, applied to
// the credential itself.
//
// Secure only over TLS. Setting it unconditionally on a homelab hub served
// over http means the browser silently discards the cookie and every login
// appears to succeed and then fail.
func (a *Auth) setSession(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    a.issue(),
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   r.TLS != nil,
		MaxAge:   int(a.ttl().Seconds()),
	})
}

func (a *Auth) clearSession(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   r.TLS != nil,
		MaxAge:   -1,
	})
}

// handleLogin renders the form and checks the password.
//
// Failures say only that the password was wrong. Distinguishing "no password
// configured" from "wrong password" would tell an unauthenticated caller which
// of the two it is looking at.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if s.Auth.SignedIn(r) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if r.Method == http.MethodGet {
		s.renderLogin(w, "")
		return
	}
	if !sameSite(r) {
		http.Error(w, "refused: this request did not come from the dashboard", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		s.renderLogin(w, "Could not read that form.")
		return
	}
	// Checked before the throttle so a forged submission cannot arm somebody
	// else's backoff — otherwise a page you visited could lock you out of your
	// own dashboard for fifteen seconds at a time without ever guessing.
	if !s.validCSRF(r) {
		s.renderLoginStatus(w, http.StatusForbidden,
			"That sign-in form was stale. Reload the page and try again.")
		return
	}

	// Refused before any hashing. Verifying a password costs 64 MiB, so an
	// endpoint that hashes on demand for anyone who can reach the port is a
	// memory amplifier as much as it is a guessing target.
	now := time.Now()
	if wait := s.logins.wait(now); wait > 0 {
		seconds := int(wait.Seconds()) + 1
		w.Header().Set("Retry-After", strconv.Itoa(seconds))
		s.renderLoginStatus(w, http.StatusTooManyRequests,
			fmt.Sprintf("Too many attempts. Try again in %d second(s).", seconds))
		return
	}

	if !s.logins.attempt(now, func() bool {
		return secret.Verify(r.PostFormValue("password"), s.Auth.PasswordHash)
	}) {
		// Deliberately not logged with the attempt. A password typed into the
		// wrong field is the most common way one ends up in a log file.
		s.renderLogin(w, "That password did not match.")
		return
	}
	s.Auth.setSession(w, r)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.Auth.clearSession(w, r)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) renderLogin(w http.ResponseWriter, problem string) {
	s.renderLoginStatus(w, http.StatusOK, problem)
}

// renderLoginStatus draws the login page with an explicit status, so a refused
// attempt can answer 429 and still be a readable page rather than a bare error.
func (s *Server) renderLoginStatus(w http.ResponseWriter, status int, problem string) {
	tpl, ok := s.templates["login"]
	if !ok {
		http.Error(w, "login page unavailable", http.StatusInternalServerError)
		return
	}
	// Header, then status, then body. Setting a header after WriteHeader is
	// silently dropped.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	tpl.ExecuteTemplate(w, "login", map[string]any{
		"Identity": s.identity(),
		"Problem":  problem,
		"CSRF":     s.csrf,
	})
}
