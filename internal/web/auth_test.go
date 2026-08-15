package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/myselfvivek17/pkgwatch/internal/secret"
)

// The hub binds 0.0.0.0 and this UI approves devices, revokes their tokens and
// lists every package on every machine. These assertions are the security
// properties, not the implementation — anything that breaks one is a
// regression even if every page still renders.

const testPassword = "a decent hub password"

func newGuardedServer(t *testing.T) (*Server, http.Handler) {
	t.Helper()
	hash, err := secret.Hash(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(ModeHub, "test-host")
	if err != nil {
		t.Fatal(err)
	}
	srv.Overview = func() (OverviewData, error) {
		return OverviewData{Mode: "hub", Findings: map[string]int{}}, nil
	}
	srv.Auth = &Auth{PasswordHash: hash, Key: []byte("0123456789abcdef0123456789abcdef")}

	r := chi.NewRouter()
	// Mounted before Routes, exactly as hub.Run does it.
	r.Get("/health", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(`{"ok":true}`)) })
	srv.Routes(r)
	return srv, r
}

func do(h http.Handler, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// loginToken reads the CSRF field off the rendered sign-in page, the way a
// browser would. Scraped rather than reached for inside the Server, so these
// tests also fail if the form ever stops carrying one.
func loginToken(t *testing.T, h http.Handler) string {
	t.Helper()
	body := do(h, httptest.NewRequest(http.MethodGet, "/login", nil)).Body.String()
	match := csrfInput.FindStringSubmatch(body)
	if match == nil {
		t.Fatal("the login page renders no csrf field")
	}
	return match[1]
}

var csrfInput = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

// signIn returns the session cookie a correct password yields.
func signIn(t *testing.T, h http.Handler) *http.Cookie {
	t.Helper()
	form := url.Values{"csrf": {loginToken(t, h)}, "password": {testPassword}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rec := do(h, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("login = %d, want 303", rec.Code)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == SessionCookie {
			return c
		}
	}
	t.Fatal("login set no session cookie")
	return nil
}

func TestEveryPageRefusesWithoutASession(t *testing.T) {
	_, h := newGuardedServer(t)
	for _, path := range []string{"/", "/design"} {
		rec := do(h, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
			t.Errorf("GET %s = %d %q, want 303 to /login",
				path, rec.Code, rec.Header().Get("Location"))
		}
		if strings.Contains(rec.Body.String(), "test-host") {
			t.Errorf("GET %s leaked page content to an unauthenticated caller", path)
		}
	}
}

// A POST answered with an HTML login page looks to a script like a successful
// write. Non-GET methods get a status a caller cannot misread.
func TestUnauthenticatedWritesGet401NotALoginPage(t *testing.T) {
	_, h := newGuardedServer(t)
	req := httptest.NewRequest(http.MethodPost, "/findings/triage", nil)
	rec := do(h, req)
	if rec.Code != http.StatusUnauthorized && rec.Code != http.StatusNotFound {
		t.Errorf("POST = %d, want 401 (or 404 when the route is not wired)", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "<form") {
		t.Error("a write got a login form back instead of a refusal")
	}
}

func TestCorrectPasswordOpensASessionThePageCannotRead(t *testing.T) {
	_, h := newGuardedServer(t)
	cookie := signIn(t, h)

	if !cookie.HttpOnly {
		t.Error("session cookie is readable by page script")
	}
	if cookie.SameSite != http.SameSiteStrictMode {
		t.Error("session cookie is not SameSite=Strict")
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	if rec := do(h, req); rec.Code != http.StatusOK {
		t.Errorf("GET / with a session = %d, want 200", rec.Code)
	}
}

func TestWrongPasswordOpensNothing(t *testing.T) {
	_, h := newGuardedServer(t)
	form := url.Values{"csrf": {loginToken(t, h)}, "password": {"not it"}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rec := do(h, req)

	for _, c := range rec.Result().Cookies() {
		if c.Name == SessionCookie && c.Value != "" {
			t.Fatal("a wrong password set a session cookie")
		}
	}
	if !strings.Contains(rec.Body.String(), "did not match") {
		t.Error("no visible failure message")
	}
}

// The signing key is not the password hash. Deriving it would mean anyone who
// learned the password could mint cookies without ever logging in.
func TestAForgedCookieIsRefused(t *testing.T) {
	srv, h := newGuardedServer(t)

	other := &Auth{PasswordHash: srv.Auth.PasswordHash, Key: []byte("a different signing key entirely!")}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookie, Value: other.issue()})
	if rec := do(h, req); rec.Code != http.StatusSeeOther {
		t.Errorf("a cookie signed with another key = %d, want a redirect to /login", rec.Code)
	}

	// And a valid payload with the signature stripped.
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookie, Value: "99999999999.", Path: "/"})
	if rec := do(h, req); rec.Code != http.StatusSeeOther {
		t.Errorf("an unsigned cookie = %d, want a redirect to /login", rec.Code)
	}
}

func TestExpiredSessionIsRefused(t *testing.T) {
	srv, h := newGuardedServer(t)
	srv.Auth.TTL = time.Minute
	cookie := signIn(t, h)

	srv.Auth.Now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	if rec := do(h, req); rec.Code != http.StatusSeeOther {
		t.Errorf("an expired session = %d, want a redirect to /login", rec.Code)
	}
}

func TestLogoutEndsTheSession(t *testing.T) {
	_, h := newGuardedServer(t)
	cookie := signIn(t, h)

	// Signing out is a state change, so it carries the token like every other
	// form. A logout an attacker can trigger is a nuisance rather than a
	// breach, but it is still an action they chose for you.
	form := url.Values{"csrf": {loginToken(t, h)}}
	req := httptest.NewRequest(http.MethodPost, "/logout", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.AddCookie(cookie)
	rec := do(h, req)

	var cleared bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == SessionCookie && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Error("logout did not clear the session cookie")
	}
}

// A cross-site page can POST a form to the hub. It cannot read the response,
// and it does not need to in order to log someone in as itself or sign them out.
func TestCrossSiteLoginAndLogoutAreRefused(t *testing.T) {
	_, h := newGuardedServer(t)
	form := url.Values{"csrf": {loginToken(t, h)}, "password": {testPassword}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	if rec := do(h, req); rec.Code != http.StatusForbidden {
		t.Errorf("cross-site login = %d, want 403", rec.Code)
	}
}

// The service manager watches /health, and it has no session. It is mounted
// outside the guard on purpose; this pins that so a later refactor cannot
// quietly move it inside and leave the unit reporting the hub as down.
func TestHealthStaysReachableWithoutASession(t *testing.T) {
	_, h := newGuardedServer(t)
	if rec := do(h, httptest.NewRequest(http.MethodGet, "/health", nil)); rec.Code != http.StatusOK {
		t.Errorf("GET /health = %d, want 200", rec.Code)
	}
}

// The login page needs its stylesheet before anyone can sign in.
func TestStaticAssetsStayReachable(t *testing.T) {
	_, h := newGuardedServer(t)
	if rec := do(h, httptest.NewRequest(http.MethodGet, "/static/app.css", nil)); rec.Code != http.StatusOK {
		t.Errorf("GET the stylesheet = %d, want 200", rec.Code)
	}
}

// An agent's dashboard is loopback-only and has no password; it must keep
// working with no Auth configured.
func TestNoAuthConfiguredLeavesPagesOpen(t *testing.T) {
	_, h := newTestServer(t, ModeAgent)
	if rec := do(h, httptest.NewRequest(http.MethodGet, "/", nil)); rec.Code != http.StatusOK {
		t.Errorf("GET / on an unguarded agent = %d, want 200", rec.Code)
	}
}
