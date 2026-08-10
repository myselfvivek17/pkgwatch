package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/myselfvivek17/pkgwatch/internal/repo"
)

// triageServer records what reached the write path, so a refused request can be
// told apart from one that was allowed and merely failed.
func triageServer(t *testing.T, applied *[]string) http.Handler {
	t.Helper()
	srv, err := New(ModeAgent, "test-host")
	if err != nil {
		t.Fatal(err)
	}
	srv.Overview = func() (OverviewData, error) { return OverviewData{Mode: "agent"}, nil }
	srv.Findings = func(repo.FindingFilter) ([]repo.Finding, bool, error) {
		return sampleFindings(), true, nil
	}
	srv.Acknowledge = func(purl, advisoryID, note string) error {
		*applied = append(*applied, "ack:"+purl)
		return nil
	}
	srv.Ignore = func(purl, advisoryID, note string, days int) error {
		*applied = append(*applied, "ignore:"+purl)
		return nil
	}
	r := chi.NewRouter()
	srv.Routes(r)
	return r
}

func postTriage(h http.Handler, form url.Values, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/findings/triage", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "127.0.0.1:4875"
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// Binding to 127.0.0.1 keeps other machines out and does nothing about the
// browser already on this one: any page you visit can POST a form here. It
// cannot read the response, and it does not need to in order to ignore a
// finding.
func TestTriageRefusesCrossSitePosts(t *testing.T) {
	var applied []string
	h := triageServer(t, &applied)

	form := url.Values{"purl": {"pkg:npm/lodash@4.17.20"}, "advisory": {"GHSA-x"}, "action": {"ack"}}

	for _, tc := range []struct {
		name    string
		headers map[string]string
	}{
		{"cross-site fetch", map[string]string{"Sec-Fetch-Site": "cross-site"}},
		{"same-site subdomain", map[string]string{"Sec-Fetch-Site": "same-site"}},
		{"forged origin", map[string]string{"Origin": "http://evil.example"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := postTriage(h, form, tc.headers)
			if rec.Code != http.StatusForbidden {
				t.Errorf("code = %d, want 403", rec.Code)
			}
		})
	}
	if len(applied) != 0 {
		t.Fatalf("a refused request still changed state: %v", applied)
	}
}

func TestTriageAcceptsThePageItself(t *testing.T) {
	var applied []string
	h := triageServer(t, &applied)

	rec := postTriage(h,
		url.Values{"purl": {"pkg:npm/lodash@4.17.20"}, "advisory": {"GHSA-x"}, "action": {"ack"}},
		map[string]string{"Sec-Fetch-Site": "same-origin", "Origin": "http://127.0.0.1:4875"})

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("code = %d, want 303 — a redirect stops a refresh repeating the action", rec.Code)
	}
	if len(applied) != 1 || applied[0] != "ack:pkg:npm/lodash@4.17.20" {
		t.Errorf("applied = %v", applied)
	}
}

// The mandatory expiry has to survive the trip through the form. A zero here
// would be an ignore that never comes back, which is what --days exists to stop.
func TestTriageRejectsAnIgnoreWithNoWindow(t *testing.T) {
	var applied []string
	h := triageServer(t, &applied)

	for _, days := range []string{"0", "", "-5", "soon"} {
		rec := postTriage(h,
			url.Values{"purl": {"pkg:npm/lodash@4.17.20"}, "advisory": {"GHSA-x"},
				"action": {"ignore"}, "days": {days}},
			map[string]string{"Sec-Fetch-Site": "same-origin"})
		if rec.Code != http.StatusBadRequest {
			t.Errorf("days=%q gave %d, want 400", days, rec.Code)
		}
	}
	if len(applied) != 0 {
		t.Fatalf("an ignore with no window was applied: %v", applied)
	}
}

// An open redirect on a form post is a small hole with no reason to exist.
func TestTriageOnlyRedirectsBackToFindings(t *testing.T) {
	var applied []string
	h := triageServer(t, &applied)

	rec := postTriage(h,
		url.Values{"purl": {"pkg:npm/lodash@4.17.20"}, "advisory": {"GHSA-x"},
			"action": {"ack"}, "back": {"https://evil.example/"}},
		map[string]string{"Sec-Fetch-Site": "same-origin"})

	if got := rec.Header().Get("Location"); got != "/findings" {
		t.Errorf("Location = %q, want /findings", got)
	}
}
