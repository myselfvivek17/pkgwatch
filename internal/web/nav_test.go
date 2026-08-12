package web

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/myselfvivek17/pkgwatch/internal/repo"
)

// The hub's sidebar offered Findings triage, Install block and Inventory while
// Routes never mounted any of them, so three menu items and the fleet page's own
// "View findings" link all led to a 404. A nav item is a promise that a page
// exists; this is the test that keeps the promise honest.

var hrefPattern = regexp.MustCompile(`<a class="pw-nav-item[^"]*" href="([^"]+)"`)

// enabledNavLinks scrapes the hrefs the sidebar actually offers.
func enabledNavLinks(t *testing.T, h http.Handler, path string) []string {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d", path, rec.Code)
	}

	var out []string
	for _, m := range hrefPattern.FindAllStringSubmatch(rec.Body.String(), -1) {
		out = append(out, m[1])
	}
	if len(out) == 0 {
		t.Fatal("no enabled nav links found — the scrape is broken, not the nav")
	}
	return out
}

func assertNoDeadLinks(t *testing.T, h http.Handler, links []string) {
	t.Helper()
	for _, href := range links {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, href, nil))
		if rec.Code == http.StatusNotFound {
			t.Errorf("the sidebar offers %s and nothing serves it", href)
		}
	}
}

// A hub wired the way hub.Run wires one.
func hubServer(t *testing.T) http.Handler {
	t.Helper()
	srv, err := New(ModeHub, "homelab")
	if err != nil {
		t.Fatal(err)
	}
	srv.Overview = func() (OverviewData, error) { return OverviewData{Mode: "hub"}, nil }
	srv.Devices = func() ([]repo.Device, error) { return nil, nil }
	srv.DeviceFindings = func(string) (map[string]int, error) { return nil, nil }
	srv.SetDeviceStatus = func(string, string) error { return nil }
	srv.Events = func(repo.EventFilter) ([]repo.Event, error) { return nil, nil }
	srv.OldestEvent = func() (time.Time, error) { return time.Time{}, nil }
	srv.Findings = func(repo.FindingFilter) ([]repo.Finding, bool, error) { return nil, false, nil }
	srv.SearchPackages = func(string) ([]repo.FleetSearchHit, error) { return nil, nil }
	srv.InventoryCoverage = func() ([]string, []string, error) { return nil, nil, nil }

	r := chi.NewRouter()
	srv.Routes(r)
	return r
}

func TestHubSidebarOffersNoDeadLinks(t *testing.T) {
	h := hubServer(t)
	assertNoDeadLinks(t, h, enabledNavLinks(t, h, "/"))
}

func TestAgentSidebarOffersNoDeadLinks(t *testing.T) {
	_, h := newTestServer(t, ModeAgent)
	assertNoDeadLinks(t, h, enabledNavLinks(t, h, "/"))
}

// A page nothing serves must render disabled rather than be hidden. The design
// models this state on purpose: hiding it would misrepresent what the tool does,
// and enabling it would 404.
func TestUnwiredPagesRenderDisabledNotOffered(t *testing.T) {
	// A bare server with nothing but the overview wired.
	srv, err := New(ModeAgent, "host")
	if err != nil {
		t.Fatal(err)
	}
	srv.Overview = func() (OverviewData, error) { return OverviewData{Mode: "agent"}, nil }
	r := chi.NewRouter()
	srv.Routes(r)

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	body := rec.Body.String()

	if !contains(body, `is-disabled`) {
		t.Error("unbuilt pages are not shown as disabled")
	}
	assertNoDeadLinks(t, r, enabledNavLinks(t, r, "/"))
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && regexp.MustCompile(regexp.QuoteMeta(needle)).MatchString(haystack)
}
