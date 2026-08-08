package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

func newTestServer(t *testing.T, mode Mode) (*Server, http.Handler) {
	t.Helper()
	srv, err := New(mode, "test-host")
	if err != nil {
		t.Fatalf("New(%s): %v", mode, err)
	}
	srv.Overview = func() (OverviewData, error) {
		return OverviewData{Mode: string(mode), Version: "test", Findings: map[string]int{"critical": 2, "low": 1}}, nil
	}
	r := chi.NewRouter()
	srv.Routes(r)
	return srv, r
}

func get(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200", path, rec.Code)
	}
	return rec
}

func TestOverviewRendersInBothModes(t *testing.T) {
	for _, tc := range []struct{ mode, wantIdentity string }{
		{"hub", "hub · test-host"},
		{"agent", "agent · test-host"},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			_, h := newTestServer(t, Mode(tc.mode))
			body := get(t, h, "/").Body.String()
			if !strings.Contains(body, tc.wantIdentity) {
				t.Errorf("identity line %q missing from page", tc.wantIdentity)
			}
		})
	}
}

// An unpaired agent must not imply a hub connection it does not have — the same
// refusal to render absent state as healthy that the offline machine card makes.
func TestUnpairedAgentSaysSo(t *testing.T) {
	srv, h := newTestServer(t, ModeAgent)
	srv.Paired = false

	body := get(t, h, "/").Body.String()
	if !strings.Contains(body, "local only") {
		t.Error("unpaired agent should say it has no hub")
	}
	if strings.Contains(body, "connected to") {
		t.Error("unpaired agent claimed a hub connection")
	}
}

// Every tier needs its own glyph so severity survives greyscale and colour
// blindness. Collapsing these into coloured pills is the regression this guards.
func TestSeverityBadgesCarryDistinctGlyphs(t *testing.T) {
	_, h := newTestServer(t, ModeHub)
	body := get(t, h, "/design").Body.String()

	glyphs := map[string]string{
		"critical": `<polygon points="5,0 10,9 0,9"`,
		"high":     `<polygon points="5,0.5 9.5,5 5,9.5 0.5,5"`,
		"medium":   `<circle cx="5" cy="5" r="4.1"`,
		"low":      `<rect x="1" y="1" width="8" height="8"`,
	}
	for tier, glyph := range glyphs {
		if !strings.Contains(body, glyph) {
			t.Errorf("tier %s lost its glyph (%s)", tier, glyph)
		}
		if !strings.Contains(body, "pw-badge-"+tier) {
			t.Errorf("tier %s badge class missing", tier)
		}
	}
}

// html/template drops `background: var({{.}})` from a style attribute, which
// renders every swatch blank. Assert the declaration survives.
func TestTokenSwatchesKeepTheirBackground(t *testing.T) {
	_, h := newTestServer(t, ModeHub)
	body := get(t, h, "/design").Body.String()

	if strings.Contains(body, "ZgotmplZ") {
		t.Error("template sanitizer voided a style attribute")
	}
	if !strings.Contains(body, "background: var(--sev-critical-bg)") {
		t.Error("token swatch lost its background declaration")
	}
}

// Unbuilt pages render disabled rather than hidden, and must not be links.
func TestUnbuiltNavItemsAreDisabledNotLinks(t *testing.T) {
	_, h := newTestServer(t, ModeHub)
	body := get(t, h, "/").Body.String()

	if n := strings.Count(body, "pw-nav-item"); n < 9 {
		t.Errorf("found %d nav items, want all 9 from the design", n)
	}
	if !strings.Contains(body, `<span class="pw-nav-item is-disabled"`) {
		t.Error("disabled nav items should be spans, not anchors")
	}
	if strings.Contains(body, `<a class="pw-nav-item is-disabled"`) {
		t.Error("a disabled nav item is still a clickable link")
	}
}

func TestStaticAssetsAreServed(t *testing.T) {
	_, h := newTestServer(t, ModeHub)
	for _, asset := range []string{"/static/theme.css", "/static/app.css", "/static/app.js"} {
		if body := get(t, h, asset).Body.String(); len(body) == 0 {
			t.Errorf("%s served empty", asset)
		}
	}
}

func TestFindingTiersAreOrderedBySeverity(t *testing.T) {
	data := OverviewData{Findings: map[string]int{"low": 1, "critical": 2}}
	tiers := data.FindingTiers()

	want := []string{"critical", "high", "medium", "low"}
	for i, tier := range want {
		if tiers[i].Tier != tier {
			t.Fatalf("position %d = %s, want %s", i, tiers[i].Tier, tier)
		}
	}
	if !data.HasFindings() {
		t.Error("HasFindings should be true when any tier is non-zero")
	}
	if (OverviewData{Findings: map[string]int{"low": 0}}).HasFindings() {
		t.Error("HasFindings should be false when every tier is zero")
	}
}
