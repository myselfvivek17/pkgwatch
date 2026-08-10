package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/myselfvivek17/pkgwatch/internal/repo"
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

// timelineServer wires the page to a fixed set of events.
func timelineServer(t *testing.T, events []repo.Event) http.Handler {
	t.Helper()
	srv, err := New(ModeAgent, "test-host")
	if err != nil {
		t.Fatal(err)
	}
	srv.Overview = func() (OverviewData, error) { return OverviewData{Mode: "agent"}, nil }
	srv.Events = func(f repo.EventFilter) ([]repo.Event, error) {
		var out []repo.Event
		for _, e := range events {
			if f.Kind != "" && f.Kind != "routine" && f.Kind != "actionable" && e.Kind != f.Kind {
				continue
			}
			if f.Kind == "routine" && !e.Routine() {
				continue
			}
			if f.Kind == "actionable" && e.Routine() {
				continue
			}
			if f.SinceID > 0 && e.ID <= f.SinceID {
				continue
			}
			out = append(out, e)
		}
		return out, nil
	}
	srv.OldestEvent = func() (time.Time, error) { return time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC), nil }
	srv.HistoryDays = 90
	srv.StreamInterval = 5 * time.Millisecond
	r := chi.NewRouter()
	srv.Routes(r)
	return r
}

func sampleEvents(now time.Time) []repo.Event {
	return []repo.Event{
		{ID: 3, At: now, Kind: repo.EventGateDegraded,
			PURL: "pkg:npm/left-pad@1.0.0", Detail: map[string]string{"detail": "bundle stale"}},
		{ID: 2, At: now, Kind: repo.EventFindingNew, Severity: "critical",
			PURL: "pkg:npm/lodash@4.17.20", AdvisoryID: "GHSA-x"},
		{ID: 1, At: now, Kind: repo.EventScan,
			Detail: map[string]string{"packages": "1200", "new": "0", "gone": "0", "findings": "0"}},
	}
}

// The design's hierarchy is the page doing triage: a six-hourly scan must not
// carry the same weight as a block. If routine rows lose their class the page
// still "works" and stops being useful, so it is asserted rather than eyeballed.
func TestTimelineMarksRoutineAndAlarmingRows(t *testing.T) {
	h := timelineServer(t, sampleEvents(time.Now()))
	body := get(t, h, "/timeline").Body.String()

	if !strings.Contains(body, "pw-row-routine") {
		t.Error("the scan row lost its routine treatment — routine and actionable now look alike")
	}
	if !strings.Contains(body, "pw-row-alarming") {
		t.Error("no alarming row: a degraded gate and a critical finding must both stand out")
	}
	// A degraded gate is the one failure that cannot be discovered afterwards,
	// so its summary is never softened.
	if !strings.Contains(body, "allowed without evaluation") {
		t.Error("gate_degraded summary missing or reworded")
	}
	if !strings.Contains(body, "1200 packages") {
		t.Error("scan summary missing — a scan that reports nothing looks like a stopped agent")
	}
}

// Events are deleted at the retention horizon. A timeline that simply stops is
// indistinguishable from a machine that did nothing, so it has to say which.
func TestTimelineNamesItsHorizon(t *testing.T) {
	h := timelineServer(t, sampleEvents(time.Now()))
	body := get(t, h, "/timeline").Body.String()
	if !strings.Contains(body, "History begins 1 May 2026") {
		t.Error("timeline does not say when its history starts")
	}
	if !strings.Contains(body, "90 days") {
		t.Error("retention window not named")
	}
}

func TestTimelineFilters(t *testing.T) {
	h := timelineServer(t, sampleEvents(time.Now()))
	body := get(t, h, "/timeline?kind=actionable").Body.String()
	if strings.Contains(body, "1200 packages") {
		t.Error("actionable filter still shows the routine scan row")
	}
	if !strings.Contains(body, "allowed without evaluation") {
		t.Error("actionable filter dropped an actionable row")
	}
}

// The stream exists because scan runs in the CLI while the daemon serves this
// page. If it fanned out from an in-process channel it would sit silent through
// exactly the activity someone ran a command to watch.
func TestStreamPushesRowsWrittenByAnotherProcess(t *testing.T) {
	h := timelineServer(t, sampleEvents(time.Now()))

	req := httptest.NewRequest(http.MethodGet, "/events/stream?since=1", nil)
	ctx, cancel := context.WithTimeout(req.Context(), 2*time.Second)
	defer cancel()

	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		h.ServeHTTP(rec, req.WithContext(ctx))
		close(done)
	}()
	<-done

	body := rec.Body.String()
	if !strings.Contains(body, "event: row") {
		t.Fatalf("no SSE row frames emitted; got %q", body)
	}
	if !strings.Contains(body, "pw-row") {
		t.Error("stream did not push rendered HTML — the browser would have to template it again")
	}
	if strings.Contains(body, "1200 packages") {
		t.Error("stream replayed an event at or before the cursor")
	}
}
