package web

import (
	"strings"
	"testing"
	"time"

	"github.com/myselfvivek17/pkgwatch/internal/repo"
)

// Every day in the window gets a column, including the ones nothing happened
// on.
//
// This is the whole reason the axis is generated rather than taken from the
// query: SQL returns only days with rows, so a chart drawn from it would render
// a fortnight with two busy afternoons as two fat bars — a quiet period would
// look identical to a busy one.
func TestEveryDayInTheWindowGetsAColumn(t *testing.T) {
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.Local)
	counts := []repo.EventDay{
		{Day: "2026-08-14", Kind: repo.EventFindingNew, Severity: "critical", Count: 3},
		{Day: "2026-08-10", Kind: repo.EventFindingNew, Severity: "low", Count: 1},
	}

	trends := buildTrends(counts, nil, nil, now)

	if len(trends.Findings) != TrendDays {
		t.Fatalf("%d columns, want %d — the axis must not come from the query",
			len(trends.Findings), TrendDays)
	}
	if trends.Total != 4 {
		t.Errorf("total = %d, want 4", trends.Total)
	}
	// Oldest first, newest last: the same direction the timeline reads.
	if last := trends.Findings[TrendDays-1]; last.Total != 3 {
		t.Errorf("the newest column holds %d, want today's 3", last.Total)
	}
	empty := 0
	for _, d := range trends.Findings {
		if d.Total == 0 {
			empty++
		}
	}
	if empty != TrendDays-2 {
		t.Errorf("%d empty columns, want %d — quiet days have to stay visible",
			empty, TrendDays-2)
	}
}

// Heights are a share of the busiest day, so a single huge day cannot flatten
// every other column into an invisible sliver.
func TestBarHeightsAreRelativeToTheBusiestDay(t *testing.T) {
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.Local)
	counts := []repo.EventDay{
		{Day: "2026-08-14", Kind: repo.EventFindingNew, Severity: "high", Count: 10},
		{Day: "2026-08-13", Kind: repo.EventFindingNew, Severity: "high", Count: 5},
	}

	trends := buildTrends(counts, nil, nil, now)
	newest := trends.Findings[TrendDays-1].Segments[0]
	previous := trends.Findings[TrendDays-2].Segments[0]

	if newest.Percent != 100 {
		t.Errorf("busiest day is %d%% tall, want 100", newest.Percent)
	}
	if previous.Percent != 50 {
		t.Errorf("half-as-busy day is %d%% tall, want 50", previous.Percent)
	}
}

// A window with nothing in it must not produce a sparkline that implies
// activity, and must not divide by zero getting there.
func TestAnEmptyWindowDrawsAFlatLine(t *testing.T) {
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.Local)
	trends := buildTrends(nil, nil, nil, now)

	if trends.BlockTotal != 0 || trends.Total != 0 {
		t.Fatal("counts are not zero on an empty window")
	}
	if trends.BlockLine == "" {
		t.Fatal("no sparkline path at all")
	}
	// Every point on the floor of the viewBox.
	if strings.Contains(trends.BlockLine, ",0.0") {
		t.Errorf("the flat line is drawn at the top of the chart: %s", trends.BlockLine)
	}
	for _, d := range trends.Findings {
		if len(d.Segments) != 0 {
			t.Error("an empty day produced a bar segment")
		}
	}
}

// An ecosystem with no advisories to match against gets its own treatment. A
// solid bar the same as every other reads as coverage.
func TestAnUnexaminedEcosystemIsMarkedInTheBars(t *testing.T) {
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.Local)
	trends := buildTrends(nil,
		map[string]int{"npm": 100, "Ubuntu:22.04:LTS": 50},
		[]string{"npm"}, now)

	if len(trends.Ecosystems) != 2 {
		t.Fatalf("%d ecosystem bars, want 2", len(trends.Ecosystems))
	}
	for _, bar := range trends.Ecosystems {
		switch bar.Name {
		case "npm":
			if !bar.Covered || bar.Percent != 100 {
				t.Errorf("npm bar = %+v, want covered and full width", bar)
			}
		case "Ubuntu:22.04:LTS":
			if bar.Covered {
				t.Error("an ecosystem with no bundle is marked as examined")
			}
			if bar.Percent != 50 {
				t.Errorf("bar is %d%% wide, want 50", bar.Percent)
			}
		}
	}
}
