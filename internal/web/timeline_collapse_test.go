package web

import (
	"strings"
	"testing"
)

func row(time, kind, tier, purl, summary string) TimelineRow {
	return TimelineRow{
		Time: time, Kind: kind, KindLabel: kind, Tier: tier, PURL: purl, Summary: summary,
	}
}

func runOf(n int, time, kind, tier string) []TimelineRow {
	out := make([]TimelineRow, 0, n)
	for i := range n {
		out = append(out, row(time, kind, tier, "pkg:npm/p"+string(rune('a'+i%3)), "s"))
	}
	return out
}

// One bundle sync wrote 156 finding_new events in a single second. Rendered one
// per line, the day they landed on is a page nobody scrolls.
func TestABurstCollapsesToOneRow(t *testing.T) {
	rows := collapse(runOf(156, "20:47", "finding_new", "medium"))
	if len(rows) != 1 {
		t.Fatalf("%d rows, want 1", len(rows))
	}
	if rows[0].Count() != 156 {
		t.Errorf("Count() = %d, want 156", rows[0].Count())
	}
	if !strings.Contains(rows[0].Summary, "156") {
		t.Errorf("summary %q does not say how many", rows[0].Summary)
	}
	// The distinct-package count is what makes a burst legible: 156 rows over 3
	// packages is one advisory feed landing, not 156 separate problems.
	if !strings.Contains(rows[0].Summary, "3 packages") {
		t.Errorf("summary %q does not say how many packages", rows[0].Summary)
	}
	if len(rows[0].Members) != 156 {
		t.Error("members were dropped rather than folded")
	}
}

// The one thing collapsing must never do.
func TestAGroupTakesTheWorstTierInIt(t *testing.T) {
	rows := runOf(20, "20:47", "finding_new", "medium")
	rows[13].Tier = "critical"
	rows[4].Tier = "low"

	got := collapse(rows)
	if len(got) != 1 {
		t.Fatalf("%d rows, want 1", len(got))
	}
	if got[0].Tier != "critical" {
		t.Errorf("group tier = %q, want critical — one critical among a hundred mediums is exactly the row collapsing must not hide", got[0].Tier)
	}
}

func TestAlarmingSurvivesCollapsing(t *testing.T) {
	rows := runOf(5, "09:00", "install_blocked", "high")
	rows[2].Alarming = true
	got := collapse(rows)
	if !got[0].Alarming {
		t.Error("a group containing an alarming event is not alarming")
	}
}

// Two rows are still readable. Collapsing them would hide detail for no gain.
func TestSmallRunsAreLeftAlone(t *testing.T) {
	got := collapse(runOf(2, "20:47", "finding_new", "medium"))
	if len(got) != 2 {
		t.Fatalf("%d rows, want 2 left uncollapsed", len(got))
	}
	if got[0].Grouped() {
		t.Error("a run of two was grouped")
	}
}

// Only adjacent same-kind, same-minute events fold together. A block sitting in
// the middle of a run of scans must not be swallowed by either side.
func TestDifferentKindsAndMinutesDoNotMerge(t *testing.T) {
	rows := []TimelineRow{}
	rows = append(rows, runOf(4, "20:47", "scan", "")...)
	rows = append(rows, row("20:47", "install_blocked", "critical", "pkg:npm/evil", "blocked"))
	rows = append(rows, runOf(4, "20:47", "scan", "")...)
	rows = append(rows, runOf(4, "20:48", "scan", "")...)

	got := collapse(rows)
	if len(got) != 4 {
		t.Fatalf("%d rows, want 4 (scans, the block, scans, next minute)", len(got))
	}
	if got[1].Kind != "install_blocked" || got[1].Grouped() {
		t.Errorf("the block was merged into a neighbouring run: %+v", got[1])
	}
	if got[3].Time != "20:48" {
		t.Errorf("rows from a different minute merged: %q", got[3].Time)
	}
}

func TestCollapsingEmptyIsSafe(t *testing.T) {
	if got := collapse(nil); len(got) != 0 {
		t.Errorf("collapse(nil) = %v", got)
	}
}
