package repo_test

import (
	"testing"
	"time"

	"github.com/myselfvivek17/pkgwatch/internal/repo"
)

func queue(t *testing.T, store repo.Agent, kind, severity string, n int) {
	t.Helper()
	for i := range n {
		if err := store.RecordEvent(kind, severity, "", "", map[string]any{"i": i}, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
}

func TestTheCursorOnlyMovesToWhatWasAcknowledged(t *testing.T) {
	store := newAgentDB(t)
	queue(t, store, repo.EventScan, "", 5)

	queued, err := store.QueuedEvents(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(queued) != 5 {
		t.Fatalf("queued %d, want 5", len(queued))
	}
	// Oldest first: the hub's timeline is assembled from these and a cursor only
	// moves forwards, so newest-first would leave a permanent gap.
	if queued[0].ID > queued[len(queued)-1].ID {
		t.Error("queue is not in ascending order")
	}

	// The hub only committed the first three.
	if _, err := store.MarkEventsSynced(queued[2].ID); err != nil {
		t.Fatal(err)
	}
	depth, err := store.QueueDepth()
	if err != nil {
		t.Fatal(err)
	}
	if depth != 2 {
		t.Errorf("depth = %d, want 2 — the unacknowledged events must be re-sent", depth)
	}
}

// A cap that dropped uniformly, or dropped the newest, would lose the one
// blocked install in a fortnight of scan events.
func TestTrimGivesUpOnTheLeastImportantFirst(t *testing.T) {
	store := newAgentDB(t)
	queue(t, store, repo.EventScan, "", 8)          // routine
	queue(t, store, repo.EventFindingNew, "low", 4) //
	queue(t, store, repo.EventInstallBlocked, "critical", 2)

	dropped, err := store.TrimQueue(4, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	total := 0
	for _, n := range dropped {
		total += n
	}
	if total != 10 {
		t.Fatalf("dropped %d (%v), want 10", total, dropped)
	}
	if dropped["critical"] != 0 {
		t.Errorf("dropped %d critical events — those are the reason the queue exists", dropped["critical"])
	}
	if dropped["routine"] != 8 {
		t.Errorf("dropped %d routine events, want all 8 before touching anything else", dropped["routine"])
	}

	// What survives is what mattered.
	left, err := store.QueuedEvents(50)
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 4 {
		t.Fatalf("%d events left, want 4", len(left))
	}
	criticals := 0
	for _, e := range left {
		if e.Severity == "critical" {
			criticals++
		}
	}
	if criticals != 2 {
		t.Errorf("%d criticals survived the trim, want 2", criticals)
	}
}

func TestTrimDoesNothingUnderTheCap(t *testing.T) {
	store := newAgentDB(t)
	queue(t, store, repo.EventScan, "", 3)

	dropped, err := store.TrimQueue(repo.EventQueueCap, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(dropped) != 0 {
		t.Errorf("dropped %v from a queue well under cap", dropped)
	}
}

// Trimming abandons the intent to send, never the record. The local timeline is
// the audit trail an incident is reconstructed from.
func TestTrimKeepsTheLocalTimeline(t *testing.T) {
	store := newAgentDB(t)
	queue(t, store, repo.EventScan, "", 6)

	if _, err := store.TrimQueue(2, time.Now()); err != nil {
		t.Fatal(err)
	}
	events, err := store.Events(repo.EventFilter{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 6 {
		t.Errorf("%d events on the timeline after a trim, want all 6", len(events))
	}
}

// A finding's absence from the snapshot is what tells the hub it closed, so
// fixed findings must not travel — and ignored ones must, or the hub concludes
// they vanished.
func TestTheSnapshotCarriesEverythingButFixed(t *testing.T) {
	store := newAgentDB(t)
	seedFinding(t, store, "pkg:npm/open@1", "GHSA-1", "high", 8)
	seedFinding(t, store, "pkg:npm/hushed@1", "GHSA-2", "low", 2)
	seedFinding(t, store, "pkg:npm/gone@1", "GHSA-3", "high", 8)

	if err := store.IgnoreFinding("pkg:npm/hushed@1", "GHSA-2", "noise", time.Now().Add(30*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB.Exec("UPDATE findings SET state = ? WHERE purl = ?",
		repo.StateFixed, "pkg:npm/gone@1"); err != nil {
		t.Fatal(err)
	}

	snapshot, err := store.SyncableFindings()
	if err != nil {
		t.Fatal(err)
	}
	states := map[string]string{}
	for _, f := range snapshot {
		states[f.PURL] = f.State
	}
	if _, ok := states["pkg:npm/gone@1"]; ok {
		t.Error("a fixed finding is in the snapshot — absence is what carries closure")
	}
	if states["pkg:npm/hushed@1"] != repo.StateIgnored {
		t.Error("an ignored finding is missing — the hub would read that as closed")
	}
	if states["pkg:npm/open@1"] != repo.StateNew {
		t.Errorf("open finding state = %q", states["pkg:npm/open@1"])
	}
}
