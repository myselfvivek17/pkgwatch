package repo_test

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/myselfvivek17/pkgwatch/internal/db"
	"github.com/myselfvivek17/pkgwatch/internal/repo"
)

func newAgentDB(t *testing.T) repo.Agent {
	t.Helper()

	handle, err := db.Open(filepath.Join(t.TempDir(), "agent.db"), db.SchemaAgent)
	if err != nil {
		t.Fatalf("open agent db: %v", err)
	}
	t.Cleanup(func() { handle.Close() })
	return repo.Agent{DB: handle}
}

func count(t *testing.T, handle *sql.DB, query string, args ...any) int {
	t.Helper()

	var n int
	if err := handle.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// seedSession writes one install session with the given number of routine
// decisions and one blocked verdict, at the given time.
func seedSession(t *testing.T, store repo.Agent, id string, at time.Time, routine int) {
	t.Helper()

	if err := store.StartSession(id, "npm", ".", "npm install", "interactive", at); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < routine; i++ {
		if err := store.RecordDecision(repo.Decision{
			SessionID: id, PURL: "pkg:npm/dep@1.0.0",
			Decision: repo.DecisionAllowed, At: at,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.RecordDecision(repo.Decision{
		SessionID: id, PURL: "pkg:npm/lodash@4.17.20",
		Decision: repo.DecisionBlocked, Reason: "vulnerability",
		AdvisoryID: "GHSA-35jh-r3h4-6jhm", At: at,
	}); err != nil {
		t.Fatal(err)
	}
}

// One npm install writes roughly 1,200 decisions and about 95% of them say
// "allowed". Without retention the audit trail outgrows everything else in the
// database by two orders of magnitude.
func TestPruneDropsRoutineDecisionsButKeepsVerdicts(t *testing.T) {
	store := newAgentDB(t)
	now := time.Now()

	// Old enough to be outside the routine floor, recent enough to be inside the
	// history window.
	old := now.Add(-30 * 24 * time.Hour)
	for i := 0; i < 25; i++ {
		seedSession(t, store, sessionID(i), old.Add(time.Duration(i)*time.Minute), 10)
	}

	before := count(t, store.DB, "SELECT COUNT(*) FROM install_decisions")
	if before != 25*11 {
		t.Fatalf("seeded %d decisions, want %d", before, 25*11)
	}

	pruned, err := store.Prune(90*24*time.Hour, false, now)
	if err != nil {
		t.Fatal(err)
	}

	blocked := count(t, store.DB,
		"SELECT COUNT(*) FROM install_decisions WHERE decision = ?", repo.DecisionBlocked)
	if blocked != 25 {
		t.Errorf("blocked verdicts = %d, want all 25 kept — they are the audit trail", blocked)
	}

	routine := count(t, store.DB,
		"SELECT COUNT(*) FROM install_decisions WHERE decision = ?", repo.DecisionAllowed)
	// The twenty most recent sessions keep their detail; the five oldest do not.
	if routine != 20*10 {
		t.Errorf("routine decisions = %d, want %d (detail for the last 20 sessions)", routine, 20*10)
	}
	if pruned.RoutineDecisions != 5*10 {
		t.Errorf("reported %d pruned, want %d", pruned.RoutineDecisions, 5*10)
	}
}

// Decisions from a few minutes ago are what the user is looking at right now.
func TestPruneKeepsRecentRoutineDecisions(t *testing.T) {
	store := newAgentDB(t)
	now := time.Now()

	// More sessions than the detail window, but all of them from today.
	for i := 0; i < 30; i++ {
		seedSession(t, store, sessionID(i), now.Add(-time.Duration(i)*time.Minute), 5)
	}

	if _, err := store.Prune(90*24*time.Hour, false, now); err != nil {
		t.Fatal(err)
	}
	routine := count(t, store.DB,
		"SELECT COUNT(*) FROM install_decisions WHERE decision = ?", repo.DecisionAllowed)
	if routine != 30*5 {
		t.Errorf("routine decisions = %d, want all %d — nothing is a week old yet", routine, 30*5)
	}
}

// An agent with a hub owes it every event it has not sent. Deleting those on
// age would silently lose fleet history.
func TestPruneNeverDropsUnsyncedEventsWhenPaired(t *testing.T) {
	store := newAgentDB(t)
	now := time.Now()
	old := now.Add(-200 * 24 * time.Hour)

	for i := 0; i < 5; i++ {
		if err := store.RecordEvent(repo.EventInstallBlocked, "high",
			"pkg:npm/lodash@4.17.20", "GHSA-x", nil, old); err != nil {
			t.Fatal(err)
		}
	}

	pruned, err := store.Prune(90*24*time.Hour, true, now)
	if err != nil {
		t.Fatal(err)
	}
	if pruned.Events != 0 {
		t.Errorf("pruned %d unsynced events on a paired agent", pruned.Events)
	}
	if n := count(t, store.DB, "SELECT COUNT(*) FROM events"); n != 5 {
		t.Errorf("events = %d, want 5", n)
	}

	// With no hub configured there is no one to owe them to, so age governs.
	if _, err := store.Prune(90*24*time.Hour, false, now); err != nil {
		t.Fatal(err)
	}
	if n := count(t, store.DB, "SELECT COUNT(*) FROM events"); n != 0 {
		t.Errorf("events = %d, want 0 once unpaired and past the window", n)
	}
}

// install_decisions cascades on session delete, so removing a session too eagerly
// would take its blocked verdicts with it — the rows retention exists to keep.
func TestPruneDoesNotCascadeAwayKeptVerdicts(t *testing.T) {
	store := newAgentDB(t)
	now := time.Now()

	seedSession(t, store, "old-session", now.Add(-30*24*time.Hour), 10)

	if _, err := store.Prune(90*24*time.Hour, false, now); err != nil {
		t.Fatal(err)
	}
	if n := count(t, store.DB, "SELECT COUNT(*) FROM install_sessions"); n != 1 {
		t.Errorf("session was deleted while its verdict still references it")
	}
	if n := count(t, store.DB,
		"SELECT COUNT(*) FROM install_decisions WHERE decision = ?", repo.DecisionBlocked); n != 1 {
		t.Errorf("blocked verdict = %d, want 1", n)
	}
}

// A session row is only worth keeping while something still points at it.
func TestPruneRemovesSessionsWithNothingLeft(t *testing.T) {
	store := newAgentDB(t)
	now := time.Now()

	// One old session that never blocked anything, so it holds only routine
	// decisions...
	if err := store.StartSession("stale-session", "npm", ".", "npm install", "interactive",
		now.Add(-60*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if err := store.RecordDecision(repo.Decision{
			SessionID: "stale-session", PURL: "pkg:npm/dep@1.0.0",
			Decision: repo.DecisionAllowed, At: now.Add(-60 * 24 * time.Hour),
		}); err != nil {
			t.Fatal(err)
		}
	}
	// ...and enough newer ones to push it out of the detail window.
	for i := 0; i < 25; i++ {
		seedSession(t, store, sessionID(i), now.Add(-time.Duration(i)*time.Minute), 2)
	}

	if _, err := store.Prune(90*24*time.Hour, false, now); err != nil {
		t.Fatal(err)
	}

	if n := count(t, store.DB,
		"SELECT COUNT(*) FROM install_decisions WHERE session_id = 'stale-session'"); n != 0 {
		t.Errorf("stale routine decisions = %d, want 0", n)
	}
	if n := count(t, store.DB,
		"SELECT COUNT(*) FROM install_sessions WHERE id = 'stale-session'"); n != 0 {
		t.Errorf("a session with nothing left pointing at it should be removed")
	}
	// The sessions that still hold verdicts must survive.
	if n := count(t, store.DB, "SELECT COUNT(*) FROM install_sessions"); n != 25 {
		t.Errorf("sessions = %d, want the 25 that still carry verdicts", n)
	}
}

func sessionID(i int) string {
	return string(rune('a'+i/26)) + string(rune('a'+i%26)) + "00000000000000"
}
