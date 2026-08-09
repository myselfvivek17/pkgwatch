package repo

import "time"

// Retention constants.
//
// One install writes roughly 1,200 decision rows, and about 95% of them say
// "allowed" — every version of every transitive dependency the resolver looked
// at. Those are worth having while the wrapper builds its report and worthless
// the moment the session ends, so they are kept by session count rather than by
// age. Verdicts that actually stopped something are kept by age, because those
// are the audit trail.
const (
	// detailSessions is how many recent install sessions keep their full
	// decision detail.
	//
	// ponytail: a count, not a second time window. "The last twenty installs"
	// is a thing a person can reason about, and it bounds the table regardless
	// of whether they install ten times a day or twice a month.
	detailSessions = 20

	// routineFloor keeps recent routine decisions even outside those sessions,
	// so decisions from the agent's shared proxy ports — which belong to no
	// session and can never be in the most recent twenty — are not pruned the
	// instant they are written.
	routineFloor = 7 * 24 * time.Hour
)

// Pruned reports what a retention pass removed.
type Pruned struct {
	RoutineDecisions int
	Events           int
	Sessions         int
	Approvals        int
}

// Any reports whether anything was removed.
func (p Pruned) Any() bool {
	return p.RoutineDecisions+p.Events+p.Sessions+p.Approvals > 0
}

// Prune enforces retention.
//
// hubConfigured decides whether unsynced events are safe to remove. An agent
// with a hub owes it every event it has not yet sent, and deleting those would
// silently lose fleet history; an agent with no hub has no one to owe, so
// synced=0 means nothing and age alone governs.
func (a Agent) Prune(historyFor time.Duration, hubConfigured bool, now time.Time) (Pruned, error) {
	var out Pruned

	cutoff := now.Add(-historyFor).Unix()
	routineCutoff := now.Add(-routineFloor).Unix()

	tx, err := a.DB.Begin()
	if err != nil {
		return out, err
	}
	defer tx.Rollback()

	// Routine decisions: keep the last few sessions in full, plus anything
	// recent enough that a person might still be looking at it.
	result, err := tx.Exec(`DELETE FROM install_decisions
		WHERE decision IN (?, ?)
		  AND requested_at < ?
		  AND (session_id IS NULL OR session_id NOT IN (
		        SELECT id FROM install_sessions ORDER BY started_at DESC LIMIT ?))`,
		DecisionAllowed, DecisionWithheld, routineCutoff, detailSessions)
	if err != nil {
		return out, err
	}
	out.RoutineDecisions = rowsAffected(result)

	// Blocked and overridden verdicts are the audit trail and keep the full
	// window.
	result, err = tx.Exec(`DELETE FROM install_decisions
		WHERE decision NOT IN (?, ?) AND requested_at < ?`,
		DecisionAllowed, DecisionWithheld, cutoff)
	if err != nil {
		return out, err
	}
	out.RoutineDecisions += rowsAffected(result)

	// Events feed the timeline and, once paired, the hub.
	result, err = tx.Exec(`DELETE FROM events
		WHERE ts < ? AND (? = 0 OR synced = 1)`, cutoff, boolToInt(hubConfigured))
	if err != nil {
		return out, err
	}
	out.Events = rowsAffected(result)

	result, err = tx.Exec(`DELETE FROM session_approvals WHERE approved_at < ?`, cutoff)
	if err != nil {
		return out, err
	}
	out.Approvals = rowsAffected(result)

	// Sessions last, and only once nothing references them: install_decisions
	// cascades on delete, so removing a session early would take its blocked
	// verdicts with it — exactly the rows the window above exists to keep.
	//
	// Bounded by the routine floor rather than the history window, because that
	// is what actually empties a session. Routine decisions are pruned by recent
	// session count, so a session can be left holding nothing long before it is
	// ninety days old, and an empty session row carries no information at all.
	// The floor keeps this from racing a session that is still being written.
	result, err = tx.Exec(`DELETE FROM install_sessions
		WHERE started_at < ?
		  AND id NOT IN (SELECT session_id FROM install_decisions WHERE session_id IS NOT NULL)`,
		routineCutoff)
	if err != nil {
		return out, err
	}
	out.Sessions = rowsAffected(result)

	return out, tx.Commit()
}

func rowsAffected(result interface{ RowsAffected() (int64, error) }) int {
	n, err := result.RowsAffected()
	if err != nil {
		return 0
	}
	return int(n)
}
