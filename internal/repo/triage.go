package repo

import (
	"fmt"
	"time"
)

// ErrNoSuchFinding is returned when a triage command names a finding that is
// not on file. Silently succeeding would let a typo read as "handled".
var ErrNoSuchFinding = fmt.Errorf("no such finding")

// AcknowledgeFinding records that someone has seen it and is not acting yet.
//
// Distinct from ignoring: an acknowledged finding stays in the list and keeps
// its severity, it just stops being news. Ignoring takes it out of the list, and
// that is a bigger decision with an expiry attached.
func (a Agent) AcknowledgeFinding(purl, advisoryID, note string) error {
	result, err := a.DB.Exec(`UPDATE findings SET state = ?, notes = ?
		WHERE purl = ? AND advisory_id = ? AND state NOT IN (?, ?)`,
		StateAcknowledged, nullable(note), purl, advisoryID, StateFixed, StateIgnored)
	if err != nil {
		return err
	}
	if rowsAffected(result) == 0 {
		return fmt.Errorf("%w: %s / %s (already fixed or ignored?)", ErrNoSuchFinding, purl, advisoryID)
	}
	return nil
}

// IgnoreFinding hides a finding until a date.
//
// The expiry is mandatory at the command layer (§10) and enforced here by
// storing it: an ignore with no end is how a real finding gets forgotten, and
// the difference between "deliberately deferred" and "quietly lost" is entirely
// whether something brings it back.
func (a Agent) IgnoreFinding(purl, advisoryID, note string, until time.Time) error {
	result, err := a.DB.Exec(`UPDATE findings SET state = ?, ignore_until = ?, notes = ?
		WHERE purl = ? AND advisory_id = ? AND state <> ?`,
		StateIgnored, until.Unix(), nullable(note), purl, advisoryID, StateFixed)
	if err != nil {
		return err
	}
	if rowsAffected(result) == 0 {
		return fmt.Errorf("%w: %s / %s", ErrNoSuchFinding, purl, advisoryID)
	}
	return nil
}

// ExpireIgnores brings back findings whose ignore window has passed.
//
// This is what makes --days mean anything. Without it the expiry is a note in a
// column nobody reads, every ignore is permanent, and "ignore it for a week"
// silently becomes "never mention this again" — the exact way a deferred
// decision turns into a forgotten one.
//
// Restored at the severity it would have had: critical and high are news again,
// lower tiers come back quiet, matching the baseline rule and the reopen rule.
// A week-old ignore expiring must not produce the alert storm those exist to
// prevent.
func (a Agent) ExpireIgnores(now time.Time) (int, error) {
	result, err := a.DB.Exec(`UPDATE findings
		SET state = CASE WHEN tier IN ('critical', 'high') THEN ? ELSE ? END,
		    ignore_until = NULL
		WHERE state = ? AND ignore_until IS NOT NULL AND ignore_until <= ?`,
		StateNew, StateAcknowledged, StateIgnored, now.Unix())
	if err != nil {
		return 0, err
	}
	return rowsAffected(result), nil
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}
