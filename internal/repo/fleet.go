package repo

import (
	"time"
)

// FleetEvent is one timeline row received from a device.
type FleetEvent struct {
	DeviceID   string
	AgentID    int64
	At         time.Time
	Kind       string
	Severity   string
	PURL       string
	AdvisoryID string
	Detail     string
}

// IngestEvents stores events from one device and reports the highest agent
// event ID it durably holds.
//
// INSERT OR IGNORE against UNIQUE(device_id, agent_event_id) is what makes a
// replayed push harmless, and it is why there is no nonce store here: an agent
// whose acknowledgement was lost re-sends, and the constraint absorbs it. That
// is correct at-least-once delivery rather than a bug worked around.
//
// The returned cursor is the maximum ID actually committed, not the maximum
// sent. The agent advances its own cursor from this, so a push that only half
// landed is re-sent rather than skipped — the alternative loses events on every
// interrupted sync and leaves a hole in the fleet timeline that reads as quiet.
func (h Hub) IngestEvents(deviceID string, events []FleetEvent, now time.Time) (accepted int, through int64, err error) {
	if len(events) == 0 {
		return 0, 0, nil
	}

	tx, err := h.DB.Begin()
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`INSERT OR IGNORE INTO fleet_events
		(device_id, agent_event_id, ts, kind, severity, purl, advisory_id, detail_json, received_at)
		VALUES (?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return 0, 0, err
	}
	defer stmt.Close()

	for _, e := range events {
		result, err := stmt.Exec(deviceID, e.AgentID, e.At.Unix(), e.Kind,
			nullIfEmpty(e.Severity), nullIfEmpty(e.PURL), nullIfEmpty(e.AdvisoryID),
			nullIfEmpty(e.Detail), now.Unix())
		if err != nil {
			return 0, 0, err
		}
		if n, _ := result.RowsAffected(); n > 0 {
			accepted++
		}
		// Counted whether inserted or absorbed by the constraint: an event the
		// hub already holds is one the agent never needs to send again.
		if e.AgentID > through {
			through = e.AgentID
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, err
	}
	return accepted, through, nil
}

// FleetFinding is one finding received from a device.
type FleetFinding struct {
	PURL       string
	AdvisoryID string
	Tier       string
	Score      float64
	State      string
	DetectedAt time.Time
}

// ReplaceFindings swaps in a device's complete finding set.
//
// Delete-then-insert inside one transaction, because findings arrive as a
// snapshot rather than a delta. A delta can only ever add: nothing in an
// append-only stream says "this one is closed now", so the hub's counts would
// climb forever and a fleet that is getting better would look like one getting
// worse. That is the same bug as the agent's INSERT OR IGNORE closure, one
// layer up.
//
// The caller must only reach here with a complete set. A truncated snapshot
// applied this way deletes every finding it happened to leave out.
func (h Hub) ReplaceFindings(deviceID string, findings []FleetFinding, now time.Time) (int, error) {
	tx, err := h.DB.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	if _, err := tx.Exec("DELETE FROM fleet_findings WHERE device_id = ?", deviceID); err != nil {
		return 0, err
	}

	stmt, err := tx.Prepare(`INSERT INTO fleet_findings
		(device_id, purl, advisory_id, tier, score, state, detected_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?)`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	for _, f := range findings {
		if _, err := stmt.Exec(deviceID, f.PURL, f.AdvisoryID, f.Tier, f.Score,
			f.State, f.DetectedAt.Unix(), now.Unix()); err != nil {
			return 0, err
		}
	}
	return len(findings), tx.Commit()
}

// FleetPackage is one inventory row, received only at sync_level = full.
type FleetPackage struct {
	PURL      string
	Ecosystem string
	Name      string
	Version   string
	Scope     string
	LastSeen  time.Time
}

// ReplacePackages swaps in a device's inventory, for the same reason findings
// are replaced rather than merged: an uninstall has to be able to reach the hub.
func (h Hub) ReplacePackages(deviceID string, packages []FleetPackage) (int, error) {
	tx, err := h.DB.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	if _, err := tx.Exec("DELETE FROM fleet_packages WHERE device_id = ?", deviceID); err != nil {
		return 0, err
	}

	stmt, err := tx.Prepare(`INSERT INTO fleet_packages
		(device_id, purl, ecosystem, name, version, scope, last_seen) VALUES (?,?,?,?,?,?,?)`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	for _, p := range packages {
		if _, err := stmt.Exec(deviceID, p.PURL, p.Ecosystem, p.Name, p.Version,
			p.Scope, p.LastSeen.Unix()); err != nil {
			return 0, err
		}
	}
	return len(packages), tx.Commit()
}

// FleetFindingCounts returns open findings per tier for one device.
//
// Ignored and fixed are excluded, matching the agent's own count, so the number
// on the fleet card and the number on that machine's dashboard agree. Two
// screens disagreeing about how many problems a machine has is worse than
// either number alone.
func (h Hub) FleetFindingCounts(deviceID string) (map[string]int, error) {
	rows, err := h.DB.Query(`SELECT tier, COUNT(*) FROM fleet_findings
		WHERE device_id = ? AND state NOT IN ('ignored','fixed') GROUP BY tier`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	counts := map[string]int{}
	for rows.Next() {
		var tier string
		var n int
		if err := rows.Scan(&tier, &n); err != nil {
			return nil, err
		}
		counts[tier] = n
	}
	return counts, rows.Err()
}
