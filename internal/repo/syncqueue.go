package repo

import (
	"time"
)

// EventQueueCap bounds how many unsent events an agent will hold for a hub it
// cannot reach (§7).
//
// A single npm install writes roughly 1,200 gate decisions, so an agent that
// has been offline for a fortnight would otherwise hand the hub a queue larger
// than its own database. The cap exists so the local database stays a local
// database; nothing about it makes the agent work less well.
const EventQueueCap = 50_000

// QueuedEvent is one event on its way to the hub.
//
// Detail is carried verbatim rather than decoded and re-encoded: it was written
// by some version of this binary and the hub should receive what was recorded,
// not this build's reading of it.
type QueuedEvent struct {
	ID         int64
	At         time.Time
	Kind       string
	Severity   string
	PURL       string
	AdvisoryID string
	Detail     string
}

// QueuedEvents returns the oldest unsent events, in order.
//
// Oldest first because the hub's timeline is assembled from them and a cursor
// only moves forwards — sending the newest first would leave a permanent gap.
func (a Agent) QueuedEvents(limit int) ([]QueuedEvent, error) {
	if limit <= 0 {
		limit = 1000
	}
	rows, err := a.DB.Query(`SELECT id, ts, kind, COALESCE(severity, ''), COALESCE(purl, ''),
		COALESCE(advisory_id, ''), COALESCE(detail_json, '')
		FROM events WHERE synced = 0 ORDER BY id ASC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []QueuedEvent
	for rows.Next() {
		var e QueuedEvent
		var ts int64
		if err := rows.Scan(&e.ID, &ts, &e.Kind, &e.Severity, &e.PURL, &e.AdvisoryID, &e.Detail); err != nil {
			return nil, err
		}
		e.At = time.Unix(ts, 0)
		out = append(out, e)
	}
	return out, rows.Err()
}

// MarkEventsSynced advances the cursor to an ID the hub has acknowledged.
func (a Agent) MarkEventsSynced(through int64) (int, error) {
	if through <= 0 {
		return 0, nil
	}
	result, err := a.DB.Exec("UPDATE events SET synced = 1 WHERE synced = 0 AND id <= ?", through)
	if err != nil {
		return 0, err
	}
	return rowsAffected(result), nil
}

// QueueDepth is how many events are waiting to be sent.
func (a Agent) QueueDepth() (int, error) {
	var n int
	err := a.DB.QueryRow("SELECT COUNT(*) FROM events WHERE synced = 0").Scan(&n)
	return n, err
}

// TrimQueue gives up on the least important events once the queue is over cap,
// and reports what it abandoned.
//
// Least important first: routine and low-severity rows before anything that
// says something happened. A cap that dropped the newest, or dropped uniformly,
// would lose the one blocked install in a fortnight of scan events.
//
// The rows stay in the local timeline — only the cursor moves past them. What
// is dropped is the intent to send, not the record.
//
// The counts are returned rather than discarded because a silent cap is a hole
// in the fleet timeline that reads as a quiet week. The caller records an event
// naming what was lost, which itself syncs.
func (a Agent) TrimQueue(cap int, now time.Time) (map[string]int, error) {
	depth, err := a.QueueDepth()
	if err != nil {
		return nil, err
	}
	if cap <= 0 || depth <= cap {
		return nil, nil
	}

	rows, err := a.DB.Query(`UPDATE events SET synced = 1 WHERE id IN (
			SELECT id FROM events WHERE synced = 0
			ORDER BY CASE COALESCE(severity, '')
				WHEN 'critical' THEN 3 WHEN 'high' THEN 2 WHEN 'medium' THEN 1 ELSE 0 END ASC,
				id ASC
			LIMIT ?)
		RETURNING COALESCE(severity, 'routine')`, depth-cap)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	dropped := map[string]int{}
	for rows.Next() {
		var severity string
		if err := rows.Scan(&severity); err != nil {
			return nil, err
		}
		if severity == "" {
			severity = "routine"
		}
		dropped[severity]++
	}
	return dropped, rows.Err()
}

// SyncableFindings is the snapshot pushed to the hub.
//
// Everything except fixed. A finding's absence from the snapshot is what tells
// the hub it closed, so including fixed ones would both grow the payload
// without bound and rob absence of its meaning. Ignored ones travel because the
// hub should know a decision was taken, not conclude the finding vanished.
func (a Agent) SyncableFindings() ([]Finding, error) {
	rows, err := a.DB.Query(`SELECT purl, advisory_id, score, tier, state, detected_at
		FROM findings WHERE state != ? ORDER BY score DESC`, StateFixed)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Finding
	for rows.Next() {
		var f Finding
		var detected int64
		if err := rows.Scan(&f.PURL, &f.AdvisoryID, &f.Score, &f.Tier, &f.State, &detected); err != nil {
			return nil, err
		}
		f.DetectedAt = time.Unix(detected, 0)
		out = append(out, f)
	}
	return out, rows.Err()
}

// SyncPackage is one inventory row on its way to the hub.
//
// Its own type rather than PackageRow: what the hub is told is deliberately
// less than what the agent knows — no install path, no script flag. Those say
// where on the disk to find something and whether it runs code on install,
// which is a map worth having and not one the hub needs (§3.3).
type SyncPackage struct {
	PURL      string
	Ecosystem string
	Name      string
	Version   string
	Scope     string
	LastSeen  time.Time
}

// SyncablePackages is the inventory snapshot, sent only at sync_level = full.
//
// Retired packages are left out: the hub is being told what is installed, and
// a row for something uninstalled last March is not that.
func (a Agent) SyncablePackages() ([]SyncPackage, error) {
	rows, err := a.DB.Query(`SELECT purl, ecosystem, name, version, scope, last_seen
		FROM packages WHERE gone_at IS NULL`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []SyncPackage
	for rows.Next() {
		var p SyncPackage
		var seen int64
		if err := rows.Scan(&p.PURL, &p.Ecosystem, &p.Name, &p.Version, &p.Scope, &seen); err != nil {
			return nil, err
		}
		p.LastSeen = time.Unix(seen, 0)
		out = append(out, p)
	}
	return out, rows.Err()
}
