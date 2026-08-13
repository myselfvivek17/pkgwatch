package repo

import (
	"database/sql"
	"strings"
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

// FleetEvents returns the fleet timeline, reusing the agent timeline's filter
// and row type so one set of templates renders both (§8).
//
// Kind and severity filters apply as they do locally. The machine filter the
// design shows on the hub is not wired yet — the rows carry a device, but the
// Event type does not, and inventing a column here would mean the two timelines
// stop being the same thing.
func (h Hub) FleetEvents(f EventFilter) ([]Event, error) {
	query := `SELECT id, ts, kind, COALESCE(severity, ''), COALESCE(purl, ''),
		COALESCE(advisory_id, ''), COALESCE(detail_json, '')
		FROM fleet_events WHERE 1=1`
	var args []any

	if f.Kind != "" {
		if f.Kind == "routine" || f.Kind == "actionable" {
			kinds := make([]string, 0, len(routineKinds))
			for kind := range routineKinds {
				kinds = append(kinds, kind)
			}
			op := "IN"
			if f.Kind == "actionable" {
				op = "NOT IN"
			}
			query += " AND kind " + op + " (?" + strings.Repeat(",?", len(kinds)-1) + ")"
			for _, kind := range kinds {
				args = append(args, kind)
			}
		} else {
			query += " AND kind = ?"
			args = append(args, f.Kind)
		}
	}
	if f.Severity != "" {
		query += " AND severity = ?"
		args = append(args, f.Severity)
	}

	limit := f.Limit
	if limit <= 0 {
		limit = 200
	}
	if f.SinceID > 0 {
		query += " AND id > ? ORDER BY id ASC LIMIT ?"
		args = append(args, f.SinceID, limit)
	} else {
		query += " ORDER BY id DESC LIMIT ?"
		args = append(args, limit)
	}

	rows, err := h.DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Event
	for rows.Next() {
		var e Event
		var ts int64
		var detail string
		if err := rows.Scan(&e.ID, &ts, &e.Kind, &e.Severity, &e.PURL,
			&e.AdvisoryID, &detail); err != nil {
			return nil, err
		}
		e.At = time.Unix(ts, 0)
		e.Detail = decodeDetail(detail)
		out = append(out, e)
	}
	return out, rows.Err()
}

// OldestFleetEventAt reports where the hub's timeline actually begins, so a
// page that runs out can say so rather than implying nothing happened before.
func (h Hub) OldestFleetEventAt() (time.Time, error) {
	var ts sql.NullInt64
	if err := h.DB.QueryRow("SELECT MIN(ts) FROM fleet_events").Scan(&ts); err != nil {
		return time.Time{}, err
	}
	if !ts.Valid {
		return time.Time{}, nil
	}
	return time.Unix(ts.Int64, 0), nil
}

// FleetSearchHit is one machine holding a package.
type FleetSearchHit struct {
	DeviceID  string
	Hostname  string
	Ecosystem string
	Name      string
	Version   string
	Scope     string
	LastSeen  time.Time
}

// SearchPackages answers "which of my machines has this installed".
//
// Only devices at sync_level = full have packages here at all, which is why
// the caller is also told which devices were searchable. A search across three
// machines that returns nothing, when only one of them ever sent an inventory,
// is the difference between "nowhere" and "we did not look" — and this project
// has shipped that bug twice already.
func (h Hub) SearchPackages(query string, limit int) ([]FleetSearchHit, error) {
	if limit <= 0 {
		limit = 200
	}
	// Matched on name only, not the full purl. A person searching "lodash"
	// wants every version of it, which is the whole question being asked.
	rows, err := h.DB.Query(`SELECT p.device_id, d.hostname, p.ecosystem, p.name,
		p.version, p.scope, p.last_seen
		FROM fleet_packages p JOIN devices d ON d.id = p.device_id
		WHERE p.name LIKE ? ESCAPE '\'
		ORDER BY p.name, d.hostname, p.version LIMIT ?`, "%"+likeEscape(query)+"%", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []FleetSearchHit
	for rows.Next() {
		var hit FleetSearchHit
		var seen int64
		if err := rows.Scan(&hit.DeviceID, &hit.Hostname, &hit.Ecosystem, &hit.Name,
			&hit.Version, &hit.Scope, &seen); err != nil {
			return nil, err
		}
		hit.LastSeen = time.Unix(seen, 0)
		out = append(out, hit)
	}
	return out, rows.Err()
}

// likeEscape stops a package name containing % or _ from turning into a
// wildcard — "node_modules" would otherwise match "nodeXmodules".
func likeEscape(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}

// InventoryCoverage names the devices whose packages are actually on file, and
// those approved but sending only findings.
//
// Returned together because a search result is meaningless without it. Sync
// level defaults to findings (§3.3), so on a default fleet the package table is
// empty and every search correctly returns nothing — which reads as "you do not
// have it" unless the page says otherwise.
func (h Hub) InventoryCoverage() (searched, notSearched []string, err error) {
	rows, err := h.DB.Query(`SELECT d.hostname, d.sync_level,
		EXISTS(SELECT 1 FROM fleet_packages p WHERE p.device_id = d.id)
		FROM devices d WHERE d.status = ? ORDER BY d.hostname`, DeviceStatusApproved)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var hostname, level string
		var hasPackages bool
		if err := rows.Scan(&hostname, &level, &hasPackages); err != nil {
			return nil, nil, err
		}
		if hasPackages {
			searched = append(searched, hostname)
		} else {
			notSearched = append(notSearched, hostname+" ("+level+")")
		}
	}
	return searched, notSearched, rows.Err()
}

// fleetScanCap bounds how many findings are read before the fixable filter is
// applied in Go. Filtering after a LIMIT would mean "the fixable ones among the
// worst 100", which reads as "the fixable ones" and is a different list.
const fleetScanCap = 5000

// FleetFindings returns open findings across the whole fleet, worst first.
//
// attached says whether an advisory bundle is available to this hub. With one,
// each row is enriched with the summary, the advisory's own CVSS and the fix
// version — the three columns that answer "what do I actually do about this",
// which is the question the hub's own findings page exists to answer. Without
// one the findings are still listed, because they are recorded facts, and the
// caller reports attached=false so the page says those columns are unknown
// rather than leaving them blank: a blank fix column reads as "no fix exists"
// and that is the opposite of true.
//
// The lookup goes through the finding's own purl rather than through
// fleet_packages. Inventory only arrives at sync_level = full, so on a fleet
// syncing findings only that join is empty and every fix would come back NULL —
// the same inversion, arrived at by a different route.
//
// Read-only by construction. The agent is authoritative for its own findings
// (§3.3) and sync is outbound-only, so there is no channel to write a triage
// decision back down — which is why the page hides its ack and ignore controls
// here rather than offering buttons that would silently do nothing.
func (h Hub) FleetFindings(attached bool, f FindingFilter) ([]Finding, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	if f.FixableOnly && !attached {
		// Whether a fix exists is only knowable from a bundle. Returning
		// everything here would claim each one is unfixable.
		return nil, nil
	}

	// Read past the limit only when the filter runs afterwards.
	scan := limit
	if f.FixableOnly {
		scan = fleetScanCap
	}

	query := `SELECT d.hostname, f.purl, f.advisory_id, f.score, f.tier, f.state, f.detected_at
		FROM fleet_findings f JOIN devices d ON d.id = f.device_id
		WHERE f.state NOT IN ('ignored','fixed')`
	var args []any
	if f.Tier != "" {
		query += " AND f.tier = ?"
		args = append(args, f.Tier)
	}
	query += " ORDER BY f.score DESC, d.hostname LIMIT ?"
	args = append(args, scan)

	rows, err := h.DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Finding
	for rows.Next() {
		var finding Finding
		var detected int64
		if err := rows.Scan(&finding.Machine, &finding.PURL, &finding.AdvisoryID,
			&finding.Score, &finding.Tier, &finding.State, &detected); err != nil {
			return nil, err
		}
		finding.DetectedAt = time.Unix(detected, 0)
		out = append(out, finding)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if !attached {
		return out, nil
	}

	if err := enrichFixes(h.DB, out); err != nil {
		return nil, err
	}
	if f.FixableOnly {
		kept := out[:0]
		for _, finding := range out {
			if finding.FixedIn != "" {
				kept = append(kept, finding)
			}
		}
		out = kept
	}
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
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
