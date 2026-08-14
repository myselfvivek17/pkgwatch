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
	// Count only on a commit that happened. `return len(x), tx.Commit()` reports
	// rows stored alongside the error saying they were not.
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(findings), nil
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
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(packages), nil
}

// FleetExposure is one machine that ran a malicious package.
type FleetExposure struct {
	DeviceID   string
	Hostname   string
	PURL       string
	AdvisoryID string
	Summary    string
	DetectedAt time.Time
}

// FleetMalwareFindings returns the fleet's open malware findings.
//
// These, not the replicated ticks, are what the hub's rotation page is built
// from. Ticks only exist once somebody has started, so a page driven by them
// would show nothing at all for the machine that has done nothing — which is
// precisely the machine the page exists for.
//
// Requires the advisory bundle: kind lives there, not on the finding. Without
// one this returns nil and the caller says it cannot tell.
func (h Hub) FleetMalwareFindings(attached bool) ([]FleetExposure, error) {
	if !attached {
		return nil, nil
	}
	rows, err := h.DB.Query(`SELECT f.device_id, COALESCE(d.hostname, f.device_id),
			f.purl, f.advisory_id, COALESCE(t.summary, ''), f.detected_at
		FROM fleet_findings f
		LEFT JOIN devices d ON d.id = f.device_id
		LEFT JOIN adv.advisory_text t ON t.id = f.advisory_id
		WHERE f.state NOT IN ('ignored', 'fixed')
		  AND EXISTS (SELECT 1 FROM adv.advisories a
		              WHERE a.id = f.advisory_id AND a.kind = 'malware')
		ORDER BY f.detected_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []FleetExposure
	for rows.Next() {
		var e FleetExposure
		var at int64
		if err := rows.Scan(&e.DeviceID, &e.Hostname, &e.PURL, &e.AdvisoryID,
			&e.Summary, &at); err != nil {
			return nil, err
		}
		e.DetectedAt = time.Unix(at, 0)
		out = append(out, e)
	}
	return out, rows.Err()
}

// FleetRotationTick is one replicated checklist row.
type FleetRotationTick struct {
	DeviceID   string
	Hostname   string
	PURL       string
	AdvisoryID string
	ItemID     string
	CheckedAt  time.Time
}

// ReplaceRotation swaps in a device's checklist state.
//
// Replaced rather than merged because unticking is a removal, and an append-only
// stream has no way to say "this one is not done after all" — the hub's progress
// would only ever climb, which on this page means reporting a rotation finished
// that nobody finished.
func (h Hub) ReplaceRotation(deviceID string, ticks []FleetRotationTick) (int, error) {
	tx, err := h.DB.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	if _, err := tx.Exec("DELETE FROM fleet_rotation WHERE device_id = ?", deviceID); err != nil {
		return 0, err
	}

	stmt, err := tx.Prepare(`INSERT INTO fleet_rotation
		(device_id, purl, advisory_id, item_id, checked_at) VALUES (?,?,?,?,?)`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	for _, t := range ticks {
		var checked any
		if !t.CheckedAt.IsZero() {
			checked = t.CheckedAt.Unix()
		}
		if _, err := stmt.Exec(deviceID, t.PURL, t.AdvisoryID, t.ItemID, checked); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(ticks), nil
}

// FleetRotation returns every replicated checklist row, with the hostname the
// page needs to say which machine still owes the work.
func (h Hub) FleetRotation() ([]FleetRotationTick, error) {
	rows, err := h.DB.Query(`SELECT r.device_id, COALESCE(d.hostname, r.device_id),
			r.purl, r.advisory_id, r.item_id, COALESCE(r.checked_at, 0)
		FROM fleet_rotation r LEFT JOIN devices d ON d.id = r.device_id
		ORDER BY d.hostname, r.purl`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []FleetRotationTick
	for rows.Next() {
		var t FleetRotationTick
		var at int64
		if err := rows.Scan(&t.DeviceID, &t.Hostname, &t.PURL, &t.AdvisoryID,
			&t.ItemID, &at); err != nil {
			return nil, err
		}
		if at > 0 {
			t.CheckedAt = time.Unix(at, 0)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// FleetQuarantineRow is one replicated quarantine record.
//
// PathReplicated distinguishes "taken from nowhere" from "the path did not
// cross the wire at this sync level" — an empty string alone cannot.
type FleetQuarantineRow struct {
	DeviceID       string
	Hostname       string
	ID             string
	PURL           string
	AdvisoryID     string
	State          string
	OriginPath     string
	PathReplicated bool
	At             time.Time
	RestoredAt     time.Time
}

// ReplaceQuarantine swaps in a device's quarantine set. Restoring a package
// removes nothing here — the row stays with state 'restored' — but the agent is
// still the only writer, so a replace is what keeps the two in step.
func (h Hub) ReplaceQuarantine(deviceID string, items []FleetQuarantineRow) (int, error) {
	tx, err := h.DB.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	if _, err := tx.Exec("DELETE FROM fleet_quarantine WHERE device_id = ?", deviceID); err != nil {
		return 0, err
	}

	stmt, err := tx.Prepare(`INSERT INTO fleet_quarantine
		(device_id, id, purl, advisory_id, state, origin_path, quarantined_at, restored_at)
		VALUES (?,?,?,?,?,?,?,?)`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	for _, q := range items {
		var restored any
		if !q.RestoredAt.IsZero() {
			restored = q.RestoredAt.Unix()
		}
		if _, err := stmt.Exec(deviceID, q.ID, q.PURL, q.AdvisoryID, q.State,
			nullIfEmpty(q.OriginPath), q.At.Unix(), restored); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(items), nil
}

// FleetQuarantine lists what the fleet has put away, newest first.
func (h Hub) FleetQuarantine(limit int) ([]FleetQuarantineRow, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := h.DB.Query(`SELECT q.device_id, COALESCE(d.hostname, q.device_id),
			q.id, q.purl, q.advisory_id, q.state, q.origin_path,
			q.quarantined_at, COALESCE(q.restored_at, 0)
		FROM fleet_quarantine q LEFT JOIN devices d ON d.id = q.device_id
		ORDER BY q.quarantined_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []FleetQuarantineRow
	for rows.Next() {
		var q FleetQuarantineRow
		var path sql.NullString
		var at, restored int64
		if err := rows.Scan(&q.DeviceID, &q.Hostname, &q.ID, &q.PURL, &q.AdvisoryID,
			&q.State, &path, &at, &restored); err != nil {
			return nil, err
		}
		q.OriginPath, q.PathReplicated = path.String, path.Valid
		q.At = time.Unix(at, 0)
		if restored > 0 {
			q.RestoredAt = time.Unix(restored, 0)
		}
		out = append(out, q)
	}
	return out, rows.Err()
}

// EventDay is one day's count of one kind of event, at one severity.
//
// Deliberately not pre-bucketed into a fixed number of days here. SQL can only
// return days that have rows, and a chart that drew a column per returned row
// would compress a quiet fortnight into three fat bars — the axis has to be
// generated by the caller and filled from this, so the empty days stay empty
// and visible.
type EventDay struct {
	Day      string
	Kind     string
	Severity string
	Count    int
}

// FleetEventCounts summarises the fleet timeline by day for the trend charts.
//
// Local time, matching every other date on the dashboard: a chart whose day
// boundaries are UTC puts an evening block on tomorrow's column for half the
// world, which makes "when did this happen" unanswerable from the picture.
func (h Hub) FleetEventCounts(since time.Time) ([]EventDay, error) {
	rows, err := h.DB.Query(`SELECT date(ts, 'unixepoch', 'localtime') AS day,
			kind, COALESCE(severity, ''), COUNT(*)
		FROM fleet_events WHERE ts >= ?
		GROUP BY day, kind, severity`, since.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []EventDay
	for rows.Next() {
		var d EventDay
		if err := rows.Scan(&d.Day, &d.Kind, &d.Severity, &d.Count); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// FleetBlock is one install this fleet refused to complete.
//
// Built from the install_blocked event rather than from a session, because
// install_sessions and the per-package decisions never leave the machine. The
// hub can say what was blocked and why; the dependency chain that led there is
// only on the agent, and the page has to say so rather than implying it has it.
type FleetBlock struct {
	DeviceID   string
	Hostname   string
	At         time.Time
	Tier       string
	PURL       string
	AdvisoryID string
	Detail     string
}

// FleetBlocks returns the fleet's blocked installs, newest first.
func (h Hub) FleetBlocks(limit int) ([]FleetBlock, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := h.DB.Query(`SELECT e.device_id, COALESCE(d.hostname, e.device_id),
			e.ts, COALESCE(e.severity, ''), COALESCE(e.purl, ''),
			COALESCE(e.advisory_id, ''), COALESCE(e.detail_json, '')
		FROM fleet_events e LEFT JOIN devices d ON d.id = e.device_id
		WHERE e.kind = ?
		ORDER BY e.ts DESC LIMIT ?`, EventInstallBlocked, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []FleetBlock
	for rows.Next() {
		var b FleetBlock
		var at int64
		if err := rows.Scan(&b.DeviceID, &b.Hostname, &at, &b.Tier,
			&b.PURL, &b.AdvisoryID, &b.Detail); err != nil {
			return nil, err
		}
		b.At = time.Unix(at, 0)
		out = append(out, b)
	}
	return out, rows.Err()
}

// FleetInventoryRow is one package on one machine, or one machine that reports
// no inventory at all.
//
// The second case is why this is a LEFT JOIN from devices. A machine at
// sync_level = findings contributes no package rows, and a fleet inventory that
// simply omitted it would describe a partial fleet as the whole one — the same
// silence that the credential list had to be built to avoid.
type FleetInventoryRow struct {
	DeviceID  string
	Hostname  string
	SyncLevel string
	Ecosystem string
	Name      string
	Version   string
	Scope     string

	// Total is how many packages this machine has matching the filter, which is
	// not how many rows came back — the query caps per machine.
	Total int
}

// Reported says whether this row is a package rather than a placeholder for a
// machine that sends none.
func (r FleetInventoryRow) Reported() bool { return r.Name != "" }

// FleetInventory lists the fleet's packages, and every approved machine
// whether or not it sends any.
//
// perMachine caps the rows returned FOR EACH MACHINE, not the result as a
// whole. A single LIMIT over the joined rows looks equivalent and is not: the
// rows come back ordered by hostname, so the first machine's packages fill the
// budget and every machine after it disappears from the page entirely. On this
// fleet that was literal — a laptop with 2,183 packages sorted ahead of the
// server, so a 1,000-row cap rendered a two-machine fleet as one. A missing
// machine reads as a machine with nothing wrong, which is the failure this
// page's LEFT JOIN exists to prevent, arriving through the LIMIT instead.
//
// Total comes back with each row so the page can say how much of a machine it
// is showing rather than quietly ending mid-inventory.
func (h Hub) FleetInventory(ecosystem, scope string, perMachine int) ([]FleetInventoryRow, error) {
	if perMachine <= 0 {
		perMachine = 500
	}

	// The filters apply to the package side of the join only. Moving them into
	// the WHERE clause would drop the placeholder rows and take every
	// non-reporting machine off the page the moment anyone filtered.
	rows, err := h.DB.Query(`WITH ranked AS (
			SELECT d.id AS device_id, d.hostname AS hostname, d.sync_level AS sync_level,
				p.ecosystem AS ecosystem, p.name AS name, p.version AS version, p.scope AS scope,
				ROW_NUMBER() OVER (PARTITION BY d.id ORDER BY p.ecosystem, p.name, p.version) AS rn,
				COUNT(p.name) OVER (PARTITION BY d.id) AS total
			FROM devices d
			LEFT JOIN fleet_packages p ON p.device_id = d.id
				AND (? = '' OR p.ecosystem = ?)
				AND (? = '' OR p.scope = ?)
			WHERE d.status = ?
		)
		SELECT device_id, hostname, sync_level,
			COALESCE(ecosystem, ''), COALESCE(name, ''),
			COALESCE(version, ''), COALESCE(scope, ''), total
		FROM ranked WHERE rn <= ?
		ORDER BY hostname, ecosystem, name, version`,
		ecosystem, ecosystem, scope, scope, DeviceStatusApproved, perMachine)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []FleetInventoryRow
	for rows.Next() {
		var r FleetInventoryRow
		if err := rows.Scan(&r.DeviceID, &r.Hostname, &r.SyncLevel,
			&r.Ecosystem, &r.Name, &r.Version, &r.Scope, &r.Total); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// FleetEcosystemCounts counts the fleet's packages per ecosystem.
//
// Counted over what was actually reported, which is not the same as what is
// installed: machines the hub takes findings from contribute nothing here. The
// caller pairs this with the count of those machines, so the total is never
// presented as the fleet's whole software estate.
func (h Hub) FleetEcosystemCounts() (map[string]int, error) {
	rows, err := h.DB.Query(
		"SELECT ecosystem, COUNT(*) FROM fleet_packages GROUP BY ecosystem")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	counts := map[string]int{}
	for rows.Next() {
		var name string
		var n int
		if err := rows.Scan(&name, &n); err != nil {
			return nil, err
		}
		counts[name] = n
	}
	return counts, rows.Err()
}

// FleetCredential is one row of "what could be read on this machine".
//
// A machine with nothing to report still produces one row, with ItemID empty:
// the list is per-machine, and a machine missing from it entirely would read as
// one with no credentials rather than one that never said.
type FleetCredential struct {
	DeviceID  string
	Hostname  string
	SyncLevel string
	ItemID    string
	Category  string
	Path      string
}

// ReplaceCredentials swaps in what a machine reports it holds.
//
// Replaced, so deleting a credential file reaches the hub. A merge would leave
// the hub listing an AWS key that was removed months ago, and sending someone
// to rotate a credential that no longer exists teaches them to distrust the page.
func (h Hub) ReplaceCredentials(deviceID string, items []FleetCredential, ranks []int) (int, error) {
	tx, err := h.DB.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	if _, err := tx.Exec("DELETE FROM fleet_credentials WHERE device_id = ?", deviceID); err != nil {
		return 0, err
	}

	stmt, err := tx.Prepare(`INSERT INTO fleet_credentials
		(device_id, item_id, category, path, rank) VALUES (?,?,?,?,?)`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	for i, c := range items {
		rank := i
		if i < len(ranks) {
			rank = ranks[i]
		}
		if _, err := stmt.Exec(deviceID, c.ItemID, c.Category, c.Path, rank); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(items), nil
}

// FleetCredentials lists what each approved machine holds.
//
// A LEFT JOIN from devices, deliberately: every approved machine appears
// whether or not it has reported credentials, carrying its sync level so the
// page can tell "this machine holds none" from "this hub is not set to receive
// them". Those render identically otherwise, and only one of them is good news.
func (h Hub) FleetCredentials() ([]FleetCredential, error) {
	rows, err := h.DB.Query(`SELECT d.id, d.hostname, d.sync_level,
			COALESCE(c.item_id, ''), COALESCE(c.category, ''), COALESCE(c.path, '')
		FROM devices d
		LEFT JOIN fleet_credentials c ON c.device_id = d.id
		WHERE d.status = ?
		ORDER BY d.hostname, c.rank`, DeviceStatusApproved)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []FleetCredential
	for rows.Next() {
		var c FleetCredential
		if err := rows.Scan(&c.DeviceID, &c.Hostname, &c.SyncLevel,
			&c.ItemID, &c.Category, &c.Path); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
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
