package repo

import "time"

// RotationChecked returns which checklist items have been ticked for a finding.
func (a Agent) RotationChecked(purl, advisoryID string) (map[string]time.Time, error) {
	rows, err := a.DB.Query(`SELECT item_id, checked_at FROM rotation_items
		WHERE purl = ? AND advisory_id = ? AND checked_at IS NOT NULL`, purl, advisoryID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	checked := map[string]time.Time{}
	for rows.Next() {
		var id string
		var at int64
		if err := rows.Scan(&id, &at); err != nil {
			return nil, err
		}
		checked[id] = time.Unix(at, 0)
	}
	return checked, rows.Err()
}

// SetRotationChecked ticks or unticks one item.
//
// Unticking clears the timestamp rather than deleting the row, so the record
// that someone once considered this item survives changing their mind about it.
func (a Agent) SetRotationChecked(purl, advisoryID, itemID string, at time.Time) error {
	var checked any
	if !at.IsZero() {
		checked = at.Unix()
	}
	_, err := a.DB.Exec(`INSERT INTO rotation_items (purl, advisory_id, item_id, checked_at)
		VALUES (?,?,?,?)
		ON CONFLICT (purl, advisory_id, item_id) DO UPDATE SET checked_at = excluded.checked_at`,
		purl, advisoryID, itemID, checked)
	return err
}

// RotationTick is one checklist row on its way to the hub.
type RotationTick struct {
	PURL       string
	AdvisoryID string
	ItemID     string
	CheckedAt  time.Time
}

// SyncableRotation returns every checklist row, ticked or not.
//
// Unticked rows travel too. "Three of five done" and "three done, two unknown"
// are different states, and a hub sent only the ticks cannot tell them apart —
// it would render a half-finished rotation as a complete one.
func (a Agent) SyncableRotation() ([]RotationTick, error) {
	rows, err := a.DB.Query(
		`SELECT purl, advisory_id, item_id, COALESCE(checked_at, 0) FROM rotation_items`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []RotationTick
	for rows.Next() {
		var t RotationTick
		var at int64
		if err := rows.Scan(&t.PURL, &t.AdvisoryID, &t.ItemID, &at); err != nil {
			return nil, err
		}
		if at > 0 {
			t.CheckedAt = time.Unix(at, 0)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// MalwareFindings returns open findings whose advisory is a malware record.
//
// These are the ones that mean code ran rather than that code could be
// exploited, and they are the only findings a credential rotation follows from.
// Requires the advisory bundle: kind lives there, not on the finding.
func (a Agent) MalwareFindings(attached bool, limit int) ([]Finding, error) {
	if !attached {
		return nil, nil
	}
	if limit <= 0 {
		limit = 50
	}

	rows, err := a.DB.Query(`SELECT f.purl, f.advisory_id, f.score, f.tier, f.state,
			f.detected_at, COALESCE(t.summary, ''), NULL, ''
		FROM findings f
		LEFT JOIN adv.advisory_text t ON t.id = f.advisory_id
		WHERE f.state NOT IN ('ignored', 'fixed')
		  AND EXISTS (SELECT 1 FROM adv.advisories a
		              WHERE a.id = f.advisory_id AND a.kind = 'malware')
		ORDER BY f.detected_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	return scanFindings(rows)
}

// PackageExposure reports when a package was first seen and last seen, which is
// the window in which whatever it did was running.
//
// Both ends matter. "Installed three months ago" and "last seen an hour ago"
// scope a rotation very differently from a package that was present for one
// afternoon, and the second date is the one that says whether it is still here.
func (a Agent) PackageExposure(purl string) (firstSeen, lastSeen time.Time, err error) {
	var first, last int64
	err = a.DB.QueryRow(`SELECT first_seen, last_seen FROM packages WHERE purl = ?`, purl).
		Scan(&first, &last)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	return time.Unix(first, 0), time.Unix(last, 0), nil
}
