package repo

import (
	"database/sql"
	"errors"
	"time"
)

// Quarantine states. A row is not simply "restored or not": the two failure
// shapes matter more than the happy path, because this is the one feature that
// takes a package off the machine.
const (
	QuarantineActive   = "active"
	QuarantineRestored = "restored"
	QuarantineFailed   = "failed"
	QuarantineMissing  = "missing"
)

// ErrNoSuchQuarantine means the id names nothing this machine holds.
var ErrNoSuchQuarantine = errors.New("no quarantined package with that id")

// QuarantineItem is one package moved out of the way.
type QuarantineItem struct {
	ID          string
	PURL        string
	OriginPath  string
	ArchivePath string
	SHA256      string
	AdvisoryID  string
	State       string
	At          time.Time
	RestoredAt  time.Time
	RestoredSHA string
}

// Restorable reports whether this row can still be put back.
func (q QuarantineItem) Restorable() bool { return q.State == QuarantineActive }

// RecordQuarantine stores a package that has been archived and removed.
func (a Agent) RecordQuarantine(item QuarantineItem, now time.Time) error {
	_, err := a.DB.Exec(`INSERT INTO quarantine
		(id, purl, origin_path, archive_path, sha256, advisory_id, quarantined_at, state)
		VALUES (?,?,?,?,?,?,?,?)`,
		item.ID, item.PURL, item.OriginPath, item.ArchivePath, item.SHA256,
		nullIfEmpty(item.AdvisoryID), now.Unix(), QuarantineActive)
	return err
}

// MarkRestored records the outcome of putting a package back.
//
// The digest that came back is stored whether or not it matched. When it did
// not, the pair of digests is the whole evidence that the files on disk are not
// the files that were taken — a single "failed" flag would leave nobody able to
// say in what way.
func (a Agent) MarkRestored(id, state, digest string, now time.Time) error {
	var restoredAt any
	if state == QuarantineRestored {
		restoredAt = now.Unix()
	}
	result, err := a.DB.Exec(
		`UPDATE quarantine SET state = ?, restored_sha256 = ?, restored_at = ? WHERE id = ?`,
		state, nullIfEmpty(digest), restoredAt, id)
	if err != nil {
		return err
	}
	if rowsAffected(result) == 0 {
		return ErrNoSuchQuarantine
	}
	return nil
}

// MarkQuarantineMissing records that the archive is no longer on disk.
func (a Agent) MarkQuarantineMissing(id string) error {
	_, err := a.DB.Exec("UPDATE quarantine SET state = ? WHERE id = ?", QuarantineMissing, id)
	return err
}

// QuarantineItems lists what this machine holds, newest first.
func (a Agent) QuarantineItems(limit int) ([]QuarantineItem, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := a.DB.Query(`SELECT id, purl, origin_path, archive_path, sha256,
		COALESCE(advisory_id, ''), state, quarantined_at, COALESCE(restored_at, 0),
		COALESCE(restored_sha256, '')
		FROM quarantine ORDER BY quarantined_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []QuarantineItem
	for rows.Next() {
		item, err := scanQuarantine(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// quarantineSyncCap bounds one push. Far above any real machine's count — a
// person quarantines packages one at a time — and here only so a corrupt table
// cannot produce an unbounded request body.
const quarantineSyncCap = 5_000

// SyncableQuarantine returns what to send the hub, and whether that is all of
// it. The second value gates the hub's replace: a truncated snapshot applied as
// a complete one would delete every row past the cap.
func (a Agent) SyncableQuarantine() ([]QuarantineItem, bool, error) {
	items, err := a.QuarantineItems(quarantineSyncCap)
	return items, len(items) < quarantineSyncCap, err
}

// QuarantineItem returns one row by id.
func (a Agent) QuarantineItem(id string) (QuarantineItem, error) {
	row := a.DB.QueryRow(`SELECT id, purl, origin_path, archive_path, sha256,
		COALESCE(advisory_id, ''), state, quarantined_at, COALESCE(restored_at, 0),
		COALESCE(restored_sha256, '')
		FROM quarantine WHERE id = ?`, id)

	item, err := scanQuarantine(row)
	if errors.Is(err, sql.ErrNoRows) {
		return QuarantineItem{}, ErrNoSuchQuarantine
	}
	return item, err
}

// ActiveQuarantineFor reports whether a package is already put away, so a second
// quarantine of the same thing cannot bury the first archive.
func (a Agent) ActiveQuarantineFor(purl string) (QuarantineItem, error) {
	row := a.DB.QueryRow(`SELECT id, purl, origin_path, archive_path, sha256,
		COALESCE(advisory_id, ''), state, quarantined_at, COALESCE(restored_at, 0),
		COALESCE(restored_sha256, '')
		FROM quarantine WHERE purl = ? AND state = ? ORDER BY quarantined_at DESC LIMIT 1`,
		purl, QuarantineActive)

	item, err := scanQuarantine(row)
	if errors.Is(err, sql.ErrNoRows) {
		return QuarantineItem{}, ErrNoSuchQuarantine
	}
	return item, err
}

// scanner is what both Query rows and QueryRow satisfy.
type scanner interface{ Scan(...any) error }

func scanQuarantine(row scanner) (QuarantineItem, error) {
	var item QuarantineItem
	var at, restoredAt int64
	if err := row.Scan(&item.ID, &item.PURL, &item.OriginPath, &item.ArchivePath,
		&item.SHA256, &item.AdvisoryID, &item.State, &at, &restoredAt, &item.RestoredSHA); err != nil {
		return QuarantineItem{}, err
	}
	item.At = time.Unix(at, 0)
	if restoredAt > 0 {
		item.RestoredAt = time.Unix(restoredAt, 0)
	}
	return item, nil
}

// MarkFindingsQuarantined moves every open finding for a package to the
// quarantined state.
//
// Quarantined findings keep counting as open, here and on the hub. The package
// is off the machine but the archive is one command away from putting it back,
// and a critical that disappears from the count the moment it is boxed up would
// make the fleet look clean while the malware is still on disk. The scanner
// closes them properly on its next pass, when the package is genuinely gone.
func (a Agent) MarkFindingsQuarantined(purl string, now time.Time) (int, error) {
	result, err := a.DB.Exec(
		`UPDATE findings SET state = ? WHERE purl = ? AND state NOT IN (?, ?)`,
		StateQuarantined, purl, StateIgnored, StateFixed)
	if err != nil {
		return 0, err
	}
	return int(rowsAffected(result)), nil
}
