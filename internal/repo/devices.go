package repo

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

// Device statuses.
const (
	DeviceStatusPending  = "pending"
	DeviceStatusApproved = "approved"
	DeviceStatusRevoked  = "revoked"
)

// PairCodeTTL is how long a pairing code lives (§4).
//
// Ten minutes and single use is what bounds guessing rather than any rate
// limit: the code is eight characters from a 29-symbol alphabet, so even a
// thousand attempts a second across the whole window covers about one part in
// a million of the space.
const PairCodeTTL = 10 * time.Minute

// ErrBadPairCode is returned for a code that is unknown, expired or already
// used. Deliberately one error for all three: telling an unauthenticated caller
// which of them applies turns the endpoint into an oracle for enumerating
// codes that exist.
var ErrBadPairCode = errors.New(
	"pairing code is not valid — it may have expired (they last ten minutes) or already been used")

// ErrNoSuchDevice means the ID is not enrolled here.
var ErrNoSuchDevice = errors.New("no device with that ID is enrolled")

// HashCode is how pairing codes are stored: never in the clear, and normalised
// first so the dashes and case a person types do not decide whether it matches.
func HashCode(code string) string {
	normalised := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(code), "-", ""))
	sum := sha256.Sum256([]byte(normalised))
	return hex.EncodeToString(sum[:])
}

// IssuePairCode records a freshly generated code.
func (h Hub) IssuePairCode(code string, now time.Time) error {
	_, err := h.DB.Exec(`INSERT INTO pair_codes (code_hash, created_at, expires_at) VALUES (?,?,?)`,
		HashCode(code), now.Unix(), now.Add(PairCodeTTL).Unix())
	return err
}

// RedeemPairCode spends a code, or reports that it cannot be spent.
//
// One statement, not a SELECT followed by an UPDATE. The two-query version
// passes a sequential "a reused code is refused" test and still lets two
// concurrent enrolments both succeed, because both read used_at as NULL before
// either wrote it.
func (h Hub) RedeemPairCode(code string, now time.Time) error {
	result, err := h.DB.Exec(`UPDATE pair_codes SET used_at = ?
		WHERE code_hash = ? AND used_at IS NULL AND expires_at > ?`,
		now.Unix(), HashCode(code), now.Unix())
	if err != nil {
		return err
	}
	if rowsAffected(result) != 1 {
		return ErrBadPairCode
	}
	return nil
}

// ExpirePairCodes drops codes past their window. Housekeeping only — redemption
// already checks expiry, so a code left here is spent, not live.
func (h Hub) ExpirePairCodes(now time.Time) (int, error) {
	result, err := h.DB.Exec("DELETE FROM pair_codes WHERE expires_at <= ?", now.Unix())
	if err != nil {
		return 0, err
	}
	return rowsAffected(result), nil
}

// Device is one enrolled machine.
type Device struct {
	ID         string
	PublicKey  []byte
	TokenHash  string
	Hostname   string
	OS         string
	Arch       string
	Status     string
	SyncLevel  string
	EnrolledAt time.Time
	ApprovedAt time.Time

	// LastSeen is the zero time when a device has never reported. That is a
	// third state, not a stale one — an approved machine that has never sent
	// anything and a machine that stopped sending yesterday are different
	// problems, and collapsing them is how a silent agent renders as healthy.
	LastSeen time.Time
	Version  string
}

// Approved reports whether this device may sync. Pending and revoked both
// cannot, for different reasons.
func (d Device) Approved() bool { return d.Status == DeviceStatusApproved }

// EverReported distinguishes "approved and silent" from "was reporting, stopped".
func (d Device) EverReported() bool { return !d.LastSeen.IsZero() }

// Enroll records a device as pending approval.
//
// Pending, never approved: §4's approval step is a person comparing the device
// ID on the agent's screen with the one on the hub's, and it is the only thing
// standing between this and anyone on the network who guessed a code. A device
// that enrolled itself into an approved state would make that check decorative.
//
// Re-enrolling an existing ID replaces its token and returns it to pending. The
// same machine pairing again is the normal recovery path after a lost token,
// and it still needs approving again — the key is the same, so the ID a person
// checks is the same too.
func (h Hub) Enroll(d Device, now time.Time) error {
	_, err := h.DB.Exec(`INSERT INTO devices
		(id, pubkey, token_hash, hostname, os, arch, status, sync_level, enrolled_at, agent_version)
		VALUES (?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET
			token_hash = excluded.token_hash,
			hostname = excluded.hostname, os = excluded.os, arch = excluded.arch,
			agent_version = excluded.agent_version,
			status = ?, approved_at = NULL`,
		d.ID, d.PublicKey, d.TokenHash, d.Hostname, d.OS, d.Arch,
		DeviceStatusPending, orDefault(d.SyncLevel, "findings"), now.Unix(), d.Version,
		DeviceStatusPending)
	return err
}

func orDefault(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

const deviceColumns = `id, pubkey, token_hash, hostname, os, arch, status, sync_level,
	enrolled_at, COALESCE(approved_at, 0), COALESCE(last_seen_at, 0), COALESCE(agent_version, '')`

func scanDevice(row interface{ Scan(...any) error }) (Device, error) {
	var d Device
	var enrolled, approved, seen int64
	err := row.Scan(&d.ID, &d.PublicKey, &d.TokenHash, &d.Hostname, &d.OS, &d.Arch,
		&d.Status, &d.SyncLevel, &enrolled, &approved, &seen, &d.Version)
	if err != nil {
		return Device{}, err
	}
	d.EnrolledAt = time.Unix(enrolled, 0)
	if approved > 0 {
		d.ApprovedAt = time.Unix(approved, 0)
	}
	// Left as the zero time when never reported, so callers cannot accidentally
	// read "never" as "just now".
	if seen > 0 {
		d.LastSeen = time.Unix(seen, 0)
	}
	return d, nil
}

func (h Hub) Device(id string) (Device, error) {
	d, err := scanDevice(h.DB.QueryRow("SELECT "+deviceColumns+" FROM devices WHERE id = ?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return Device{}, ErrNoSuchDevice
	}
	return d, err
}

// Devices lists every enrolled machine, pending first — those are the ones
// waiting on a person.
func (h Hub) Devices() ([]Device, error) {
	rows, err := h.DB.Query("SELECT " + deviceColumns + ` FROM devices
		ORDER BY CASE status WHEN 'pending' THEN 0 WHEN 'approved' THEN 1 ELSE 2 END,
		         hostname`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Device
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// SetDeviceStatus approves or revokes a device.
//
// Revoking leaves the row in place rather than deleting it. The device's events
// and findings hang off it by foreign key with ON DELETE CASCADE, and losing
// the history of a machine you just stopped trusting is exactly backwards.
func (h Hub) SetDeviceStatus(id, status string, now time.Time) error {
	var approvedAt any
	if status == DeviceStatusApproved {
		approvedAt = now.Unix()
	}
	result, err := h.DB.Exec("UPDATE devices SET status = ?, approved_at = ? WHERE id = ?",
		status, approvedAt, id)
	if err != nil {
		return err
	}
	if rowsAffected(result) == 0 {
		return ErrNoSuchDevice
	}
	return nil
}

// TouchDevice records that a device reported in.
func (h Hub) TouchDevice(id, version string, now time.Time) error {
	_, err := h.DB.Exec("UPDATE devices SET last_seen_at = ?, agent_version = ? WHERE id = ?",
		now.Unix(), version, id)
	return err
}
