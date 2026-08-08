// Package repo holds typed accessors over the agent and hub databases.
//
// ponytail: only the queries something actually calls live here. Accessors for
// tables no code reads yet (quarantine, script_allowlist, session_approvals)
// arrive with the milestone that needs them — a full CRUD layer written up
// front is a layer written against guesses.
package repo

import (
	"database/sql"
	"errors"
	"strconv"
	"time"
)

type Agent struct{ DB *sql.DB }

type Hub struct{ DB *sql.DB }

// Tiers in descending severity — the order findings should be presented in.
var Tiers = []string{"critical", "high", "medium", "low"}

// FindingCounts returns open findings per tier. Ignored and fixed findings are
// excluded: they are resolved, and counting them makes a clean machine look dirty.
func (a Agent) FindingCounts() (map[string]int, error) {
	rows, err := a.DB.Query(`SELECT tier, COUNT(*) FROM findings
		WHERE state NOT IN ('ignored','fixed') GROUP BY tier`)
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

func (a Agent) PackageCount() (int, error) {
	var n int
	err := a.DB.QueryRow("SELECT COUNT(*) FROM packages").Scan(&n)
	return n, err
}

// HubState reads a single key from the agent's hub_state bag. Missing keys
// return "" with no error — an unpaired agent is a normal state, not a failure.
func (a Agent) HubState(key string) (string, error) {
	var v sql.NullString
	err := a.DB.QueryRow("SELECT v FROM hub_state WHERE k = ?", key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return v.String, nil
}

// BundleInfo describes the attached advisory bundle.
type BundleInfo struct {
	Attached    bool
	Version     string
	Schema      string
	BuiltAt     time.Time
	RecordCount int
}

// Bundle reads bundle_meta from the attached advisory database. Callers pass
// attached=false when no bundle exists yet; the zero value is a valid answer.
func Bundle(handle *sql.DB, attached bool) (BundleInfo, error) {
	info := BundleInfo{Attached: attached}
	if !attached {
		return info, nil
	}

	rows, err := handle.Query("SELECT k, v FROM adv.bundle_meta")
	if err != nil {
		// A bundle present but unreadable is a real problem, but not one worth
		// crashing over — report it as no-bundle and let the caller warn.
		return BundleInfo{}, err
	}
	defer rows.Close()

	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return info, err
		}
		switch k {
		case "version":
			info.Version = v
		case "schema":
			info.Schema = v
		case "built_at":
			if ts, err := time.Parse(time.RFC3339, v); err == nil {
				info.BuiltAt = ts
			}
		case "record_count":
			if n, err := strconv.Atoi(v); err == nil {
				info.RecordCount = n
			}
		}
	}
	return info, rows.Err()
}

// DeviceCounts returns hub device totals by status.
func (h Hub) DeviceCounts() (map[string]int, error) {
	rows, err := h.DB.Query("SELECT status, COUNT(*) FROM devices GROUP BY status")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	counts := map[string]int{}
	for rows.Next() {
		var status string
		var n int
		if err := rows.Scan(&status, &n); err != nil {
			return nil, err
		}
		counts[status] = n
	}
	return counts, rows.Err()
}
