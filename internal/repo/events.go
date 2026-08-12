package repo

import (
	"database/sql"
	"encoding/json"
	"strings"
	"time"
)

// Event kinds beyond the gate's own (EventInstallBlocked, EventGateDegraded,
// EventPackageFiltered in sessions.go).
const (
	EventScan        = "scan"
	EventFeedSync    = "feed_sync"
	EventFindingNew  = "finding_new"
	EventFindingBack = "finding_reopened"

	// EventFindingFixed is a finding closing because its package went away.
	//
	// Neither this nor EventFindingBack counts as routine. They are unattended
	// state changes with no person behind them, so the timeline is the only
	// place they are ever visible — filing them under the "machinery ran" rule
	// would dim the one row that says a vulnerability came back.
	EventFindingFixed = "finding_fixed"
)

// routineKinds are the events that say the machinery ran, not that something
// happened. The timeline renders them dimmed and tighter — a scan every six
// hours is reassurance, and it must not compete visually with a block.
//
// They are recorded rather than merely logged because their absence is
// information: a timeline with no scan events for two days says the agent
// stopped, which is exactly what a silently dead watchdog looks like.
var routineKinds = map[string]bool{
	EventScan:            true,
	EventFeedSync:        true,
	EventPackageFiltered: true,
}

// Event is one row of the timeline.
type Event struct {
	ID         int64
	At         time.Time
	Kind       string
	Severity   string
	PURL       string
	AdvisoryID string

	// Detail is the decoded detail_json, flattened to strings for display. The
	// column holds whatever the recording site passed, so the reader cannot
	// assume a shape and the template must not either.
	Detail map[string]string
}

// Routine reports whether this event is machinery rather than news.
func (e Event) Routine() bool { return routineKinds[e.Kind] }

// Alarming reports whether the row gets the critical background treatment. A
// degraded gate qualifies regardless of severity: it means installs were
// allowed without being evaluated, which is the one failure this tool cannot
// discover after the fact.
func (e Event) Alarming() bool {
	return e.Severity == "critical" || e.Kind == EventGateDegraded
}

// Day is the grouping key the timeline renders under.
func (e Event) Day() string { return e.At.Format("2006-01-02") }

// EventFilter narrows the timeline. Empty fields mean no restriction.
type EventFilter struct {
	Kind     string
	Severity string
	// SinceID returns only events newer than this, for the live stream.
	SinceID int64
	Limit   int
}

// Events returns timeline rows, newest first, or oldest first when streaming
// from a cursor — the stream appends in order, the page renders in reverse.
func (a Agent) Events(f EventFilter) ([]Event, error) {
	query := `SELECT id, ts, kind, COALESCE(severity, ''), COALESCE(purl, ''),
		COALESCE(advisory_id, ''), COALESCE(detail_json, '')
		FROM events WHERE 1=1`
	var args []any

	if f.Kind != "" {
		if f.Kind == "routine" || f.Kind == "actionable" {
			// One filter for the distinction the design already draws visually,
			// so "hide the noise" is one click rather than three.
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

	rows, err := a.DB.Query(query, args...)
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

// decodeDetail flattens the stored JSON object to strings.
//
// Unparseable detail is shown rather than dropped: it was written by some
// version of this binary and a person reading the timeline is better served by
// the raw text than by a row that quietly lost half its content.
func decodeDetail(raw string) map[string]string {
	if raw == "" {
		return nil
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		return map[string]string{"detail": raw}
	}
	out := make(map[string]string, len(parsed))
	for key, value := range parsed {
		switch typed := value.(type) {
		case string:
			out[key] = typed
		case nil:
			continue
		default:
			encoded, err := json.Marshal(typed)
			if err != nil {
				continue
			}
			out[key] = string(encoded)
		}
	}
	return out
}

// OldestEventAt reports when the timeline actually begins, so the page can say
// so instead of just running out.
//
// Events are pruned at history_days, which means a timeline that ends is
// indistinguishable from a machine that did nothing before that date. Naming
// the horizon is the same rule as --gone naming its truncation.
func (a Agent) OldestEventAt() (time.Time, error) {
	var ts sql.NullInt64
	if err := a.DB.QueryRow("SELECT MIN(ts) FROM events").Scan(&ts); err != nil {
		return time.Time{}, err
	}
	if !ts.Valid {
		return time.Time{}, nil
	}
	return time.Unix(ts.Int64, 0), nil
}
