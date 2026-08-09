package repo

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// Install session outcomes.
const (
	OutcomeClean    = "clean"
	OutcomeBlocked  = "blocked"
	OutcomeApproved = "approved"
	OutcomeAborted  = "aborted"
)

// Gate decisions, as recorded against a session.
//
// Withheld and blocked are deliberately different things. Withholding a version
// from a packument is routine and invisible — the resolver simply picks another,
// and a typical npm install withholds dozens of ancient versions nobody asked
// for. Blocking is a refusal to hand over bytes the resolver had already chosen,
// which is the only one that stopped anything.
const (
	DecisionAllowed  = "allowed"
	DecisionWithheld = "withheld"
	DecisionBlocked  = "blocked"
	DecisionOverride = "approved-override"
)

// Decision is one gate verdict about one concrete package version.
type Decision struct {
	SessionID  string
	PURL       string
	Decision   string
	Reason     string
	AdvisoryID string
	LatencyMS  int
	At         time.Time
}

// StartSession records an install session. The wrapper owns the id so it can
// attribute decisions before npm has produced any output.
func (a Agent) StartSession(id, ecosystem, cwd, argv, context string, at time.Time) error {
	_, err := a.DB.Exec(`INSERT INTO install_sessions
		(id, started_at, ecosystem, cwd, argv, context) VALUES (?,?,?,?,?,?)`,
		id, at.Unix(), ecosystem, cwd, argv, context)
	return err
}

func (a Agent) EndSession(id, outcome string, at time.Time) error {
	_, err := a.DB.Exec(`UPDATE install_sessions SET ended_at = ?, outcome = ? WHERE id = ?`,
		at.Unix(), outcome, id)
	return err
}

// RecordDecision appends a gate verdict.
//
// session_id is nullable on purpose: the agent's shared proxy ports (:4873,
// :4874) serve whatever is configured to point at them, and there is no way to
// know which install a request belongs to. Attributing those to some other
// session would be worse than leaving them unattributed.
func (a Agent) RecordDecision(d Decision) error {
	_, err := a.DB.Exec(`INSERT INTO install_decisions
		(session_id, purl, requested_at, decision, reason, advisory_id, latency_ms)
		VALUES (?,?,?,?,?,?,?)`,
		nullIfEmpty(d.SessionID), d.PURL, d.At.Unix(), d.Decision, d.Reason,
		nullIfEmpty(d.AdvisoryID), d.LatencyMS)
	return err
}

// SessionDecisions returns the decisions in a session that actually stopped
// something, oldest first — the material the wrapper's report is built from.
//
// Withheld versions are excluded on purpose. Listing every version filtered out
// of a packument buries the one line that matters under a hundred that do not.
func (a Agent) SessionDecisions(sessionID string) ([]Decision, error) {
	rows, err := a.DB.Query(`SELECT purl, decision, reason, advisory_id, requested_at
		FROM install_decisions
		WHERE session_id = ? AND decision IN (?, ?)
		ORDER BY id`, sessionID, DecisionBlocked, DecisionOverride)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Decision
	for rows.Next() {
		d := Decision{SessionID: sessionID}
		var advisory sql.NullString
		var at int64
		if err := rows.Scan(&d.PURL, &d.Decision, &d.Reason, &advisory, &at); err != nil {
			return nil, err
		}
		d.AdvisoryID = advisory.String
		d.At = time.Unix(at, 0).UTC()
		out = append(out, d)
	}
	return out, rows.Err()
}

// Withheld summarises the versions filtered out of one package's listing.
type Withheld struct {
	PURLBase   string // ecosystem and name, no version
	Count      int
	Advisories []string
}

// SessionWithheld groups withheld versions by package.
//
// The user's real decision is "I accept this package's advisories for this
// install", not "I accept version 3.5.0 specifically" — so the report and the
// override prompt both work at package granularity.
func (a Agent) SessionWithheld(sessionID string) ([]Withheld, error) {
	rows, err := a.DB.Query(`SELECT
			substr(purl, 1, instr(purl, '@' ) - 1) AS base,
			COUNT(*), GROUP_CONCAT(DISTINCT advisory_id)
		FROM install_decisions
		WHERE session_id = ? AND decision = ?
		GROUP BY base
		ORDER BY COUNT(*) DESC`, sessionID, DecisionWithheld)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Withheld
	for rows.Next() {
		var w Withheld
		var advisories sql.NullString
		if err := rows.Scan(&w.PURLBase, &w.Count, &advisories); err != nil {
			return nil, err
		}
		if advisories.String != "" {
			w.Advisories = strings.Split(advisories.String, ",")
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// ApproveInSession records an explicit override. The gate consults this before
// blocking, so an approved package installs on the re-run.
func (a Agent) ApproveInSession(sessionID, purl string, at time.Time) error {
	_, err := a.DB.Exec(`INSERT OR IGNORE INTO session_approvals
		(session_id, purl, approved_at) VALUES (?,?,?)`, sessionID, purl, at.Unix())
	return err
}

// IsApproved reports whether a session carries an override for this exact
// version or for the package as a whole.
func (a Agent) IsApproved(sessionID, purl, purlBase string) (bool, error) {
	if sessionID == "" {
		return false, nil
	}
	var one int
	err := a.DB.QueryRow(
		`SELECT 1 FROM session_approvals WHERE session_id = ? AND purl IN (?, ?) LIMIT 1`,
		sessionID, purl, purlBase).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// Event kinds the gate emits.
const (
	EventInstallBlocked = "install_blocked"
	EventGateDegraded   = "gate_degraded"
	// EventPackageFiltered is one summary per package whose listing was
	// filtered, not one per version — a routine install withholds dozens.
	EventPackageFiltered = "package_filtered"
)

// RecordEvent appends to the timeline. detail is marshalled to JSON; a detail
// that will not marshal is dropped rather than losing the event itself.
func (a Agent) RecordEvent(kind, severity, purl, advisoryID string, detail any, at time.Time) error {
	var detailJSON any
	if detail != nil {
		if encoded, err := json.Marshal(detail); err == nil {
			detailJSON = string(encoded)
		}
	}
	_, err := a.DB.Exec(`INSERT INTO events (ts, kind, severity, purl, advisory_id, detail_json)
		VALUES (?,?,?,?,?,?)`,
		at.Unix(), kind, nullIfEmpty(severity), nullIfEmpty(purl), nullIfEmpty(advisoryID), detailJSON)
	return err
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
