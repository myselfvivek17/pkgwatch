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
		// Local, like every other timestamp this tool shows. Rendering these in
		// UTC while the session header beside them was local put a five and a
		// half hour gap between an install and the refusal that happened inside
		// it — two clocks in one report, and the reader has no way to tell which
		// is which. Advisory published and modified dates stay UTC: those are
		// facts about the wider world rather than about this machine's day.
		d.At = time.Unix(at, 0)
		out = append(out, d)
	}
	return out, rows.Err()
}

// Withheld summarises the versions filtered out of one package's listing.
type Withheld struct {
	PURLBase   string // ecosystem and name, no version
	Count      int
	Advisories []string

	// TooNew counts versions held back only because they were published
	// recently, with nothing on file against them. Those carry no advisory id,
	// so without this the report would show a withheld count and an empty
	// reason.
	TooNew int
}

// SessionWithheld groups withheld versions by package.
//
// The user's real decision is "I accept this package's advisories for this
// install", not "I accept version 3.5.0 specifically" — so the report and the
// override prompt both work at package granularity.
func (a Agent) SessionWithheld(sessionID string) ([]Withheld, error) {
	// The version separator is the first literal '@': a scoped npm namespace is
	// percent-encoded (pkg:npm/%40ctrl/tinycolor@4.1.2), so there is no earlier
	// one to trip over.
	rows, err := a.DB.Query(`SELECT
			substr(purl, 1, instr(purl, '@' ) - 1) AS base,
			COUNT(*), GROUP_CONCAT(DISTINCT advisory_id),
			SUM(CASE WHEN reason = 'cooldown' THEN 1 ELSE 0 END)
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
		if err := rows.Scan(&w.PURLBase, &w.Count, &advisories, &w.TooNew); err != nil {
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

// Session is one gated install run.
type Session struct {
	ID        string
	StartedAt time.Time
	EndedAt   time.Time
	Ecosystem string
	CWD       string
	Argv      string
	Context   string
	Outcome   string

	// Counts by decision, so the list can say what happened without loading
	// every decision row for every session.
	Blocked  int
	Withheld int
	Allowed  int
}

// Sessions returns recent install runs, newest first.
func (a Agent) Sessions(limit int) ([]Session, error) {
	rows, err := a.DB.Query(`SELECT s.id, s.started_at, COALESCE(s.ended_at, 0),
		s.ecosystem, s.cwd, s.argv, s.context, COALESCE(s.outcome, ''),
		COALESCE(SUM(d.decision = ?), 0),
		COALESCE(SUM(d.decision = ?), 0),
		COALESCE(SUM(d.decision = ?), 0)
		FROM install_sessions s
		LEFT JOIN install_decisions d ON d.session_id = s.id
		GROUP BY s.id
		ORDER BY s.started_at DESC LIMIT ?`,
		DecisionBlocked, DecisionWithheld, DecisionAllowed, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanSessions(rows)
}

// SessionByID returns one run, or a zero Session when there is no such id.
func (a Agent) SessionByID(id string) (Session, error) {
	rows, err := a.DB.Query(`SELECT s.id, s.started_at, COALESCE(s.ended_at, 0),
		s.ecosystem, s.cwd, s.argv, s.context, COALESCE(s.outcome, ''),
		COALESCE(SUM(d.decision = ?), 0),
		COALESCE(SUM(d.decision = ?), 0),
		COALESCE(SUM(d.decision = ?), 0)
		FROM install_sessions s
		LEFT JOIN install_decisions d ON d.session_id = s.id
		WHERE s.id = ?
		GROUP BY s.id`,
		DecisionBlocked, DecisionWithheld, DecisionAllowed, id)
	if err != nil {
		return Session{}, err
	}
	defer rows.Close()

	found, err := scanSessions(rows)
	if err != nil || len(found) == 0 {
		return Session{}, err
	}
	return found[0], nil
}

func scanSessions(rows *sql.Rows) ([]Session, error) {
	var out []Session
	for rows.Next() {
		var s Session
		var started, ended int64
		if err := rows.Scan(&s.ID, &started, &ended, &s.Ecosystem, &s.CWD, &s.Argv,
			&s.Context, &s.Outcome, &s.Blocked, &s.Withheld, &s.Allowed); err != nil {
			return nil, err
		}
		s.StartedAt = time.Unix(started, 0)
		if ended > 0 {
			s.EndedAt = time.Unix(ended, 0)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
