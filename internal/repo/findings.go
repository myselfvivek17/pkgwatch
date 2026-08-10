package repo

import (
	"database/sql"
	"time"
)

// Finding states.
const (
	StateNew          = "new"
	StateNotified     = "notified"
	StateAcknowledged = "acknowledged"
	StateIgnored      = "ignored"
	StateQuarantined  = "quarantined"
	StateFixed        = "fixed"
)

// Finding is one advisory that applies to one installed package.
type Finding struct {
	PURL       string
	AdvisoryID string
	Score      float64
	Tier       string
	State      string
	DetectedAt time.Time

	// Summary and FixedIn come from the advisory bundle, not the findings table
	// — they would be duplicated into every row for no gain, and the bundle is
	// replaced wholesale on every sync.
	Summary string
	FixedIn string

	// BaseCVSS is what the advisory itself rates, before install context is
	// applied. Score is that number multiplied by scope and script factors, so
	// the two differ routinely and showing only Score reads as a mistake.
	BaseCVSS *float64
}

// RecordFindings inserts findings that are not already known.
//
// INSERT OR IGNORE against the (purl, advisory_id) primary key is what makes
// this alert-once: the watcher runs after every scan and every bundle sync, and
// a finding that re-notified on each pass would train you to ignore it.
func (a Agent) RecordFindings(findings []Finding, at time.Time) (int, error) {
	if len(findings) == 0 {
		return 0, nil
	}

	tx, err := a.DB.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`INSERT OR IGNORE INTO findings
		(purl, advisory_id, score, tier, detected_at, state) VALUES (?,?,?,?,?,?)`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	added := 0
	for _, finding := range findings {
		result, err := stmt.Exec(finding.PURL, finding.AdvisoryID, finding.Score,
			finding.Tier, at.Unix(), finding.State)
		if err != nil {
			return 0, err
		}
		if n, _ := result.RowsAffected(); n > 0 {
			added++
		}
	}
	return added, tx.Commit()
}

// FindingFirstSeen returns when a finding was first detected, which is what
// distinguishes one this pass just inserted from one INSERT OR IGNORE left
// alone. The zero time means there is no such finding.
func (a Agent) FindingFirstSeen(purl, advisoryID string) (time.Time, error) {
	var detectedAt int64
	err := a.DB.QueryRow(
		"SELECT detected_at FROM findings WHERE purl = ? AND advisory_id = ?",
		purl, advisoryID).Scan(&detectedAt)
	if err == sql.ErrNoRows {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(detectedAt, 0), nil
}

// HasFindings reports whether anything has ever been recorded.
//
// This is what decides a baseline run. A machine seeing its inventory matched
// for the first time has years of accumulated low-severity findings that were
// never news, and announcing all of them at once is how notifications get
// switched off in week one.
func (a Agent) HasFindings() (bool, error) {
	var one int
	err := a.DB.QueryRow("SELECT EXISTS(SELECT 1 FROM findings)").Scan(&one)
	return one == 1, err
}

// ResolveFindingsForGonePackages closes findings whose package is no longer
// installed.
//
// Uninstalling is a fix. Leaving the finding open would keep a machine looking
// dirty for something it no longer has, and an ignored one stays ignored
// because that was a deliberate decision about a package, not about its state.
func (a Agent) ResolveFindingsForGonePackages(at time.Time) (int, error) {
	result, err := a.DB.Exec(`UPDATE findings SET state = ?
		WHERE state NOT IN (?, ?)
		  AND purl IN (SELECT purl FROM packages WHERE gone_at IS NOT NULL)`,
		StateFixed, StateIgnored, StateFixed)
	if err != nil {
		return 0, err
	}
	return rowsAffected(result), nil
}

// ReopenFindingsForPresentPackages undoes a close when the package comes back.
//
// A finding is only ever marked fixed here because its package stopped being
// installed, so a package that is present again is not fixed. Without this the
// close is permanent: RecordFindings is INSERT OR IGNORE against (purl,
// advisory_id), so a row that already exists in the fixed state absorbs every
// later attempt to record the same finding and the vulnerability never comes
// back into view.
//
// This is not hypothetical. Two stopped containers had their packages retired
// and 322 findings closed; when the collector started reading stopped
// containers the packages returned and the scan reported zero new findings,
// because every one of them was silently absorbed.
//
// Ignored stays ignored — that was a decision about the package, not about
// whether it happened to be installed this week.
//
// Low and medium come back acknowledged rather than announced, matching what a
// baseline pass would have done with them. Otherwise stopping and starting a
// container promotes every quiet finding it holds into an announcement, which
// is the "hundreds of alerts at once" failure arriving by a side door.
func (a Agent) ReopenFindingsForPresentPackages() (int, error) {
	result, err := a.DB.Exec(`UPDATE findings
		SET state = CASE WHEN tier IN ('critical', 'high') THEN ? ELSE ? END
		WHERE state = ?
		  AND purl IN (SELECT purl FROM packages WHERE gone_at IS NULL)`,
		StateNew, StateAcknowledged, StateFixed)
	if err != nil {
		return 0, err
	}
	return rowsAffected(result), nil
}

// OpenFindings returns findings that still want attention, worst first, with
// the advisory text joined in from the attached bundle.
//
// attached says whether the advisory database is available. Without it the
// findings are still listed — they are recorded facts — but with no summary,
// because inventing one would be worse than an empty column.
//
// fixableOnly restricts to findings with a published fix. It has to happen in
// the query rather than over the returned slice: filtering afterwards would
// mean "the fixable ones among the worst N", which reads as "the fixable ones"
// and is not the same list — a machine can have a hundred unfixable criticals
// burying every finding you could act on.
func (a Agent) OpenFindings(attached bool, limit int, fixableOnly bool) ([]Finding, error) {
	if !attached {
		if fixableOnly {
			// Whether a fix exists is only knowable from the bundle. Returning
			// everything here would claim each one is unfixable.
			return nil, nil
		}
		rows, err := a.DB.Query(`SELECT f.purl, f.advisory_id, f.score, f.tier, f.state,
			f.detected_at, '', NULL, ''
			FROM findings f
			WHERE f.state NOT IN ('ignored', 'fixed')
			ORDER BY f.score DESC, f.purl LIMIT ?`, limit)
		if err != nil {
			return nil, err
		}
		return scanFindings(rows)
	}

	// The advisory's own CVSS comes along for the ride. The stored score is
	// contextual — install scope and lifecycle scripts multiply it (§5.2) —
	// so a finding can sit two tiers above what the advisory itself rates,
	// and showing only one of the two numbers makes that look like an error.
	//
	// MAX rather than a join: one advisory id covers several packages and
	// would otherwise multiply the result set.
	//
	// FixedIn is looked up from the bundle rather than stored on the finding.
	// Whether a fix exists changes when the advisory is updated, not when the
	// finding was detected — freezing it at detection time would keep saying
	// "no fix" for something patched last week.
	//
	// The join goes through packages because a finding is keyed by purl and
	// the advisory rows are keyed by ecosystem and package name.
	query := `WITH open AS (
			SELECT f.purl AS purl, f.advisory_id AS advisory_id, f.score AS score,
				f.tier AS tier, f.state AS state, f.detected_at AS detected_at,
				COALESCE(t.summary, '') AS summary,
				(SELECT MAX(a.severity_cvss) FROM adv.advisories a
				 WHERE a.id = f.advisory_id) AS base_cvss,
				COALESCE((
					SELECT MIN(r.fixed) FROM adv.advisories a
					JOIN adv.advisory_ranges r ON r.advisory_id = a.rowid
					WHERE a.id = f.advisory_id
					  AND a.ecosystem = p.ecosystem
					  AND a.package_name = p.name
					  AND a.kind <> 'malware'
					  AND r.fixed IS NOT NULL
				), '') AS fixed_in
			FROM findings f
			LEFT JOIN packages p ON p.purl = f.purl
			LEFT JOIN adv.advisory_text t ON t.id = f.advisory_id
			WHERE f.state NOT IN ('ignored', 'fixed')
		)
		SELECT purl, advisory_id, score, tier, state, detected_at, summary, base_cvss, fixed_in
		FROM open
		WHERE (? = 0 OR fixed_in <> '')
		ORDER BY score DESC, purl LIMIT ?`

	only := 0
	if fixableOnly {
		only = 1
	}
	rows, err := a.DB.Query(query, only, limit)
	if err != nil {
		return nil, err
	}
	return scanFindings(rows)
}

func scanFindings(rows *sql.Rows) ([]Finding, error) {
	defer rows.Close()

	var out []Finding
	for rows.Next() {
		var finding Finding
		var detectedAt int64
		var summary sql.NullString
		var baseCVSS sql.NullFloat64
		if err := rows.Scan(&finding.PURL, &finding.AdvisoryID, &finding.Score,
			&finding.Tier, &finding.State, &detectedAt, &summary, &baseCVSS,
			&finding.FixedIn); err != nil {
			return nil, err
		}
		finding.DetectedAt = time.Unix(detectedAt, 0)
		finding.Summary = summary.String
		if baseCVSS.Valid {
			score := baseCVSS.Float64
			finding.BaseCVSS = &score
		}
		out = append(out, finding)
	}
	return out, rows.Err()
}
