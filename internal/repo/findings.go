package repo

import (
	"database/sql"
	"time"
)

// AnnounceAbove is the contextual score at or above which a finding is
// announced rather than filed quietly.
const AnnounceAbove = 7.0

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

	// Machine names the device a finding came from, and is set only on the hub.
	// On an agent every finding is this machine's, and a column repeating the
	// hostname on every row is a column that says nothing.
	Machine string

	// FixUnknown means the bundle in hand carries no record of this advisory for
	// this package, so nothing here knows whether a fix exists. It is a third
	// state, distinct from an empty FixedIn, which is the positive claim that the
	// advisory has no published fix. The hub is where the two come apart: it
	// aggregates findings from machines whose ecosystems its own bundle may not
	// cover, and rendering "none yet" for a Debian finding against an npm-only
	// bundle would be inventing an answer.
	FixUnknown bool
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
func (a Agent) ResolveFindingsForGonePackages(at time.Time) ([]FindingChange, error) {
	return a.changed(`UPDATE findings SET state = ?
		WHERE state NOT IN (?, ?)
		  AND purl IN (SELECT purl FROM packages WHERE gone_at IS NOT NULL)
		RETURNING purl, advisory_id, tier`,
		StateFixed, StateIgnored, StateFixed)
}

// FindingChange is one finding whose state moved on its own — closed because
// its package went away, or reopened because the package came back.
//
// Returned rather than counted because these are the two transitions nothing
// else records. Every other state change has a person behind it and a timeline
// row already; these happen during an unattended pass, and a count alone cannot
// say what closed or how bad it was.
type FindingChange struct {
	PURL       string
	AdvisoryID string
	Tier       string
}

// changed runs an UPDATE ... RETURNING and collects the rows it touched.
//
// RETURNING rather than SELECT-then-UPDATE: the two-query version can report a
// row it did not actually change, and the whole point here is to describe what
// happened rather than what was about to.
func (a Agent) changed(query string, args ...any) ([]FindingChange, error) {
	rows, err := a.DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []FindingChange
	for rows.Next() {
		var c FindingChange
		if err := rows.Scan(&c.PURL, &c.AdvisoryID, &c.Tier); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// WorstTier returns the most severe tier among changes, or "" for none. It is
// what a summary event is filed under, so a critical coming back gets the
// timeline's critical treatment instead of being averaged into a quiet row.
func WorstTier(changes []FindingChange) string {
	seen := map[string]bool{}
	for _, c := range changes {
		seen[c.Tier] = true
	}
	for _, tier := range Tiers {
		if seen[tier] {
			return tier
		}
	}
	return ""
}

// TierCounts breaks changes down for a summary event's detail.
func TierCounts(changes []FindingChange) map[string]int {
	counts := map[string]int{}
	for _, c := range changes {
		counts[c.Tier]++
	}
	return counts
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
// Quiet findings come back quiet, matching what a baseline pass would have done
// with them. Otherwise stopping and starting a container promotes every quiet
// finding it holds into an announcement, which is the "hundreds of alerts at
// once" failure arriving by a side door.
//
// Keyed on score rather than tier, like the baseline rule: whether something is
// worth announcing is a triage question and install context belongs in it,
// while the tier says how bad the advisory is.
func (a Agent) ReopenFindingsForPresentPackages() ([]FindingChange, error) {
	return a.changed(`UPDATE findings
		SET state = CASE WHEN score >= ? THEN ? ELSE ? END
		WHERE state = ?
		  AND purl IN (SELECT purl FROM packages WHERE gone_at IS NULL)
		RETURNING purl, advisory_id, tier`,
		AnnounceAbove, StateNew, StateAcknowledged, StateFixed)
}

// OpenFindings returns findings that still want attention, worst first, with
// the advisory text joined in from the attached bundle.
//
// attached says whether the advisory database is available. Without it the
// findings are still listed — they are recorded facts — but with no summary,
// because inventing one would be worse than an empty column.
//
// Every restriction in FindingFilter is applied in the query rather than over
// the returned slice. Filtering afterwards would mean "the matching ones among
// the worst N", which reads as "the matching ones" and is not the same list — a
// machine can have a hundred unfixable criticals burying every finding you
// could act on.
type FindingFilter struct {
	Limit       int
	FixableOnly bool
	Tier        string
}

func (a Agent) OpenFindings(attached bool, f FindingFilter) ([]Finding, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}
	fixableOnly := f.FixableOnly

	// Two spellings because the two queries differ in shape: one selects from
	// findings directly, the other from a CTE whose columns are already
	// unqualified. Rewriting one into the other with string replacement would
	// work until a column named "tier" appeared somewhere else in the query.
	tierClause, cteTierClause := "", ""
	var tierArg []any
	if f.Tier != "" {
		tierClause = " AND f.tier = ?"
		cteTierClause = " AND tier = ?"
		tierArg = append(tierArg, f.Tier)
	}

	if !attached {
		if fixableOnly {
			// Whether a fix exists is only knowable from the bundle. Returning
			// everything here would claim each one is unfixable.
			return nil, nil
		}
		args := append(append([]any{}, tierArg...), limit)
		rows, err := a.DB.Query(`SELECT f.purl, f.advisory_id, f.score, f.tier, f.state,
			f.detected_at, '', NULL, ''
			FROM findings f
			WHERE f.state NOT IN ('ignored', 'fixed')`+tierClause+`
			ORDER BY f.score DESC, f.purl LIMIT ?`, args...)
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
		WHERE (? = 0 OR fixed_in <> '')` + cteTierClause + `
		ORDER BY score DESC, purl LIMIT ?`

	only := 0
	if fixableOnly {
		only = 1
	}
	args := append(append([]any{only}, tierArg...), limit)
	rows, err := a.DB.Query(query, args...)
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

// RescoreFindings updates the score and tier of findings already on file.
//
// RecordFindings is INSERT OR IGNORE, which is what makes the watcher alert
// once — and it means a finding's score and tier are frozen at the moment it
// was first detected. That is wrong twice over: the scoring policy can change,
// and so can the package's context (a project dependency goes stale, a package
// gets installed globally as well). Without this, changing the tier policy
// would appear to do nothing at all on any machine that already has findings,
// which is every machine that has ever run a scan.
//
// State is deliberately untouched. How bad a finding is and whether someone has
// dealt with it are different questions, and rescoring must not quietly reopen
// something that was acknowledged.
func (a Agent) RescoreFindings(findings []Finding) (int, error) {
	if len(findings) == 0 {
		return 0, nil
	}

	tx, err := a.DB.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`UPDATE findings SET score = ?, tier = ?
		WHERE purl = ? AND advisory_id = ? AND (score <> ? OR tier <> ?)`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	changed := 0
	for _, finding := range findings {
		result, err := stmt.Exec(finding.Score, finding.Tier,
			finding.PURL, finding.AdvisoryID, finding.Score, finding.Tier)
		if err != nil {
			return 0, err
		}
		changed += rowsAffected(result)
	}
	return changed, tx.Commit()
}
