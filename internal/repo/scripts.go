package repo

import "time"

// How an allowance was granted, recorded so a list of packages permitted to run
// code at install time can say where each permission came from.
const (
	ApprovedViaCLI       = "cli"
	ApprovedViaDashboard = "dashboard"
)

// ScriptAllowance is one package permitted to run install scripts.
//
// Package is a purl with no version, which is the identity the allowlist has
// carried since the schema's first migration: allowing a package and then
// upgrading it must not silently re-block the build.
type ScriptAllowance struct {
	Package   string
	AllowedAt time.Time
	RevokedAt time.Time
	Via       string
	Note      string
}

// Active reports whether the allowance still stands.
func (s ScriptAllowance) Active() bool { return s.RevokedAt.IsZero() }

// AllowScripts records that a package may run its install scripts.
//
// Re-allowing something previously withdrawn clears the revocation, because the
// decision being recorded is the current one — but approved_at is left alone,
// so how long this package has been trusted stays answerable.
func (a Agent) AllowScripts(pkg, via, note string, at time.Time) error {
	_, err := a.DB.Exec(`INSERT INTO script_allowlist (package, approved_at, approved_via, note)
		VALUES (?,?,?,?)
		ON CONFLICT (package) DO UPDATE SET
			revoked_at = NULL, approved_via = excluded.approved_via, note = excluded.note`,
		pkg, at.Unix(), via, nullIfEmpty(note))
	return err
}

// RevokeScripts withdraws an allowance without forgetting it was made.
//
// Only the first revocation sets the date, mirroring the way re-allowing leaves
// approved_at alone. Running it twice otherwise moves the timestamp forward and
// the record stops answering when the decision was actually taken.
func (a Agent) RevokeScripts(pkg string, at time.Time) error {
	_, err := a.DB.Exec(
		"UPDATE script_allowlist SET revoked_at = ? WHERE package = ? AND revoked_at IS NULL",
		at.Unix(), pkg)
	return err
}

// ScriptsAllowed reports whether this package may run scripts right now.
func (a Agent) ScriptsAllowed(pkg string) (bool, error) {
	var one int
	err := a.DB.QueryRow(`SELECT EXISTS(SELECT 1 FROM script_allowlist
		WHERE package = ? AND revoked_at IS NULL)`, pkg).Scan(&one)
	return one == 1, err
}

// ScriptAllowlist lists every allowance, active ones first.
func (a Agent) ScriptAllowlist() ([]ScriptAllowance, error) {
	rows, err := a.DB.Query(`SELECT package, approved_at, COALESCE(revoked_at, 0),
		approved_via, COALESCE(note, '')
		FROM script_allowlist ORDER BY revoked_at IS NOT NULL, package`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []ScriptAllowance
	for rows.Next() {
		var s ScriptAllowance
		var allowed, revoked int64
		if err := rows.Scan(&s.Package, &allowed, &revoked, &s.Via, &s.Note); err != nil {
			return nil, err
		}
		s.AllowedAt = time.Unix(allowed, 0)
		if revoked > 0 {
			s.RevokedAt = time.Unix(revoked, 0)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// PackagesWithScripts names the installed packages that carry install scripts.
//
// This is what the guard actually costs. Turning scripts off changes nothing
// already unpacked — code that has run has run — but the next clean install of
// one of these comes up unbuilt, and discovering that mid-deploy is how the
// feature gets switched off for good.
//
// Distinct by name, matching the allowlist's own per-package identity.
func (a Agent) PackagesWithScripts(ecosystem string) ([]string, error) {
	rows, err := a.DB.Query(`SELECT DISTINCT name FROM packages
		WHERE ecosystem = ? AND has_scripts = 1 AND gone_at IS NULL
		ORDER BY name`, ecosystem)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out = append(out, name)
	}
	return out, rows.Err()
}
