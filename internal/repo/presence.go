package repo

import (
	"time"

	"github.com/myselfvivek17/pkgwatch/internal/match"
)

// Installed is a package the inventory currently believes is present.
type Installed struct {
	PURL       string
	InstallDir string
	Scope      string

	// LastSeen is when a scan last found it. For packages inside containers it
	// is the only evidence available: InstallDir names a container rather than a
	// directory, so there is nothing on this filesystem to stat.
	LastSeen int64
}

// Present lists packages the inventory has not marked gone.
//
// This is the set a scan re-checks against the filesystem, and the set the
// watcher matches against advisories. Historical rows are excluded from both:
// raising a finding about a project you deleted last year is noise that reads
// exactly like a compromised machine.
func (a Agent) Present() ([]Installed, error) {
	rows, err := a.DB.Query(
		"SELECT purl, install_path, scope, last_seen FROM packages WHERE gone_at IS NULL")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Installed
	for rows.Next() {
		var item Installed
		if err := rows.Scan(&item.PURL, &item.InstallDir, &item.Scope, &item.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// PresentPackages returns the installed inventory in the shape the matcher
// wants, so the watcher can score a finding without a second query per row.
func (a Agent) PresentPackages() ([]match.Package, error) {
	rows, err := a.DB.Query(`SELECT ecosystem, name, version, scope, has_scripts, last_seen
		FROM packages WHERE gone_at IS NULL`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []match.Package
	for rows.Next() {
		var pkg match.Package
		var hasScripts int
		var lastSeen int64
		if err := rows.Scan(&pkg.Ecosystem, &pkg.Name, &pkg.Version,
			&pkg.Scope, &hasScripts, &lastSeen); err != nil {
			return nil, err
		}
		pkg.HasScripts = hasScripts != 0
		pkg.LastSeen = time.Unix(lastSeen, 0)
		out = append(out, pkg)
	}
	return out, rows.Err()
}

// MarkGone records that packages are no longer installed. Their rows stay.
func (a Agent) MarkGone(purls []string, at time.Time) error {
	if len(purls) == 0 {
		return nil
	}

	tx, err := a.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare("UPDATE packages SET gone_at = ? WHERE purl = ? AND gone_at IS NULL")
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, purl := range purls {
		if _, err := stmt.Exec(at.Unix(), purl); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// MarkSuperseded retires rows whose install directory now holds a different
// version.
//
// Upgrading a package in place leaves the old row pointing at a directory that
// still exists, so a filesystem check alone would keep calling it installed —
// and the machine would carry a finding for a version that was replaced months
// ago. Any row sharing an install path with something written by this scan, and
// not itself written by this scan, has been overwritten by definition.
func (a Agent) MarkSuperseded(scanAt time.Time) (int, error) {
	result, err := a.DB.Exec(`
		UPDATE packages SET gone_at = ?
		WHERE gone_at IS NULL
		  AND last_seen < ?
		  AND install_path IN (SELECT install_path FROM packages WHERE last_seen = ?)`,
		scanAt.Unix(), scanAt.Unix(), scanAt.Unix())
	if err != nil {
		return 0, err
	}
	n, _ := result.RowsAffected()
	return int(n), nil
}

// PresentCount reports how many packages are installed now, and how many rows
// are kept only as history.
func (a Agent) PresentCount() (present, historical int, err error) {
	err = a.DB.QueryRow(`SELECT
		COUNT(*) FILTER (WHERE gone_at IS NULL),
		COUNT(*) FILTER (WHERE gone_at IS NOT NULL) FROM packages`).Scan(&present, &historical)
	return present, historical, err
}
