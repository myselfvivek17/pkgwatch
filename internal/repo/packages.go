package repo

import (
	"database/sql"
	"time"
)

// PackageRow is one inventory record as stored.
type PackageRow struct {
	PURL       string
	Ecosystem  string
	Name       string
	Version    string
	InstallDir string
	Scope      string
	HasScripts bool
	DirMTime   int64
}

// KnownMTimes returns the recorded modification time of every install
// directory, so a scan can skip re-reading metadata that cannot have changed.
func (a Agent) KnownMTimes() (map[string]int64, error) {
	rows, err := a.DB.Query(
		"SELECT install_path, path_mtime FROM packages WHERE path_mtime IS NOT NULL")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	known := map[string]int64{}
	for rows.Next() {
		var path string
		var mtime sql.NullInt64
		if err := rows.Scan(&path, &mtime); err != nil {
			return nil, err
		}
		if mtime.Valid {
			known[path] = mtime.Int64
		}
	}
	return known, rows.Err()
}

// UpsertPackages records what a scan found, in one transaction.
//
// first_seen is preserved across scans and last_seen is moved forward, which is
// what lets the timeline say how long something has been on the machine and
// what lets the scoring discount a project dependency nobody has touched in
// months (§5.2).
//
// Nothing is deleted. A package that has been uninstalled keeps its row and
// simply stops having its last_seen advanced — removing it would take with it
// the answer to "did this machine have the compromised version when it was
// live", which is the question that matters after the fact.
func (a Agent) UpsertPackages(packages []PackageRow, at time.Time) (inserted, updated int, err error) {
	tx, err := a.DB.Begin()
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO packages
			(purl, ecosystem, name, version, install_path, scope, has_scripts,
			 first_seen, last_seen, path_mtime)
		VALUES (?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(purl) DO UPDATE SET
			last_seen    = excluded.last_seen,
			install_path = excluded.install_path,
			scope        = excluded.scope,
			has_scripts  = excluded.has_scripts,
			path_mtime   = excluded.path_mtime,
			-- Seeing it again is what makes it present, including after it was
			-- previously marked gone: reinstalling a package must bring its row
			-- back to life rather than leave it invisible to the watcher.
			gone_at      = NULL`)
	if err != nil {
		return 0, 0, err
	}
	defer stmt.Close()

	now := at.Unix()
	for _, pkg := range packages {
		result, err := stmt.Exec(pkg.PURL, pkg.Ecosystem, pkg.Name, pkg.Version,
			pkg.InstallDir, pkg.Scope, boolToInt(pkg.HasScripts), now, now, pkg.DirMTime)
		if err != nil {
			return 0, 0, err
		}
		// SQLite reports one changed row for an insert and one for an update, so
		// the two are told apart by whether first_seen is still this scan.
		if n, _ := result.RowsAffected(); n > 0 {
			var firstSeen int64
			if err := tx.QueryRow("SELECT first_seen FROM packages WHERE purl = ?", pkg.PURL).
				Scan(&firstSeen); err == nil && firstSeen == now {
				inserted++
			} else {
				updated++
			}
		}
	}
	return inserted, updated, tx.Commit()
}

// Packages returns what is installed now, ordered so two runs can be diffed.
//
// Retired rows are excluded: they are history, and listing them as inventory
// would report software the machine no longer has.
func (a Agent) Packages(limit int) ([]PackageRow, error) {
	rows, err := a.DB.Query(`SELECT purl, ecosystem, name, version, install_path,
		scope, has_scripts, COALESCE(path_mtime, 0)
		FROM packages WHERE gone_at IS NULL
		ORDER BY ecosystem, name, version LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []PackageRow
	for rows.Next() {
		var pkg PackageRow
		var hasScripts int
		if err := rows.Scan(&pkg.PURL, &pkg.Ecosystem, &pkg.Name, &pkg.Version,
			&pkg.InstallDir, &pkg.Scope, &hasScripts, &pkg.DirMTime); err != nil {
			return nil, err
		}
		pkg.HasScripts = hasScripts != 0
		out = append(out, pkg)
	}
	return out, rows.Err()
}

// EcosystemCounts reports how many packages are recorded per ecosystem — the
// raw material for deciding which advisory feeds a machine actually needs.
func (a Agent) EcosystemCounts() (map[string]int, error) {
	rows, err := a.DB.Query(
		"SELECT ecosystem, COUNT(*) FROM packages WHERE gone_at IS NULL GROUP BY ecosystem")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	counts := map[string]int{}
	for rows.Next() {
		var ecosystem string
		var n int
		if err := rows.Scan(&ecosystem, &n); err != nil {
			return nil, err
		}
		counts[ecosystem] = n
	}
	return counts, rows.Err()
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
