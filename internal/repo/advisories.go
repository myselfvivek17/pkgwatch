package repo

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/myselfvivek17/pkgwatch/internal/match"
)

// LookupAdvisories returns every advisory recorded against a package name in
// the attached bundle.
//
// The caller decides whether each one actually affects the installed version —
// this only narrows by name, which is what the (ecosystem, package_name) index
// is for. Names are normalized per ecosystem so a PyPI lookup for
// "zope.interface" finds an advisory filed against "zope-interface".
func LookupAdvisories(handle *sql.DB, ecosystem, name string) ([]match.Advisory, error) {
	normalized := match.NormalizeName(ecosystem, name)

	rows, err := handle.Query(`
		SELECT a.rowid, a.id, a.source, a.kind, a.ecosystem, a.package_name, t.summary,
		       a.severity_cvss, a.published, a.modified, a.withdrawn
		FROM adv.advisories a
		LEFT JOIN adv.advisory_text t ON t.id = a.id
		WHERE a.ecosystem = ? AND a.name_normalized = ?`, ecosystem, normalized)
	if err != nil {
		return nil, fmt.Errorf("repo: query advisories: %w", err)
	}
	defer rows.Close()

	var (
		advisories []match.Advisory
		keys       []int64
	)
	for rows.Next() {
		var (
			key                            int64
			id, source, kind, eco, pkgName string
			summary                        sql.NullString
			severity                       sql.NullFloat64
			published, modified            int64
			withdrawn                      sql.NullInt64
		)
		if err := rows.Scan(&key, &id, &source, &kind, &eco, &pkgName, &summary,
			&severity, &published, &modified, &withdrawn); err != nil {
			return nil, err
		}

		adv := match.Advisory{
			ID:          id,
			Kind:        kind,
			Source:      source,
			Ecosystem:   eco,
			PackageName: pkgName,
			Summary:     summary.String,
			Withdrawn:   withdrawn.Valid,
			Published:   time.Unix(published, 0).UTC(),
			Modified:    time.Unix(modified, 0).UTC(),
		}
		if severity.Valid {
			score := severity.Float64
			adv.SeverityCVSS = &score
		}

		advisories = append(advisories, adv)
		keys = append(keys, key)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	for i, key := range keys {
		if advisories[i].Versions, err = advisoryVersions(handle, key); err != nil {
			return nil, err
		}
		if advisories[i].Ranges, err = advisoryRanges(handle, key); err != nil {
			return nil, err
		}
	}
	return advisories, nil
}

func advisoryVersions(handle *sql.DB, key int64) ([]string, error) {
	rows, err := handle.Query("SELECT version FROM adv.advisory_versions WHERE advisory_id = ?", key)
	if err != nil {
		return nil, fmt.Errorf("repo: query advisory versions: %w", err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func advisoryRanges(handle *sql.DB, key int64) ([]match.Range, error) {
	rows, err := handle.Query(
		"SELECT introduced, fixed, last_affected FROM adv.advisory_ranges WHERE advisory_id = ?", key)
	if err != nil {
		return nil, fmt.Errorf("repo: query advisory ranges: %w", err)
	}
	defer rows.Close()

	var out []match.Range
	for rows.Next() {
		var introduced, fixed, lastAffected sql.NullString
		if err := rows.Scan(&introduced, &fixed, &lastAffected); err != nil {
			return nil, err
		}
		out = append(out, match.Range{
			Introduced:   introduced.String,
			Fixed:        fixed.String,
			LastAffected: lastAffected.String,
		})
	}
	return out, rows.Err()
}
