package bundle

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/myselfvivek17/pkgwatch/internal/match"
)

// Schema of the advisory bundle.
//
// Deviation from spec §6.1, which makes advisories.id the primary key: a single
// OSV record covers several packages (GHSA-35jh-r3h4-6jhm names lodash plus
// three npm siblings), so ids are not unique. Rows are keyed by a composite
// "id|ecosystem|package_name" instead, with id kept as an indexed column.
// Every agent downloads this file, so its size is a feature. Two choices below
// are made for that reason and matter more than they look: rows are keyed by
// SQLite's integer rowid rather than by a 39-byte composite string, and there
// is no index on id. A text key is duplicated into every child row and every
// index that references it; on the real npm corpus that alone cost ~25 MB.
const schemaSQL = `
CREATE TABLE advisories (
  id TEXT NOT NULL, source TEXT NOT NULL,
  kind TEXT NOT NULL,                  -- vulnerability|malware
  ecosystem TEXT NOT NULL, package_name TEXT NOT NULL,
  -- name_normalized is computed at build time so lookups hit the index.
  -- PEP 503 folding is not something SQLite can express, and filtering in Go
  -- would mean scanning the whole ecosystem per lookup — the watcher does one
  -- lookup per installed package.
  name_normalized TEXT NOT NULL,
  severity_cvss REAL,
  published INTEGER NOT NULL, modified INTEGER NOT NULL, withdrawn INTEGER
);
CREATE INDEX idx_adv_pkg ON advisories(ecosystem, name_normalized);

-- Summaries live once per advisory id, not once per affected package. A single
-- CVE lands in Debian 11, 12, 13 and 14 with the same prose, and OSV summaries
-- average ~245 characters for distributions; storing them per row duplicated
-- 40MB across a bundle every agent downloads.
CREATE TABLE advisory_text (
  id TEXT PRIMARY KEY, summary TEXT
) WITHOUT ROWID;

CREATE TABLE advisory_versions (           -- exact hits, the fast path
  advisory_id INTEGER NOT NULL, version TEXT NOT NULL,
  PRIMARY KEY (advisory_id, version)
) WITHOUT ROWID;

CREATE TABLE advisory_ranges (
  advisory_id INTEGER NOT NULL,
  introduced TEXT, fixed TEXT, last_affected TEXT
);
CREATE INDEX idx_range_adv ON advisory_ranges(advisory_id);

CREATE TABLE bundle_meta (k TEXT PRIMARY KEY, v TEXT);
`

// SchemaVersion is the bundle layout this build reads and writes.
//
// A bundle arrives as a file swap, so nothing else would catch a layout change:
// without this check a newer builder's output would simply return no rows,
// which reads as "no advisories" rather than as an error. Bump it whenever
// schemaSQL changes shape.
const SchemaVersion = "6"

// versionFormat constrains bundle versions to fixed-width, lexicographically
// sortable strings: YYYYMMDD, optionally with an hourly delta suffix
// (20260809T1400).
//
// The agent's rollback guard compares versions as strings, because that is the
// only ordering available without a version grammar of its own. Free-text
// versions like "2026-08-09" or "v20260809" would sort wrong against "20260808"
// and the guard would fail silently — in whichever direction. Enforcing the
// format at signing time is what keeps that comparison honest.
var versionFormat = regexp.MustCompile(`^[0-9]{8}(T[0-9]{4})?$`)

// ValidateVersion reports whether a bundle version is safely comparable.
func ValidateVersion(version string) error {
	if !versionFormat.MatchString(version) {
		return fmt.Errorf(
			"bundle version %q must be YYYYMMDD or YYYYMMDDThhmm — the agent's "+
				"rollback check compares versions as strings, and anything else sorts wrong",
			version)
	}
	return nil
}

// coveredEcosystems lists the ecosystems present, in full, sorted.
//
// Full identifiers, including the release. An earlier version recorded base
// names only — a bundle carrying Debian:11 said it covered "Debian" — and that
// is precisely wrong at the granularity that matters. A bundle holding only
// Ubuntu:24.04:LTS would claim to cover Ubuntu, so a machine running
// Ubuntu:25.10 would be reported as examined, every lookup would return no
// rows, and 1,830 packages would read as clean. That happened on a real
// machine, and the coverage check existed specifically to prevent it.
func coveredEcosystems(advisories []match.Advisory) []string {
	seen := map[string]struct{}{}
	for _, adv := range advisories {
		seen[adv.Ecosystem] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for ecosystem := range seen {
		out = append(out, ecosystem)
	}
	sort.Strings(out)
	return out
}

// advisoryKey identifies an advisory row for build-time deduplication. It is
// not stored: keeping it out of the file is worth more than the index it would
// otherwise provide, and nothing queries by it at runtime.
func advisoryKey(adv match.Advisory) string {
	return adv.ID + "|" + adv.Ecosystem + "|" + adv.PackageName
}

// Build writes a complete advisory database at path and returns its manifest,
// unsigned. The caller signs the file's bytes.
func Build(path, version, scope string, advisories []match.Advisory, builtAt time.Time) (Manifest, error) {
	if err := ValidateVersion(version); err != nil {
		return Manifest{}, err
	}
	if scope == "" {
		return Manifest{}, fmt.Errorf("bundle: a bundle must declare what it covers")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return Manifest{}, fmt.Errorf("bundle: create output dir: %w", err)
	}
	// Build into a fresh file: an incremental write over an old bundle would
	// leave withdrawn advisories behind.
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return Manifest{}, fmt.Errorf("bundle: clear previous build: %w", err)
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return Manifest{}, fmt.Errorf("bundle: open %s: %w", path, err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	if _, err := db.Exec(schemaSQL); err != nil {
		return Manifest{}, fmt.Errorf("bundle: create schema: %w", err)
	}

	written, err := insertAll(db, advisories)
	if err != nil {
		return Manifest{}, err
	}

	meta := map[string]string{
		"version":      version,
		"built_at":     builtAt.UTC().Format(time.RFC3339),
		"record_count": fmt.Sprint(written),
		"schema":       SchemaVersion,
		// What this bundle claims to cover, kept alongside the ecosystems it
		// actually contains so a mismatch between the two is detectable.
		"scope": scope,
		// What this bundle actually covers, so an ecosystem that is simply
		// absent can be reported as unknown rather than as clean. A bundle built
		// without the PyPI feed answers "no advisories" for every Python package
		// on the machine, which is indistinguishable from safety and is the one
		// wrong answer this tool must never give.
		"ecosystems": strings.Join(coveredEcosystems(advisories), ","),
	}
	for k, v := range meta {
		if _, err := db.Exec("INSERT INTO bundle_meta (k, v) VALUES (?, ?)", k, v); err != nil {
			return Manifest{}, fmt.Errorf("bundle: write meta %s: %w", k, err)
		}
	}

	// Compact and checkpoint so the published file is stable and small.
	if _, err := db.Exec("VACUUM"); err != nil {
		return Manifest{}, fmt.Errorf("bundle: vacuum: %w", err)
	}
	if err := db.Close(); err != nil {
		return Manifest{}, fmt.Errorf("bundle: close: %w", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("bundle: read back: %w", err)
	}

	return Manifest{
		Version:     version,
		Scope:       scope,
		SHA256:      Digest(data),
		Size:        int64(len(data)),
		BuiltAt:     builtAt.UTC(),
		RecordCount: written,
	}, nil
}

func insertAll(db *sql.DB, advisories []match.Advisory) (int, error) {
	tx, err := db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	insAdv, err := tx.Prepare(`INSERT INTO advisories
		(id, source, kind, ecosystem, package_name, name_normalized,
		 severity_cvss, published, modified, withdrawn)
		VALUES (?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return 0, err
	}
	defer insAdv.Close()

	insText, err := tx.Prepare(`INSERT OR IGNORE INTO advisory_text (id, summary) VALUES (?,?)`)
	if err != nil {
		return 0, err
	}
	defer insText.Close()

	insVer, err := tx.Prepare(`INSERT OR IGNORE INTO advisory_versions (advisory_id, version) VALUES (?,?)`)
	if err != nil {
		return 0, err
	}
	defer insVer.Close()

	insRange, err := tx.Prepare(`INSERT INTO advisory_ranges
		(advisory_id, introduced, fixed, last_affected) VALUES (?,?,?,?)`)
	if err != nil {
		return 0, err
	}
	defer insRange.Close()

	// Deduplicate here rather than with a UNIQUE index: the index would ship in
	// every downloaded bundle, and this map is discarded when the build ends.
	seen := make(map[string]struct{}, len(advisories))

	written := 0
	for _, adv := range advisories {
		key := advisoryKey(adv)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}

		var severity any
		if adv.SeverityCVSS != nil {
			severity = *adv.SeverityCVSS
		}
		var withdrawn any
		if adv.Withdrawn {
			// The exact retraction time is not used; presence is what matters.
			withdrawn = adv.Modified.Unix()
		}

		result, err := insAdv.Exec(adv.ID, adv.Source, adv.Kind, adv.Ecosystem,
			adv.PackageName, match.NormalizeName(adv.Ecosystem, adv.PackageName),
			severity, adv.Published.Unix(), adv.Modified.Unix(), withdrawn)
		if err != nil {
			return 0, fmt.Errorf("bundle: insert %s: %w", key, err)
		}
		if adv.Summary != "" {
			if _, err := insText.Exec(adv.ID, adv.Summary); err != nil {
				return 0, fmt.Errorf("bundle: insert summary for %s: %w", adv.ID, err)
			}
		}
		rowID, err := result.LastInsertId()
		if err != nil {
			return 0, fmt.Errorf("bundle: row id for %s: %w", key, err)
		}

		for _, v := range adv.Versions {
			if _, err := insVer.Exec(rowID, v); err != nil {
				return 0, fmt.Errorf("bundle: insert version %s@%s: %w", key, v, err)
			}
		}
		for _, r := range adv.Ranges {
			if _, err := insRange.Exec(rowID,
				nullIfEmpty(r.Introduced), nullIfEmpty(r.Fixed), nullIfEmpty(r.LastAffected)); err != nil {
				return 0, fmt.Errorf("bundle: insert range %s: %w", key, err)
			}
		}
		written++
	}

	return written, tx.Commit()
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
