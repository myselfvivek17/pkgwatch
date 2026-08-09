package bundle

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Merge combines several verified bundles into the single advisory database the
// agent queries.
//
// Splitting bundles per ecosystem is a distribution decision, and it stops
// there. The alternative — attaching one database per ecosystem and routing
// every lookup — would change the repo layer, the watcher and the gate, and
// SQLite's default limit of ten attached databases is uncomfortably close to
// the six a container host already needs. Merging leaves all of that untouched.
//
// The merged file is local and unsigned, which is correct: the trust boundary
// is where each source was verified against the publisher key. Nothing here
// re-decides trust, and a source that was never verified must never reach this
// function.
func Merge(sources []string, out string, builtAt time.Time) (Manifest, error) {
	if len(sources) == 0 {
		return Manifest{}, fmt.Errorf("bundle: nothing to merge")
	}
	sort.Strings(sources) // deterministic, so a rebuild produces the same file

	dir := filepath.Dir(out)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Manifest{}, fmt.Errorf("bundle: create %s: %w", dir, err)
	}

	tmpPath := filepath.Join(dir, ".merged-advisories.tmp")
	if err := os.Remove(tmpPath); err != nil && !os.IsNotExist(err) {
		return Manifest{}, err
	}
	defer os.Remove(tmpPath)

	db, err := sql.Open("sqlite", tmpPath)
	if err != nil {
		return Manifest{}, err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	if _, err := db.Exec(schemaSQL); err != nil {
		return Manifest{}, fmt.Errorf("bundle: create merged schema: %w", err)
	}

	var (
		version    string
		ecosystems = map[string]struct{}{}
		scopes     []string
		total      int
	)

	for _, source := range sources {
		added, meta, err := mergeOne(db, source)
		if err != nil {
			return Manifest{}, err
		}
		total += added

		if meta["version"] > version {
			// The merged file is only as fresh as its freshest part, and the
			// rollback guard runs per source anyway.
			version = meta["version"]
		}
		if scope := meta["scope"]; scope != "" {
			scopes = append(scopes, scope)
		}
		for _, ecosystem := range strings.Split(meta["ecosystems"], ",") {
			if ecosystem != "" {
				ecosystems[ecosystem] = struct{}{}
			}
		}
	}

	covered := make([]string, 0, len(ecosystems))
	for ecosystem := range ecosystems {
		covered = append(covered, ecosystem)
	}
	sort.Strings(covered)
	sort.Strings(scopes)

	meta := map[string]string{
		"version":      version,
		"built_at":     builtAt.UTC().Format(time.RFC3339),
		"record_count": strconv.Itoa(total),
		"schema":       SchemaVersion,
		"scope":        strings.Join(scopes, "+"),
		"ecosystems":   strings.Join(covered, ","),
	}
	for k, v := range meta {
		if _, err := db.Exec("INSERT INTO bundle_meta (k, v) VALUES (?, ?)", k, v); err != nil {
			return Manifest{}, fmt.Errorf("bundle: write merged meta %s: %w", k, err)
		}
	}

	if _, err := db.Exec("VACUUM"); err != nil {
		return Manifest{}, fmt.Errorf("bundle: vacuum merged: %w", err)
	}
	if err := db.Close(); err != nil {
		return Manifest{}, err
	}

	data, err := os.ReadFile(tmpPath)
	if err != nil {
		return Manifest{}, err
	}
	// Same write-then-rename as a downloaded bundle: a half-written advisory
	// database silently disarms matching, and a machine updating its advisories
	// must never be able to disarm itself.
	if err := Install(out, data); err != nil {
		return Manifest{}, err
	}

	return Manifest{
		Version:     version,
		Scope:       meta["scope"],
		SHA256:      Digest(data),
		Size:        int64(len(data)),
		BuiltAt:     builtAt.UTC(),
		RecordCount: total,
	}, nil
}

// mergeOne copies one source bundle into the open merged database.
//
// Child rows key on the parent's integer rowid, so every rowid is shifted by
// the number of advisories already merged. Copying them unshifted would attach
// one bundle's version lists to another bundle's advisories — every row present,
// every answer wrong, and nothing to notice it by.
func mergeOne(db *sql.DB, source string) (int, map[string]string, error) {
	uri := "file:" + filepath.ToSlash(source) + "?mode=ro"
	if _, err := db.Exec("ATTACH DATABASE ? AS src", uri); err != nil {
		if _, err := db.Exec("ATTACH DATABASE ? AS src", source); err != nil {
			return 0, nil, fmt.Errorf("bundle: attach %s: %w", source, err)
		}
	}
	defer db.Exec("DETACH DATABASE src")

	var schema string
	if err := db.QueryRow("SELECT v FROM src.bundle_meta WHERE k = 'schema'").Scan(&schema); err != nil {
		return 0, nil, fmt.Errorf("bundle: %s has no readable schema version: %w", source, err)
	}
	if schema != SchemaVersion {
		return 0, nil, ErrSchemaMismatch{Source: source, Found: schema, Want: SchemaVersion}
	}

	var offset int64
	if err := db.QueryRow("SELECT COALESCE(MAX(rowid), 0) FROM main.advisories").Scan(&offset); err != nil {
		return 0, nil, err
	}

	tx, err := db.Begin()
	if err != nil {
		return 0, nil, err
	}
	defer tx.Rollback()

	statements := []string{
		`INSERT INTO main.advisories
		   (rowid, id, source, kind, ecosystem, package_name, name_normalized,
		    severity_cvss, published, modified, withdrawn)
		 SELECT rowid + ?, id, source, kind, ecosystem, package_name, name_normalized,
		    severity_cvss, published, modified, withdrawn FROM src.advisories`,
		`INSERT INTO main.advisory_versions (advisory_id, version)
		 SELECT advisory_id + ?, version FROM src.advisory_versions`,
		`INSERT INTO main.advisory_ranges (advisory_id, introduced, fixed, last_affected)
		 SELECT advisory_id + ?, introduced, fixed, last_affected FROM src.advisory_ranges`,
	}
	for _, statement := range statements {
		if _, err := tx.Exec(statement, offset); err != nil {
			return 0, nil, fmt.Errorf("bundle: merge %s: %w", source, err)
		}
	}
	// Summaries are keyed by advisory id, which is shared across bundles: the
	// same CVE in the Debian 12 and Debian 13 bundles carries identical prose.
	if _, err := tx.Exec(
		`INSERT OR IGNORE INTO main.advisory_text (id, summary) SELECT id, summary FROM src.advisory_text`,
	); err != nil {
		return 0, nil, fmt.Errorf("bundle: merge summaries from %s: %w", source, err)
	}

	var added int
	if err := tx.QueryRow("SELECT COUNT(*) FROM src.advisories").Scan(&added); err != nil {
		return 0, nil, err
	}

	meta := map[string]string{}
	rows, err := tx.Query("SELECT k, v FROM src.bundle_meta")
	if err != nil {
		return 0, nil, err
	}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			rows.Close()
			return 0, nil, err
		}
		meta[k] = v
	}
	rows.Close()

	return added, meta, tx.Commit()
}

// ErrSchemaMismatch means a source bundle uses a layout this build cannot read.
type ErrSchemaMismatch struct{ Source, Found, Want string }

func (e ErrSchemaMismatch) Error() string {
	return fmt.Sprintf("bundle %s uses schema %q but this build reads %q — re-sync it",
		e.Source, e.Found, e.Want)
}
