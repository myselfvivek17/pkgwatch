// Package db opens pkgwatch's SQLite databases, applies embedded migrations,
// and attaches the replaceable advisory bundle.
package db

import (
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	_ "modernc.org/sqlite" // pure-Go driver: no cgo, so cross-compilation stays trivial
)

//go:embed migrations
var migrationsFS embed.FS

// Schema selects which migration set to apply.
type Schema string

const (
	SchemaAgent Schema = "agent"
	SchemaHub   Schema = "hub"
)

// AdvisorySchema is the alias the advisory bundle is attached under.
const AdvisorySchema = "adv"

// Open creates the parent directory if needed, opens the database, applies the
// PRAGMAs the spec requires, and runs any pending migrations.
func Open(path string, schema Schema) (*sql.DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}

	handle, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}

	// ponytail: single connection. PRAGMAs, foreign_keys and — importantly —
	// ATTACH are all per-connection state, so a pool would leave some
	// connections without the advisory bundle attached. The gate keeps its
	// malware set in memory (§5.1) so the DB is not in the hot path. If
	// dashboard reads ever contend with writes, move to a connector that
	// re-applies this setup on every new connection rather than raising this.
	handle.SetMaxOpenConns(1)

	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA foreign_keys=ON",
		"PRAGMA busy_timeout=5000",
	} {
		if _, err := handle.Exec(pragma); err != nil {
			handle.Close()
			return nil, fmt.Errorf("%s: %w", pragma, err)
		}
	}

	if err := migrate(handle, schema); err != nil {
		handle.Close()
		return nil, err
	}
	return handle, nil
}

// ErrSchemaMismatch means the bundle on disk uses a layout this binary does not
// read. It is deliberately distinguishable: an incompatible bundle is a
// different situation from a missing one, and callers treat them differently.
type ErrSchemaMismatch struct{ Found, Want string }

func (e ErrSchemaMismatch) Error() string {
	return fmt.Sprintf("advisory bundle uses schema %q but this build reads %q — upgrade pkgwatch",
		orUnknown(e.Found), e.Want)
}

func orUnknown(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

// CheckAdvisorySchema verifies an attached bundle's layout.
//
// A bundle arrives as a whole-file swap, so nothing else catches a layout
// change: a mismatch would otherwise surface as a raw "no such column" from
// deep inside a query, or worse, as zero rows — which reads as "no advisories"
// rather than "cannot evaluate".
func CheckAdvisorySchema(handle *sql.DB, want string) error {
	var found string
	err := handle.QueryRow("SELECT v FROM " + AdvisorySchema + ".bundle_meta WHERE k = 'schema'").Scan(&found)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return ErrSchemaMismatch{Want: want}
	}
	if found != want {
		return ErrSchemaMismatch{Found: found, Want: want}
	}
	return nil
}

// AttachAdvisories attaches the advisory bundle read-only. A missing bundle is
// not an error: a fresh machine has not synced one yet, and every caller must
// already handle "no bundle" rather than crash (§3.2). Returns whether it
// attached.
func AttachAdvisories(handle *sql.DB, path string) (bool, error) {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("stat advisory bundle: %w", err)
	}

	// Prefer the URI form so SQLite enforces read-only — a stray write to the
	// bundle would corrupt it mid-swap. Not every build enables URI filenames
	// for ATTACH, so fall back to a plain attach.
	uri := "file:" + filepath.ToSlash(path) + "?mode=ro"
	if _, err := handle.Exec("ATTACH DATABASE ? AS "+AdvisorySchema, uri); err == nil {
		return true, nil
	}

	if _, err := handle.Exec("ATTACH DATABASE ? AS "+AdvisorySchema, path); err != nil {
		return false, fmt.Errorf("attach advisory bundle: %w", err)
	}
	// Writable. Nothing writes through the adv. schema, but say so rather than
	// let a lost guarantee pass silently.
	slog.Warn("advisory bundle attached writable — read-only URI attach was rejected", "path", path)
	return true, nil
}

// DetachAdvisories releases the bundle so the file can be swapped.
func DetachAdvisories(handle *sql.DB) error {
	_, err := handle.Exec("DETACH DATABASE " + AdvisorySchema)
	return err
}

func migrate(handle *sql.DB, schema Schema) error {
	if _, err := handle.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL)`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	applied := map[int]bool{}
	rows, err := handle.Query("SELECT version FROM schema_migrations")
	if err != nil {
		return fmt.Errorf("read schema_migrations: %w", err)
	}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return err
		}
		applied[v] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	pending, err := loadMigrations(schema)
	if err != nil {
		return err
	}
	for _, m := range pending {
		if applied[m.version] {
			continue
		}
		tx, err := handle.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(m.sql); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %s: %w", m.name, err)
		}
		if _, err := tx.Exec("INSERT INTO schema_migrations (version, applied_at) VALUES (?, unixepoch())", m.version); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %s: %w", m.name, err)
		}
	}
	return nil
}

type migration struct {
	version int
	name    string
	sql     string
}

func loadMigrations(schema Schema) ([]migration, error) {
	dir := "migrations/" + string(schema)
	entries, err := fs.ReadDir(migrationsFS, dir)
	if err != nil {
		return nil, fmt.Errorf("read migrations for %s: %w", schema, err)
	}

	var out []migration
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		version, err := strconv.Atoi(strings.SplitN(e.Name(), "_", 2)[0])
		if err != nil {
			return nil, fmt.Errorf("migration %s: filename must start with a version number", e.Name())
		}
		body, err := migrationsFS.ReadFile(dir + "/" + e.Name())
		if err != nil {
			return nil, err
		}
		out = append(out, migration{version: version, name: e.Name(), sql: string(body)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	return out, nil
}
