// Package bundlesync installs advisory bundles, from wherever they came.
//
// It exists as its own package because two callers need the same code and
// neither can import the other: `pkgwatch sync` runs it once from a terminal,
// and the agent daemon runs it on a schedule. A second implementation for the
// daemon would be a second place for the verification rules to be subtly
// different, and those rules are the whole trust boundary (§0, hard rule 2).
package bundlesync

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/myselfvivek17/pkgwatch/internal/bundle"
	"github.com/myselfvivek17/pkgwatch/internal/config"
	"github.com/myselfvivek17/pkgwatch/internal/db"
	"github.com/myselfvivek17/pkgwatch/internal/fleet"
	"github.com/myselfvivek17/pkgwatch/internal/repo"
)

// Options carry the two things a caller decides.
type Options struct {
	// AllowDowngrade installs a bundle older than the one already held.
	AllowDowngrade bool

	// Swap runs the step that replaces the merged advisory database, which is
	// the only step that needs every reader of that file to let go of it first.
	//
	// The daemon passes a guard that quiesces its own dashboard, gates and
	// scanner; a one-shot CLI run has no readers of its own and passes nothing.
	// It cannot help with readers in *another* process — on Windows those hold
	// the file open and the swap fails, which is why routine updates belong to
	// the daemon.
	Swap func(func() error) error
}

func (o Options) swap(fn func() error) error {
	if o.Swap == nil {
		return fn()
	}
	return o.Swap(fn)
}

// Report is what happened, for the caller to render however it renders things.
//
// Everything that was *not* done is a field here too. A sync that quietly took
// four of five scopes and printed only successes is how a machine ends up
// missing an ecosystem while looking up to date.
type Report struct {
	Offered   int
	Installed int
	Current   int

	// Staged names the scopes written this run.
	Staged []string

	// Skipped is offered and not taken: nothing on this machine belongs to
	// those ecosystems.
	Skipped []string

	// NotRelayed is held here and not offered by the hub, so those scopes stay
	// at whatever version this machine already had.
	NotRelayed []string

	// Unmerged were installed but absent from the merged database, which is the
	// state an interrupted rebuild leaves behind.
	Unmerged []string

	// Rebuilt, Merged, Sources and Covers describe the merged database as it
	// now stands.
	Rebuilt bool
	Merged  bundle.Manifest
	Sources int
	Covers  []string
}

// ErrNoHub means this agent has no hub to pull from, which is a supported way
// to run and not a failure of anything.
var ErrNoHub = fmt.Errorf("this agent is not paired with a hub, so there is nothing to pull from")

// FromHub installs whatever the paired hub relays.
//
// The hub is a bandwidth cache: it saves every machine downloading the same
// corpus, and it decides nothing. Each bundle goes through the same staging
// path as one handed over on a USB stick — digest, signed scope, publisher
// signature, anti-rollback — because a hub that has been taken over must not be
// able to serve a bundle that says everything is fine.
func FromHub(cfg config.Config, client *fleet.Client, opts Options) (Report, error) {
	var report Report
	if client == nil {
		return report, ErrNoHub
	}

	offers, err := client.Bundles()
	if err != nil {
		return report, fmt.Errorf("ask the hub for its bundles: %w", err)
	}
	report.Offered = len(offers)
	if len(offers) == 0 {
		// Not an install of zero bundles. Nothing was replaced, and saying so
		// matters: "sync succeeded" over an empty relay reads as up to date.
		return report, fmt.Errorf("the hub holds no advisory bundles to relay — nothing was " +
			"installed and this machine's advisories are unchanged. Give the hub a bundle with " +
			"`pkgwatch sync --dir` on the hub machine")
	}

	held, err := HeldVersions(cfg)
	if err != nil {
		return report, err
	}
	wanted, err := scopesWorthHolding(cfg, held)
	if err != nil {
		return report, err
	}

	offered := map[string]bool{}
	for _, offer := range offers {
		manifest := offer.Manifest
		offered[manifest.Scope] = true

		// A hub serves the whole fleet's scopes and this machine is one member
		// of it. Taking all of them would put a server's 137 MB of Ubuntu
		// advisories on a Windows laptop and merge them into everything it
		// queries — the split into per-scope bundles exists precisely so a
		// machine carries only what it can match against.
		if !wanted[manifest.Scope] {
			report.Skipped = append(report.Skipped, manifest.Scope)
			continue
		}
		if have := held[manifest.Scope]; have != "" && manifest.Version <= have && !opts.AllowDowngrade {
			report.Current++
			continue
		}

		data, err := client.FetchBundle(offer.File)
		if err != nil {
			return report, fmt.Errorf("fetch %s from the hub: %w", offer.File, err)
		}
		sig, err := hex.DecodeString(manifest.Signature)
		if err != nil {
			return report, fmt.Errorf("%s: signature in the hub's manifest is not hex: %w", offer.File, err)
		}
		// Stage places the bundle by the scope inside the signature, not by the
		// name it was fetched under, so a hub serving the npm bundle as the
		// Debian one still lands it as npm.
		if err := Stage(cfg, data, manifest, sig, opts); err != nil {
			return report, fmt.Errorf("%s: %w", offer.File, err)
		}
		report.Installed++
		report.Staged = append(report.Staged, manifest.Scope)
	}

	// A hub that relays four of the five scopes this machine holds leaves the
	// fifth frozen at whatever it already had, and every other line of a report
	// would read as "updated".
	for scope := range held {
		if !offered[scope] {
			report.NotRelayed = append(report.NotRelayed, scope)
		}
	}
	sort.Strings(report.NotRelayed)
	sort.Strings(report.Skipped)

	// Nothing new, but a scope this machine holds may still be absent from the
	// merged database — an interrupted rebuild leaves exactly that, and the
	// sources alone are never queried. Without this the next run says "already
	// current" and matches against a bundle missing an ecosystem, which is the
	// difference between a clean machine and an unexamined one.
	if report.Installed == 0 {
		if report.Unmerged, err = ScopesMissingFromMerged(cfg, held); err != nil {
			return report, err
		}
		if len(report.Unmerged) == 0 {
			return report, nil
		}
	}
	return report, rebuild(cfg, &report, opts)
}

// FromDir installs every bundle in a directory, which is what the publisher's
// --split output is.
//
// Each is verified and staged on its own and the merge runs once at the end;
// six bundles would otherwise mean six full merges. A bundle that fails
// verification stops the run — installing the four that passed and skipping the
// fifth leaves a machine that looks updated and is missing an ecosystem.
func FromDir(cfg config.Config, dir string, opts Options) (Report, error) {
	var report Report

	entries, err := os.ReadDir(dir)
	if err != nil {
		return report, fmt.Errorf("read bundle directory: %w", err)
	}
	var bundles []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".db") {
			bundles = append(bundles, filepath.Join(dir, entry.Name()))
		}
	}
	if len(bundles) == 0 {
		return report, fmt.Errorf("no .db bundles found in %s", dir)
	}
	sort.Strings(bundles)

	for _, path := range bundles {
		scope, err := stageFile(cfg, path, path+".json", path+".sig", opts)
		if err != nil {
			return report, fmt.Errorf("%s: %w", filepath.Base(path), err)
		}
		report.Installed++
		report.Staged = append(report.Staged, scope)
	}
	return report, rebuild(cfg, &report, opts)
}

// FromFile installs a single bundle.
func FromFile(cfg config.Config, bundlePath, manifestPath, sigPath string, opts Options) (Report, error) {
	var report Report
	if manifestPath == "" {
		manifestPath = bundlePath + ".json"
	}
	if sigPath == "" {
		sigPath = bundlePath + ".sig"
	}

	scope, err := stageFile(cfg, bundlePath, manifestPath, sigPath, opts)
	if err != nil {
		return report, err
	}
	report.Installed++
	report.Staged = append(report.Staged, scope)
	return report, rebuild(cfg, &report, opts)
}

// Rebuild re-merges the sources already on disk.
//
// They were verified when they were installed and the merged file is derived
// from them, so this needs no network and re-decides no trust.
func Rebuild(cfg config.Config, opts Options) (Report, error) {
	var report Report
	return report, rebuild(cfg, &report, opts)
}

// stageFile reads a bundle and its manifest from disk, then stages it.
func stageFile(cfg config.Config, bundlePath, manifestPath, sigPath string, opts Options) (string, error) {
	data, err := os.ReadFile(bundlePath)
	if err != nil {
		return "", fmt.Errorf("read bundle: %w", err)
	}

	// Everything needed to decide whether to trust these bytes must come from
	// outside them. Reading the version out of the candidate database and then
	// verifying against that version would let the file choose what it is
	// signed as, which is no binding at all — and it would mean parsing a
	// hostile SQLite file before establishing any trust in it.
	manifest, err := readManifest(manifestPath)
	if err != nil {
		return "", err
	}
	sig, err := readSignature(manifest, sigPath)
	if err != nil {
		return "", err
	}
	return manifest.Scope, Stage(cfg, data, manifest, sig, opts)
}

// Stage is the one place a bundle becomes installed, whatever carried it here —
// a file, a directory, or a relay from the hub.
func Stage(cfg config.Config, data []byte, manifest bundle.Manifest, sig []byte, opts Options) error {
	if got := bundle.Digest(data); !strings.EqualFold(got, manifest.SHA256) {
		return fmt.Errorf("REFUSING to install: bundle digest %s does not match the manifest's %s",
			got, manifest.SHA256)
	}
	if manifest.Scope == "" {
		return fmt.Errorf("REFUSING to install: manifest declares no scope — " +
			"a bundle that does not say what it covers cannot be placed")
	}
	if err := bundle.Default().Verify(manifest.Version, manifest.Scope, data, sig); err != nil {
		return fmt.Errorf("REFUSING to install: %w", err)
	}

	// Anti-rollback, per scope. Signature binding stops a bundle being
	// relabelled; it cannot stop someone replaying a genuinely old, genuinely
	// signed bundle to freeze this machine's view of the world. Only the agent
	// knows what it already has, so the check belongs here — and it is per scope
	// because the npm bundle being newer says nothing about the Debian one.
	scopePath := cfg.ScopedBundlePath(manifest.Scope)
	current := scopedBundleVersion(scopePath)
	if current != "" && manifest.Version < current && !opts.AllowDowngrade {
		return fmt.Errorf("REFUSING to install: %s bundle %s is older than the installed %s "+
			"(pass --allow-downgrade if this is deliberate)",
			manifest.Scope, manifest.Version, current)
	}

	// The verified source is kept. The merged database is derived and can be
	// rebuilt at any time; the sources are what was actually signed, and
	// throwing them away would mean re-downloading every other scope to change
	// one of them.
	if err := bundle.Install(scopePath, data); err != nil {
		return err
	}
	// The manifest is kept beside the bundle because the signature cannot be
	// re-derived, and without it this machine could pass the bundle on but
	// nobody downstream could check it.
	return bundle.SaveManifest(scopePath, manifest, sig)
}

// rebuild regenerates the merged database every query actually runs against.
func rebuild(cfg config.Config, report *Report, opts Options) error {
	sources, err := cfg.ScopedBundles()
	if err != nil {
		return err
	}
	if len(sources) == 0 {
		return fmt.Errorf("no verified bundles to merge")
	}

	// The swap and the release of the current file have to happen inside the
	// same guard. Detaching, then merging for thirty seconds, then installing
	// would leave every reader without advisories for that whole window.
	err = opts.swap(func() error {
		// Release the merged database before replacing it. On Windows an open
		// handle blocks the rename outright.
		handle, err := db.Open(cfg.AgentDBPath(), db.SchemaAgent)
		if err != nil {
			return err
		}
		if attached, err := db.AttachAdvisories(handle, cfg.AdvisoryDBPath()); err == nil && attached {
			if err := db.DetachAdvisories(handle); err != nil {
				handle.Close()
				return fmt.Errorf("detach current bundle: %w", err)
			}
		}
		handle.Close()

		merged, err := bundle.Merge(sources, cfg.AdvisoryDBPath(), time.Now())
		if err != nil {
			return err
		}
		report.Merged = merged
		return nil
	})
	if err != nil {
		// The commonest cause on Windows by some distance, and the OS error says
		// only "used by another process" without naming which one. A staged
		// bundle that never reached the merged database is a machine matching
		// against advisories it has already downloaded — the gap that reads as a
		// quiet week.
		return fmt.Errorf("rebuild the merged advisory database: %w\n"+
			"If the pkgwatch agent is running it holds this file open — it will merge this "+
			"itself on its next bundle check. To do it now, stop the agent "+
			"(`schtasks /end /tn pkgwatch-agent` on Windows, "+
			"`systemctl --user stop pkgwatch-agent` on Linux) and run `pkgwatch sync --rebuild`", err)
	}

	// Only now that the bytes are trusted, read what the merged file says about
	// itself and check it is usable.
	installed, err := ReadBundleMeta(cfg.AdvisoryDBPath(), true)
	if err != nil {
		return fmt.Errorf("merged advisory database is unreadable: %w", err)
	}
	report.Rebuilt = true
	report.Covers = installed.CoveredScopes()
	report.Sources = len(sources)
	return nil
}

// HeldVersions reports the version of each scope already installed here.
func HeldVersions(cfg config.Config) (map[string]string, error) {
	sources, err := cfg.ScopedBundles()
	if err != nil {
		return nil, err
	}

	held := map[string]string{}
	for _, path := range sources {
		// The stored manifest names the scope as it was signed. Falling back to
		// the filename would let a mis-stored bundle claim a scope it was never
		// signed for, and the anti-rollback check is per scope.
		manifest, err := bundle.LoadManifest(path)
		if err != nil || manifest.Scope == "" {
			continue
		}
		held[manifest.Scope] = manifest.Version
	}
	return held, nil
}

// ScopesMissingFromMerged reports held scopes the merged database does not
// carry. A missing merged file counts as everything missing.
func ScopesMissingFromMerged(cfg config.Config, held map[string]string) ([]string, error) {
	info, err := ReadBundleMeta(cfg.AdvisoryDBPath(), false)
	if err != nil {
		// Unreadable or absent: whatever is held is not being matched against.
		info = repo.BundleInfo{}
	}

	var missing []string
	for scope := range held {
		if !info.Covers(scope) {
			missing = append(missing, scope)
		}
	}
	sort.Strings(missing)
	return missing, nil
}

// scopesWorthHolding is what this machine can actually match against: the
// scopes it already holds, plus every ecosystem its inventory names.
//
// Inventory rather than held-only, because a machine that has never held a
// scope is exactly the one that needs it — a new container pulls in Alpine
// packages and the Alpine bundle should arrive on the next sync rather than
// waiting for someone to notice.
func scopesWorthHolding(cfg config.Config, held map[string]string) (map[string]bool, error) {
	wanted := map[string]bool{}
	for scope := range held {
		wanted[scope] = true
	}

	handle, err := db.Open(cfg.AgentDBPath(), db.SchemaAgent)
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	counts, err := repo.Agent{DB: handle}.EcosystemCounts()
	if err != nil {
		return nil, err
	}
	for ecosystem, n := range counts {
		if n > 0 {
			wanted[ecosystem] = true
		}
	}
	return wanted, nil
}

// scopedBundleVersion reports the version of the source bundle already held for
// a scope, or "" if there is none.
//
// Deliberately tolerant: a source that will not open should not block replacing
// it, which is exactly what a sync is for.
func scopedBundleVersion(path string) string {
	if _, err := os.Stat(path); err != nil {
		return ""
	}
	info, err := ReadBundleMeta(path, false)
	if err != nil {
		return ""
	}
	return info.Version
}

func readManifest(path string) (bundle.Manifest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return bundle.Manifest{}, fmt.Errorf("read manifest: %w "+
			"(the manifest carries the version and digest a signature is checked against)", err)
	}

	var manifest bundle.Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return bundle.Manifest{}, fmt.Errorf("parse manifest: %w", err)
	}
	if manifest.Version == "" {
		return bundle.Manifest{}, fmt.Errorf("manifest declares no version")
	}
	if manifest.SHA256 == "" {
		return bundle.Manifest{}, fmt.Errorf("manifest declares no digest")
	}
	return manifest, nil
}

// readSignature prefers the detached .sig file and falls back to the manifest's
// own field, so either publication style works.
func readSignature(manifest bundle.Manifest, sigPath string) ([]byte, error) {
	encoded := manifest.Signature

	if raw, err := os.ReadFile(sigPath); err == nil {
		encoded = strings.TrimSpace(string(raw))
	} else if encoded == "" {
		return nil, fmt.Errorf("no signature: %s is missing and the manifest carries none "+
			"(an unsigned bundle cannot be trusted)", sigPath)
	}

	sig, err := hex.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("signature is not hex: %w", err)
	}
	return sig, nil
}

// ReadBundleMeta opens an already-trusted bundle to read what it declares.
// checkSchema is false when only the version matters.
func ReadBundleMeta(path string, checkSchema bool) (repo.BundleInfo, error) {
	handle, err := db.Open(":memory:", db.SchemaAgent)
	if err != nil {
		return repo.BundleInfo{}, err
	}
	defer handle.Close()

	attached, err := db.AttachAdvisories(handle, path)
	if err != nil {
		return repo.BundleInfo{}, fmt.Errorf("bundle is unreadable: %w", err)
	}
	if !attached {
		return repo.BundleInfo{}, fmt.Errorf("bundle %s does not exist", path)
	}

	info, err := repo.Bundle(handle, true)
	if err != nil {
		return repo.BundleInfo{}, fmt.Errorf("bundle has no readable metadata: %w", err)
	}
	if info.Version == "" {
		return repo.BundleInfo{}, fmt.Errorf("bundle declares no version")
	}
	if checkSchema {
		if err := db.CheckAdvisorySchema(handle, bundle.SchemaVersion); err != nil {
			return repo.BundleInfo{}, err
		}
	}
	return info, nil
}
