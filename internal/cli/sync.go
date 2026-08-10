package cli

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/myselfvivek17/pkgwatch/internal/agent"
	"github.com/myselfvivek17/pkgwatch/internal/bundle"
	"github.com/myselfvivek17/pkgwatch/internal/config"
	"github.com/myselfvivek17/pkgwatch/internal/db"
	"github.com/myselfvivek17/pkgwatch/internal/repo"
)

func syncCmd() *cobra.Command {
	var fromFile, fromDir, sigPath, manifestPath string
	var allowDowngrade bool

	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Install advisory bundles",
		Long: "Install one or more advisory bundles.\n\n" +
			"--file installs a single bundle. --dir installs every bundle in a directory,\n" +
			"which is what the publisher's --split output is: one signed bundle per\n" +
			"ecosystem and release, of which a machine takes only the ones it needs.\n\n" +
			"The signature is verified against the publisher key compiled into this binary in\n" +
			"every case, and it covers the scope as well as the version — so a bundle cannot\n" +
			"be served as one it was not signed to be. A bundle is trusted because of who\n" +
			"signed it, never because of where it came from.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(configPath)
			if err != nil {
				return err
			}
			switch {
			case fromDir != "":
				if err := installDir(cmd, cfg, fromDir, allowDowngrade); err != nil {
					return err
				}
			case fromFile != "":
				if manifestPath == "" {
					manifestPath = fromFile + ".json"
				}
				if sigPath == "" {
					sigPath = fromFile + ".sig"
				}
				if err := installBundle(cmd, cfg, fromFile, manifestPath, sigPath, allowDowngrade); err != nil {
					return err
				}
			default:
				return fmt.Errorf("network sync lands with the hub in M5; " +
					"use --file or --dir to install bundles you already have")
			}

			// A new bundle is one of the two events that can change what is true
			// about an already-installed package — the other is a scan. Matching
			// here is what turns "an advisory landed this morning" into a finding
			// without waiting for the user to think of running something else.
			st, err := agent.Open(cfg)
			if err != nil {
				return err
			}
			defer st.Close()

			// Routine, dimmed on the timeline, and load-bearing: a bundle that
			// stopped arriving is a watchdog matching against a frozen view of
			// the world, which looks exactly like a quiet week.
			now := time.Now()
			if err := st.Repo.RecordEvent(repo.EventFeedSync, "", "", "", map[string]any{
				"bundle":  st.Bundle.Version,
				"records": fmt.Sprint(st.Bundle.RecordCount),
				"covers":  strings.Join(st.Bundle.CoveredScopes(), ", "),
			}, now); err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "note: could not record sync event: %v\n", err)
			}
			return runWatch(cmd, st, now)
		},
	}

	cmd.Flags().StringVar(&fromFile, "file", "", "install this advisory bundle file")
	cmd.Flags().StringVar(&fromDir, "dir", "", "install every advisory bundle in this directory")
	cmd.Flags().StringVar(&manifestPath, "manifest", "", "manifest file (default: <file>.json)")
	cmd.Flags().StringVar(&sigPath, "sig", "", "signature file (default: <file>.sig)")
	cmd.Flags().BoolVar(&allowDowngrade, "allow-downgrade", false,
		"install a bundle older than the one already present (normally refused)")
	return cmd
}

// installDir installs every bundle in a directory.
//
// Each is verified and staged on its own, and the merged database is rebuilt
// once at the end rather than once per bundle — six bundles would otherwise
// mean six full merges of everything before them.
//
// A bundle that fails verification stops the whole run. Installing the four
// that passed and quietly skipping the fifth would leave a machine that looks
// updated and is missing an ecosystem, which is the failure this project keeps
// coming back to.
func installDir(cmd *cobra.Command, cfg config.Config, dir string, allowDowngrade bool) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read bundle directory: %w", err)
	}

	var bundles []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".db") {
			bundles = append(bundles, filepath.Join(dir, entry.Name()))
		}
	}
	if len(bundles) == 0 {
		return fmt.Errorf("no .db bundles found in %s", dir)
	}
	sort.Strings(bundles)

	for _, path := range bundles {
		if err := stageBundle(cmd, cfg, path, path+".json", path+".sig", allowDowngrade); err != nil {
			return fmt.Errorf("%s: %w", filepath.Base(path), err)
		}
	}
	return rebuildMerged(cmd, cfg)
}

// installBundle stages one bundle and rebuilds the merged database.
func installBundle(cmd *cobra.Command, cfg config.Config, bundlePath, manifestPath, sigPath string, allowDowngrade bool) error {
	if err := stageBundle(cmd, cfg, bundlePath, manifestPath, sigPath, allowDowngrade); err != nil {
		return err
	}
	return rebuildMerged(cmd, cfg)
}

// stageBundle verifies a bundle and stores it as a source, without rebuilding.
func stageBundle(cmd *cobra.Command, cfg config.Config, bundlePath, manifestPath, sigPath string, allowDowngrade bool) error {
	data, err := os.ReadFile(bundlePath)
	if err != nil {
		return fmt.Errorf("read bundle: %w", err)
	}

	// Everything needed to decide whether to trust these bytes must come from
	// outside them. Reading the version out of the candidate database and then
	// verifying against that version would let the file choose what it is
	// signed as, which is no binding at all — and it would mean parsing a
	// hostile SQLite file before establishing any trust in it.
	manifest, err := readManifest(manifestPath)
	if err != nil {
		return err
	}

	sig, err := readSignature(manifest, sigPath)
	if err != nil {
		return err
	}

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
	if current != "" && manifest.Version < current && !allowDowngrade {
		return fmt.Errorf("REFUSING to install: %s bundle %s is older than the installed %s "+
			"(pass --allow-downgrade if this is deliberate)",
			manifest.Scope, manifest.Version, current)
	}

	// Release the merged database before rebuilding it. On Windows an open
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

	// The verified source is kept. The merged database is derived and can be
	// rebuilt at any time; the sources are what was actually signed, and
	// throwing them away would mean re-downloading every other scope to change
	// one of them.
	if err := bundle.Install(scopePath, data); err != nil {
		return err
	}

	fmt.Fprintf(cmd.OutOrStdout(), "staged %s bundle %s\n", manifest.Scope, manifest.Version)
	return nil
}

// rebuildMerged regenerates the single database the agent queries from every
// verified source it holds.
func rebuildMerged(cmd *cobra.Command, cfg config.Config) error {
	sources, err := cfg.ScopedBundles()
	if err != nil {
		return err
	}
	if len(sources) == 0 {
		return fmt.Errorf("no verified bundles to merge")
	}

	merged, err := bundle.Merge(sources, cfg.AdvisoryDBPath(), time.Now())
	if err != nil {
		return fmt.Errorf("rebuild the merged advisory database: %w", err)
	}

	// Only now that the bytes are trusted, read what the merged file says about
	// itself and check it is usable.
	installed, err := readBundleMeta(cfg.AdvisoryDBPath(), true)
	if err != nil {
		return fmt.Errorf("merged advisory database is unreadable: %w", err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "advisories now %d records from %d scope(s) · covers %s\n",
		merged.RecordCount, len(sources), strings.Join(installed.Ecosystems, ", "))
	return nil
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
	info, err := readBundleMeta(path, false)
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

// readBundleMeta opens an already-trusted bundle to read what it declares.
// checkSchema is false when only the version matters.
func readBundleMeta(path string, checkSchema bool) (repo.BundleInfo, error) {
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
