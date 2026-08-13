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
	"github.com/myselfvivek17/pkgwatch/internal/fleet"
	"github.com/myselfvivek17/pkgwatch/internal/repo"
)

func syncCmd() *cobra.Command {
	var fromFile, fromDir, sigPath, manifestPath string
	var allowDowngrade, rebuild bool

	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Install advisory bundles",
		Long: "Install one or more advisory bundles.\n\n" +
			"With no flags, bundles are pulled from the hub this agent is paired with,\n" +
			"which holds them so that one machine downloads the corpus and the rest copy\n" +
			"it across the LAN.\n\n" +
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
			case rebuild:
				// Re-merge the sources already on disk. They were verified when
				// they were installed and the merged file is derived from them,
				// so this needs no network and re-decides no trust. It exists
				// because the merged database can need rebuilding on its own --
				// a new local index, or a file that got truncated.
				if err := rebuildMerged(cmd, cfg); err != nil {
					return err
				}
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
				if err := installFromHub(cmd, cfg, allowDowngrade); err != nil {
					return err
				}
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
	cmd.Flags().BoolVar(&rebuild, "rebuild", false,
		"re-merge the bundles already installed, without fetching anything")
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

// installFromHub pulls whatever the paired hub relays.
//
// The hub is a bandwidth cache: it saves every machine downloading the same
// corpus, and it decides nothing. Each bundle goes through the same staging
// path as one handed over on a USB stick — digest, signed scope, publisher
// signature, anti-rollback — because a hub that has been taken over must not be
// able to serve a bundle that says everything is fine (§0, hard rule 2).
func installFromHub(cmd *cobra.Command, cfg config.Config, allowDowngrade bool) error {
	client, err := hubClient(cfg)
	if err != nil {
		return err
	}
	if client == nil {
		return fmt.Errorf("no bundle source: this agent is not paired with a hub, " +
			"so there is nothing to pull from — use --file or --dir, or pair with `pkgwatch agent pair`")
	}

	offers, err := client.Bundles()
	if err != nil {
		return fmt.Errorf("ask the hub for its bundles: %w", err)
	}
	if len(offers) == 0 {
		// Not an install of zero bundles. Nothing was replaced, and saying so
		// matters: "sync succeeded" over an empty relay would read as up to date.
		return fmt.Errorf("the hub holds no advisory bundles to relay — nothing was installed " +
			"and this machine's advisories are unchanged. Give the hub a bundle with " +
			"`pkgwatch sync --dir` on the hub machine")
	}

	held, err := heldBundleVersions(cfg)
	if err != nil {
		return err
	}

	out := cmd.OutOrStdout()
	installed, current := 0, 0
	offered := map[string]bool{}

	for _, offer := range offers {
		manifest := offer.Manifest
		offered[manifest.Scope] = true

		if have := held[manifest.Scope]; have != "" && manifest.Version <= have && !allowDowngrade {
			current++
			continue
		}

		data, err := client.FetchBundle(offer.File)
		if err != nil {
			return fmt.Errorf("fetch %s from the hub: %w", offer.File, err)
		}
		sig, err := hex.DecodeString(manifest.Signature)
		if err != nil {
			return fmt.Errorf("%s: signature in the hub's manifest is not hex: %w", offer.File, err)
		}
		// stageVerified places the bundle by the scope inside the signature, not
		// by the name it was fetched under, so a hub serving the npm bundle as
		// the Debian one still lands it as npm.
		if err := stageVerified(cmd, cfg, data, manifest, sig, allowDowngrade); err != nil {
			return fmt.Errorf("%s: %w", offer.File, err)
		}
		installed++
	}

	// A hub that relays four of the five scopes this machine holds leaves the
	// fifth frozen at whatever it already had, and every other line of output
	// here would read as "updated". Name them.
	var missing []string
	for scope := range held {
		if !offered[scope] {
			missing = append(missing, scope)
		}
	}
	sort.Strings(missing)

	fmt.Fprintf(out, "hub offered %d bundle(s): %d installed, %d already current\n",
		len(offers), installed, current)
	if len(missing) > 0 {
		fmt.Fprintf(out, "NOT RELAYED: the hub carries no %s bundle, so that scope stays at "+
			"the version this machine already had\n", strings.Join(missing, ", "))
	}

	// Nothing new, but a scope this machine holds may still be absent from the
	// merged database — a previous rebuild that failed leaves exactly that, and
	// the sources alone are never queried. Without this check the next run says
	// "already current" and matches against a bundle missing an ecosystem, which
	// is the difference between a clean machine and an unexamined one.
	if installed == 0 {
		unmerged, err := scopesMissingFromMerged(cfg, held)
		if err != nil || len(unmerged) == 0 {
			return err
		}
		verb := "is"
		if len(unmerged) > 1 {
			verb = "are"
		}
		fmt.Fprintf(out, "%s %s installed but missing from the merged database, rebuilding\n",
			strings.Join(unmerged, ", "), verb)
	}
	return rebuildMerged(cmd, cfg)
}

// scopesMissingFromMerged reports held scopes the merged database does not
// carry. A missing merged file counts as everything missing.
func scopesMissingFromMerged(cfg config.Config, held map[string]string) ([]string, error) {
	info, err := readBundleMeta(cfg.AdvisoryDBPath(), false)
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

// heldBundleVersions reports the version of each scope already installed here.
func heldBundleVersions(cfg config.Config) (map[string]string, error) {
	sources, err := cfg.ScopedBundles()
	if err != nil {
		return nil, err
	}

	held := map[string]string{}
	for _, path := range sources {
		// The stored manifest names the scope as it was signed. Falling back to
		// the filename would let a mis-stored bundle claim a scope it was never
		// signed for, and the whole point of the anti-rollback check below is
		// that it is per scope.
		manifest, err := bundle.LoadManifest(path)
		if err != nil || manifest.Scope == "" {
			continue
		}
		held[manifest.Scope] = manifest.Version
	}
	return held, nil
}

// hubClient loads the pairing this agent already has, on its own handle.
//
// Opened and closed here rather than held across the staging that follows:
// staging detaches and replaces the advisory database, and on Windows an open
// handle blocks the rename outright.
func hubClient(cfg config.Config) (*fleet.Client, error) {
	handle, err := db.Open(cfg.AgentDBPath(), db.SchemaAgent)
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	return agent.HubClient(repo.Agent{DB: handle})
}

// installBundle stages one bundle and rebuilds the merged database.
func installBundle(cmd *cobra.Command, cfg config.Config, bundlePath, manifestPath, sigPath string, allowDowngrade bool) error {
	if err := stageBundle(cmd, cfg, bundlePath, manifestPath, sigPath, allowDowngrade); err != nil {
		return err
	}
	return rebuildMerged(cmd, cfg)
}

// stageBundle verifies a bundle on disk and stores it as a source, without
// rebuilding.
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
	return stageVerified(cmd, cfg, data, manifest, sig, allowDowngrade)
}

// stageVerified is the one place a bundle becomes installed, whatever carried
// it here — a file, a directory, or a relay from the hub.
//
// There is deliberately no shorter path for a bundle that came from your own
// hub. The signature check below is identical in every case, because a hub is
// a bandwidth cache and never a trust anchor (§0, hard rule 2): a hub that has
// been taken over must not be able to serve a bundle claiming everything is
// fine and have any agent believe it.
func stageVerified(cmd *cobra.Command, cfg config.Config, data []byte, manifest bundle.Manifest, sig []byte, allowDowngrade bool) error {
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
	// The manifest is kept beside the bundle because the signature cannot be
	// re-derived, and without it this machine could pass the bundle on but
	// nobody downstream could check it.
	if err := bundle.SaveManifest(scopePath, manifest, sig); err != nil {
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
		// The commonest cause on Windows by some distance, and the OS error says
		// only "used by another process" without naming which one. A staged
		// bundle that never reached the merged database is a machine matching
		// against advisories it has already downloaded — the gap that reads as a
		// quiet week.
		return fmt.Errorf("rebuild the merged advisory database: %w\n"+
			"If the pkgwatch agent is running it holds this file open. Stop it "+
			"(`schtasks /end /tn pkgwatch-agent` on Windows, "+
			"`systemctl --user stop pkgwatch-agent` on Linux) and run `pkgwatch sync --rebuild`", err)
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
