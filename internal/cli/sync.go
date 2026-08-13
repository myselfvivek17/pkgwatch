package cli

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/myselfvivek17/pkgwatch/internal/agent"
	"github.com/myselfvivek17/pkgwatch/internal/bundlesync"
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
			"it across the LAN. A running agent does this on its own schedule; this\n" +
			"command is for doing it now, and for machines with no hub.\n\n" +
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
			opts := bundlesync.Options{AllowDowngrade: allowDowngrade}

			var report bundlesync.Report
			switch {
			case rebuild:
				report, err = bundlesync.Rebuild(cfg, opts)
			case fromDir != "":
				report, err = bundlesync.FromDir(cfg, fromDir, opts)
			case fromFile != "":
				report, err = bundlesync.FromFile(cfg, fromFile, manifestPath, sigPath, opts)
			default:
				client, hubErr := hubClient(cfg)
				if hubErr != nil {
					return hubErr
				}
				report, err = bundlesync.FromHub(cfg, client, opts)
				if err == bundlesync.ErrNoHub {
					return fmt.Errorf("no bundle source: %w — use --file or --dir, "+
						"or pair with `pkgwatch agent pair`", err)
				}
			}
			printSyncReport(cmd.OutOrStdout(), report)
			if err != nil {
				return err
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

// printSyncReport renders what the sync did, and every part of what it did not.
func printSyncReport(out io.Writer, report bundlesync.Report) {
	for _, scope := range report.Staged {
		fmt.Fprintf(out, "staged %s bundle\n", scope)
	}
	if report.Offered > 0 {
		fmt.Fprintf(out, "hub offered %d bundle(s): %d installed, %d already current\n",
			report.Offered, report.Installed, report.Current)
	}
	if len(report.Skipped) > 0 {
		// Said out loud rather than silently narrowed. If a container appears
		// later and this machine starts having packages from one of these, the
		// next sync takes it — and until then "not taken" has to be visible, or
		// an ecosystem nothing is watching looks like an ecosystem with nothing
		// wrong.
		fmt.Fprintf(out, "not taken: %s — no packages from those on this machine\n",
			strings.Join(report.Skipped, ", "))
	}
	if len(report.NotRelayed) > 0 {
		fmt.Fprintf(out, "NOT RELAYED: the hub carries no %s bundle, so that scope stays at "+
			"the version this machine already had\n", strings.Join(report.NotRelayed, ", "))
	}
	if len(report.Unavailable) > 0 {
		fmt.Fprintf(out, "NO BUNDLE ANYWHERE for %s: this machine has packages from it, holds no "+
			"bundle for it and the hub has none either — those packages are unexamined, not clean. "+
			"Build one with `pkgwatch publish build-bundle --split` and put it on the hub\n",
			strings.Join(report.Unavailable, ", "))
	}
	if len(report.Unmerged) > 0 {
		verb := "is"
		if len(report.Unmerged) > 1 {
			verb = "are"
		}
		fmt.Fprintf(out, "%s %s installed but missing from the merged database, rebuilding\n",
			strings.Join(report.Unmerged, ", "), verb)
	}
	if report.Rebuilt {
		fmt.Fprintf(out, "advisories now %d records from %d scope(s) · covers %s\n",
			report.Merged.RecordCount, report.Sources, strings.Join(report.Covers, ", "))
	}
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
