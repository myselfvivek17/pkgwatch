package cli

import (
	"fmt"
	"path/filepath"
	"sort"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/myselfvivek17/pkgwatch/internal/agent"
	"github.com/myselfvivek17/pkgwatch/internal/config"
	"github.com/myselfvivek17/pkgwatch/internal/repo"
	"github.com/myselfvivek17/pkgwatch/internal/scanner"
)

func scanCmd() *cobra.Command {
	var full bool

	cmd := &cobra.Command{
		Use:   "scan [path...]",
		Short: "Scan installed packages into the inventory",
		Long: "Record what is installed on this machine, then match it against the\n" +
			"advisory bundle.\n\n" +
			"Machine-wide installs — the npm global root, every interpreter's\n" +
			"site-packages, this machine's own distribution packages and those inside\n" +
			"running containers — are always scanned. Project trees are scanned where\n" +
			"given, or from scan_paths in the configuration.\n\n" +
			"Nothing found is executed. Package metadata is read straight off disk, and\n" +
			"container databases are copied out rather than queried from inside.",
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(configPath)
			if err != nil {
				return err
			}
			return runScan(cmd, cfg, args, full)
		},
	}

	cmd.Flags().BoolVar(&full, "full", false,
		"re-read every package instead of skipping directories whose mtime is unchanged")
	return cmd
}

func runScan(cmd *cobra.Command, cfg config.Config, paths []string, full bool) error {
	// agent.Open rather than a bare db.Open: it attaches the advisory bundle,
	// which the matching pass at the end of this scan needs.
	st, err := agent.Open(cfg)
	if err != nil {
		return err
	}
	defer st.Close()

	roots, err := ScanRoots(cfg, paths)
	if err != nil {
		return err
	}

	outcome, err := scanner.Run(st.DB, st.Repo, st.Bundle, cfg, roots, full)
	if err != nil {
		return err
	}
	return reportScan(cmd, st.Repo, outcome)
}

// ScanRoots resolves the project trees to walk: the ones named on the command
// line, or the configured ones when none are.
func ScanRoots(cfg config.Config, paths []string) ([]string, error) {
	if len(paths) == 0 {
		paths = cfg.Agent.ScanPaths
	}

	roots := make([]string, 0, len(paths))
	for _, path := range paths {
		absolute, err := filepath.Abs(path)
		if err != nil {
			return nil, fmt.Errorf("resolve %s: %w", path, err)
		}
		roots = append(roots, absolute)
	}
	return roots, nil
}

func reportScan(cmd *cobra.Command, store repo.Agent, outcome scanner.Outcome) error {
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "scanned in %s — %d new, %d seen again, %d unchanged since last scan%s\n",
		outcome.Elapsed.Round(time.Millisecond), outcome.Inserted, outcome.Updated,
		outcome.Unchanged, copiesNote(outcome.Copies))

	// A scan that quietly covered less of the disk than you think reads as a
	// clean machine, so say what could not be read.
	if outcome.Skipped > 0 {
		fmt.Fprintf(out, "%d directory(ies) looked like packages but could not be read\n", outcome.Skipped)
	}
	if outcome.Gone > 0 {
		fmt.Fprintf(out, "%d no longer installed — kept as history, no longer matched\n", outcome.Gone)
	}
	if outcome.Pruned.Any() {
		fmt.Fprintf(out, "retention: removed %d routine decision(s), %d event(s), %d session(s)\n",
			outcome.Pruned.RoutineDecisions, outcome.Pruned.Events, outcome.Pruned.Sessions)
	}

	counts, err := store.EcosystemCounts()
	if err != nil {
		return err
	}
	if len(counts) == 0 {
		fmt.Fprintln(out, "\nnothing found. Pass a project directory to scan it: pkgwatch scan .")
		return nil
	}

	ecosystems := make([]string, 0, len(counts))
	for ecosystem := range counts {
		ecosystems = append(ecosystems, ecosystem)
	}
	sort.Strings(ecosystems)

	fmt.Fprintln(out)
	table := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(table, "ECOSYSTEM\tPACKAGES")
	for _, ecosystem := range ecosystems {
		fmt.Fprintf(table, "%s\t%d\n", ecosystem, counts[ecosystem])
	}
	table.Flush()

	if !outcome.Matched {
		fmt.Fprintln(cmd.ErrOrStderr(),
			"\nno advisory bundle installed — the inventory was recorded but nothing was matched")
		return nil
	}
	reportWatch(out, outcome.Watch)
	return nil
}

// copiesNote reports duplicate installs, which are collapsed into one row.
func copiesNote(copies int) string {
	if copies == 0 {
		return ""
	}
	return fmt.Sprintf("\n%d further cop%s of packages already counted (same version, another directory)",
		copies, plural(copies, "y", "ies"))
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
