package cli

import (
	"fmt"
	"path/filepath"
	"sort"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/myselfvivek17/pkgwatch/internal/collect"
	"github.com/myselfvivek17/pkgwatch/internal/config"
	"github.com/myselfvivek17/pkgwatch/internal/db"
	"github.com/myselfvivek17/pkgwatch/internal/match"
	"github.com/myselfvivek17/pkgwatch/internal/repo"
)

func scanCmd() *cobra.Command {
	var full bool

	cmd := &cobra.Command{
		Use:   "scan [path...]",
		Short: "Scan installed packages into the inventory",
		Long: "Record what is installed on this machine.\n\n" +
			"Machine-wide installs — the npm global root and every interpreter's\n" +
			"site-packages — are always scanned. Project trees are scanned only where\n" +
			"given, because there is no safe guess at where your projects live and\n" +
			"walking a home directory to find out is slow enough that nobody runs it twice.\n\n" +
			"Nothing found is executed. Python metadata is read straight off disk rather\n" +
			"than by asking each interpreter, which would mean running it.",
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
	handle, err := db.Open(cfg.AgentDBPath(), db.SchemaAgent)
	if err != nil {
		return err
	}
	defer handle.Close()
	store := repo.Agent{DB: handle}

	var known collect.Known
	if !full {
		mtimes, err := store.KnownMTimes()
		if err != nil {
			return fmt.Errorf("read previous scan state: %w", err)
		}
		known = mtimes
	}

	roots := make([]string, 0, len(paths))
	for _, path := range paths {
		absolute, err := filepath.Abs(path)
		if err != nil {
			return fmt.Errorf("resolve %s: %w", path, err)
		}
		roots = append(roots, absolute)
	}

	started := time.Now()
	result := collect.Everything(roots, known)

	// Collapse copies before writing. The inventory is keyed by purl (§6.1), so
	// the same version installed in five projects is one row — and counting the
	// copies as five inserts would report a machine as carrying far more than it
	// does. The copy count is kept and reported, because "lodash 4.17.21 is here
	// five times" is worth knowing even when it is one finding.
	rows := make([]repo.PackageRow, 0, len(result.Packages))
	seen := make(map[string]int, len(result.Packages))
	copies := 0
	for _, pkg := range result.Packages {
		purl := pkg.PURL()
		if index, dup := seen[purl]; dup {
			copies++
			// Prefer the widest scope: a package that is installed globally is on
			// your PATH, and that is the fact that decides its score.
			if scopeRank(pkg.Scope) > scopeRank(rows[index].Scope) {
				rows[index].Scope = pkg.Scope
				rows[index].InstallDir = pkg.InstallDir
				rows[index].DirMTime = pkg.DirMTime
			}
			rows[index].HasScripts = rows[index].HasScripts || pkg.HasScripts
			continue
		}
		seen[purl] = len(rows)
		rows = append(rows, repo.PackageRow{
			PURL:       purl,
			Ecosystem:  pkg.Ecosystem,
			Name:       pkg.Name,
			Version:    pkg.Version,
			InstallDir: pkg.InstallDir,
			Scope:      pkg.Scope,
			HasScripts: pkg.HasScripts,
			DirMTime:   pkg.DirMTime,
		})
	}
	result.Copies = copies

	inserted, updated, err := store.UpsertPackages(rows, time.Now())
	if err != nil {
		return fmt.Errorf("record inventory: %w", err)
	}

	return reportScan(cmd, store, result, inserted, updated, time.Since(started))
}

func reportScan(cmd *cobra.Command, store repo.Agent, result collect.Result,
	inserted, updated int, elapsed time.Duration) error {

	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "scanned in %s — %d new, %d seen again, %d unchanged since last scan%s\n",
		elapsed.Round(time.Millisecond), inserted, updated, result.Unchanged, copiesNote(result.Copies))

	// A scan that quietly covered less of the disk than you think reads as a
	// clean machine, so say what could not be read.
	if result.Skipped > 0 {
		fmt.Fprintf(out, "%d directory(ies) looked like packages but could not be read\n", result.Skipped)
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

	fmt.Fprintln(out, "\nMatching the inventory against advisories lands next in M3.")
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

// scopeRank orders scopes by how much a finding in them matters. Global installs
// are on your PATH; a project dependency in a directory you have not opened in a
// year is not the same risk (§5.2).
func scopeRank(scope string) int {
	switch scope {
	case match.ScopeGlobal:
		return 4
	case match.ScopeSystem:
		return 3
	case match.ScopeVenv:
		return 2
	default:
		return 1
	}
}
