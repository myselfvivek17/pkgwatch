package cli

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/myselfvivek17/pkgwatch/internal/agent"
	"github.com/myselfvivek17/pkgwatch/internal/config"
)

// inventoryCmd prints what the last scan recorded.
//
// It exists because "does detection actually work on this machine" cannot be
// answered without seeing the list, and comparing against `npm ls -g`,
// `pip list` or `dpkg-query` inside a container means machine-readable output —
// not a table, and not a SQLite query that assumes sqlite3 is installed on the
// machine being audited.
func inventoryCmd() *cobra.Command {
	var (
		ecosystem string
		scope     string
		limit     int
		plain     bool
		gone      bool
	)

	cmd := &cobra.Command{
		Use:   "inventory",
		Short: "List packages recorded by the last scan",
		Long: "List what the inventory holds.\n\n" +
			"--plain emits tab-separated ecosystem, name, version and scope, which is\n" +
			"what to diff against a package manager's own listing when checking whether\n" +
			"detection missed anything.\n\n" +
			"--gone lists rows the scanner decided are no longer installed, newest\n" +
			"first, and says whether something replaced each one. Retiring a row closes\n" +
			"every finding attached to it, so a collector that loses rows marks real\n" +
			"vulnerabilities fixed; a retirement with nothing taking its place at the\n" +
			"same install path is what that looks like.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(configPath)
			if err != nil {
				return err
			}
			st, err := agent.Open(cfg)
			if err != nil {
				return err
			}
			defer st.Close()

			if gone {
				return printRetired(cmd.OutOrStdout(), st, ecosystem, scope, limit, plain)
			}

			rows, err := st.Repo.Packages(limit)
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			table := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
			if !plain {
				fmt.Fprintln(table, "ECOSYSTEM\tNAME\tVERSION\tSCOPE\tWHERE")
			}

			shown := 0
			for _, pkg := range rows {
				if ecosystem != "" && !strings.EqualFold(pkg.Ecosystem, ecosystem) {
					continue
				}
				if scope != "" && !strings.EqualFold(pkg.Scope, scope) {
					continue
				}
				shown++
				if plain {
					fmt.Fprintf(out, "%s\t%s\t%s\t%s\n",
						pkg.Ecosystem, pkg.Name, pkg.Version, pkg.Scope)
					continue
				}
				fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%s\n",
					pkg.Ecosystem, pkg.Name, pkg.Version, pkg.Scope, pkg.InstallDir)
			}
			if !plain {
				table.Flush()
				fmt.Fprintf(out, "\n%d package(s) shown. Historical rows for uninstalled "+
					"packages are excluded.\n", shown)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&ecosystem, "ecosystem", "", "only this ecosystem, e.g. npm or Debian:13")
	cmd.Flags().StringVar(&scope, "scope", "", "only this scope: global, project, venv, system, container")
	cmd.Flags().IntVar(&limit, "limit", 100000, "maximum rows to read")
	cmd.Flags().BoolVar(&plain, "plain", false, "tab-separated output with no header, for diffing")
	cmd.Flags().BoolVar(&gone, "gone", false,
		"list retired rows instead — what the scanner decided is no longer installed")
	return cmd
}

// printRetired shows what stopped being seen, and whether anything replaced it.
func printRetired(out io.Writer, st *agent.State, ecosystem, scope string, limit int, plain bool) error {
	rows, err := st.Repo.RetiredPackages(limit)
	if err != nil {
		return err
	}

	table := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	if !plain {
		fmt.Fprintln(table, "RETIRED\tREPLACED\tECOSYSTEM\tNAME\tVERSION\tWHERE")
	}

	shown, orphaned := 0, 0
	for _, pkg := range rows {
		if ecosystem != "" && !strings.EqualFold(pkg.Ecosystem, ecosystem) {
			continue
		}
		if scope != "" && !strings.EqualFold(pkg.Scope, scope) {
			continue
		}
		shown++
		replaced := "yes"
		if !pkg.Superseded {
			replaced = "NO"
			orphaned++
		}
		when := time.Unix(pkg.GoneAt, 0).Format("2006-01-02 15:04")
		if plain {
			fmt.Fprintf(out, "%s\t%s\t%s\t%s\t%s\t%s\n",
				when, replaced, pkg.Ecosystem, pkg.Name, pkg.Version, pkg.InstallDir)
			continue
		}
		fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%s\t%s\n",
			when, replaced, pkg.Ecosystem, pkg.Name, pkg.Version, pkg.InstallDir)
	}
	if plain {
		return nil
	}
	table.Flush()

	fmt.Fprintf(out, "\n%d retired row(s) shown.\n", shown)
	if shown == limit {
		fmt.Fprintf(out, "This is the %d most recent — there are more. Raise --limit to see them.\n", limit)
	}
	// An upgrade leaves something at the same install path. Nothing there means
	// the row was not replaced, which is either a genuine uninstall or a
	// collector that lost it — and the second silently closes findings.
	if orphaned > 0 {
		fmt.Fprintf(out, "%d were retired with nothing replacing them at the same path. "+
			"Expected for a real uninstall;\notherwise it is a collector that lost the row, "+
			"which closes that package's findings.\n", orphaned)
	}
	return nil
}
