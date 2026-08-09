package cli

import (
	"fmt"
	"strings"
	"text/tabwriter"

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
	)

	cmd := &cobra.Command{
		Use:   "inventory",
		Short: "List packages recorded by the last scan",
		Long: "List what the inventory holds.\n\n" +
			"--plain emits tab-separated ecosystem, name, version and scope, which is\n" +
			"what to diff against a package manager's own listing when checking whether\n" +
			"detection missed anything.",
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
	return cmd
}
