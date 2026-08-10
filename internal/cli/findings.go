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
	"github.com/myselfvivek17/pkgwatch/internal/repo"
	"github.com/myselfvivek17/pkgwatch/internal/watch"
)

func findingsCmd() *cobra.Command {
	var limit int
	var fixableOnly bool

	cmd := &cobra.Command{
		Use:   "findings",
		Short: "List advisories affecting installed packages",
		Long: "List advisories affecting installed packages, worst first.\n\n" +
			"FIX is the version that resolves it, or \"none yet\" when the advisory has\n" +
			"no published fix. --fixable narrows the list to what can actually be acted\n" +
			"on today, which is not the same as what scores highest: a package can carry\n" +
			"a dozen unpatched critical advisories while already being at the newest\n" +
			"version its distribution ships.",
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

			findings, err := st.Repo.OpenFindings(st.BundleAttached, repo.FindingFilter{Limit: limit, FixableOnly: fixableOnly})
			if err != nil {
				return err
			}
			printFindings(cmd.OutOrStdout(), findings, st.BundleAttached, limit, fixableOnly)
			return nil
		},
	}

	cmd.Flags().IntVar(&limit, "limit", 50, "how many findings to show")
	cmd.Flags().BoolVar(&fixableOnly, "fixable", false,
		"only findings with a published fix — what can be acted on today")
	return cmd
}

func printFindings(out io.Writer, findings []repo.Finding, bundleAttached bool, limit int, fixableOnly bool) {
	if len(findings) == 0 {
		// Without a bundle nothing is known about fixes, so --fixable returns
		// nothing — which is not the same as there being nothing to fix, and
		// "no open findings" alone would say the opposite on a machine with
		// hundreds of them.
		if fixableOnly && !bundleAttached {
			fmt.Fprintln(out, "cannot tell what is fixable: no advisory bundle is installed.")
			fmt.Fprintln(out, "Open findings are still recorded — see them with `pkgwatch findings`.")
			return
		}
		fmt.Fprintln(out, "no open findings.")
		if !bundleAttached {
			fmt.Fprintln(out, "\nNote: no advisory bundle is installed, so nothing has been matched.")
		} else {
			fmt.Fprintln(out, "Run `pkgwatch scan` if the inventory is out of date.")
		}
		return
	}

	table := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(table, "TIER\tSCORE\tCVSS\tFIX\tPACKAGE\tADVISORY")
	promoted, fixable := 0, 0
	for _, finding := range findings {
		base := "—"
		if finding.BaseCVSS != nil {
			base = fmt.Sprintf("%.1f", *finding.BaseCVSS)
			if finding.Score > *finding.BaseCVSS+0.05 {
				promoted++
			}
		}

		// Whether anything can be done about it is the first question a person
		// actually has, so it goes next to the severity rather than being
		// something to look up one advisory at a time.
		fix := "none yet"
		if finding.FixedIn != "" {
			fix = finding.FixedIn
			fixable++
		}

		fmt.Fprintf(table, "%s\t%.1f\t%s\t%s\t%s\t%s\n",
			strings.ToUpper(finding.Tier), finding.Score, base, fix,
			finding.PURL, finding.AdvisoryID)
	}
	table.Flush()

	// A triage list whose top entry cannot be acted on teaches you to ignore the
	// list. The highest-scoring finding on a real machine turned out to be
	// nineteen unpatched snapd advisories on a package already at the latest
	// version its distribution ships — correct, and useless to act on.
	//
	// Silent under --fixable, where every row is fixable by construction and the
	// line would only ever read "N of N".
	if fixable < len(findings) {
		fmt.Fprintf(out, "\n%d of %d shown have a fix available.\n", fixable, len(findings))
	}

	// A full page is indistinguishable from the whole list, and that footer was
	// the only thing hinting at a window before --fixable silenced it. Say it
	// outright: a truncated list that does not admit to being truncated reads as
	// the complete picture.
	if len(findings) == limit {
		fmt.Fprintf(out, "\nShowing the worst %d — there are more. Raise --limit to see them.\n", limit)
	}

	// Two numbers that routinely disagree need saying out loud once, or the
	// table reads as a bug. SCORE is the advisory's CVSS multiplied by where the
	// package is installed and whether it runs install scripts (§5.2); CVSS is
	// what the advisory itself rates.
	if promoted > 0 {
		fmt.Fprintf(out, "\n%d of these score above their CVSS: a globally installed package is on your\n"+
			"PATH, and one with install scripts already ran code. TIER follows SCORE.\n", promoted)
	}
	if !bundleAttached {
		fmt.Fprintln(out, "\nNote: the advisory bundle is unavailable, so summaries and CVSS are missing.")
	}
}

// reportWatch prints what a matching pass did, for scan and sync to share.
func reportWatch(out io.Writer, report watch.Report) {
	if report.Baseline {
		// Say plainly that the quiet ones were filed quietly. A summary the user
		// never sees is indistinguishable from a tool that missed them.
		fmt.Fprintf(out, "\nfirst match against the advisory bundle: %d package(s) examined, "+
			"%d finding(s) recorded\n", report.Examined, report.New)
		if report.Acknowledged > 0 {
			fmt.Fprintf(out, "%d pre-existing low/medium finding(s) filed as acknowledged rather than "+
				"announced — see them with `pkgwatch findings`\n", report.Acknowledged)
		}
	} else {
		fmt.Fprintf(out, "\nmatched %d package(s) against the bundle: %d new finding(s)\n",
			report.Examined, report.New)
	}

	if report.Resolved > 0 {
		fmt.Fprintf(out, "%d finding(s) closed — the package is no longer installed\n", report.Resolved)
	}
	if report.Reopened > 0 {
		fmt.Fprintf(out, "%d finding(s) reopened — the package is installed again\n", report.Reopened)
	}
	if len(report.Uncovered) > 0 {
		fmt.Fprintf(out, "NOT EXAMINED: the bundle carries no advisories for %s — "+
			"those packages are unknown, not clean\n", strings.Join(report.Uncovered, ", "))
	}
	if report.Unevaluated > 0 {
		fmt.Fprintf(out, "%d advisory check(s) could not be evaluated (unparseable version bounds)\n",
			report.Unevaluated)
	}
}

// runWatch is the shared entry point: match the inventory, then report.
func runWatch(cmd *cobra.Command, st *agent.State, now time.Time) error {
	if !st.BundleAttached {
		fmt.Fprintln(cmd.ErrOrStderr(),
			"no advisory bundle installed — the inventory was recorded but nothing was matched")
		return nil
	}

	report, err := watch.Run(st.DB, st.Repo, st.Bundle, now)
	if err != nil {
		return err
	}
	reportWatch(cmd.OutOrStdout(), report)
	return nil
}
