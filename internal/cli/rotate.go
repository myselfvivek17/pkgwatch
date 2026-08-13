package cli

import (
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/myselfvivek17/pkgwatch/internal/agent"
	"github.com/myselfvivek17/pkgwatch/internal/config"
	"github.com/myselfvivek17/pkgwatch/internal/repo"
	"github.com/myselfvivek17/pkgwatch/internal/rotate"
)

func rotateCmd() *cobra.Command {
	var check, uncheck string
	var credentialsOnly bool

	cmd := &cobra.Command{
		Use:   "rotate [purl]",
		Short: "Credential rotation checklist for a machine that ran malicious code",
		Long: "List the credentials on this machine that should be rotated after a malicious\n" +
			"package ran, worst blast radius first.\n\n" +
			"Only credentials that actually exist here are listed. A generic checklist reads\n" +
			"as a form to fill in; the short true list is the one that gets worked through.\n\n" +
			"With no argument, lists the malware findings that warrant one. Progress is\n" +
			"stored per finding, so it survives a reboot and a closed browser.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Worth being able to ask before anything has gone wrong: this is
			// the list of what a malicious postinstall script on this machine
			// would have been able to read, and it is a different list on every
			// machine.
			if credentialsOnly {
				printCredentials(cmd.OutOrStdout(), rotate.Detect(rotate.Home()))
				return nil
			}

			cfg, err := config.Load(configPath)
			if err != nil {
				return err
			}
			st, err := agent.Open(cfg)
			if err != nil {
				return err
			}
			defer st.Close()

			if len(args) == 0 {
				return listExposures(cmd, st)
			}

			finding, err := malwareFindingFor(st, args[0])
			if err != nil {
				return err
			}
			if check != "" || uncheck != "" {
				return tickItem(cmd, st, finding, check, uncheck)
			}
			return printChecklist(cmd, st, finding)
		},
	}

	cmd.Flags().StringVar(&check, "check", "", "mark an item rotated (its id from the list)")
	cmd.Flags().StringVar(&uncheck, "uncheck", "", "unmark an item")
	cmd.Flags().BoolVar(&credentialsOnly, "credentials", false,
		"just list the credentials found on this machine, without a finding")
	return cmd
}

// printCredentials renders what was found, with nothing about a finding.
func printCredentials(out io.Writer, items []rotate.Item) {
	if len(items) == 0 {
		fmt.Fprintln(out, "none of the credential files this checks for exist in your home directory.")
		fmt.Fprintln(out, "\nThat is not the same as nothing being exposed: project .env files, "+
			"environment variables and password manager caches are outside what this can see.")
		return
	}

	table := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(table, "ID\tCATEGORY\tWHAT\tWHERE")
	for _, item := range items {
		fmt.Fprintf(table, "%s\t%s\t%s\t%s\n", item.ID, item.Category, item.Label, item.Path)
	}
	table.Flush()

	fmt.Fprintf(out, "\n%d credential(s), worst blast radius first. Anything that ran as you "+
		"could have read every one of them.\n", len(items))
}

// listExposures shows which findings mean credentials were exposed.
func listExposures(cmd *cobra.Command, st *agent.State) error {
	findings, err := st.Repo.MalwareFindings(st.BundleAttached, 50)
	if err != nil {
		return err
	}

	out := cmd.OutOrStdout()
	if !st.BundleAttached {
		// Without a bundle nothing here can tell malware from a vulnerability,
		// and "no exposures" would be a claim rather than an answer.
		fmt.Fprintln(out, "no advisory bundle installed, so malware findings cannot be told from "+
			"ordinary ones. Run `pkgwatch sync` first.")
		return nil
	}
	if len(findings) == 0 {
		fmt.Fprintln(out, "no open malware findings on this machine.")
		fmt.Fprintln(out, "\nRotation follows from code having run, not from a package being "+
			"vulnerable. `pkgwatch findings` lists everything else.")
		return nil
	}

	table := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(table, "PACKAGE\tADVISORY\tFOUND\tROTATED")
	for _, f := range findings {
		checked, err := st.Repo.RotationChecked(f.PURL, f.AdvisoryID)
		if err != nil {
			return err
		}
		items := rotate.Detect(rotate.Home())
		fmt.Fprintf(table, "%s\t%s\t%s\t%d of %d\n", f.PURL, f.AdvisoryID,
			f.DetectedAt.Format("2006-01-02"), countChecked(items, checked), len(items))
	}
	table.Flush()

	fmt.Fprintf(out, "\n`pkgwatch rotate <purl>` for the checklist.\n")
	return nil
}

// malwareFindingFor resolves an argument that may be a purl or an advisory id.
func malwareFindingFor(st *agent.State, arg string) (repo.Finding, error) {
	findings, err := st.Repo.MalwareFindings(st.BundleAttached, 200)
	if err != nil {
		return repo.Finding{}, err
	}
	for _, f := range findings {
		if f.PURL == arg || f.AdvisoryID == arg {
			return f, nil
		}
	}

	if !st.BundleAttached {
		return repo.Finding{}, fmt.Errorf("no advisory bundle installed, so nothing here knows " +
			"which findings are malware — run `pkgwatch sync` first")
	}
	return repo.Finding{}, fmt.Errorf("%s is not an open malware finding on this machine. "+
		"`pkgwatch rotate` lists the ones that are", arg)
}

func tickItem(cmd *cobra.Command, st *agent.State, finding repo.Finding, check, uncheck string) error {
	id, at := check, time.Now()
	if uncheck != "" {
		id, at = uncheck, time.Time{}
	}

	// Only against something on the list. A tick on an item this machine does
	// not have would record work nobody could have done.
	items := rotate.Detect(rotate.Home())
	if !hasItem(items, id) {
		return fmt.Errorf("%q is not on this machine's checklist for %s", id, finding.PURL)
	}
	if err := st.Repo.SetRotationChecked(finding.PURL, finding.AdvisoryID, id, at); err != nil {
		return err
	}

	verb := "rotated"
	if uncheck != "" {
		verb = "not rotated"
	}
	fmt.Fprintf(cmd.OutOrStdout(), "%s marked %s for %s\n", id, verb, finding.PURL)
	return nil
}

func printChecklist(cmd *cobra.Command, st *agent.State, finding repo.Finding) error {
	out := cmd.OutOrStdout()
	items := rotate.Detect(rotate.Home())
	checked, err := st.Repo.RotationChecked(finding.PURL, finding.AdvisoryID)
	if err != nil {
		return err
	}

	fmt.Fprintf(out, "%s\n  advisory %s\n  found    %s\n",
		finding.PURL, finding.AdvisoryID, finding.DetectedAt.Format("2006-01-02 15:04"))

	// The exposure window, because it decides how much of this matters. A
	// package present for three months and one present for an afternoon call
	// for the same list and a very different urgency.
	if first, last, err := st.Repo.PackageExposure(finding.PURL); err == nil {
		fmt.Fprintf(out, "  present  %s → %s (%s)\n",
			first.Format("2006-01-02"), last.Format("2006-01-02"),
			roundedDuration(last.Sub(first)))
	} else {
		// Not installed any more is worth saying: the window closed, and the
		// credentials were still exposed while it was open.
		fmt.Fprintf(out, "  present  no longer installed — the exposure window has closed, "+
			"but anything read during it is still read\n")
	}

	if finding.Summary != "" {
		fmt.Fprintf(out, "  what     %s\n", finding.Summary)
	}

	if len(items) == 0 {
		fmt.Fprintln(out, "\nNo credentials of the kinds this checks were found in your home "+
			"directory. That is not the same as nothing being exposed: application secrets in "+
			"project .env files, environment variables and anything in a password manager's CLI "+
			"cache are outside what this can see.")
		return nil
	}

	fmt.Fprintf(out, "\n%d credential(s) on this machine, worst blast radius first:\n\n", len(items))

	table := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(table, "  \tID\tWHAT\tWHERE")
	for _, item := range items {
		mark := "[ ]"
		if _, done := checked[item.ID]; done {
			mark = "[x]"
		}
		fmt.Fprintf(table, "%s\t%s\t%s\t%s\n", mark, item.ID, item.Label, item.Path)
	}
	table.Flush()

	fmt.Fprintln(out)
	for _, item := range items {
		if _, done := checked[item.ID]; done {
			continue
		}
		fmt.Fprintf(out, "  %-14s %s\n", item.ID, item.Why)
		if item.RotateURL != "" {
			fmt.Fprintf(out, "  %-14s rotate at %s\n", "", item.RotateURL)
		}
	}

	fmt.Fprintf(out, "\n%d of %d done. Mark one with `pkgwatch rotate %s --check <id>`.\n",
		countChecked(items, checked), len(items), finding.PURL)
	return nil
}

func countChecked(items []rotate.Item, checked map[string]time.Time) int {
	n := 0
	for _, item := range items {
		if _, done := checked[item.ID]; done {
			n++
		}
	}
	return n
}

func hasItem(items []rotate.Item, id string) bool {
	for _, item := range items {
		if item.ID == id {
			return true
		}
	}
	return false
}

// roundedDuration renders a span in the units a person thinks in.
func roundedDuration(d time.Duration) string {
	switch {
	case d < time.Hour:
		return "under an hour"
	case d < 48*time.Hour:
		return fmt.Sprintf("%d hours", int(d.Hours()))
	default:
		return fmt.Sprintf("%d days", int(d.Hours()/24))
	}
}
