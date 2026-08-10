package cli

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/myselfvivek17/pkgwatch/internal/agent"
	"github.com/myselfvivek17/pkgwatch/internal/config"
)

func ackCmd() *cobra.Command {
	var note string
	cmd := &cobra.Command{
		Use:   "ack <purl> <advisory-id>",
		Short: "Acknowledge a finding",
		Long: "Mark a finding as seen without hiding it.\n\n" +
			"It keeps its severity and stays in `pkgwatch findings`; it just stops being\n" +
			"announced. Use `ignore` to take something out of the list, which needs an\n" +
			"expiry because it is the bigger decision.",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := openAgent()
			if err != nil {
				return err
			}
			defer st.Close()

			if err := st.Repo.AcknowledgeFinding(args[0], args[1], note); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(),
				"acknowledged %s / %s — still listed, no longer announced\n", args[0], args[1])
			return nil
		},
	}
	cmd.Flags().StringVar(&note, "note", "", "why, for whoever reads this in three months")
	return cmd
}

// ignoreCmd requires --days (§10). An ignore with no expiry is how a real
// finding gets forgotten, and the flag is what makes the difference between
// deferring a decision and losing one.
func ignoreCmd() *cobra.Command {
	var days int
	var note string

	cmd := &cobra.Command{
		Use:   "ignore <purl> <advisory-id>",
		Short: "Ignore a finding for a fixed number of days",
		Long: "Hide a finding until a date.\n\n" +
			"--days is required and has no \"forever\" value. The expiry is enforced on\n" +
			"every scan and sync, so an ignored finding comes back on its own — critical\n" +
			"and high as news, lower tiers quietly, the same rule a first scan uses.",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if days < 1 {
				return fmt.Errorf("--days must be at least 1: an ignore with no end is how a finding gets forgotten")
			}
			st, err := openAgent()
			if err != nil {
				return err
			}
			defer st.Close()

			until := time.Now().AddDate(0, 0, days)
			if err := st.Repo.IgnoreFinding(args[0], args[1], note, until); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "ignored %s / %s until %s (%d days)\n",
				args[0], args[1], until.Format("2 Jan 2006"), days)
			return nil
		},
	}
	cmd.Flags().IntVar(&days, "days", 0, "days to ignore this finding for (required)")
	cmd.Flags().StringVar(&note, "note", "", "why, for whoever reads this in three months")
	cmd.MarkFlagRequired("days")
	return cmd
}

// openAgent is the three lines every command that touches the database repeats.
func openAgent() (*agent.State, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, err
	}
	return agent.Open(cfg)
}
