// Package cli defines pkgwatch's command surface.
//
// The whole command tree from spec §10 exists from M0 onward. Unbuilt leaves
// return errNotImplemented rather than being absent: the surface is the contract
// later milestones fill in, and a command that silently does not exist yet is
// harder to notice than one that says so.
package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/myselfvivek17/pkgwatch/internal/agent"
	"github.com/myselfvivek17/pkgwatch/internal/buildinfo"
	"github.com/myselfvivek17/pkgwatch/internal/config"
	"github.com/myselfvivek17/pkgwatch/internal/hub"
	"github.com/myselfvivek17/pkgwatch/internal/repo"
)

var configPath string

func notImplemented(milestone string) error {
	return fmt.Errorf("not implemented yet — lands in %s", milestone)
}

// stub builds a command that documents itself and refuses to pretend.
func stub(use, short, milestone string, args cobra.PositionalArgs) *cobra.Command {
	return &cobra.Command{
		Use:   use,
		Short: short,
		Args:  args,
		RunE:  func(*cobra.Command, []string) error { return notImplemented(milestone) },
	}
}

func Root() *cobra.Command {
	root := &cobra.Command{
		Use:           "pkgwatch",
		Short:         "Supply-chain watchdog for a small fleet of personal machines",
		SilenceUsage:  true,
		Version:       fmt.Sprintf("%s (%s)", buildinfo.Version, buildinfo.Commit),
		RunE:          func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
		SilenceErrors: false,
	}
	root.PersistentFlags().StringVar(&configPath, "config", "", "path to pkgwatch.toml (default: <data dir>/pkgwatch.toml)")

	root.AddCommand(
		agentCmd(),
		hubCmd(),
		statusCmd(),

		stub("npm [args...]", "Run a gated npm install", "M2", cobra.ArbitraryArgs),
		stub("pip [args...]", "Run a gated pip install", "M2", cobra.ArbitraryArgs),
		stub("shell-init [bash|zsh|fish|powershell]", "Print shell integration", "M2", cobra.ExactArgs(1)),

		stub("scan", "Scan installed packages into the inventory", "M3", cobra.NoArgs),
		syncCmd(),
		checkCmd(),
		publishCmd(),

		stub("findings", "List findings", "M3", cobra.NoArgs),
		stub("ack <purl> <advisory-id>", "Acknowledge a finding", "M3", cobra.ExactArgs(2)),
		ignoreCmd(),
		stub("quarantine <purl>", "Quarantine an installed package", "M6", cobra.ExactArgs(1)),
		stub("restore <quarantine-id>", "Restore a quarantined package", "M6", cobra.ExactArgs(1)),
		stub("rotate <advisory-id>", "Print the credential rotation checklist", "M6", cobra.ExactArgs(1)),

		stub("enable-script-guard", "Set ignore-scripts globally and seed the allowlist", "M6", cobra.NoArgs),
		stub("allow-scripts <package>", "Allow install scripts for one package", "M6", cobra.ExactArgs(1)),
	)
	return root
}

func agentCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "agent",
		Short: "Run the agent daemon (foreground)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(configPath)
			if err != nil {
				return err
			}
			ctx, stop := signalContext()
			defer stop()
			return agent.Run(ctx, cfg)
		},
	}

	pair := stub("pair", "Pair this agent with a hub", "M5", cobra.NoArgs)
	pair.Flags().String("hub", "", "hub base URL, e.g. https://homelab:4875")
	pair.Flags().String("code", "", "pairing code from `pkgwatch hub pair-code`")

	cmd.AddCommand(pair, stub("unpair", "Forget the paired hub", "M5", cobra.NoArgs))
	return cmd
}

func hubCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "hub",
		Short: "Run the hub daemon (foreground)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(configPath)
			if err != nil {
				return err
			}
			ctx, stop := signalContext()
			defer stop()
			return hub.Run(ctx, cfg)
		},
	}

	devices := &cobra.Command{Use: "devices", Short: "Manage paired devices"}
	devices.AddCommand(
		stub("list", "List enrolled devices", "M5", cobra.NoArgs),
		stub("approve <id>", "Approve a pending device", "M5", cobra.ExactArgs(1)),
		stub("revoke <id>", "Revoke a device's token", "M5", cobra.ExactArgs(1)),
	)

	cmd.AddCommand(stub("pair-code", "Generate a single-use pairing code", "M5", cobra.NoArgs), devices)
	return cmd
}

// ignoreCmd exists separately because --days is mandatory (§10): an ignore with
// no expiry is how a finding gets silently forgotten.
func ignoreCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ignore <purl> <advisory-id>",
		Short: "Ignore a finding for a fixed number of days",
		Args:  cobra.ExactArgs(2),
		RunE:  func(*cobra.Command, []string) error { return notImplemented("M3") },
	}
	cmd.Flags().Int("days", 0, "days to ignore this finding for (required)")
	cmd.MarkFlagRequired("days")
	return cmd
}

func statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show health, feed freshness, findings and pairing state",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(configPath)
			if err != nil {
				return err
			}
			return printStatus(cmd, cfg)
		},
	}
}

func printStatus(cmd *cobra.Command, cfg config.Config) error {
	st, err := agent.Open(cfg)
	if err != nil {
		return err
	}
	defer st.Close()

	counts, err := st.Repo.FindingCounts()
	if err != nil {
		return err
	}
	packages, err := st.Repo.PackageCount()
	if err != nil {
		return err
	}

	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "pkgwatch\t%s (%s)\n", buildinfo.Version, buildinfo.Commit)
	fmt.Fprintf(w, "host\t%s\n", st.Hostname)
	fmt.Fprintf(w, "data dir\t%s\n", cfg.DataDir)
	fmt.Fprintf(w, "agent db\tok — %s\n", cfg.AgentDBPath())

	switch {
	case st.Bundle.Attached:
		age := "unknown age"
		if !st.Bundle.BuiltAt.IsZero() {
			age = fmt.Sprintf("built %s ago", time.Since(st.Bundle.BuiltAt).Round(time.Hour))
		}
		fmt.Fprintf(w, "advisories\t%s · %d records · %s\n", st.Bundle.Version, st.Bundle.RecordCount, age)
	case st.BundleWarning() != nil:
		fmt.Fprintf(w, "advisories\tPRESENT BUT UNUSABLE — %v\n", st.BundleWarning())
	default:
		fmt.Fprintf(w, "advisories\tnone — never synced, nothing can be matched yet\n")
	}

	fmt.Fprintf(w, "packages\t%d known\n", packages)

	total := 0
	for _, tier := range repo.Tiers {
		total += counts[tier]
	}
	if total == 0 {
		fmt.Fprintf(w, "findings\tnone recorded\n")
	} else {
		fmt.Fprintf(w, "findings\t%d critical · %d high · %d medium · %d low\n",
			counts["critical"], counts["high"], counts["medium"], counts["low"])
	}

	if st.Paired {
		fmt.Fprintf(w, "hub\tpaired — %s\n", orDash(st.HubURL))
	} else {
		fmt.Fprintf(w, "hub\tnot paired — local only (the agent does not need one)\n")
	}

	fmt.Fprintf(w, "ports\tnpm %d · pypi %d · dashboard %d\n",
		cfg.Agent.NPMPort, cfg.Agent.PyPIPort, cfg.Agent.DashboardPort)

	// Only warn about hub config on a machine that actually runs a hub. The
	// default bind is 0.0.0.0 with no password, so warning unconditionally
	// would fire on every agent-only box in the fleet — a permanent false
	// alarm is how a real one gets ignored.
	if runsHub(cfg) {
		if err := hub.CheckBind(cfg); errors.Is(err, hub.ErrAuthRequired) {
			fmt.Fprintf(w, "hub mode\tWILL NOT START — %s bind has no password configured\n", cfg.Hub.Bind)
		}
	}

	return w.Flush()
}

// runsHub reports whether this machine has ever run a hub — the hub database
// only exists once `pkgwatch hub` has started successfully at least once.
func runsHub(cfg config.Config) bool {
	_, err := os.Stat(cfg.HubDBPath())
	return err == nil
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

// Execute runs the root command, logging structured output to stderr.
func Execute() int {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))
	if err := Root().Execute(); err != nil {
		return 1
	}
	return 0
}
