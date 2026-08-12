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
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/myselfvivek17/pkgwatch/internal/agent"
	"github.com/myselfvivek17/pkgwatch/internal/buildinfo"
	"github.com/myselfvivek17/pkgwatch/internal/config"
	"github.com/myselfvivek17/pkgwatch/internal/hub"
	"github.com/myselfvivek17/pkgwatch/internal/match"
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

		// The wrapper commands set DisableFlagParsing so that every flag belongs
		// to npm or pip. Without traversal cobra would then hand them --config
		// too, and `pkgwatch --config x npm install` would silently run with the
		// default configuration while passing a stray argument to npm.
		TraverseChildren: true,
	}
	root.PersistentFlags().StringVar(&configPath, "config", "", "path to pkgwatch.toml (default: <data dir>/pkgwatch.toml)")

	root.AddCommand(
		agentCmd(),
		hubCmd(),
		statusCmd(),

		npmCmd(),
		pipCmd(),
		shellInitCmd(),

		scanCmd(),
		inventoryCmd(),
		syncCmd(),
		checkCmd(),
		publishCmd(),

		findingsCmd(),
		ackCmd(),
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

	cmd.AddCommand(pairCmd(), unpairCmd())
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

	cmd.AddCommand(pairCodeCmd(), setPasswordCmd(), devicesCmd())
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
		// Coverage, not just volume. A half-million records means nothing if the
		// ecosystem you install from is not among them.
		if len(st.Bundle.Ecosystems) > 0 {
			// Collapsed to distinct ecosystems. Six Debian and Alpine releases are
			// a long line and a short fact; the full per-release list is what the
			// matching uses, not what a person needs to read.
			fmt.Fprintf(w, "covers\t%s\n", strings.Join(st.Bundle.CoveredScopes(), ", "))
			for _, gated := range []string{match.EcosystemNPM, match.EcosystemPyPI} {
				if !st.Bundle.Covers(gated) {
					fmt.Fprintf(w, "\tWARNING: %s installs are gated but this bundle has no %s advisories\n",
						gated, gated)
				}
			}
		}
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
		// A wrapped package manager's exit status passes through unchanged, so
		// `pkgwatch npm ci` behaves like `npm ci` in a script.
		if code := ExitCode(err); code >= 0 {
			return code
		}
		return 1
	}
	return 0
}
