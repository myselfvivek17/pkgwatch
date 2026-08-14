package cli

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/myselfvivek17/pkgwatch/internal/agent"
	"github.com/myselfvivek17/pkgwatch/internal/config"
	"github.com/myselfvivek17/pkgwatch/internal/match"
	"github.com/myselfvivek17/pkgwatch/internal/repo"
	"github.com/myselfvivek17/pkgwatch/internal/scriptguard"
)

func scriptGuardCmd() *cobra.Command {
	var off bool

	cmd := &cobra.Command{
		Use:   "enable-script-guard",
		Short: "Set ignore-scripts globally and seed the allowlist",
		Long: "Turn off npm install scripts for every install this user runs.\n\n" +
			"A lifecycle script is arbitrary code running as you, at install time, before\n" +
			"any advisory has had a chance to describe it — the mechanism nearly every npm\n" +
			"supply-chain attack actually used. npm runs them by default.\n\n" +
			"This edits your user npm config rather than working per invocation, because a\n" +
			"guard that only applied when you remembered to type `pkgwatch npm` would not\n" +
			"be a guard. --off removes the setting again.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := cmd.OutOrStdout()

			// Turning the guard off touches npm's config and nothing else, so
			// it must not depend on the database opening. This is the escape
			// hatch: needing a healthy agent.db to undo a change to your npm
			// config is the wrong thing to discover while trying to undo it.
			if off {
				return disableGuard(out)
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

			return enableGuard(out, st.Repo)
		},
	}
	cmd.Flags().BoolVar(&off, "off", false, "remove the setting and let scripts run again")
	return cmd
}

func enableGuard(out io.Writer, store repo.Agent) error {
	before, err := scriptguard.Status()
	if err != nil {
		return err
	}
	if err := scriptguard.Enable(); err != nil {
		return err
	}

	fmt.Fprintf(out, "install scripts are now off for every npm run as this user\n")
	fmt.Fprintf(out, "  wrote   ignore-scripts=true to %s\n", before.UserConfig)
	fmt.Fprintf(out, "  undo    pkgwatch enable-script-guard --off\n\n")

	// What this actually costs. Nothing already unpacked changes — scripts that
	// have run have run — but the next clean install of one of these comes up
	// unbuilt, and finding that out during a deploy is the way this feature
	// gets switched off for good.
	needing, err := store.PackagesWithScripts(scriptguard.Ecosystem)
	if err != nil {
		return err
	}
	if len(needing) == 0 {
		// An inventory with no npm packages in it and an inventory that was
		// never taken produce the same empty answer here, and only one of them
		// means "nothing on this machine runs install scripts".
		counts, err := store.EcosystemCounts()
		if err != nil {
			return err
		}
		if counts[scriptguard.Ecosystem] == 0 {
			fmt.Fprintf(out, "This machine has no npm packages on file, so nothing here can say what\n"+
				"would come up unbuilt. That is an empty inventory, not an empty answer —\n"+
				"run `pkgwatch scan` and then `pkgwatch allow-scripts list`.\n")
			return nil
		}
		fmt.Fprintf(out, "None of the %d npm packages on file declares an install script, so nothing\n"+
			"here needed one. That is this machine today, not a guarantee about the next\n"+
			"thing you install.\n", counts[scriptguard.Ecosystem])
		return nil
	}

	allowed, err := store.ScriptAllowlist()
	if err != nil {
		return err
	}
	active := map[string]bool{}
	for _, a := range allowed {
		if a.Active() {
			active[a.Package] = true
		}
	}

	fmt.Fprintf(out, "%d installed package(s) declare install scripts. They keep working as they\n"+
		"are — this changes nothing already unpacked — but a clean reinstall will leave\n"+
		"them unbuilt until you allow them:\n\n", len(needing))

	shown := 0
	for _, name := range needing {
		if active[match.PURLBase(scriptguard.Ecosystem, name)] {
			continue
		}
		if shown == 20 {
			fmt.Fprintf(out, "  ... and %d more\n", len(needing)-shown)
			break
		}
		fmt.Fprintf(out, "  %s\n", name)
		shown++
	}

	fmt.Fprintf(out, "\nAllow the ones you actually need, one at a time:\n"+
		"  pkgwatch allow-scripts <package>\n\n"+
		"Deliberately not seeded automatically. Allowing every package that already runs\n"+
		"code would grant the permission to exactly the packages that already have it,\n"+
		"which is the set this guard exists to shrink.\n")
	return nil
}

func disableGuard(out io.Writer) error {
	state, err := scriptguard.Status()
	if err != nil {
		return err
	}
	if !state.SetByUserConfig {
		fmt.Fprintf(out, "your user npm config does not set ignore-scripts, so there is nothing to remove\n")
		if state.Enabled {
			// Removing our line would not have helped: something else is
			// setting it, and reporting success would send someone hunting.
			fmt.Fprintf(out, "\nnpm still reports ignore-scripts=true, so something else sets it —\n"+
				"a project .npmrc, an environment variable, or an organisation config.\n"+
				"Run `npm config list` to see which.\n")
		}
		return nil
	}

	if err := scriptguard.Disable(); err != nil {
		return err
	}
	fmt.Fprintf(out, "removed ignore-scripts from %s\n", state.UserConfig)

	after, err := scriptguard.Status()
	if err != nil {
		return err
	}
	if after.Enabled {
		fmt.Fprintf(out, "\nnpm still reports ignore-scripts=true — something other than your user\n"+
			"config sets it too. Run `npm config list` to see which.\n")
		return nil
	}
	fmt.Fprintf(out, "install scripts will run again on the next install\n")
	return nil
}

func allowScriptsCmd() *cobra.Command {
	var (
		note   string
		revoke bool
		dir    string
	)

	cmd := &cobra.Command{
		Use:   "allow-scripts <package>",
		Short: "Allow install scripts for one package",
		Long: "Record that one package may run its install scripts, and build it now.\n\n" +
			"npm has no per-package allowlist of its own, so an allowance is the guard\n" +
			"staying on everywhere and this one package being built by hand with\n" +
			"`npm rebuild <package> --ignore-scripts=false`.\n\n" +
			"With no allowlist entry a package stays unbuilt rather than half-built, which\n" +
			"is the failure you can see.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(configPath)
			if err != nil {
				return err
			}
			st, err := agent.Open(cfg)
			if err != nil {
				return err
			}
			defer st.Close()

			out := cmd.OutOrStdout()
			name := args[0]
			now := time.Now()

			// Stored as a versionless purl, which is the identity the allowlist
			// has carried since the first migration — allowing a package and
			// then upgrading it must not silently re-block its build.
			pkg := match.PURLBase(scriptguard.Ecosystem, name)

			if revoke {
				if err := st.Repo.RevokeScripts(pkg, now); err != nil {
					return err
				}
				fmt.Fprintf(out, "%s may no longer run install scripts\n", name)
				fmt.Fprintf(out, "\nAnything it built while it was allowed is still on disk. This records the\n"+
					"decision; it does not undo what already ran.\n")
				return nil
			}

			if err := st.Repo.AllowScripts(pkg, repo.ApprovedViaCLI, note, now); err != nil {
				return err
			}
			fmt.Fprintf(out, "%s may run install scripts\n", name)

			// Recorded either way — allowing ahead of turning the guard on is a
			// legitimate order to do this in — but an allowance while every
			// package can already run scripts grants nothing, and letting that
			// read as protection is the failure mode this project keeps
			// chasing. Said once, not enforced.
			if state, err := scriptguard.Status(); err == nil && !state.Enabled {
				fmt.Fprintf(out, "\nNote: the script guard is OFF, so every package already runs its\n"+
					"install scripts and this allowance grants nothing on its own. Turn it on with\n"+
					"`pkgwatch enable-script-guard`; the allowance is on file and will apply then.\n")
			}

			// npm rebuild exits 0 whether or not it matched anything, so a
			// typo reads exactly like a successful build. The allowance still
			// stands — allowing ahead of an install is legitimate — but the
			// difference is worth naming rather than leaving to be discovered
			// the next time the package silently does not work.
			installed, err := st.Repo.PackagesWithScripts(scriptguard.Ecosystem)
			if err != nil {
				return err
			}
			known := false
			for _, have := range installed {
				if have == name {
					known = true
					break
				}
			}
			if !known {
				fmt.Fprintf(out, "\nNote: no installed npm package called %q declares install scripts on\n"+
					"this machine. The allowance is recorded and will apply when one does —\n"+
					"but if you meant a package that is already here, check the spelling with\n"+
					"`pkgwatch inventory`.\n", name)
			}

			if dir == "" {
				dir, err = os.Getwd()
				if err != nil {
					return err
				}
			}
			output, err := scriptguard.Run(cmd.Context(), dir, name)
			if err != nil {
				// The allowance stands either way. It is a recorded decision, and
				// a rebuild that failed for its own reasons — wrong directory, not
				// installed here — must not quietly discard it.
				fmt.Fprintf(out, "\nrecorded, but the rebuild failed: %v\n", err)
				if output != "" {
					fmt.Fprintf(out, "%s\n", output)
				}
				fmt.Fprintf(out, "\nRun it yourself where the package is installed:\n"+
					"  npm rebuild %s --ignore-scripts=false\n", name)
				return nil
			}
			fmt.Fprintf(out, "  built in %s\n", dir)
			return nil
		},
	}

	cmd.Flags().StringVar(&note, "note", "", "why this package needs scripts")
	cmd.Flags().BoolVar(&revoke, "revoke", false, "withdraw an allowance")
	cmd.Flags().StringVar(&dir, "dir", "", "project directory to rebuild in (default: current)")
	cmd.AddCommand(scriptListCmd())
	return cmd
}

func scriptListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "Show the script guard and everything allowed",
		Args:  cobra.NoArgs,
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

			out := cmd.OutOrStdout()
			state, err := scriptguard.Status()
			switch {
			case err == scriptguard.ErrNoNPM:
				fmt.Fprintf(out, "npm is not on PATH, so the guard cannot be read from here\n")
			case err != nil:
				return err
			case state.Enabled && state.SetByUserConfig:
				fmt.Fprintf(out, "script guard ON — ignore-scripts=true in %s\n", state.UserConfig)
			case state.Enabled:
				// On, but not by us. Worth distinguishing: this can go away with
				// a directory change and take the protection with it.
				fmt.Fprintf(out, "script guard ON, but not from your user config — something else sets\n"+
					"ignore-scripts (a project .npmrc, an env var, an organisation config).\n"+
					"It will stop applying wherever that stops applying.\n")
			default:
				fmt.Fprintf(out, "script guard OFF — install scripts run on every install\n"+
					"  turn on   pkgwatch enable-script-guard\n")
			}

			allowed, err := st.Repo.ScriptAllowlist()
			if err != nil {
				return err
			}
			if len(allowed) == 0 {
				fmt.Fprintf(out, "\nNothing is allowed to run install scripts.\n")
				return nil
			}

			fmt.Fprintf(out, "\n%-28s %-8s %s\n", "PACKAGE", "STATE", "WHEN")
			for _, a := range allowed {
				state, when := "allowed", a.AllowedAt
				if !a.Active() {
					state, when = "revoked", a.RevokedAt
				}
				// The stored purl reads as noise in a list of one ecosystem, so
				// show the name — but fall back to the purl rather than an empty
				// cell if it will not parse, since the row is the record.
				label := a.Package
				if parsed, err := match.ParsePURLBase(a.Package); err == nil && parsed.Name != "" {
					label = parsed.Name
				}
				fmt.Fprintf(out, "%-28s %-8s %s", label, state, when.Format("2006-01-02 15:04"))
				if a.Note != "" {
					fmt.Fprintf(out, "  %s", a.Note)
				}
				fmt.Fprintln(out)
			}
			return nil
		},
	}
}
