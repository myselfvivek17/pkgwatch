package cli

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/myselfvivek17/pkgwatch/internal/config"
	"github.com/myselfvivek17/pkgwatch/internal/gate"
	"github.com/myselfvivek17/pkgwatch/internal/match"
	"github.com/myselfvivek17/pkgwatch/internal/repo"
)

// wrapped describes one package manager the gate fronts.
type wrapped struct {
	name      string // the command run
	ecosystem string
	// env returns the variables that point the tool at our proxy. Configuring
	// via environment rather than editing .npmrc / pip.conf means nothing is
	// left behind if the wrapper dies: the gate applies to this one invocation
	// and no other.
	env func(p *gate.Proxies) []string
}

var npmWrapper = wrapped{
	name:      "npm",
	ecosystem: match.EcosystemNPM,
	env: func(p *gate.Proxies) []string {
		return []string{"npm_config_registry=" + p.NPMURL + "/"}
	},
}

var pipWrapper = wrapped{
	name:      "pip",
	ecosystem: match.EcosystemPyPI,
	env: func(p *gate.Proxies) []string {
		return []string{
			"PIP_INDEX_URL=" + p.PyPIURL + "/simple/",
			// pip refuses a plain-http index unless the host is trusted. This is
			// loopback and the proxy is this process; the transport to the real
			// index is still TLS.
			"PIP_TRUSTED_HOST=127.0.0.1",
		}
	},
}

func npmCmd() *cobra.Command { return wrapperCmd(npmWrapper) }
func pipCmd() *cobra.Command { return wrapperCmd(pipWrapper) }

// gateEnvMarker tells a shadowing shell function that it is already running
// inside a gated invocation.
//
// Without it the integration recurses: the function shadows npm, the wrapper
// runs npm, the shell resolves the function again. The wrapper's own exec does
// not go through a shell so it is not affected directly, but an install script
// that shells out to npm would be — and that is the case worth gating, not the
// case worth hanging.
const gateEnvMarker = "PKGWATCH_GATE"

// shellSnippets shadow npm and pip with the gated wrappers.
//
// Shell functions rather than aliases: aliases are not expanded in
// non-interactive shells, and `npm` inside a Makefile or a package.json script
// is exactly the invocation worth gating.
var shellSnippets = map[string]string{
	"bash": `npm()  { if [ -n "$PKGWATCH_GATE" ]; then command npm  "$@"; else pkgwatch npm "$@"; fi; }
pip()  { if [ -n "$PKGWATCH_GATE" ]; then command pip  "$@"; else pkgwatch pip "$@"; fi; }
pip3() { if [ -n "$PKGWATCH_GATE" ]; then command pip3 "$@"; else pkgwatch pip "$@"; fi; }`,

	"zsh": `npm()  { if [ -n "$PKGWATCH_GATE" ]; then command npm  "$@"; else pkgwatch npm "$@"; fi; }
pip()  { if [ -n "$PKGWATCH_GATE" ]; then command pip  "$@"; else pkgwatch pip "$@"; fi; }
pip3() { if [ -n "$PKGWATCH_GATE" ]; then command pip3 "$@"; else pkgwatch pip "$@"; fi; }`,

	"fish": `function npm;  if set -q PKGWATCH_GATE; command npm  $argv; else; pkgwatch npm $argv; end; end
function pip;  if set -q PKGWATCH_GATE; command pip  $argv; else; pkgwatch pip $argv; end; end
function pip3; if set -q PKGWATCH_GATE; command pip3 $argv; else; pkgwatch pip $argv; end; end`,

	"powershell": `function npm  { if ($env:PKGWATCH_GATE) { & (Get-Command npm  -CommandType Application | Select-Object -First 1).Source @args } else { pkgwatch npm @args } }
function pip  { if ($env:PKGWATCH_GATE) { & (Get-Command pip  -CommandType Application | Select-Object -First 1).Source @args } else { pkgwatch pip @args } }
function pip3 { if ($env:PKGWATCH_GATE) { & (Get-Command pip3 -CommandType Application | Select-Object -First 1).Source @args } else { pkgwatch pip @args } }`,
}

func shellInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "shell-init [bash|zsh|fish|powershell]",
		Short: "Print shell integration",
		Long: "Print shell functions that route npm and pip through the gate.\n\n" +
			"Add to your shell profile:\n\n" +
			"  bash/zsh    eval \"$(pkgwatch shell-init bash)\"\n" +
			"  fish        pkgwatch shell-init fish | source\n" +
			"  powershell  pkgwatch shell-init powershell | Out-String | Invoke-Expression",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			snippet, ok := shellSnippets[strings.ToLower(args[0])]
			if !ok {
				return fmt.Errorf("no integration for shell %q — supported: bash, zsh, fish, powershell", args[0])
			}
			fmt.Fprintln(cmd.OutOrStdout(), snippet)
			return nil
		},
	}
}

func wrapperCmd(tool wrapped) *cobra.Command {
	return &cobra.Command{
		Use:   tool.name + " [args...]",
		Short: "Run " + tool.name + " with installs gated",
		Long: "Run " + tool.name + " with every package version checked against the advisory\n" +
			"bundle before it can be downloaded.\n\n" +
			"Arguments are passed through untouched. The gate runs on a loopback port for\n" +
			"the lifetime of this command only — nothing is written to your " + tool.name + " config,\n" +
			"and the agent daemon does not need to be running.",
		Args:               cobra.ArbitraryArgs,
		DisableFlagParsing: true, // every flag belongs to the wrapped tool
		RunE: func(cmd *cobra.Command, args []string) error {
			return runWrapped(cmd, tool, args)
		},
	}
}

func runWrapped(cmd *cobra.Command, tool wrapped, args []string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}

	// The wrapper prints its own summary, and the package manager's output is
	// what the user is actually reading. Per-package gate logging interleaved
	// with npm's progress just buries it — a 68-package install filters nine of
	// them. Warnings and errors still come through.
	slog.SetDefault(slog.New(slog.NewTextHandler(cmd.ErrOrStderr(),
		&slog.HandlerOptions{Level: slog.LevelWarn})))

	g, err := gate.Open(cfg)
	if err != nil {
		return err
	}
	defer g.DB.Close()

	sessionID, err := newSessionID()
	if err != nil {
		return err
	}
	cwd, _ := os.Getwd()
	started := time.Now()
	if err := g.Repo.StartSession(sessionID, tool.ecosystem, cwd,
		strings.Join(append([]string{tool.name}, args...), " "), runContext(), started); err != nil {
		return fmt.Errorf("record install session: %w", err)
	}

	proxies, err := gate.StartEphemeral(g, sessionID, cfg.Agent.NPMUpstream, cfg.Agent.PyPIUpstream)
	if err != nil {
		return err
	}
	defer proxies.Close()

	if !g.BundleAttached {
		fmt.Fprintln(cmd.ErrOrStderr(),
			"pkgwatch: no advisory bundle installed — nothing is being checked. Run `pkgwatch sync`.")
	}

	exitCode, runErr := runTool(cmd, tool, proxies, args)

	blocked, err := g.Repo.SessionDecisions(sessionID)
	if err != nil {
		return fmt.Errorf("read gate decisions: %w", err)
	}
	withheld, err := g.Repo.SessionWithheld(sessionID)
	if err != nil {
		return fmt.Errorf("read gate decisions: %w", err)
	}

	// Withholding versions is routine and usually invisible: the resolver picks
	// a clean one and the install succeeds. It is only worth raising when the
	// resolver could not find anything left to pick.
	resolutionFailed := exitCode != 0 && len(withheld) > 0
	if len(blocked) == 0 && !resolutionFailed {
		outcome := repo.OutcomeClean
		if exitCode != 0 {
			// The tool failed for reasons of its own. Not our business, but the
			// session should not claim a clean install that never happened.
			outcome = repo.OutcomeAborted
		}
		g.Repo.EndSession(sessionID, outcome, time.Now())
		reportWithheld(cmd.OutOrStdout(), withheld, false)
		return passthroughExit(cmd, exitCode, runErr)
	}

	printBlockReport(cmd.OutOrStdout(), tool, blocked)
	reportWithheld(cmd.OutOrStdout(), withheld, resolutionFailed)

	if !interactive() {
		g.Repo.EndSession(sessionID, repo.OutcomeBlocked, time.Now())
		fmt.Fprintln(cmd.ErrOrStderr(),
			"\nNot a terminal — refusing to prompt. Override with `pkgwatch "+tool.name+"` from a shell.")
		return passthroughExit(cmd, exitCode, runErr)
	}

	approved, err := promptOverride(cmd, blocked, withheld)
	if err != nil {
		return err
	}
	if len(approved) == 0 {
		g.Repo.EndSession(sessionID, repo.OutcomeAborted, time.Now())
		fmt.Fprintln(cmd.OutOrStdout(), "aborted — nothing was installed")
		return passthroughExit(cmd, exitCode, runErr)
	}

	for _, purl := range approved {
		if err := g.Repo.ApproveInSession(sessionID, purl, time.Now()); err != nil {
			return fmt.Errorf("record override: %w", err)
		}
	}
	fmt.Fprintf(cmd.OutOrStdout(), "\noverride recorded for %d package(s) — re-running %s\n\n",
		len(approved), tool.name)

	exitCode, runErr = runTool(cmd, tool, proxies, args)
	g.Repo.EndSession(sessionID, repo.OutcomeApproved, time.Now())
	return passthroughExit(cmd, exitCode, runErr)
}

// runTool executes the wrapped package manager with the gate in front of it.
func runTool(cmd *cobra.Command, tool wrapped, proxies *gate.Proxies, args []string) (int, error) {
	child := exec.Command(tool.name, args...)
	child.Env = append(os.Environ(), append(tool.env(proxies), gateEnvMarker+"=1")...)
	child.Stdin = cmd.InOrStdin()
	child.Stdout = cmd.OutOrStdout()
	child.Stderr = cmd.ErrOrStderr()

	err := child.Run()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode(), nil
	}
	if err != nil {
		return 1, fmt.Errorf("running %s: %w", tool.name, err)
	}
	return 0, nil
}

// passthroughExit reproduces the wrapped tool's exit code, so scripts calling
// `pkgwatch npm ci` see what they would have seen calling npm directly.
func passthroughExit(cmd *cobra.Command, code int, err error) error {
	if err != nil {
		return err
	}
	if code == 0 {
		return nil
	}
	// The wrapped tool has already printed why it failed; cobra adding
	// "Error: exit status 1" on top only obscures it.
	cmd.SilenceErrors = true
	return exitCodeError(code)
}

// exitCodeError carries an exit status out to main without printing anything
// extra — the wrapped tool has already said its piece.
type exitCodeError int

func (e exitCodeError) Error() string { return fmt.Sprintf("exit status %d", int(e)) }

// ExitCode reports the status a wrapped tool exited with, or -1.
func ExitCode(err error) int {
	var code exitCodeError
	if errors.As(err, &code) {
		return int(code)
	}
	return -1
}

// printBlockReport lists the downloads that were actually refused — the ones
// that stopped something.
func printBlockReport(w io.Writer, tool wrapped, decisions []repo.Decision) {
	if len(decisions) == 0 {
		return
	}
	fmt.Fprintf(w, "\npkgwatch blocked %d download(s) during this %s run:\n\n",
		len(decisions), tool.name)

	table := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(table, "  PACKAGE\tREASON\tADVISORY")
	for _, d := range decisions {
		fmt.Fprintf(table, "  %s\t%s\t%s\n", d.PURL, d.Reason, d.AdvisoryID)
	}
	table.Flush()
}

// reportWithheld summarises versions filtered out of resolution, one line per
// package.
//
// When the install succeeded this is a footnote — the resolver found something
// clean and nothing needs doing. When it failed it is the explanation for an
// npm error that otherwise says only "no matching version found".
func reportWithheld(w io.Writer, withheld []repo.Withheld, explainFailure bool) {
	if len(withheld) == 0 {
		return
	}

	total := 0
	for _, item := range withheld {
		total += item.Count
	}

	if !explainFailure {
		fmt.Fprintf(w, "\npkgwatch withheld %d affected version(s) across %d package(s); "+
			"resolution found clean ones.\n", total, len(withheld))
		return
	}

	fmt.Fprintf(w, "\npkgwatch withheld %d affected version(s) from resolution:\n\n", total)
	table := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(table, "  PACKAGE\tWITHHELD\tADVISORIES")
	for _, item := range withheld {
		fmt.Fprintf(table, "  %s\t%d\t%s\n", item.PURLBase, item.Count,
			strings.Join(item.Advisories, ", "))
	}
	table.Flush()
	fmt.Fprintln(w, "\n  If the version you asked for could not be found, this is why.")
}

// promptOverride asks what to do and returns the purls the user approved.
//
// This is why the proxy does not prompt. By the time we get here the package
// manager has exited, stdin is ours again, and there is a terminal to talk to —
// none of which is true inside an HTTP handler serving npm.
func promptOverride(cmd *cobra.Command, decisions []repo.Decision, withheld []repo.Withheld) ([]string, error) {
	reader := bufio.NewReader(cmd.InOrStdin())

	for {
		fmt.Fprint(cmd.OutOrStdout(), "\n[a]bort, [v]iew details, or [o]verride and install anyway? [a] ")
		line, err := reader.ReadString('\n')
		if err != nil && line == "" {
			return nil, nil // EOF: treat as abort, the safe default
		}

		switch strings.ToLower(strings.TrimSpace(line)) {
		case "", "a", "abort":
			return nil, nil

		case "v", "view":
			for _, d := range decisions {
				fmt.Fprintf(cmd.OutOrStdout(), "\n  %s\n    reason:   %s\n    advisory: %s\n",
					d.PURL, d.Reason, orNone(d.AdvisoryID))
			}
			for _, item := range withheld {
				fmt.Fprintf(cmd.OutOrStdout(), "\n  %s\n    %d version(s) withheld\n    advisories: %s\n",
					item.PURLBase, item.Count, strings.Join(item.Advisories, ", "))
			}

		case "o", "override":
			// Nothing is offered as a bulk yes. Every override is named
			// individually so nobody approves a compromised package by reflex.
			var approved []string
			for _, d := range decisions {
				fmt.Fprintf(cmd.OutOrStdout(), "  install %s anyway? [y/N] ", d.PURL)
				answer, _ := reader.ReadString('\n')
				if strings.HasPrefix(strings.ToLower(strings.TrimSpace(answer)), "y") {
					approved = append(approved, d.PURL)
				}
			}
			// Withheld versions are approved per package, not per version: the
			// real decision is "I accept this package's advisories for this
			// install", and there is no way to know which of a hundred filtered
			// versions the resolver would have picked.
			for _, item := range withheld {
				fmt.Fprintf(cmd.OutOrStdout(),
					"  allow all %d withheld version(s) of %s for this run? [y/N] ",
					item.Count, item.PURLBase)
				answer, _ := reader.ReadString('\n')
				if strings.HasPrefix(strings.ToLower(strings.TrimSpace(answer)), "y") {
					approved = append(approved, item.PURLBase)
				}
			}
			return approved, nil

		default:
			fmt.Fprintln(cmd.ErrOrStderr(), "  didn't catch that")
		}
	}
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

func newSessionID() (string, error) {
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate session id: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

// runContext labels how this install was started, so the timeline can tell a
// person typing a command apart from a build agent.
func runContext() string {
	if os.Getenv("CI") != "" || os.Getenv("GITHUB_ACTIONS") != "" {
		return "ci"
	}
	if os.Getenv("TERM_PROGRAM") == "vscode" || os.Getenv("VSCODE_PID") != "" {
		return "ide"
	}
	if interactive() {
		return "interactive"
	}
	return "unknown"
}

// interactive reports whether stdin is a terminal. Without a terminal there is
// nobody to prompt, and blocking to read stdin would hang a build.
func interactive() bool {
	info, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
