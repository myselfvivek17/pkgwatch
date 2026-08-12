package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/myselfvivek17/pkgwatch/internal/config"
	"github.com/myselfvivek17/pkgwatch/internal/secret"
)

// setPasswordCmd prints an argon2id hash to paste into the config.
//
// It prints rather than writes: pkgwatch.toml is hand-edited and carries
// comments, and rewriting a TOML file in place to change one line is how those
// comments get eaten.
//
// ponytail: no terminal echo suppression, which would cost a ninth dependency
// against a budget of eight (§1). Piping is the documented path and is what a
// person setting up a service does anyway.
func setPasswordCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "set-password",
		Short: "Hash a hub dashboard password for the config file",
		Long: "Reads the password from stdin and prints the config line to paste.\n\n" +
			"Pipe it so the password does not stay on screen or in shell history:\n" +
			"    printf '%s' 'your password' | pkgwatch hub set-password",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			plain, err := readPassword(cmd)
			if err != nil {
				return err
			}
			if len(plain) < 12 {
				// A hub on a LAN with a four-character password is not meaningfully
				// different from no password, and this command is the only place
				// anyone would ever be told so.
				return fmt.Errorf("password is %d characters — use at least 12; this guards a dashboard that approves installs and lists every package on every machine", len(plain))
			}

			hash, err := secret.Hash(plain)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "\nAdd this to %s:\n\n", config.DefaultPath())
			fmt.Fprintf(out, "[hub]\npassword_hash = %q\n\n", hash)
			fmt.Fprintf(out, "Then restart the hub. Existing sessions survive — the signing key\n"+
				"is separate from the password and is not changed by this.\n")
			return nil
		},
	}
}

func readPassword(cmd *cobra.Command) (string, error) {
	stat, err := os.Stdin.Stat()
	if err == nil && stat.Mode()&os.ModeCharDevice != 0 {
		// An interactive terminal: warn, because it will echo.
		fmt.Fprintln(cmd.ErrOrStderr(),
			"Reading from the terminal — what you type will be visible.\n"+
				"Ctrl-C and pipe it instead if that matters here.")
		fmt.Fprint(cmd.ErrOrStderr(), "password: ")
	}

	line, err := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
	if err != nil && line == "" {
		return "", fmt.Errorf("read password from stdin: %w", err)
	}
	// Trailing newline only. Leading and inner spaces are part of a password.
	return strings.TrimRight(line, "\r\n"), nil
}
