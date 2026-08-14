package cli

import (
	"bufio"
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/myselfvivek17/pkgwatch/internal/agent"
	"github.com/myselfvivek17/pkgwatch/internal/config"
	"github.com/myselfvivek17/pkgwatch/internal/quarantine"
	"github.com/myselfvivek17/pkgwatch/internal/repo"
)

func quarantineCmd() *cobra.Command {
	var advisoryID string
	var yes bool

	cmd := &cobra.Command{
		Use:   "quarantine [purl]",
		Short: "Move an installed package out of the way, reversibly",
		Long: "Archive an installed package, verify the archive, then delete the original.\n\n" +
			"With no argument, lists what this machine has quarantined.\n\n" +
			"The digest recorded is of the tree rather than of the archive file, so a\n" +
			"restore can be checked against it. `pkgwatch restore <id>` puts the package\n" +
			"back and refuses to call it restored unless every file, link and executable\n" +
			"bit comes back identical.\n\n" +
			"System and container packages are refused. A system package's recorded path\n" +
			"is the package manager's own database, shared by everything on the machine;\n" +
			"a container package does not live on this filesystem at all.",
		Args: cobra.MaximumNArgs(1),
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

			if len(args) == 0 {
				items, err := st.Repo.QuarantineItems(50)
				if err != nil {
					return err
				}
				printQuarantine(cmd.OutOrStdout(), items)
				return nil
			}
			return runQuarantine(cmd, cfg, st, args[0], advisoryID, yes)
		},
	}

	cmd.Flags().StringVar(&advisoryID, "advisory", "", "record which advisory prompted this")
	cmd.Flags().BoolVar(&yes, "yes", false, "do not ask for confirmation")
	return cmd
}

// runQuarantine archives a package and then removes it.
//
// The order is the whole safety property: pack, verify what was packed by
// reading it back, and only then delete. A delete-first implementation that
// failed to write the archive would have destroyed the thing it was protecting.
func runQuarantine(cmd *cobra.Command, cfg config.Config, st *agent.State, purl, advisoryID string, yes bool) error {
	pkg, err := st.Repo.PackageByPURL(purl)
	if err != nil {
		return err
	}
	if !quarantine.CanQuarantine(pkg.Scope) {
		return quarantine.ErrScope{Scope: pkg.Scope, PURL: pkg.PURL, Path: pkg.InstallDir}
	}
	if existing, err := st.Repo.ActiveQuarantineFor(purl); err == nil {
		return fmt.Errorf("%s is already quarantined as %s — restore it first if you want to redo this",
			purl, existing.ID)
	} else if err != repo.ErrNoSuchQuarantine {
		return err
	}

	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "%s\n  scope   %s\n  path    %s\n", pkg.PURL, pkg.Scope, pkg.InstallDir)
	if !yes {
		// This deletes a directory. The confirmation names the path, because the
		// purl is not what is about to be removed from the disk.
		ok, err := confirm(cmd, fmt.Sprintf("Archive and delete %s?", pkg.InstallDir))
		if err != nil || !ok {
			fmt.Fprintln(out, "nothing was moved.")
			return err
		}
	}

	id, err := quarantineID()
	if err != nil {
		return err
	}

	archive, err := quarantine.Pack(pkg.InstallDir, cfg.QuarantineDir(), id)
	if err != nil {
		return err
	}

	// Read the archive back before anything is deleted. A tar that cannot be
	// unpacked is discovered here, while the original is still on disk, rather
	// than at the moment someone needs it back.
	verifyDir, err := os.MkdirTemp(cfg.QuarantineDir(), ".verify-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(verifyDir)

	check, err := quarantine.Unpack(archive.Path, verifyDir)
	if err != nil {
		os.Remove(archive.Path)
		return fmt.Errorf("REFUSING to delete anything: the archive cannot be read back: %w", err)
	}
	if check != archive.Digest {
		os.Remove(archive.Path)
		return fmt.Errorf("REFUSING to delete anything: the archive does not reproduce the tree "+
			"(packed %s, read back %s)", archive.Digest, check)
	}

	now := time.Now()
	item := repo.QuarantineItem{
		ID: id, PURL: pkg.PURL, OriginPath: pkg.InstallDir,
		ArchivePath: archive.Path, SHA256: archive.Digest, AdvisoryID: advisoryID,
	}
	// Recorded before the delete. A crash between the two leaves a row whose
	// package is still installed, which is recoverable; the other order leaves a
	// deleted package nothing knows about.
	if err := st.Repo.RecordQuarantine(item, now); err != nil {
		return err
	}
	if err := os.RemoveAll(pkg.InstallDir); err != nil {
		return fmt.Errorf("archived to %s but could not remove %s: %w", archive.Path, pkg.InstallDir, err)
	}

	// Findings stay open on purpose: the package is off the machine and one
	// command away from coming back, so a count that dropped here would make
	// this machine look clean while the malware sits in the quarantine folder.
	changed, err := st.Repo.MarkFindingsQuarantined(pkg.PURL, now)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "note: could not update findings: %v\n", err)
	}
	if err := st.Repo.RecordEvent(repo.EventQuarantine, "critical", pkg.PURL, advisoryID,
		map[string]any{"id": id, "path": pkg.InstallDir, "files": archive.Files}, now); err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "note: could not record the event: %v\n", err)
	}

	fmt.Fprintf(out, "\nquarantined %s\n  id      %s\n  archive %s (%d files, %s)\n  digest  %s\n",
		pkg.PURL, id, archive.Path, archive.Files, humanBytes(archive.Bytes), archive.Digest)
	fmt.Fprintf(out, "\n%d finding(s) marked quarantined. They still count as open: the package is "+
		"one `pkgwatch restore %s` away from being back.\n", changed, id)
	return nil
}

func restoreCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "restore <quarantine-id>",
		Short: "Put a quarantined package back where it was",
		Long: "Unpack a quarantined package to its original path.\n\n" +
			"The restored tree is hashed and compared with what was taken. A mismatch is\n" +
			"reported as a failure and recorded as one — the files are back, but they are\n" +
			"not the files that were removed, and nobody could tell afterwards.",
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

			return runRestore(cmd, st, args[0])
		},
	}
	return cmd
}

func runRestore(cmd *cobra.Command, st *agent.State, id string) error {
	item, err := quarantine.Restore(st.Repo, id, time.Now())
	if err != nil {
		return err
	}

	fmt.Fprintf(cmd.OutOrStdout(),
		"restored %s to %s\n  digest %s (identical to what was taken)\n\n"+
			"The package is installed again and its findings apply again. Run `pkgwatch scan` to "+
			"bring the inventory back in step.\n",
		item.PURL, item.OriginPath, item.SHA256)
	return nil
}

func printQuarantine(out io.Writer, items []repo.QuarantineItem) {
	if len(items) == 0 {
		fmt.Fprintln(out, "nothing quarantined on this machine.")
		return
	}

	table := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(table, "ID\tSTATE\tWHEN\tPACKAGE\tORIGIN")
	for _, item := range items {
		fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%s\n", item.ID, item.State,
			item.At.Format("2006-01-02 15:04"), item.PURL, item.OriginPath)
	}
	table.Flush()

	// Naming the states that are not "put back cleanly", because those are the
	// rows where something is expected of a person.
	var failed, missing int
	for _, item := range items {
		switch item.State {
		case repo.QuarantineFailed:
			failed++
		case repo.QuarantineMissing:
			missing++
		}
	}
	if failed > 0 {
		fmt.Fprintf(out, "\n%d restore(s) did not reproduce what was taken — the files on disk are "+
			"not the files that were removed.\n", failed)
	}
	if missing > 0 {
		fmt.Fprintf(out, "\n%d archive(s) are gone from disk. Those packages cannot be restored.\n", missing)
	}
}

// confirm asks a yes/no question, defaulting to no.
//
// EOF is a no. A pipe with nothing on the other end must not be able to delete
// a directory by silence.
func confirm(cmd *cobra.Command, question string) (bool, error) {
	fmt.Fprintf(cmd.OutOrStdout(), "\n%s [y/N] ", question)
	line, err := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
	if err != nil && line == "" {
		return false, nil
	}
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "y"), nil
}

// quarantineID is short, sortable-ish and unambiguous to type back.
func quarantineID() (string, error) {
	raw := make([]byte, 5)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)), nil
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}
