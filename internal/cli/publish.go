package cli

import (
	"archive/zip"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/myselfvivek17/pkgwatch/internal/bundle"
	"github.com/myselfvivek17/pkgwatch/internal/bundlesync"
	"github.com/myselfvivek17/pkgwatch/internal/match"
	"github.com/myselfvivek17/pkgwatch/internal/osv"
)

// publishCmd holds the publisher-side tooling. It is hidden because it is not
// part of an agent's job: compiling and signing bundles happens on the
// maintainer's machine, not on the fleet.
func publishCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:    "publish",
		Short:  "Publisher-side bundle tooling",
		Hidden: true,
	}
	cmd.AddCommand(keygenCmd(), buildBundleCmd(), signCmd())
	return cmd
}

// signCmd re-creates the manifest for a bundle that already exists.
//
// It is here for the machines that staged bundles before the manifest was kept
// beside them. Those installations hold verified bytes and no signature, which
// means they cannot relay: a hub can hand over the file but nothing downstream
// could check it, and "trust it, the hub sent it" is the one thing that is not
// allowed to be an answer.
//
// Signing is deterministic, so re-signing the same bytes with the same key
// reproduces the signature they arrived with. Nothing new is trusted here — the
// key is the publisher's, exactly as it was when the bundle was built.
func signCmd() *cobra.Command {
	var bundlePath, keyPath, version string

	cmd := &cobra.Command{
		Use:   "sign",
		Short: "Write the manifest for an existing bundle",
		Long: "Write the manifest and signature for a bundle that already exists.\n\n" +
			"The version and scope are read out of the bundle itself, so what gets signed\n" +
			"is what the file says it is.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if bundlePath == "" || keyPath == "" {
				return fmt.Errorf("--file and --key are both required")
			}

			info, err := bundlesync.ReadBundleMeta(bundlePath, false)
			if err != nil {
				return err
			}
			if info.Scope == "" {
				return fmt.Errorf("%s declares no scope — it cannot be signed as anything", bundlePath)
			}
			if version == "" {
				version = info.Version
			}

			data, err := os.ReadFile(bundlePath)
			if err != nil {
				return err
			}
			manifest := bundle.Manifest{
				Version: version, Scope: info.Scope,
				SHA256: bundle.Digest(data), Size: int64(len(data)),
				BuiltAt: info.BuiltAt, RecordCount: info.RecordCount,
			}
			if err := signBundle(bundlePath, keyPath, &manifest); err != nil {
				return err
			}

			sig, err := hex.DecodeString(manifest.Signature)
			if err != nil {
				return err
			}
			// Written through the same helper staging uses, so a hand-signed
			// bundle and a freshly installed one are the same thing on disk.
			if err := bundle.SaveManifest(bundlePath, manifest, sig); err != nil {
				return err
			}

			fmt.Fprintf(cmd.OutOrStdout(), "signed %s %s (%d records) -> %s\n",
				manifest.Scope, manifest.Version, manifest.RecordCount, bundle.ManifestPath(bundlePath))
			return nil
		},
	}

	cmd.Flags().StringVar(&bundlePath, "file", "", "bundle to sign (required)")
	cmd.Flags().StringVar(&keyPath, "key", "", "base64 ed25519 private key to sign with (required)")
	cmd.Flags().StringVar(&version, "version", "", "override the version recorded in the bundle")
	return cmd
}

func keygenCmd() *cobra.Command {
	var out string

	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate a publisher signing key",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if out == "" {
				return fmt.Errorf("--out is required: say where the private key should be written")
			}
			if _, err := os.Stat(out); err == nil {
				return fmt.Errorf("%s already exists — refusing to overwrite a signing key", out)
			}

			pub, priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Dir(out), 0o700); err != nil {
				return err
			}
			if err := os.WriteFile(out, []byte(base64.StdEncoding.EncodeToString(priv)+"\n"), 0o600); err != nil {
				return err
			}

			fmt.Fprintf(cmd.OutOrStdout(),
				"private key written to %s (0600)\n\n"+
					"Add the public half to publisherKeysBase64 in internal/bundle/keys.go,\n"+
					"release a build carrying it, and only then start signing with it —\n"+
					"agents must be able to verify the new key before it is used.\n\n"+
					"  %q,\n", out, base64.StdEncoding.EncodeToString(pub))
			return nil
		},
	}

	cmd.Flags().StringVar(&out, "out", "", "path to write the private key to (required)")
	return cmd
}

func buildBundleCmd() *cobra.Command {
	var input, out, keyPath, version string
	var split bool

	cmd := &cobra.Command{
		Use:   "build-bundle",
		Short: "Compile OSV records into a signed advisory bundle",
		Long: "Compile OSV records into a signed advisory bundle.\n\n" +
			"--input accepts a directory of OSV JSON files or an OSV all.zip.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if input == "" || out == "" {
				return fmt.Errorf("--input and --out are both required")
			}
			if version == "" {
				version = time.Now().UTC().Format("20060102")
			}

			advisories, skipped, err := readOSVRecords(input)
			if err != nil {
				return err
			}
			if len(advisories) == 0 {
				return fmt.Errorf("no usable advisories found in %s", input)
			}
			// Say what was dropped. A bundle that silently covers less than you
			// think reads as "all clear" when it is not.
			fmt.Fprintf(cmd.OutOrStdout(),
				"parsed %d advisories (%d records skipped: unsupported ecosystem or unreadable)\n",
				len(advisories), skipped)

			if split {
				return buildSplit(cmd, out, version, keyPath, advisories)
			}
			return buildOne(cmd, out, version, bundle.ScopeAll, keyPath, advisories)
		},
	}

	cmd.Flags().StringVar(&input, "input", "", "directory of OSV JSON files, or an OSV all.zip (required)")
	cmd.Flags().StringVar(&out, "out", "", "path to write advisories.db to (required)")
	cmd.Flags().StringVar(&keyPath, "key", "", "base64 ed25519 private key to sign with")
	cmd.Flags().StringVar(&version, "version", "", "bundle version (default: today, YYYYMMDD)")
	cmd.Flags().BoolVar(&split, "split", false,
		"emit one signed bundle per ecosystem and release into --out as a directory")
	return cmd
}

// buildOne writes and signs a single bundle covering scope.
func buildOne(cmd *cobra.Command, out, version, scope, keyPath string, advisories []match.Advisory) error {
	manifest, err := bundle.Build(out, version, scope, advisories, time.Now())
	if err != nil {
		return err
	}

	if keyPath != "" {
		if err := signBundle(out, keyPath, &manifest); err != nil {
			return err
		}
	} else {
		fmt.Fprintln(cmd.OutOrStdout(),
			"warning: no --key given, bundle is unsigned and every agent will reject it")
	}

	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(out+".json", append(encoded, '\n'), 0o644); err != nil {
		return err
	}

	fmt.Fprintf(cmd.OutOrStdout(), "%-24s %7.1f MB  %8d records  %s\n",
		manifest.Scope, float64(manifest.Size)/(1024*1024), manifest.RecordCount, out)
	return nil
}

// buildSplit emits one bundle per ecosystem *and release*.
//
// Release, not just ecosystem, because that is where the saving is: Debian
// ships thirteen releases in the corpus at roughly a quarter of its records
// apiece and a machine can only ever match one of them. It is also the only way
// Ubuntu fits at all — its feed alone is larger than every other ecosystem
// combined, and a fleet-wide bundle simply cannot carry it.
func buildSplit(cmd *cobra.Command, outDir, version, keyPath string, advisories []match.Advisory) error {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}

	byScope := map[string][]match.Advisory{}
	for _, adv := range advisories {
		byScope[adv.Ecosystem] = append(byScope[adv.Ecosystem], adv)
	}

	scopes := make([]string, 0, len(byScope))
	for scope := range byScope {
		scopes = append(scopes, scope)
	}
	sort.Strings(scopes)

	fmt.Fprintf(cmd.OutOrStdout(), "building %d bundles\n\n", len(scopes))
	fmt.Fprintf(cmd.OutOrStdout(), "%-24s %10s  %16s  %s\n", "SCOPE", "SIZE", "RECORDS", "FILE")

	var totalBytes int64
	for _, scope := range scopes {
		out := filepath.Join(outDir, "advisories-"+bundle.ScopeFileName(scope)+".db")
		if err := buildOne(cmd, out, version, scope, keyPath, byScope[scope]); err != nil {
			return fmt.Errorf("scope %s: %w", scope, err)
		}
		if info, err := os.Stat(out); err == nil {
			totalBytes += info.Size()
		}
	}

	fmt.Fprintf(cmd.OutOrStdout(),
		"\n%d bundles, %.1f MB total. An agent downloads only the scopes its inventory names.\n",
		len(scopes), float64(totalBytes)/(1024*1024))
	return nil
}

func signBundle(bundlePath, keyPath string, manifest *bundle.Manifest) error {
	encoded, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("read signing key: %w", err)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		return fmt.Errorf("signing key is not base64: %w", err)
	}
	if len(raw) != ed25519.PrivateKeySize {
		return fmt.Errorf("signing key is %d bytes, want %d", len(raw), ed25519.PrivateKeySize)
	}

	data, err := os.ReadFile(bundlePath)
	if err != nil {
		return err
	}

	sig := bundle.Sign(ed25519.PrivateKey(raw), manifest.Version, manifest.Scope, data)
	manifest.Signature = hex.EncodeToString(sig)

	return os.WriteFile(bundlePath+".sig", []byte(manifest.Signature+"\n"), 0o644)
}

// readOSVRecords reads every OSV JSON document under input, which may be a
// directory tree or a zip archive. Returns the advisories and how many records
// were skipped.
func readOSVRecords(input string) ([]match.Advisory, int, error) {
	info, err := os.Stat(input)
	if err != nil {
		return nil, 0, fmt.Errorf("read input: %w", err)
	}

	if info.IsDir() {
		return readOSVDir(input)
	}
	if strings.HasSuffix(strings.ToLower(input), ".zip") {
		return readOSVZip(input)
	}

	// A single record file.
	data, err := os.ReadFile(input)
	if err != nil {
		return nil, 0, err
	}
	advisories, err := osv.ParseRecord(data)
	if err != nil {
		return nil, 1, nil
	}
	return advisories, 0, nil
}

func readOSVDir(dir string) ([]match.Advisory, int, error) {
	var advisories []match.Advisory
	skipped := 0

	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		// OSV publishes one all.zip per ecosystem, so a directory of archives
		// is the shape the publisher actually works with.
		if strings.HasSuffix(strings.ToLower(d.Name()), ".zip") {
			fromZip, zipSkipped, zipErr := readOSVZip(path)
			if zipErr != nil {
				slog.Warn("skipping unreadable archive", "path", path, "error", zipErr)
				skipped++
				return nil
			}
			advisories = append(advisories, fromZip...)
			skipped += zipSkipped
			return nil
		}

		if !strings.HasSuffix(strings.ToLower(d.Name()), ".json") {
			return nil
		}

		data, readErr := os.ReadFile(path)
		if readErr != nil {
			slog.Warn("skipping unreadable OSV file", "path", path, "error", readErr)
			skipped++
			return nil
		}
		parsed, parseErr := osv.ParseRecord(data)
		if parseErr != nil {
			slog.Warn("skipping unparseable OSV record", "path", path, "error", parseErr)
			skipped++
			return nil
		}
		if len(parsed) == 0 {
			skipped++ // every affected package was in an ecosystem we cannot match
			return nil
		}
		advisories = append(advisories, parsed...)
		return nil
	})

	return advisories, skipped, err
}

func readOSVZip(path string) ([]match.Advisory, int, error) {
	archive, err := zip.OpenReader(path)
	if err != nil {
		return nil, 0, fmt.Errorf("open zip: %w", err)
	}
	defer archive.Close()

	var advisories []match.Advisory
	skipped := 0

	for _, file := range archive.File {
		if file.FileInfo().IsDir() || !strings.HasSuffix(strings.ToLower(file.Name), ".json") {
			continue
		}

		handle, err := file.Open()
		if err != nil {
			skipped++
			continue
		}
		data, err := io.ReadAll(handle)
		handle.Close()
		if err != nil {
			skipped++
			continue
		}

		parsed, err := osv.ParseRecord(data)
		if err != nil || len(parsed) == 0 {
			skipped++
			continue
		}
		advisories = append(advisories, parsed...)
	}

	return advisories, skipped, nil
}
