package cli

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/package-url/packageurl-go"
	"github.com/spf13/cobra"

	"github.com/myselfvivek17/pkgwatch/internal/bundle"
	"github.com/myselfvivek17/pkgwatch/internal/config"
	"github.com/myselfvivek17/pkgwatch/internal/db"
	"github.com/myselfvivek17/pkgwatch/internal/match"
	"github.com/myselfvivek17/pkgwatch/internal/repo"
)

func checkCmd() *cobra.Command {
	var scope string
	var hasScripts bool

	cmd := &cobra.Command{
		Use:   "check <purl>",
		Short: "Check one package against the advisory bundle",
		Long: "Check a package against the local advisory bundle.\n\n" +
			"Examples:\n" +
			"  pkgwatch check pkg:npm/lodash@4.17.20\n" +
			"  pkgwatch check pkg:npm/%40ctrl/tinycolor@4.1.2\n" +
			"  pkgwatch check pkg:pypi/django@3.2.0",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(configPath)
			if err != nil {
				return err
			}
			pkg, err := packageFromPURL(args[0])
			if err != nil {
				return err
			}
			pkg.Scope = scope
			pkg.HasScripts = hasScripts
			pkg.LastSeen = time.Now()

			return runCheck(cmd.OutOrStdout(), cfg, pkg)
		},
	}

	cmd.Flags().StringVar(&scope, "scope", match.ScopeProject,
		"how the package is installed: global|project|venv|system|container (affects scoring)")
	cmd.Flags().BoolVar(&hasScripts, "has-scripts", false,
		"treat the package as having install scripts (affects scoring)")
	return cmd
}

// packageFromPURL converts a package URL into the inventory's shape.
func packageFromPURL(raw string) (match.Package, error) {
	parsed, err := packageurl.FromString(raw)
	if err != nil {
		return match.Package{}, fmt.Errorf("not a valid purl: %w", err)
	}
	if parsed.Version == "" {
		return match.Package{}, fmt.Errorf("purl has no version: %s", raw)
	}

	ecosystem, err := ecosystemFromPURL(parsed)
	if err != nil {
		return match.Package{}, err
	}

	// npm scoped packages arrive split: namespace "@ctrl", name "tinycolor".
	// Distro purls put the distribution there instead (pkg:deb/debian/openssl),
	// which is not part of the package name.
	name := parsed.Name
	if parsed.Namespace != "" && (parsed.Type == "npm" || parsed.Type == "golang" || parsed.Type == "maven") {
		name = parsed.Namespace + "/" + parsed.Name
	}

	return match.Package{Ecosystem: ecosystem, Name: name, Version: parsed.Version}, nil
}

// purlTypeToEcosystem maps package-URL types onto OSV ecosystem names.
var purlTypeToEcosystem = map[string]string{
	"npm":    match.EcosystemNPM,
	"pypi":   match.EcosystemPyPI,
	"golang": match.EcosystemGo,
	"cargo":  match.EcosystemCrates,
	"apk":    match.EcosystemAlpine,
}

// ecosystemFromPURL resolves the OSV ecosystem, including the release qualifier
// that distribution advisories are filed against.
//
// A Debian 11 advisory and a Debian 12 advisory for the same package carry
// different fixed versions, so the release is not optional — checking without
// it would compare against another distribution's bounds.
func ecosystemFromPURL(parsed packageurl.PackageURL) (string, error) {
	qualifiers := parsed.Qualifiers.Map()

	if parsed.Type == "deb" {
		distro := qualifiers["distro"]
		if distro == "" {
			return "", fmt.Errorf("deb purls need a distro qualifier naming the release, " +
				"e.g. pkg:deb/debian/openssl@3.0.11-1?distro=debian-12 — advisories are release-specific")
		}
		return debEcosystem(parsed.Namespace, distro)
	}

	ecosystem, ok := purlTypeToEcosystem[strings.ToLower(parsed.Type)]
	if !ok {
		sort.Strings(supported)
		return "", fmt.Errorf("purl type %q is not matched yet; supported ecosystems: %s",
			parsed.Type, strings.Join(supported, ", "))
	}
	if parsed.Type == "apk" {
		if release := qualifiers["distro"]; release != "" {
			return match.EcosystemAlpine + ":" + release, nil
		}
	}
	return ecosystem, nil
}

// debEcosystem turns a purl namespace and distro qualifier into the ecosystem
// string OSV files Debian and Ubuntu advisories under.
func debEcosystem(namespace, distro string) (string, error) {
	base := match.EcosystemDebian
	if strings.EqualFold(namespace, "ubuntu") {
		base = match.EcosystemUbuntu
	}

	// "debian-12" and "ubuntu-22.04" are the conventional spellings; OSV wants
	// just the release.
	release := distro
	if _, after, found := strings.Cut(distro, "-"); found {
		release = after
	}
	if release == "" {
		return "", fmt.Errorf("distro qualifier %q names no release", distro)
	}
	return base + ":" + release, nil
}

var supported = match.SupportedEcosystems()

func runCheck(out io.Writer, cfg config.Config, pkg match.Package) error {
	handle, err := db.Open(cfg.AgentDBPath(), db.SchemaAgent)
	if err != nil {
		return err
	}
	defer handle.Close()

	attached, err := db.AttachAdvisories(handle, cfg.AdvisoryDBPath())
	if err != nil {
		return err
	}
	if !attached {
		// Reporting "no advisories" here would read as "clean", which is the
		// most dangerous thing this command could say.
		return fmt.Errorf("no advisory bundle installed — run `pkgwatch sync` first; " +
			"without one nothing can be matched and this command cannot tell you anything")
	}
	if err := db.CheckAdvisorySchema(handle, bundle.SchemaVersion); err != nil {
		return err
	}

	info, err := repo.Bundle(handle, true)
	if err != nil {
		return err
	}

	// A bundle built without this ecosystem's feed returns zero rows for every
	// package in it, and "no advisories match" would read as a clean bill of
	// health. Refuse rather than answer a question we cannot answer.
	if len(info.Ecosystems) > 0 && !info.Covers(pkg.Ecosystem) {
		return fmt.Errorf("bundle %s carries no %s advisories at all "+
			"(it covers %s) — this command cannot tell you anything about %s",
			info.Version, match.BaseEcosystem(pkg.Ecosystem),
			strings.Join(info.CoveredBases(), ", "), pkg.Name)
	}

	advisories, err := repo.LookupAdvisories(handle, pkg.Ecosystem, pkg.Name)
	if err != nil {
		return err
	}

	return reportCheck(out, pkg, advisories, info)
}

type checkHit struct {
	adv   match.Advisory
	score float64
	tier  string
}

func reportCheck(out io.Writer, pkg match.Package, advisories []match.Advisory, info repo.BundleInfo) error {
	now := time.Now()

	var hits []checkHit
	for _, adv := range advisories {
		affected, err := match.Affects(adv, pkg)
		if err != nil {
			// An unparseable bound is worth saying out loud rather than
			// silently treating as "not affected".
			fmt.Fprintf(out, "warning: could not evaluate %s: %v\n", adv.ID, err)
			continue
		}
		if !affected {
			continue
		}
		score, tier := match.Score(adv, pkg, now)
		hits = append(hits, checkHit{adv: adv, score: score, tier: tier})
	}

	// Most severe first.
	tierOrder := map[string]int{match.TierCritical: 0, match.TierHigh: 1, match.TierMedium: 2, match.TierLow: 3}
	sort.SliceStable(hits, func(i, j int) bool {
		if tierOrder[hits[i].tier] != tierOrder[hits[j].tier] {
			return tierOrder[hits[i].tier] < tierOrder[hits[j].tier]
		}
		return hits[i].score > hits[j].score
	})

	fmt.Fprintf(out, "%s %s (%s)\n", pkg.Ecosystem, pkg.Name, pkg.Version)
	fmt.Fprintf(out, "bundle %s · %d records · %d advisories on file for this package\n\n",
		orDash(info.Version), info.RecordCount, len(advisories))

	if len(hits) == 0 {
		fmt.Fprintln(out, "No advisories match this version.")
		return nil
	}

	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	for _, hit := range hits {
		label := strings.ToUpper(hit.tier)
		if hit.adv.Kind == match.KindMalware {
			label += " · MALWARE"
		}
		fmt.Fprintf(w, "%s\t%s\tscore %.1f\n", label, hit.adv.ID, hit.score)
		if hit.adv.Summary != "" {
			fmt.Fprintf(w, "\t%s\n", hit.adv.Summary)
		}
		fmt.Fprintf(w, "\t%s\n", describeRemedy(hit.adv))
	}
	if err := w.Flush(); err != nil {
		return err
	}

	fmt.Fprintf(out, "\n%d of %d advisories affect this version.\n", len(hits), len(advisories))
	return nil
}

// describeRemedy states the fix if upstream published one. "no fix published"
// is a materially different answer from "upgrade to X" and must not look alike.
func describeRemedy(adv match.Advisory) string {
	var fixes []string
	for _, r := range adv.Ranges {
		if r.Fixed != "" {
			fixes = append(fixes, r.Fixed)
		}
	}
	if len(fixes) == 0 {
		if adv.Kind == match.KindMalware {
			return "remove this package — malicious releases are not fixed by upgrading"
		}
		return "no fix published upstream"
	}
	return "fixed in " + strings.Join(fixes, ", ")
}
