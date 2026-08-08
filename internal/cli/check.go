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

	var ecosystem string
	switch strings.ToLower(parsed.Type) {
	case "npm":
		ecosystem = match.EcosystemNPM
	case "pypi":
		ecosystem = match.EcosystemPyPI
	default:
		return match.Package{}, fmt.Errorf(
			"ecosystem %q is not matched yet — npm and PyPI today, the rest in M1b", parsed.Type)
	}

	// npm scoped packages arrive split: namespace "@ctrl", name "tinycolor".
	name := parsed.Name
	if parsed.Namespace != "" {
		name = parsed.Namespace + "/" + parsed.Name
	}

	return match.Package{Ecosystem: ecosystem, Name: name, Version: parsed.Version}, nil
}

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

	info, err := repo.Bundle(handle, true)
	if err != nil {
		return err
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
