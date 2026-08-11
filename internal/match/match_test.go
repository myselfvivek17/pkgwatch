package match

import (
	"testing"
	"time"
)

func cvss(f float64) *float64 { return &f }

func TestNormalizeName(t *testing.T) {
	tests := []struct {
		ecosystem, in, want string
	}{
		// PEP 503: runs of -_. collapse to a single -, and case is folded.
		{EcosystemPyPI, "Django", "django"},
		{EcosystemPyPI, "zope.interface", "zope-interface"},
		{EcosystemPyPI, "backports_abc", "backports-abc"},
		{EcosystemPyPI, "a--_.-b", "a-b"},
		{EcosystemPyPI, "requests", "requests"},

		// npm names are case-sensitive and scoped names keep their slash.
		// Folding them would match the wrong package.
		{EcosystemNPM, "lodash", "lodash"},
		{EcosystemNPM, "@ctrl/tinycolor", "@ctrl/tinycolor"},
		{EcosystemNPM, "JSONStream", "JSONStream"},
		{EcosystemNPM, "left.pad", "left.pad"},
	}

	for _, tt := range tests {
		if got := NormalizeName(tt.ecosystem, tt.in); got != tt.want {
			t.Errorf("NormalizeName(%s, %q) = %q, want %q", tt.ecosystem, tt.in, got, tt.want)
		}
	}
}

// Exact version lists are the fast path and cover every malware record, which
// always names specific versions.
func TestAffectsExactVersions(t *testing.T) {
	adv := Advisory{
		ID: "MAL-2026-0001", Kind: KindMalware, Ecosystem: EcosystemNPM,
		PackageName: "@ctrl/tinycolor",
		Versions:    []string{"3.4.1", "3.4.2", "3.4.3"},
	}

	for _, tt := range []struct {
		version string
		want    bool
	}{
		{"3.4.1", true},
		{"3.4.3", true},
		{"3.4.0", false},
		{"3.4.4", false},
	} {
		got, err := Affects(adv, Package{Ecosystem: EcosystemNPM, Name: "@ctrl/tinycolor", Version: tt.version})
		if err != nil {
			t.Fatalf("Affects(%s): %v", tt.version, err)
		}
		if got != tt.want {
			t.Errorf("version %s: affected = %v, want %v", tt.version, got, tt.want)
		}
	}
}

func TestAffectsRanges(t *testing.T) {
	tests := []struct {
		name      string
		ecosystem string
		ranges    []Range
		version   string
		want      bool
	}{
		{"inside a closed range", EcosystemNPM,
			[]Range{{Introduced: "1.0.0", Fixed: "2.0.0"}}, "1.5.0", true},
		{"at the introduced bound is affected", EcosystemNPM,
			[]Range{{Introduced: "1.0.0", Fixed: "2.0.0"}}, "1.0.0", true},
		{"at the fixed bound is not", EcosystemNPM,
			[]Range{{Introduced: "1.0.0", Fixed: "2.0.0"}}, "2.0.0", false},
		{"below the range", EcosystemNPM,
			[]Range{{Introduced: "1.0.0", Fixed: "2.0.0"}}, "0.9.0", false},

		// An advisory with no fix yet affects everything from introduced on.
		// Treating a missing fix as "not affected" is the dangerous direction.
		{"unfixed advisory", EcosystemNPM,
			[]Range{{Introduced: "1.0.0"}}, "9.9.9", true},

		// Introduced "0" is OSV's way of saying "since the beginning".
		{"introduced at zero", EcosystemNPM,
			[]Range{{Introduced: "0", Fixed: "1.0.0"}}, "0.0.1", true},

		{"last_affected is inclusive", EcosystemNPM,
			[]Range{{Introduced: "1.0.0", LastAffected: "1.5.0"}}, "1.5.0", true},
		{"past last_affected", EcosystemNPM,
			[]Range{{Introduced: "1.0.0", LastAffected: "1.5.0"}}, "1.5.1", false},

		// Multiple disjoint intervals: a version can sit in the safe gap.
		{"first of two intervals", EcosystemNPM,
			[]Range{{Introduced: "1.0.0", Fixed: "1.2.0"}, {Introduced: "2.0.0", Fixed: "2.1.0"}}, "1.1.0", true},
		{"gap between intervals", EcosystemNPM,
			[]Range{{Introduced: "1.0.0", Fixed: "1.2.0"}, {Introduced: "2.0.0", Fixed: "2.1.0"}}, "1.5.0", false},
		{"second of two intervals", EcosystemNPM,
			[]Range{{Introduced: "1.0.0", Fixed: "1.2.0"}, {Introduced: "2.0.0", Fixed: "2.1.0"}}, "2.0.5", true},

		// A prerelease sorts below its release, so it is outside a range that
		// starts at that release.
		{"prerelease below introduced", EcosystemNPM,
			[]Range{{Introduced: "1.0.0", Fixed: "2.0.0"}}, "1.0.0-beta.1", false},
		{"prerelease inside the range", EcosystemNPM,
			[]Range{{Introduced: "1.0.0", Fixed: "2.0.0"}}, "1.5.0-rc.1", true},

		// PyPI, with the parts of PEP 440 that trip naive comparisons.
		{"pypi inside range", EcosystemPyPI,
			[]Range{{Introduced: "1.0", Fixed: "2.0"}}, "1.5", true},
		{"pypi post-release is still below the fix", EcosystemPyPI,
			[]Range{{Introduced: "1.0", Fixed: "2.0"}}, "1.9.post1", true},
		{"pypi epoch outranks the fix", EcosystemPyPI,
			[]Range{{Introduced: "1.0", Fixed: "2.0"}}, "1!1.5", false},
		{"pypi dev release below introduced", EcosystemPyPI,
			[]Range{{Introduced: "1.0", Fixed: "2.0"}}, "1.0.dev1", false},
		{"pypi zero padding", EcosystemPyPI,
			[]Range{{Introduced: "1.0", Fixed: "2.0"}}, "1.0.0", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adv := Advisory{ID: "TEST", Kind: KindVulnerability, Ecosystem: tt.ecosystem, PackageName: "p", Ranges: tt.ranges}
			got, err := Affects(adv, Package{Ecosystem: tt.ecosystem, Name: "p", Version: tt.version})
			if err != nil {
				t.Fatalf("Affects: %v", err)
			}
			if got != tt.want {
				t.Errorf("affected = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWithdrawnAdvisoriesNeverMatch(t *testing.T) {
	adv := Advisory{
		ID: "GHSA-withdrawn", Kind: KindVulnerability, Ecosystem: EcosystemNPM,
		PackageName: "p", Versions: []string{"1.0.0"},
		Ranges:    []Range{{Introduced: "0"}},
		Withdrawn: true,
	}

	got, err := Affects(adv, Package{Ecosystem: EcosystemNPM, Name: "p", Version: "1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	if got {
		t.Error("a withdrawn advisory matched; it was retracted and must never fire")
	}
}

func TestAffectsRejectsUnparseableVersion(t *testing.T) {
	adv := Advisory{ID: "T", Kind: KindVulnerability, Ecosystem: EcosystemNPM, PackageName: "p",
		Ranges: []Range{{Introduced: "1.0.0"}}}

	if _, err := Affects(adv, Package{Ecosystem: EcosystemNPM, Name: "p", Version: "garbage"}); err == nil {
		t.Error("expected an error for an unparseable version rather than a silent false")
	}
}

// Real feeds carry bounds no parser accepts — PYSEC's requests records give an
// introduced bound of "2.23.0-py2.7". Abandoning the advisory on the first one
// discards every other interval in it, which is a far larger false negative
// than the bad bound itself.
func TestUnparseableBoundDoesNotDiscardSiblingRanges(t *testing.T) {
	adv := Advisory{
		ID: "PYSEC-test", Kind: KindVulnerability,
		Ecosystem: EcosystemPyPI, PackageName: "requests",
		Ranges: []Range{
			{Introduced: "2.23.0-py2.7", Fixed: "2.30.0"}, // not a PEP 440 version
			{Introduced: "1.0.0", Fixed: "2.0.0"},         // perfectly usable
		},
	}

	affected, err := Affects(adv, Package{Ecosystem: EcosystemPyPI, Name: "requests", Version: "1.5.0"})
	if err != nil {
		t.Fatalf("a usable interval should still be evaluated: %v", err)
	}
	if !affected {
		t.Error("1.5.0 falls inside the second interval and must match")
	}

	// When nothing matched the error still surfaces: coverage was incomplete,
	// which is not the same as a clean result.
	affected, err = Affects(adv, Package{Ecosystem: EcosystemPyPI, Name: "requests", Version: "2.50.0"})
	if affected {
		t.Error("2.50.0 is outside every usable interval")
	}
	if err == nil {
		t.Error("the unparseable bound must still be reported, or the miss reads as clean")
	}
}

func TestScoreAndTier(t *testing.T) {
	old := time.Now().Add(-120 * 24 * time.Hour)
	now := time.Now()

	tests := []struct {
		name      string
		adv       Advisory
		pkg       Package
		wantScore float64
		wantTier  string
	}{
		{
			name:      "absent cvss defaults to 5",
			adv:       Advisory{Kind: KindVulnerability},
			pkg:       Package{Scope: ScopeProject, LastSeen: now},
			wantScore: 5.0, wantTier: TierMedium,
		},
		{
			name:      "global scope multiplies by 1.5",
			adv:       Advisory{Kind: KindVulnerability, SeverityCVSS: cvss(4.0)},
			pkg:       Package{Scope: ScopeGlobal, LastSeen: now},
			wantScore: 6.0, wantTier: TierMedium,
		},
		{
			name:      "install scripts multiply by 1.5",
			adv:       Advisory{Kind: KindVulnerability, SeverityCVSS: cvss(4.0)},
			pkg:       Package{Scope: ScopeProject, HasScripts: true, LastSeen: now},
			wantScore: 6.0, wantTier: TierMedium,
		},
		{
			// Both multipliers apply and the score more than doubles, which is
			// the point: this sorts above an untouched medium. The badge still
			// says medium, because that is what the advisory says.
			name:      "global and scripts compound",
			adv:       Advisory{Kind: KindVulnerability, SeverityCVSS: cvss(4.0)},
			pkg:       Package{Scope: ScopeGlobal, HasScripts: true, LastSeen: now},
			wantScore: 9.0, wantTier: TierMedium,
		},
		{
			// The other direction, and the one worth being sure about: a
			// forgotten dependency sinks down the list, and it is still a
			// critical vulnerability. Ranking may discount it; the badge must
			// not, or a 10.0 nobody has touched quietly reads as medium.
			name:      "a stale project dependency is discounted in rank, not in tier",
			adv:       Advisory{Kind: KindVulnerability, SeverityCVSS: cvss(10.0)},
			pkg:       Package{Scope: ScopeProject, LastSeen: old},
			wantScore: 4.0, wantTier: TierCritical,
		},
		{
			name:      "high",
			adv:       Advisory{Kind: KindVulnerability, SeverityCVSS: cvss(7.5)},
			pkg:       Package{Scope: ScopeProject, LastSeen: now},
			wantScore: 7.5, wantTier: TierHigh,
		},
		{
			name:      "low",
			adv:       Advisory{Kind: KindVulnerability, SeverityCVSS: cvss(2.0)},
			pkg:       Package{Scope: ScopeProject, LastSeen: now},
			wantScore: 2.0, wantTier: TierLow,
		},
		{
			// Active malware and a latent CVE are different products and must
			// not share a scale.
			name:      "malware is critical even with a low cvss",
			adv:       Advisory{Kind: KindMalware, SeverityCVSS: cvss(1.0)},
			pkg:       Package{Scope: ScopeProject, LastSeen: now},
			wantScore: 4.0, wantTier: TierCritical,
		},
		{
			name:      "malware with no cvss",
			adv:       Advisory{Kind: KindMalware},
			pkg:       Package{Scope: ScopeProject, LastSeen: now},
			wantScore: 20.0, wantTier: TierCritical,
		},
		{
			// The staleness discount applies to project scope only, so the
			// multiplier still lifts the score. The tier does not follow it:
			// the advisory rates this medium, and where a package happens to be
			// installed does not make the vulnerability worse than its author
			// says it is. Score is what the list sorts by; tier is what the
			// badge claims.
			name:      "a stale global package is not discounted",
			adv:       Advisory{Kind: KindVulnerability, SeverityCVSS: cvss(6.0)},
			pkg:       Package{Scope: ScopeGlobal, LastSeen: old},
			wantScore: 9.0, wantTier: TierMedium,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score, tier := Score(tt.adv, tt.pkg, now)
			if score != tt.wantScore {
				t.Errorf("score = %v, want %v", score, tt.wantScore)
			}
			if tier != tt.wantTier {
				t.Errorf("tier = %q, want %q", tier, tt.wantTier)
			}
		})
	}
}

// The old behaviour is still available for anyone who wants install context to
// drive the badge, and it has to keep working — the setting exists because both
// readings are defensible, not because one is a mistake.
func TestPromoteTiersRestoresContextDrivenTiers(t *testing.T) {
	now := time.Now()
	adv := Advisory{Kind: KindVulnerability, SeverityCVSS: cvss(6.0)}
	pkg := Package{Scope: ScopeGlobal, LastSeen: now}

	_, tier := Score(adv, pkg, now)
	if tier != TierMedium {
		t.Fatalf("default tier = %q, want medium — the advisory rates this medium", tier)
	}

	PromoteTiers = true
	defer func() { PromoteTiers = false }()

	score, tier := Score(adv, pkg, now)
	if score != 9.0 {
		t.Errorf("score = %v, want 9.0 — the multiplier applies either way", score)
	}
	if tier != TierCritical {
		t.Errorf("promoted tier = %q, want critical", tier)
	}
}

// Malware is critical under both settings. "There is a payload in this package"
// is not a severity rating, and no policy about install context should be able
// to file it as medium.
func TestMalwareIsCriticalUnderBothPolicies(t *testing.T) {
	now := time.Now()
	adv := Advisory{Kind: KindMalware, SeverityCVSS: cvss(1.0)}
	pkg := Package{Scope: ScopeProject, LastSeen: now}

	for _, promote := range []bool{false, true} {
		PromoteTiers = promote
		if _, tier := Score(adv, pkg, now); tier != TierCritical {
			t.Errorf("PromoteTiers=%v gave tier %q, want critical", promote, tier)
		}
	}
	PromoteTiers = false
}
