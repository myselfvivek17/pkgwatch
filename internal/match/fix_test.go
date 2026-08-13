package match

import "testing"

// The rule this replaced was MIN(fixed) — the lowest bound the advisory
// publishes anywhere. Salt's PYSEC records carry fifteen fixed versions, one
// per maintained branch, so a machine on 3002.x was being told to move to
// 2015.8.10: a five-year downgrade, presented as the resolution.
func TestFixForPicksTheBranchTheMachineIsOn(t *testing.T) {
	salt := Advisory{
		ID: "PYSEC-2021-362", Ecosystem: EcosystemPyPI, PackageName: "salt",
		Ranges: []Range{
			{Fixed: "2015.8.10"}, {Fixed: "2016.3.4"}, {Fixed: "2016.11.3"},
			{Fixed: "2019.2.5"}, {Fixed: "3000.6"}, {Fixed: "3001.4"}, {Fixed: "3002.5"},
		},
	}

	cases := []struct {
		installed string
		want      string
	}{
		{"3002.1", "3002.5"},
		{"3001.0", "3001.4"},
		{"2019.2.0", "2019.2.5"},
		{"2015.8.7", "2015.8.10"},
	}
	for _, tc := range cases {
		got := FixFor(salt, Package{Ecosystem: EcosystemPyPI, Name: "salt", Version: tc.installed})
		if got != tc.want {
			t.Errorf("installed %s -> fix %q, want %q", tc.installed, got, tc.want)
		}
	}
}

// String order and version order disagree once a component reaches double
// digits, and the old rule used string order.
func TestFixForOrdersByVersionNotByString(t *testing.T) {
	adv := Advisory{
		ID: "GHSA-test", Ecosystem: EcosystemNPM, PackageName: "example",
		Ranges: []Range{{Fixed: "2.10.1"}, {Fixed: "2.9.10"}},
	}
	if got := FixFor(adv, Package{Ecosystem: EcosystemNPM, Name: "example", Version: "2.10.0"}); got != "2.10.1" {
		t.Errorf("fix = %q, want 2.10.1 — string order puts 2.10.1 below 2.9.10", got)
	}
}

// There is no version of a malicious package that is safe to move to, and
// naming one would read as "upgrade and carry on" for the single finding where
// the answer is to remove it.
func TestFixForNamesNoVersionForMalware(t *testing.T) {
	mal := Advisory{
		ID: "MAL-2025-1", Kind: "malware", Ecosystem: EcosystemNPM, PackageName: "evil",
		Ranges: []Range{{Fixed: "1.0.1"}},
	}
	if got := FixFor(mal, Package{Ecosystem: EcosystemNPM, Name: "evil", Version: "1.0.0"}); got != "" {
		t.Errorf("fix = %q, want none for malware", got)
	}
}

// An ecosystem with no comparator still gets an answer, the one the old query
// gave. Degrading to the previous rule is acceptable; degrading to silence
// would turn a fixable finding into an apparently unfixable one.
func TestFixForFallsBackWhenTheEcosystemCannotBeCompared(t *testing.T) {
	adv := Advisory{
		ID: "OSV-1", Ecosystem: "Bitnami", PackageName: "thing",
		Ranges: []Range{{Fixed: "3.0.0"}, {Fixed: "1.2.3"}},
	}
	if got := FixFor(adv, Package{Ecosystem: "Bitnami", Name: "thing", Version: "1.0.0"}); got != "1.2.3" {
		t.Errorf("fix = %q, want the lowest published bound as a fallback", got)
	}
}

// No published fix at all stays empty: that is the positive claim the findings
// page renders as "none yet", and it must not be manufactured.
func TestFixForReportsNothingWhenNoFixIsPublished(t *testing.T) {
	adv := Advisory{
		ID: "GHSA-unfixed", Ecosystem: EcosystemNPM, PackageName: "example",
		Ranges: []Range{{Introduced: "0"}},
	}
	if got := FixFor(adv, Package{Ecosystem: EcosystemNPM, Name: "example", Version: "1.0.0"}); got != "" {
		t.Errorf("fix = %q, want empty", got)
	}
}
