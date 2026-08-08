package osv

import (
	"os"
	"testing"

	"github.com/myselfvivek17/pkgwatch/internal/match"
)

func loadFixture(t *testing.T, name string) []match.Advisory {
	t.Helper()

	raw, err := os.ReadFile("testdata/" + name + ".json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	advisories, err := ParseRecord(raw)
	if err != nil {
		t.Fatalf("ParseRecord(%s): %v", name, err)
	}
	return advisories
}

// A real GHSA record, fetched from OSV. Ranges, a CVSS vector and a fix.
//
// This one advisory covers five packages: lodash and three npm siblings that
// vendor the same code, plus a RubyGems package. The RubyGems entry has no
// comparator yet and must be dropped rather than stored unmatched.
func TestParseRealVulnerabilityRecord(t *testing.T) {
	advisories := loadFixture(t, "GHSA-35jh-r3h4-6jhm")

	if len(advisories) != 4 {
		names := make([]string, 0, len(advisories))
		for _, a := range advisories {
			names = append(names, a.Ecosystem+"/"+a.PackageName)
		}
		t.Fatalf("got %d advisories (%v), want the 4 npm packages", len(advisories), names)
	}

	var adv match.Advisory
	for _, a := range advisories {
		if a.PackageName == "lodash" {
			adv = a
		}
		if a.Ecosystem != match.EcosystemNPM {
			t.Errorf("kept an unsupported ecosystem: %s/%s", a.Ecosystem, a.PackageName)
		}
	}
	if adv.PackageName != "lodash" {
		t.Fatal("no advisory for lodash itself")
	}

	if adv.ID != "GHSA-35jh-r3h4-6jhm" {
		t.Errorf("ID = %q", adv.ID)
	}
	if adv.Kind != match.KindVulnerability {
		t.Errorf("Kind = %q, want vulnerability", adv.Kind)
	}
	if adv.Ecosystem != match.EcosystemNPM || adv.PackageName != "lodash" {
		t.Errorf("package = %s/%s, want npm/lodash", adv.Ecosystem, adv.PackageName)
	}
	if adv.Withdrawn {
		t.Error("record is not withdrawn upstream")
	}

	// CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H is a base score of 7.2.
	if adv.SeverityCVSS == nil {
		t.Fatal("severity was dropped; the vector is present in the record")
	}
	if *adv.SeverityCVSS != 7.2 {
		t.Errorf("SeverityCVSS = %v, want 7.2", *adv.SeverityCVSS)
	}

	if len(adv.Ranges) != 1 {
		t.Fatalf("got %d ranges, want 1", len(adv.Ranges))
	}
	if adv.Ranges[0].Introduced != "0" || adv.Ranges[0].Fixed != "4.17.21" {
		t.Errorf("range = %+v, want introduced 0 fixed 4.17.21", adv.Ranges[0])
	}

	// The acceptance criterion: this advisory must catch lodash 4.17.20.
	affected, err := match.Affects(adv, match.Package{
		Ecosystem: match.EcosystemNPM, Name: "lodash", Version: "4.17.20",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !affected {
		t.Error("lodash 4.17.20 should be affected by GHSA-35jh-r3h4-6jhm")
	}
}

// A real MAL- record for the @ctrl/tinycolor compromise: exact versions, no
// CVSS. It must still come out as malware, which the scorer floors at critical.
func TestParseRealMalwareRecord(t *testing.T) {
	advisories := loadFixture(t, "MAL-2025-47141")

	if len(advisories) != 1 {
		t.Fatalf("got %d advisories, want 1", len(advisories))
	}
	adv := advisories[0]

	if adv.Kind != match.KindMalware {
		t.Errorf("Kind = %q, want malware — a MAL- record is an active attack, not a latent CVE", adv.Kind)
	}
	if adv.PackageName != "@ctrl/tinycolor" {
		t.Errorf("PackageName = %q", adv.PackageName)
	}
	if len(adv.Versions) == 0 {
		t.Fatal("exact versions were dropped; they are the fast path for malware")
	}

	affected, err := match.Affects(adv, match.Package{
		Ecosystem: match.EcosystemNPM, Name: "@ctrl/tinycolor", Version: "4.1.2",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !affected {
		t.Error("@ctrl/tinycolor 4.1.2 should match the malware record")
	}

	_, tier := match.Score(adv, match.Package{Scope: match.ScopeProject}, adv.Published)
	if tier != match.TierCritical {
		t.Errorf("tier = %q, want critical for malware", tier)
	}
}

func TestEventsBecomeIntervals(t *testing.T) {
	tests := []struct {
		name   string
		record string
		want   []match.Range
	}{
		{
			name: "introduced and fixed",
			record: `{"id":"T-1","affected":[{"package":{"ecosystem":"npm","name":"p"},
				"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"fixed":"2.0.0"}]}]}]}`,
			want: []match.Range{{Introduced: "1.0.0", Fixed: "2.0.0"}},
		},
		{
			// No fix yet. Dropping this range would report an unfixed advisory
			// as harmless — the dangerous direction.
			name: "introduced with no fix",
			record: `{"id":"T-2","affected":[{"package":{"ecosystem":"npm","name":"p"},
				"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"}]}]}]}`,
			want: []match.Range{{Introduced: "1.0.0"}},
		},
		{
			name: "two disjoint intervals",
			record: `{"id":"T-3","affected":[{"package":{"ecosystem":"npm","name":"p"},
				"ranges":[{"type":"SEMVER","events":[
					{"introduced":"1.0.0"},{"fixed":"1.2.0"},
					{"introduced":"2.0.0"},{"fixed":"2.1.0"}]}]}]}`,
			want: []match.Range{{Introduced: "1.0.0", Fixed: "1.2.0"}, {Introduced: "2.0.0", Fixed: "2.1.0"}},
		},
		{
			name: "last_affected closes the interval",
			record: `{"id":"T-4","affected":[{"package":{"ecosystem":"npm","name":"p"},
				"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"last_affected":"1.5.0"}]}]}]}`,
			want: []match.Range{{Introduced: "1.0.0", LastAffected: "1.5.0"}},
		},
		{
			// GIT ranges are commit hashes, not versions. Keeping them would
			// feed unparseable strings to the comparator.
			name: "git ranges are skipped",
			record: `{"id":"T-5","affected":[{"package":{"ecosystem":"npm","name":"p"},
				"ranges":[{"type":"GIT","repo":"https://x","events":[{"introduced":"abc123"}]},
				          {"type":"SEMVER","events":[{"introduced":"1.0.0"}]}]}]}`,
			want: []match.Range{{Introduced: "1.0.0"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseRecord([]byte(tt.record))
			if err != nil {
				t.Fatalf("ParseRecord: %v", err)
			}
			if len(got) != 1 {
				t.Fatalf("got %d advisories, want 1", len(got))
			}
			ranges := got[0].Ranges
			if len(ranges) != len(tt.want) {
				t.Fatalf("got %d ranges %+v, want %d", len(ranges), ranges, len(tt.want))
			}
			for i := range ranges {
				if ranges[i] != tt.want[i] {
					t.Errorf("range %d = %+v, want %+v", i, ranges[i], tt.want[i])
				}
			}
		})
	}
}

// One record can name several packages; each becomes its own advisory row so
// lookups stay a single indexed query.
func TestOneRecordPerAffectedPackage(t *testing.T) {
	record := `{"id":"T-multi","affected":[
		{"package":{"ecosystem":"npm","name":"a"},"versions":["1.0.0"]},
		{"package":{"ecosystem":"npm","name":"b"},"versions":["2.0.0"]}]}`

	got, err := ParseRecord([]byte(record))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d advisories, want one per affected package", len(got))
	}
	if got[0].PackageName != "a" || got[1].PackageName != "b" {
		t.Errorf("packages = %s, %s", got[0].PackageName, got[1].PackageName)
	}
}

func TestUnsupportedEcosystemsAreDropped(t *testing.T) {
	// M1 gates and matches npm and PyPI. Other ecosystems arrive in M1b;
	// importing them now would store rows nothing can compare.
	record := `{"id":"T-eco","affected":[
		{"package":{"ecosystem":"Go","name":"golang.org/x/net"},"versions":["1.0.0"]},
		{"package":{"ecosystem":"npm","name":"a"},"versions":["1.0.0"]},
		{"package":{"ecosystem":"PyPI","name":"Django"},"versions":["1.0"]}]}`

	got, err := ParseRecord([]byte(record))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d advisories, want npm and PyPI only", len(got))
	}
}

func TestWithdrawnIsCarried(t *testing.T) {
	record := `{"id":"T-w","withdrawn":"2024-01-01T00:00:00Z","affected":[
		{"package":{"ecosystem":"npm","name":"p"},"versions":["1.0.0"]}]}`

	got, err := ParseRecord([]byte(record))
	if err != nil {
		t.Fatal(err)
	}
	if !got[0].Withdrawn {
		t.Error("withdrawn advisory was imported as live")
	}
}

func TestQualitativeSeverityFallback(t *testing.T) {
	// No vector, but GitHub's rating is present.
	record := `{"id":"T-sev","database_specific":{"severity":"CRITICAL"},"affected":[
		{"package":{"ecosystem":"npm","name":"p"},"versions":["1.0.0"]}]}`

	got, err := ParseRecord([]byte(record))
	if err != nil {
		t.Fatal(err)
	}
	if got[0].SeverityCVSS == nil {
		t.Fatal("qualitative severity was dropped, leaving the advisory unscored")
	}
	if *got[0].SeverityCVSS != 9.8 {
		t.Errorf("SeverityCVSS = %v, want 9.8", *got[0].SeverityCVSS)
	}
}

func TestParseRecordRejectsGarbage(t *testing.T) {
	for _, in := range []string{"", "{", "not json"} {
		if _, err := ParseRecord([]byte(in)); err == nil {
			t.Errorf("ParseRecord(%q) succeeded, want an error", in)
		}
	}
}
