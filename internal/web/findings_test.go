package web

import (
	"net/http"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/myselfvivek17/pkgwatch/internal/repo"
)

func findingsServer(t *testing.T, attached bool, rows []repo.Finding) http.Handler {
	t.Helper()
	srv, err := New(ModeAgent, "test-host")
	if err != nil {
		t.Fatal(err)
	}
	srv.Overview = func() (OverviewData, error) { return OverviewData{Mode: "agent"}, nil }
	srv.Findings = func(f repo.FindingFilter) ([]repo.Finding, bool, error) {
		if !attached && f.FixableOnly {
			return nil, false, nil
		}
		var out []repo.Finding
		for _, row := range rows {
			if f.Tier != "" && row.Tier != f.Tier {
				continue
			}
			if f.FixableOnly && row.FixedIn == "" {
				continue
			}
			out = append(out, row)
		}
		return out, attached, nil
	}
	r := chi.NewRouter()
	srv.Routes(r)
	return r
}

func cvss(v float64) *float64 { return &v }

func sampleFindings() []repo.Finding {
	return []repo.Finding{
		{PURL: "pkg:deb/ubuntu/snapd@2.76", AdvisoryID: "UBUNTU-CVE-1", Score: 10, Tier: "critical",
			BaseCVSS: cvss(10), Summary: "remote code execution"},
		{PURL: "pkg:deb/debian/openssl@3.0.17", AdvisoryID: "DEBIAN-CVE-2", Score: 9.8, Tier: "critical",
			BaseCVSS: cvss(9.8), FixedIn: "3.0.19-1~deb12u2"},
		{PURL: "pkg:npm/lodash@4.17.20", AdvisoryID: "GHSA-x", Score: 10.8, Tier: "critical",
			BaseCVSS: cvss(7.2), FixedIn: "4.17.21"},
	}
}

// The whole point of the FIX column: what scores highest and what can be acted
// on are different lists, and a triage page whose top row cannot be acted on
// teaches you to ignore the page.
func TestFindingsShowsWhatIsActionable(t *testing.T) {
	h := findingsServer(t, true, sampleFindings())
	body := get(t, h, "/findings").Body.String()

	if !strings.Contains(body, "3.0.19-1~deb12u2") {
		t.Error("fix version missing from the table")
	}
	if !strings.Contains(body, "none yet") {
		t.Error("unfixable findings must say so rather than showing an empty cell")
	}
	if !strings.Contains(body, "2 of 3 shown have a published fix") {
		t.Error("actionable count missing or wrong")
	}
	// lodash scores 10.8 against a CVSS of 7.2 — that gap is §5.2 doing its job
	// and has to read as intent, not as a bug.
	if !strings.Contains(body, "score above their CVSS") {
		t.Error("no explanation for scores that exceed the advisory's own rating")
	}
}

func TestFindingsFiltersInTheQuery(t *testing.T) {
	h := findingsServer(t, true, sampleFindings())
	body := get(t, h, "/findings?fix=fixable").Body.String()
	if strings.Contains(body, "snapd") {
		t.Error("fixable filter still shows a finding with no published fix")
	}
	if !strings.Contains(body, "openssl") {
		t.Error("fixable filter dropped a fixable finding")
	}
	// Tautological under the filter — every row is fixable by construction.
	if strings.Contains(body, "shown have a published fix") {
		t.Error("the actionable count should be silent when every row is fixable")
	}
}

// Without a bundle, nothing is known about fixes. Saying "nothing matches" on a
// machine with hundreds of findings is the same false-clean this tool exists to
// avoid.
func TestFindingsDistinguishesUnknownFromNone(t *testing.T) {
	h := findingsServer(t, false, sampleFindings())
	body := get(t, h, "/findings?fix=fixable").Body.String()
	if !strings.Contains(body, "Cannot tell what is fixable") {
		t.Error("page claims nothing is fixable when it simply could not look")
	}
}
