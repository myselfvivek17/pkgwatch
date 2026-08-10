package web

import (
	"fmt"
	"net/http"

	"github.com/myselfvivek17/pkgwatch/internal/repo"
)

// FindingsData is the triage page's view model.
type FindingsData struct {
	Rows          []FindingRow
	TierOptions   []Option
	FixOptions    []Option
	Limit         int
	Truncated     bool
	Fixable       int
	Promoted      int
	BundleMissing bool
	FixableOnly   bool
}

// FindingRow is one finding, shaped for display.
type FindingRow struct {
	Tier     string
	Score    string
	CVSS     string
	Fix      string
	Fixable  bool
	PURL     string
	Advisory string
	Summary  string
	State    string

	// Promoted marks a finding scoring above the advisory's own CVSS, so the
	// two numbers disagreeing reads as intent rather than as a bug.
	Promoted bool
}

func (r FindingRow) Badge() Badge { return Badge{Tier: r.Tier, Size: "sm"} }

func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	tier := r.URL.Query().Get("tier")
	fixableOnly := r.URL.Query().Get("fix") == "fixable"
	const limit = 100

	findings, attached, err := s.Findings(repo.FindingFilter{
		Limit: limit, Tier: tier, FixableOnly: fixableOnly,
	})
	if err != nil {
		http.Error(w, "findings unavailable: "+err.Error(), http.StatusInternalServerError)
		return
	}

	data := FindingsData{
		Limit:         limit,
		Truncated:     len(findings) == limit,
		BundleMissing: !attached,
		FixableOnly:   fixableOnly,
		TierOptions: options(tier,
			"", "all severities",
			"critical", "critical", "high", "high",
			"medium", "medium", "low", "low"),
		FixOptions: options(map[bool]string{true: "fixable", false: ""}[fixableOnly],
			"", "everything",
			"fixable", "with a published fix"),
	}

	for _, finding := range findings {
		row := FindingRow{
			Tier:     finding.Tier,
			Score:    fmt.Sprintf("%.1f", finding.Score),
			CVSS:     "—",
			Fix:      "none yet",
			PURL:     finding.PURL,
			Advisory: finding.AdvisoryID,
			Summary:  finding.Summary,
			State:    finding.State,
		}
		if finding.BaseCVSS != nil {
			row.CVSS = fmt.Sprintf("%.1f", *finding.BaseCVSS)
			if finding.Score > *finding.BaseCVSS+0.05 {
				row.Promoted = true
				data.Promoted++
			}
		}
		if finding.FixedIn != "" {
			row.Fix = finding.FixedIn
			row.Fixable = true
			data.Fixable++
		}
		data.Rows = append(data.Rows, row)
	}

	s.render(w, "findings", "Findings triage", "findings", data)
}
