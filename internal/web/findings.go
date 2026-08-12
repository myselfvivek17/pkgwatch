package web

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

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

	// CanTriage is false on the hub, where findings belong to another machine.
	CanTriage bool
	Back      string

	// ShowMachine adds the machine column, which only the hub has anything to
	// put in.
	ShowMachine bool
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
	Machine  string

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
		CanTriage:     s.Acknowledge != nil && s.Ignore != nil,
		Back:          "/findings?" + r.URL.RawQuery,
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
			Machine:  finding.Machine,
		}
		if finding.Machine != "" {
			data.ShowMachine = true
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

// handleTriage applies an acknowledge or an ignore from the findings page.
//
// Redirects back rather than rendering, so a refresh does not repeat the
// action — the finding is already in its new state and a second POST would
// silently extend an ignore window the user only meant to set once.
func (s *Server) handleTriage(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	purl := r.PostForm.Get("purl")
	advisory := r.PostForm.Get("advisory")
	back := "/findings"
	if q := r.PostForm.Get("back"); q != "" && strings.HasPrefix(q, "/findings") {
		// Only ever back to this page. An open redirect on a form post is a
		// small hole that needs no reason to exist.
		back = q
	}

	var err error
	switch r.PostForm.Get("action") {
	case "ack":
		err = s.Acknowledge(purl, advisory, r.PostForm.Get("note"))
	case "ignore":
		days, convErr := strconv.Atoi(r.PostForm.Get("days"))
		if convErr != nil || days < 1 {
			http.Error(w, "ignore needs a number of days of at least 1: "+
				"an ignore with no end is how a finding gets forgotten", http.StatusBadRequest)
			return
		}
		err = s.Ignore(purl, advisory, r.PostForm.Get("note"), days)
	default:
		http.Error(w, "unknown action", http.StatusBadRequest)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, back, http.StatusSeeOther)
}
