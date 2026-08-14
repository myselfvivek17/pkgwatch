package web

import (
	"fmt"
	"net/http"
	"time"

	"github.com/myselfvivek17/pkgwatch/internal/repo"
	"github.com/myselfvivek17/pkgwatch/internal/rotate"
)

// RotateData backs the credential rotation page.
type RotateData struct {
	// Exposures are the malware findings on this machine. Each is its own
	// checklist: two malicious packages a month apart are two exposures.
	Exposures []Exposure

	// BundleMissing means nothing here can tell malware from a vulnerability,
	// so an empty list is "cannot say" rather than "none".
	BundleMissing bool

	// Credentials is what exists on this machine, for the state where there is
	// nothing to rotate *for* yet. Knowing what a postinstall script could read
	// is worth having before anything goes wrong.
	Credentials []rotate.Item
}

// Exposure is one malware finding and its checklist.
type Exposure struct {
	PURL       string
	AdvisoryID string
	Summary    string
	Found      string

	// Window describes how long the package was present, or says the package is
	// gone. Absent data is never rendered as a blank: the window is what scopes
	// the urgency.
	Window string

	Items   []RotateRow
	Done    int
	Total   int
	Percent int
}

// RotateRow is one credential in one exposure's checklist.
type RotateRow struct {
	rotate.Item
	Checked   bool
	CheckedAt string
}

func (s *Server) handleRotate(w http.ResponseWriter, r *http.Request) {
	findings, attached, err := s.Exposures()
	if err != nil {
		http.Error(w, "rotation unavailable: "+err.Error(), http.StatusInternalServerError)
		return
	}

	credentials := s.Credentials()
	data := RotateData{BundleMissing: !attached, Credentials: credentials}

	for _, finding := range findings {
		checked := map[string]time.Time{}
		if s.RotationChecked != nil {
			if checked, err = s.RotationChecked(finding.PURL, finding.AdvisoryID); err != nil {
				http.Error(w, "rotation progress unavailable: "+err.Error(), http.StatusInternalServerError)
				return
			}
		}

		exposure := Exposure{
			PURL:       finding.PURL,
			AdvisoryID: finding.AdvisoryID,
			Summary:    finding.Summary,
			Found:      finding.DetectedAt.Format("2 Jan 2006, 15:04"),
			Total:      len(credentials),
			Window:     s.exposureWindow(finding.PURL),
		}
		for _, item := range credentials {
			row := RotateRow{Item: item}
			if at, done := checked[item.ID]; done {
				row.Checked, row.CheckedAt = true, at.Format("2 Jan, 15:04")
				exposure.Done++
			}
			exposure.Items = append(exposure.Items, row)
		}
		if exposure.Total > 0 {
			exposure.Percent = exposure.Done * 100 / exposure.Total
		}
		data.Exposures = append(data.Exposures, exposure)
	}

	s.render(w, "rotate", "Credential rotation", "credentials", data)
}

// exposureWindow says how long the package was here, in the terms that decide
// how much of the checklist matters.
func (s *Server) exposureWindow(purl string) string {
	if s.PackageExposure == nil {
		return ""
	}
	first, last, err := s.PackageExposure(purl)
	if err != nil {
		// No inventory row means the package has gone. The window closed, and
		// anything read while it was open is still read.
		return "no longer installed — the window has closed, but anything read during it is still read"
	}

	span := last.Sub(first)
	switch {
	case span < time.Hour:
		return fmt.Sprintf("present %s, under an hour", first.Format("2 Jan"))
	case span < 48*time.Hour:
		return fmt.Sprintf("present %s → %s, about %d hours",
			first.Format("2 Jan"), last.Format("2 Jan"), int(span.Hours()))
	default:
		return fmt.Sprintf("present %s → %s, %d days",
			first.Format("2 Jan"), last.Format("2 Jan"), int(span.Hours()/24))
	}
}

// handleRotateCheck ticks or unticks one item.
//
// Redirects rather than rendering, so a refresh does not repeat the write. The
// item is checked against this machine's own list first: a tick on a credential
// that is not here would record work nobody could have done.
func (s *Server) handleRotateCheck(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/rotate", http.StatusSeeOther)
		return
	}

	purl := r.PostFormValue("purl")
	advisoryID := r.PostFormValue("advisory")
	itemID := r.PostFormValue("item")

	known := false
	for _, item := range s.Credentials() {
		if item.ID == itemID {
			known = true
			break
		}
	}
	if purl == "" || advisoryID == "" || !known {
		http.Redirect(w, r, "/rotate", http.StatusSeeOther)
		return
	}

	at := time.Now()
	if r.PostFormValue("action") == "uncheck" {
		at = time.Time{}
	}
	if err := s.SetRotationChecked(purl, advisoryID, itemID, at); err != nil {
		http.Error(w, "could not record that: "+err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/rotate", http.StatusSeeOther)
}

// QuarantineData backs the quarantine page.
type QuarantineData struct {
	Items []QuarantineRow

	// CanRestore is false wherever nothing is wired to perform the restore,
	// which keeps the button from being a promise the page cannot keep.
	CanRestore bool

	// Failed and Missing are counted separately because they are the two rows
	// that need a person: one means the files that came back are not the files
	// that were taken, the other means they cannot come back at all.
	Failed  int
	Missing int
}

// QuarantineRow is one archived package.
type QuarantineRow struct {
	repo.QuarantineItem
	When       string
	Restorable bool
}

func (s *Server) handleQuarantine(w http.ResponseWriter, r *http.Request) {
	items, err := s.Quarantined(100)
	if err != nil {
		http.Error(w, "quarantine unavailable: "+err.Error(), http.StatusInternalServerError)
		return
	}

	data := QuarantineData{CanRestore: s.Restore != nil}
	for _, item := range items {
		data.Items = append(data.Items, QuarantineRow{
			QuarantineItem: item,
			When:           item.At.Format("2 Jan 2006, 15:04"),
			Restorable:     item.Restorable(),
		})
		switch item.State {
		case repo.QuarantineFailed:
			data.Failed++
		case repo.QuarantineMissing:
			data.Missing++
		}
	}

	s.render(w, "quarantine", "Quarantine", "quarantine", data)
}

func (s *Server) handleRestore(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/quarantine", http.StatusSeeOther)
		return
	}
	id := r.PostFormValue("id")
	if id == "" {
		http.Redirect(w, r, "/quarantine", http.StatusSeeOther)
		return
	}

	if err := s.Restore(id); err != nil {
		// Shown rather than swallowed into a redirect. A restore that did not
		// reproduce what was taken is the one outcome nobody should have to go
		// looking for.
		http.Error(w, "restore failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/quarantine", http.StatusSeeOther)
}
