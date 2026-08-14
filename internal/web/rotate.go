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

	// ReadOnly is the hub's view. The credentials being rotated are files on
	// each agent and sync is outbound-only (§7), so the hub has no channel to
	// write a tick back down — a checkbox here would be a button that lies.
	ReadOnly bool

	// Machines is the hub's per-machine credential list. Shown with or without
	// a malware finding: what an install script could read is worth knowing
	// before the day it matters, which is the whole argument for the agent's
	// own version of this card.
	Machines []MachineCredentials
}

// MachineCredentials is what one machine reports it holds.
type MachineCredentials struct {
	Hostname string
	Items    []rotate.Item

	// Withheld means this device is not set to send them, so an empty list is
	// "this hub does not receive them" rather than "this machine holds none".
	Withheld bool
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

	// Device and Reach are the hub's columns: which machine owes this work, and
	// how to get to the dashboard that can record it. Agent dashboards bind
	// loopback, so a plain link to the machine would be dead from anywhere else —
	// which is a link that fails silently, the thing this project keeps refusing
	// to ship.
	Device string
	Reach  string

	// Started is false when the hub holds no ticks for this exposure at all.
	// Zero of five and nothing-recorded are different claims, and only one of
	// them is evidence about what the machine has done.
	Started bool
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

// handleFleetRotate is the hub's read-only view of the same page.
//
// Built from the fleet's malware findings rather than from the replicated ticks:
// a tick row only exists once somebody has started, so a page driven by ticks
// would be blank for the one machine that has done nothing about its malware.
func (s *Server) handleFleetRotate(w http.ResponseWriter, r *http.Request) {
	exposures, attached, err := s.FleetExposures()
	if err != nil {
		http.Error(w, "rotation unavailable: "+err.Error(), http.StatusInternalServerError)
		return
	}
	ticks, err := s.FleetRotation()
	if err != nil {
		http.Error(w, "rotation progress unavailable: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Keyed by device as well as finding: the same malicious package on two
	// machines is two rotations, and merging them would let one machine's work
	// mark the other's done.
	type key struct{ device, purl, advisory string }
	byExposure := map[key][]repo.FleetRotationTick{}
	for _, t := range ticks {
		k := key{t.DeviceID, t.PURL, t.AdvisoryID}
		byExposure[k] = append(byExposure[k], t)
	}

	data := RotateData{BundleMissing: !attached, ReadOnly: true}
	for _, e := range exposures {
		exposure := Exposure{
			PURL:       e.PURL,
			AdvisoryID: e.AdvisoryID,
			Summary:    e.Summary,
			Found:      e.DetectedAt.Format("2 Jan 2006, 15:04"),
			Device:     e.Hostname,
			Reach:      reachCommand(e.Hostname),
		}
		for _, t := range byExposure[key{e.DeviceID, e.PURL, e.AdvisoryID}] {
			row := RotateRow{Item: rotate.Describe(t.ItemID)}
			if !t.CheckedAt.IsZero() {
				row.Checked, row.CheckedAt = true, t.CheckedAt.Format("2 Jan, 15:04")
				exposure.Done++
			}
			exposure.Items = append(exposure.Items, row)
		}
		exposure.Total = len(exposure.Items)
		exposure.Started = exposure.Total > 0
		if exposure.Total > 0 {
			exposure.Percent = exposure.Done * 100 / exposure.Total
		}
		data.Exposures = append(data.Exposures, exposure)
	}

	if data.Machines, err = s.fleetCredentials(); err != nil {
		http.Error(w, "credential list unavailable: "+err.Error(), http.StatusInternalServerError)
		return
	}

	s.render(w, "rotate", "Credential rotation", "credentials", data)
}

// fleetCredentials groups the replicated credential rows by machine.
func (s *Server) fleetCredentials() ([]MachineCredentials, error) {
	if s.FleetCredentials == nil {
		return nil, nil
	}
	rows, err := s.FleetCredentials()
	if err != nil {
		return nil, err
	}

	var out []MachineCredentials
	byHost := map[string]int{}
	for _, row := range rows {
		at, seen := byHost[row.DeviceID]
		if !seen {
			out = append(out, MachineCredentials{
				Hostname: row.Hostname,
				Withheld: row.SyncLevel != repo.SyncLevelFull,
			})
			at = len(out) - 1
			byHost[row.DeviceID] = at
		}
		// The empty ItemID is the LEFT JOIN's "this machine reported none" row,
		// which exists so the machine still appears. It is not a credential.
		if row.ItemID == "" {
			continue
		}
		item := rotate.Describe(row.ItemID)
		item.Path = row.Path
		if row.Category != "" {
			item.Category = row.Category
		}
		out[at].Items = append(out[at].Items, item)
	}
	return out, nil
}

// reachCommand is how to open a machine's own dashboard from here.
//
// A hint, not a guarantee: it assumes the hostname resolves over SSH and the
// agent is on its default port. Printed as a command rather than an anchor
// precisely because it may not work — a dead hyperlink says nothing about why.
func reachCommand(hostname string) string {
	if hostname == "" {
		return ""
	}
	return fmt.Sprintf("ssh -L 4875:127.0.0.1:4875 %s", hostname)
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

	// ReadOnly is the hub's view: it holds a replica, and the archive itself is
	// on the machine that made it.
	ReadOnly bool
}

// QuarantineRow is one archived package.
type QuarantineRow struct {
	repo.QuarantineItem
	When       string
	Restorable bool

	// Device names the machine, on the hub. Empty on an agent, where there is
	// only one machine and a column repeating its name is noise.
	Device string

	// PathHeld is false when the origin path did not cross the wire — the row is
	// replicated at findings level, where a filesystem path is withheld. Without
	// this the page cannot tell "taken from nowhere" from "not replicated".
	PathHeld bool
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
			PathHeld:       true,
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

// handleFleetQuarantine is the hub's read-only replica of the same list.
//
// No restore button, and not merely because the hook is nil: the archive is a
// file on the machine that made it, and sync is outbound-only, so there is no
// channel to ask for it back. The page says so rather than leaving a disabled
// control to be read as "broken".
func (s *Server) handleFleetQuarantine(w http.ResponseWriter, r *http.Request) {
	items, err := s.FleetQuarantine(100)
	if err != nil {
		http.Error(w, "quarantine unavailable: "+err.Error(), http.StatusInternalServerError)
		return
	}

	data := QuarantineData{ReadOnly: true}
	for _, q := range items {
		data.Items = append(data.Items, QuarantineRow{
			QuarantineItem: repo.QuarantineItem{
				ID: q.ID, PURL: q.PURL, OriginPath: q.OriginPath,
				AdvisoryID: q.AdvisoryID, State: q.State,
				At: q.At, RestoredAt: q.RestoredAt,
			},
			When:     q.At.Format("2 Jan 2006, 15:04"),
			Device:   q.Hostname,
			PathHeld: q.PathReplicated,
		})
		switch q.State {
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
