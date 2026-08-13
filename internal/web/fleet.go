package web

import (
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/myselfvivek17/pkgwatch/internal/repo"
)

// OfflineAfter is how long a device may stay quiet before the fleet page says
// so.
//
// Agents push every five minutes, so half an hour is six missed pushes — long
// enough to ride out a reboot or a sleeping laptop, short enough that a machine
// that has genuinely stopped is named the same day.
const OfflineAfter = 30 * time.Minute

// Machine is one card on the fleet page.
type Machine struct {
	Device   repo.Device
	Findings map[string]int
	Now      time.Time
}

// Reporting is the only state that may render as a normal card.
func (m Machine) Reporting() bool {
	return m.Device.Approved() && m.Device.EverReported() &&
		m.Now.Sub(m.Device.LastSeen) < OfflineAfter
}

// NeverReported is the third state, and the one a naive query loses.
//
// An approved machine that has never sent anything and one that stopped sending
// yesterday are different problems. Reading last_seen_at through a COALESCE to
// now would render the first as online — which is exactly the lie the offline
// card exists to prevent — and treating NULL as a very old timestamp would
// report it as offline since 1970.
func (m Machine) NeverReported() bool {
	return m.Device.Approved() && !m.Device.EverReported()
}

// Pending is a device waiting on a person, not a machine that has gone wrong.
func (m Machine) Pending() bool { return m.Device.Status == repo.DeviceStatusPending }

// Revoked devices are kept on the page rather than hidden. A machine you
// stopped trusting is still a machine on your network.
func (m Machine) Revoked() bool { return m.Device.Status == repo.DeviceStatusRevoked }

// Silence is how long since this device last reported.
func (m Machine) Silence() string {
	if !m.Device.EverReported() {
		return ""
	}
	return humanDuration(m.Now.Sub(m.Device.LastSeen))
}

// FindingTiers are the badge inputs, worst first.
func (m Machine) FindingTiers() []Badge {
	out := make([]Badge, 0, len(repo.Tiers))
	for _, tier := range repo.Tiers {
		if n := m.Findings[tier]; n > 0 {
			out = append(out, Badge{Tier: tier, Size: "sm", Count: n})
		}
	}
	return out
}

// Note is the card's one line of plain English.
//
// A machine that is not reporting never gets a count, not even zero. The last
// numbers it sent describe a machine that may have been patched, compromised or
// switched off since, and presenting them as current is the failure this whole
// project keeps finding.
//
// Empty for a healthy machine that has findings: the badges above it already
// say everything, and "reporting" underneath a line reading "last reported 3m
// ago" is the same fact twice.
func (m Machine) Note() string {
	switch {
	case m.Pending():
		return "enrolled, not approved. Nothing from this machine is being accepted."
	case m.Revoked():
		return "revoked. Still gating installs locally, reporting to nobody."
	case m.NeverReported():
		return "approved but never reported. Check the agent is running there."
	case !m.Reporting():
		return "gate status unknown while offline"
	case len(m.FindingTiers()) == 0:
		return "no open findings"
	default:
		return ""
	}
}

// FleetData backs the fleet overview page.
type FleetData struct {
	Machines []Machine
	Now      time.Time

	// Critical counts machines with at least one critical finding, among those
	// actually reporting. It drives the banner.
	Critical int
}

// State is the summary word, derived rather than stored.
//
// A machine that has stopped reporting counts as needing attention. Deriving
// "all clear" from the findings of machines that are still talking would mean a
// fleet where every agent had been killed reads as perfectly healthy.
func (f FleetData) State() string {
	switch {
	case f.Critical > 0:
		return "Needs attention now"
	case f.Unreporting() > 0 || f.Waiting() > 0:
		return "Needs a look"
	default:
		return "All clear"
	}
}

func (f FleetData) StateClass() string {
	switch f.State() {
	case "Needs attention now":
		return "is-critical"
	case "Needs a look":
		return "is-warn"
	default:
		return "is-clear"
	}
}

// Unreporting counts approved machines that are silent, whether they have never
// reported or have stopped.
func (f FleetData) Unreporting() int {
	n := 0
	for _, m := range f.Machines {
		if m.Device.Approved() && !m.Reporting() {
			n++
		}
	}
	return n
}

func (f FleetData) Waiting() int {
	n := 0
	for _, m := range f.Machines {
		if m.Pending() {
			n++
		}
	}
	return n
}

func (f FleetData) Reporting() int {
	n := 0
	for _, m := range f.Machines {
		if m.Reporting() {
			n++
		}
	}
	return n
}

func (f FleetData) Empty() bool { return len(f.Machines) == 0 }

// humanDuration renders a silence the way the design does: "3d 4h", "12m".
func humanDuration(d time.Duration) string {
	if d < time.Minute {
		return "just now"
	}
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60

	var parts []string
	if days > 0 {
		parts = append(parts, itoa(days)+"d")
	}
	if hours > 0 {
		parts = append(parts, itoa(hours)+"h")
	}
	// Minutes only when the whole thing is under a day; "3d 4h 12m" is more
	// precision than a silence warrants.
	if days == 0 && minutes > 0 {
		parts = append(parts, itoa(minutes)+"m")
	}
	if len(parts) == 0 {
		return "just now"
	}
	return strings.Join(parts, " ")
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

func (s *Server) handleFleet(w http.ResponseWriter, r *http.Request) {
	devices, err := s.Devices()
	if err != nil {
		http.Error(w, "devices unavailable: "+err.Error(), http.StatusInternalServerError)
		return
	}

	now := time.Now()
	data := FleetData{Now: now}
	for _, d := range devices {
		m := Machine{Device: d, Now: now}
		// Counts are only read for machines that are actually reporting. Reading
		// them for a silent one would put a number on the card, and any number
		// there reads as current.
		if d.Approved() {
			if m.Findings, err = s.DeviceFindings(d.ID); err != nil {
				http.Error(w, "findings unavailable: "+err.Error(), http.StatusInternalServerError)
				return
			}
		}
		if m.Reporting() && m.Findings["critical"] > 0 {
			data.Critical++
		}
		data.Machines = append(data.Machines, m)
	}

	// Anything wanting a person first: pending, then silent, then the rest.
	sort.SliceStable(data.Machines, func(i, j int) bool {
		return machineRank(data.Machines[i]) < machineRank(data.Machines[j])
	})

	s.render(w, "fleet", "Fleet overview", "overview", data)
}

func machineRank(m Machine) int {
	switch {
	case m.Pending():
		return 0
	case m.Device.Approved() && !m.Reporting():
		return 1
	case m.Revoked():
		return 3
	default:
		return 2
	}
}

// SearchData backs the cross-machine package search.
//
// NotSearched is not a footnote. Sync level defaults to findings, so on a
// default fleet no machine has sent an inventory and every search correctly
// returns nothing — which reads as "you do not have it" unless the page says
// which machines were actually looked at.
type SearchData struct {
	Query       string
	Hits        []repo.FleetSearchHit
	Searched    []string
	NotSearched []string
}

func (d SearchData) Asked() bool { return d.Query != "" }

func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	data := SearchData{Query: strings.TrimSpace(r.URL.Query().Get("q"))}

	var err error
	if data.Searched, data.NotSearched, err = s.InventoryCoverage(); err != nil {
		http.Error(w, "coverage unavailable: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if data.Asked() {
		if data.Hits, err = s.SearchPackages(data.Query); err != nil {
			http.Error(w, "search failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
	s.render(w, "search", "Package search", "search", data)
}

// handleDevices renders the pairing page.
func (s *Server) handleDevices(w http.ResponseWriter, r *http.Request) {
	devices, err := s.Devices()
	if err != nil {
		http.Error(w, "devices unavailable: "+err.Error(), http.StatusInternalServerError)
		return
	}
	now := time.Now()
	rows := make([]Machine, 0, len(devices))
	for _, d := range devices {
		rows = append(rows, Machine{Device: d, Now: now})
	}
	s.render(w, "devices", "Device pairing", "pairing", DevicesData{
		Devices:         rows,
		CanSetSyncLevel: s.SetDeviceSyncLevel != nil,
		Problem:         r.URL.Query().Get("problem"),
		Done:            r.URL.Query().Get("done"),
	})
}

// DevicesData backs the pairing page.
type DevicesData struct {
	Devices []Machine

	// CanSetSyncLevel hides the inventory control when nothing is wired to
	// serve it, on the same rule as the nav: a button is a promise.
	CanSetSyncLevel bool

	Problem string
	Done    string
}

// handleDeviceAction approves or revokes.
func (s *Server) handleDeviceAction(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/devices?problem=could+not+read+that+form", http.StatusSeeOther)
		return
	}
	id := r.PostFormValue("device")
	action := r.PostFormValue("action")

	// Inventory is a separate decision from trust. A machine can be approved to
	// report findings for years without this hub ever holding a list of what is
	// installed on it, which is why it is its own control rather than something
	// approval turns on.
	if action == "inventory-on" || action == "inventory-off" {
		if s.SetDeviceSyncLevel == nil {
			http.Redirect(w, r, "/devices?problem=this+hub+cannot+change+sync+levels", http.StatusSeeOther)
			return
		}
		level := repo.SyncLevelFindings
		if action == "inventory-on" {
			level = repo.SyncLevelFull
		}
		if err := s.SetDeviceSyncLevel(id, level); err != nil {
			http.Redirect(w, r, "/devices?problem="+urlSafe(err.Error()), http.StatusSeeOther)
			return
		}
		note := id + " now sends findings only; its inventory has been dropped from this hub"
		if level == repo.SyncLevelFull {
			note = id + " may now send its inventory — it arrives on that machine's next sync, " +
				"and only if its own config also says full"
		}
		http.Redirect(w, r, "/devices?done="+urlSafe(note), http.StatusSeeOther)
		return
	}

	status := repo.DeviceStatusRevoked
	if action == "approve" {
		status = repo.DeviceStatusApproved
	}
	if err := s.SetDeviceStatus(id, status); err != nil {
		http.Redirect(w, r, "/devices?problem="+urlSafe(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/devices?done="+urlSafe(id+" is now "+status), http.StatusSeeOther)
}

func urlSafe(s string) string { return url.QueryEscape(s) }
