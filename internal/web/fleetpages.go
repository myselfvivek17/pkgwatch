package web

import (
	"encoding/json"
	"net/http"
	"sort"

	"github.com/myselfvivek17/pkgwatch/internal/repo"
)

// BlocksData backs the hub's install block page.
//
// Deliberately not the agent's session list. Sessions and their per-package
// decisions never leave the machine, so what the hub holds is the blocked
// installs themselves — what was refused and why, with no dependency chain
// behind them. The page says which machine has the chain rather than rendering
// a session id with nothing behind it.
type BlocksData struct {
	Blocks []BlockRow

	// Reporting is how many machines could have contributed. An empty list
	// across a fleet that is reporting means nothing was blocked; across a fleet
	// that is not, it means nobody asked.
	Reporting int
}

// BlockRow is one refused install.
type BlockRow struct {
	Machine    string
	When       string
	Tier       string
	PURL       string
	AdvisoryID string
	Summary    string
	Reason     string
	FixedIn    string

	// SessionID and Reach are how to get to the full report, which lives on the
	// machine that blocked it.
	SessionID string
	Reach     string
}

func (s *Server) handleFleetBlocks(w http.ResponseWriter, r *http.Request) {
	blocks, err := s.FleetBlocks(200)
	if err != nil {
		http.Error(w, "install blocks unavailable: "+err.Error(), http.StatusInternalServerError)
		return
	}

	data := BlocksData{}
	if s.Devices != nil {
		devices, err := s.Devices()
		if err != nil {
			http.Error(w, "devices unavailable: "+err.Error(), http.StatusInternalServerError)
			return
		}
		for _, d := range devices {
			if d.Status == repo.DeviceStatusApproved {
				data.Reporting++
			}
		}
	}

	for _, b := range blocks {
		row := BlockRow{
			Machine: b.Hostname, When: b.At.Format("2 Jan 2006, 15:04"),
			Tier: b.Tier, PURL: b.PURL, AdvisoryID: b.AdvisoryID,
			Reach: reachCommand(b.Hostname),
		}
		// Detail is JSON written by the gate. A row whose detail will not parse
		// is still shown: what was blocked matters more than the trimmings, and
		// dropping it would make a gate that started writing bad JSON look like
		// a gate that stopped blocking.
		var detail struct {
			Reason    string `json:"reason"`
			Summary   string `json:"summary"`
			FixedIn   string `json:"fixed_in"`
			SessionID string `json:"session_id"`
		}
		if b.Detail != "" {
			_ = json.Unmarshal([]byte(b.Detail), &detail)
		}
		row.Reason, row.Summary = detail.Reason, detail.Summary
		row.FixedIn, row.SessionID = detail.FixedIn, detail.SessionID
		data.Blocks = append(data.Blocks, row)
	}

	s.render(w, "blocks", "Install block", "block", data)
}

// FleetInventoryData backs the hub's inventory page.
type FleetInventoryData struct {
	Machines []MachineInventory

	// Ecosystems counts what was reported, and Uncovered names the ecosystems
	// held with no advisories to match them against. Not the same shortfall:
	// one is software nobody sent, the other is software nothing examined.
	Ecosystems []EcosystemCount
	Uncovered  []string

	EcosystemFilter []Option
	ScopeFilter     []Option

	// Total is every row shown across the fleet. Whether a list was cut short
	// is a per-machine fact and lives on MachineInventory.
	Total int
}

// MachineInventory is one machine's packages, or its reason for having none.
type MachineInventory struct {
	Hostname string
	Rows     []InventoryRow

	// Withheld means this hub takes findings only from this machine, so an
	// empty list is a setting rather than an empty machine.
	Withheld bool

	// Total is what this machine actually has; len(Rows) is what fitted. The
	// two differ per machine, so the notice has to be per machine — a single
	// page-level "truncated" line cannot say which list is short.
	Total int
}

// Truncated reports whether this machine's list stops short of its inventory.
func (m MachineInventory) Truncated() bool { return m.Total > len(m.Rows) }

func (s *Server) handleFleetInventory(w http.ResponseWriter, r *http.Request) {
	ecosystem := r.URL.Query().Get("ecosystem")
	scope := r.URL.Query().Get("scope")

	// Per machine, not per page: a page-wide cap silently drops whole machines
	// off the end of the fleet.
	const perMachine = 400

	rows, err := s.FleetInventory(ecosystem, scope, perMachine)
	if err != nil {
		http.Error(w, "inventory unavailable: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// The same hook the agent's page uses, so "examined" has one definition.
	// Coverage is matched per release — Ubuntu:22.04:LTS is not covered by a
	// bundle carrying Ubuntu:24.04:LTS — and an ecosystem the bundle does not
	// name has no records at all, which must read as unknown rather than clean.
	counts, covered, err := s.Ecosystems()
	if err != nil {
		http.Error(w, "inventory unavailable: "+err.Error(), http.StatusInternalServerError)
		return
	}
	coveredSet := map[string]bool{}
	for _, name := range covered {
		coveredSet[name] = true
	}

	data := FleetInventoryData{
		ScopeFilter: options(scope,
			"", "any scope",
			"global", "global", "project", "project", "venv", "venv",
			"system", "system", "container", "container"),
	}

	names := make([]string, 0, len(counts))
	for name := range counts {
		names = append(names, name)
	}
	sort.Strings(names)

	ecosystemOptions := []string{"", "all ecosystems"}
	for _, name := range names {
		data.Ecosystems = append(data.Ecosystems, EcosystemCount{
			Ecosystem: name, Count: counts[name], Covered: coveredSet[name],
		})
		if !coveredSet[name] {
			data.Uncovered = append(data.Uncovered, name)
		}
		ecosystemOptions = append(ecosystemOptions, name, name)
	}
	data.EcosystemFilter = options(ecosystem, ecosystemOptions...)

	at := map[string]int{}
	for _, row := range rows {
		i, seen := at[row.DeviceID]
		if !seen {
			data.Machines = append(data.Machines, MachineInventory{
				Hostname: row.Hostname,
				Withheld: row.SyncLevel != repo.SyncLevelFull,
				Total:    row.Total,
			})
			i = len(data.Machines) - 1
			at[row.DeviceID] = i
		}
		if !row.Reported() {
			continue
		}
		data.Machines[i].Rows = append(data.Machines[i].Rows, InventoryRow{
			Ecosystem: row.Ecosystem, Name: row.Name,
			Version: row.Version, Scope: row.Scope,
		})
		data.Total++
	}

	s.render(w, "fleet-inventory", "Inventory", "inventory", data)
}
