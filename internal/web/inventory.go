package web

import (
	"net/http"
	"sort"
	"time"
)

// InventoryData is the inventory page's view model.
type InventoryData struct {
	Rows      []InventoryRow
	Shown     int
	Limit     int
	Truncated bool

	Ecosystems      []EcosystemCount
	EcosystemFilter []Option
	ScopeFilter     []Option
	ViewFilter      []Option

	// Retired switches the table to the retirement audit.
	Retired  bool
	Orphaned int
	Renamed  int

	// Uncovered names ecosystems the inventory holds and the bundle does not,
	// which is the difference between examined and unknown.
	Uncovered []string
}

// InventoryRow is one package, present or retired.
type InventoryRow struct {
	Ecosystem string
	Name      string
	Version   string
	Scope     string
	Where     string

	// Retirement columns, empty on the present view.
	RetiredAt string
	Replaced  string
	Orphaned  bool
	Renamed   bool
}

// EcosystemCount is one row of the coverage summary above the table.
type EcosystemCount struct {
	Ecosystem string
	Count     int
	Covered   bool
}

func (s *Server) handleInventory(w http.ResponseWriter, r *http.Request) {
	ecosystem := r.URL.Query().Get("ecosystem")
	scope := r.URL.Query().Get("scope")
	retired := r.URL.Query().Get("view") == "retired"
	const limit = 500

	data := InventoryData{
		Limit:   limit,
		Retired: retired,
		ViewFilter: options(map[bool]string{true: "retired", false: ""}[retired],
			"", "installed now",
			"retired", "retired — the audit"),
		ScopeFilter: options(scope,
			"", "any scope",
			"global", "global", "project", "project", "venv", "venv",
			"system", "system", "container", "container"),
	}

	counts, covered, err := s.Ecosystems()
	if err != nil {
		http.Error(w, "inventory unavailable: "+err.Error(), http.StatusInternalServerError)
		return
	}
	names := make([]string, 0, len(counts))
	for name := range counts {
		names = append(names, name)
	}
	sort.Strings(names)

	coveredSet := map[string]bool{}
	for _, name := range covered {
		coveredSet[name] = true
	}
	ecosystemOptions := []string{"", "all ecosystems"}
	for _, name := range names {
		isCovered := coveredSet[name]
		data.Ecosystems = append(data.Ecosystems, EcosystemCount{
			Ecosystem: name, Count: counts[name], Covered: isCovered,
		})
		if !isCovered {
			data.Uncovered = append(data.Uncovered, name)
		}
		ecosystemOptions = append(ecosystemOptions, name, name)
	}
	data.EcosystemFilter = options(ecosystem, ecosystemOptions...)

	rows, err := s.Inventory(retired, limit)
	if err != nil {
		http.Error(w, "inventory unavailable: "+err.Error(), http.StatusInternalServerError)
		return
	}

	for _, pkg := range rows {
		if ecosystem != "" && pkg.Ecosystem != ecosystem {
			continue
		}
		if scope != "" && pkg.Scope != scope {
			continue
		}
		row := InventoryRow{
			Ecosystem: pkg.Ecosystem,
			Name:      pkg.Name,
			Version:   pkg.Version,
			Scope:     pkg.Scope,
			Where:     pkg.InstallDir,
		}
		if retired {
			row.RetiredAt = time.Unix(pkg.GoneAt, 0).Format("2006-01-02 15:04")
			switch {
			case pkg.ReplacedBy == "":
				row.Replaced = "NOTHING"
				row.Orphaned = true
				data.Orphaned++
			case pkg.ReplacedEcosystem != pkg.Ecosystem:
				row.Replaced = pkg.ReplacedEcosystem + " " + pkg.ReplacedBy
				row.Renamed = true
				data.Renamed++
			default:
				row.Replaced = pkg.ReplacedBy
			}
		}
		data.Rows = append(data.Rows, row)
	}
	data.Shown = len(data.Rows)
	data.Truncated = len(rows) == limit

	title := "Inventory"
	if retired {
		title = "Inventory — retired"
	}
	s.render(w, "inventory", title, "inventory", data)
}
