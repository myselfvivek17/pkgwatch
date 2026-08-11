package web

import (
	"net/http"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/myselfvivek17/pkgwatch/internal/repo"
)

func inventoryServer(t *testing.T, present, retired []repo.PackageRow, covered []string) http.Handler {
	t.Helper()
	srv, err := New(ModeAgent, "test-host")
	if err != nil {
		t.Fatal(err)
	}
	srv.Overview = func() (OverviewData, error) { return OverviewData{Mode: "agent"}, nil }
	srv.Inventory = func(wantRetired bool, limit int) ([]repo.PackageRow, error) {
		if wantRetired {
			return retired, nil
		}
		return present, nil
	}
	srv.RetirementSummary = func() (int, int, int, error) {
		total, orphaned, renamed := 0, 0, 0
		for _, row := range retired {
			total++
			switch {
			case row.ReplacedBy == "":
				orphaned++
			case row.ReplacedEcosystem != row.Ecosystem:
				renamed++
			}
		}
		return total, orphaned, renamed, nil
	}
	srv.Ecosystems = func() (map[string]int, []string, error) {
		counts := map[string]int{}
		for _, row := range present {
			counts[row.Ecosystem]++
		}
		return counts, covered, nil
	}
	r := chi.NewRouter()
	srv.Routes(r)
	return r
}

func presentRows() []repo.PackageRow {
	return []repo.PackageRow{
		{Ecosystem: "Ubuntu:24.04:LTS", Name: "curl", Version: "8.5.0", Scope: "system",
			InstallDir: "/var/lib/dpkg/status"},
		{Ecosystem: "Ubuntu:22.04:LTS", Name: "curl", Version: "7.81.0", Scope: "container",
			InstallDir: "container:ml (cuda)"},
	}
}

// An ecosystem the bundle does not carry returns no advisories, and no
// advisories looks exactly like nothing wrong. The page has to say which
// packages were actually examined, next to the count — not in a footnote.
func TestInventoryFlagsUnexaminedEcosystems(t *testing.T) {
	h := inventoryServer(t, presentRows(), nil, []string{"Ubuntu:24.04:LTS"})
	body := get(t, h, "/inventory").Body.String()

	if !strings.Contains(body, "pw-eco-uncovered") {
		t.Error("uncovered ecosystem is not visually distinguished")
	}
	if !strings.Contains(body, "unexamined") {
		t.Error("uncovered ecosystem is not labelled")
	}
	if !strings.Contains(body, "not the same as finding nothing wrong") {
		t.Error("the page does not explain what unexamined means")
	}
	// The covered one must not be flagged, or the warning means nothing.
	if strings.Count(body, "pw-eco-uncovered") != 1 {
		t.Errorf("expected exactly one flagged ecosystem, got %d", strings.Count(body, "pw-eco-uncovered"))
	}
}

func retiredRows() []repo.PackageRow {
	return []repo.PackageRow{
		// An ordinary upgrade.
		{Ecosystem: "Alpine:v3.24", Name: "curl", Version: "8.20.0-r1", Scope: "container",
			InstallDir: "container:ha (home-assistant)", GoneAt: 1000,
			ReplacedBy: "8.21.0-r0", ReplacedEcosystem: "Alpine:v3.24"},
		// An ecosystem rename: same version, new identifier.
		{Ecosystem: "Ubuntu:24.04", Name: "bash", Version: "5.2.21", Scope: "system",
			InstallDir: "/var/lib/dpkg/status", GoneAt: 900,
			ReplacedBy: "5.2.21", ReplacedEcosystem: "Ubuntu:24.04:LTS"},
		// Nothing took its place — the only one that might be a lost row.
		{Ecosystem: "Debian:12", Name: "openssl", Version: "3.0.17", Scope: "container",
			InstallDir: "container:gone (dead)", GoneAt: 800},
	}
}

// Retiring a row closes every finding attached to it, so this view is how that
// decision gets audited. Upgrade, rename and disappearance have to be told
// apart, because only the third is ever a bug.
func TestRetiredViewSeparatesLossFromUpgradeAndRename(t *testing.T) {
	h := inventoryServer(t, presentRows(), retiredRows(), []string{"Ubuntu:24.04:LTS"})
	body := get(t, h, "/inventory?view=retired").Body.String()

	if !strings.Contains(body, "8.21.0-r0") {
		t.Error("an upgrade does not name its replacement")
	}
	if !strings.Contains(body, "Ubuntu:24.04:LTS 5.2.21") {
		t.Error("a rename does not show the new ecosystem identifier")
	}
	if !strings.Contains(body, "NOTHING") || !strings.Contains(body, "pw-orphaned") {
		t.Error("a retirement with no replacement is not marked")
	}
	if !strings.Contains(body, "<b>1</b> of all 3 retirements had nothing replacing them") {
		t.Error("orphan count missing, or not stated as a whole-table total")
	}
	if !strings.Contains(body, "<b>1</b> moved to a different ecosystem identifier") {
		t.Error("rename count missing — a bulk rename looks alarming and is not")
	}
}

// Counting only the visible page would let a machine with hundreds of
// unreplaced retirements below the fold report none — the audit losing exactly
// what it exists to catch. Happened on the home server: 466 renames on screen,
// zero orphans reported, 322 real ones further down.
func TestRetiredCountsCoverEveryRowNotThePage(t *testing.T) {
	srv, err := New(ModeAgent, "test-host")
	if err != nil {
		t.Fatal(err)
	}
	srv.Overview = func() (OverviewData, error) { return OverviewData{Mode: "agent"}, nil }
	// One row on the page, all of them replaced. The summary disagrees on
	// purpose: this is the shape of the real failure, where the visible page
	// was all renames and the orphans sat below the fold.
	srv.Inventory = func(bool, int) ([]repo.PackageRow, error) { return retiredRows()[:1], nil }
	srv.RetirementSummary = func() (int, int, int, error) { return 2170, 322, 466, nil }
	srv.Ecosystems = func() (map[string]int, []string, error) {
		return map[string]int{"Debian:12": 1}, []string{"Debian:12"}, nil
	}
	r := chi.NewRouter()
	srv.Routes(r)

	body := get(t, r, "/inventory?view=retired").Body.String()
	if !strings.Contains(body, "<b>322</b> of all 2170 retirements") {
		t.Error("the audit counted the page instead of the table")
	}
	if !strings.Contains(body, "<b>466</b> moved to a different ecosystem") {
		t.Error("rename total not taken from the whole table")
	}
}

// The present view must not quietly imply retired rows do not exist.
func TestInventoryPointsAtItsHistory(t *testing.T) {
	h := inventoryServer(t, presentRows(), retiredRows(), []string{"Ubuntu:24.04:LTS"})
	body := get(t, h, "/inventory").Body.String()
	if !strings.Contains(body, "/inventory?view=retired") {
		t.Error("no link to the retirement history")
	}
}
