package repo_test

import (
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/myselfvivek17/pkgwatch/internal/db"
	"github.com/myselfvivek17/pkgwatch/internal/repo"
)

// The cap is per machine, and a real database says so.
//
// The unit tests above this one drive the page through fixture hooks, so they
// would pass over any SQL at all. This runs the query: a single LIMIT over the
// joined rows returns them ordered by hostname, so a loud machine sorted first
// consumes the whole budget and every machine after it disappears — which on
// the real fleet meant a 1,000-row cap rendering a two-machine fleet as one.
func TestFleetInventoryCapsPerMachineNotPerPage(t *testing.T) {
	handle, err := db.Open(filepath.Join(t.TempDir(), "hub.db"), db.SchemaHub)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()

	hub := repo.Hub{DB: handle}
	seedDevice(t, handle, "AAAA-0001", "aaa-loud")
	seedDevice(t, handle, "ZZZZ-0002", "zzz-quiet")

	// Distinct purls, since the table is keyed on (device, purl).
	loud := make([]repo.FleetPackage, 0, 50)
	for i := 0; i < 50; i++ {
		name := "loud" + strconv.Itoa(i)
		loud = append(loud, repo.FleetPackage{
			PURL: "pkg:npm/" + name + "@1", Ecosystem: "npm", Name: name,
			Version: "1", Scope: "project", LastSeen: time.Now(),
		})
	}
	if _, err := hub.ReplacePackages("AAAA-0001", loud); err != nil {
		t.Fatal(err)
	}
	if _, err := hub.ReplacePackages("ZZZZ-0002", []repo.FleetPackage{{
		PURL: "pkg:npm/lodash@4.17.21", Ecosystem: "npm", Name: "lodash",
		Version: "4.17.21", Scope: "project", LastSeen: time.Now(),
	}}); err != nil {
		t.Fatal(err)
	}

	// A cap far below the loud machine's inventory.
	rows, err := hub.FleetInventory("", "", 5)
	if err != nil {
		t.Fatalf("FleetInventory: %v", err)
	}

	perMachine := map[string]int{}
	var total int
	for _, r := range rows {
		perMachine[r.Hostname]++
		if r.Hostname == "aaa-loud" {
			total = r.Total
		}
	}
	if perMachine["aaa-loud"] != 5 {
		t.Errorf("loud machine returned %d rows, want the cap of 5", perMachine["aaa-loud"])
	}
	if perMachine["zzz-quiet"] != 1 {
		t.Errorf("quiet machine returned %d rows, want 1 — it must not be crowded off the page",
			perMachine["zzz-quiet"])
	}
	// Total is what it has, not what came back, so the page can say the list is short.
	if total != 50 {
		t.Errorf("loud machine reports total %d, want 50", total)
	}
}
