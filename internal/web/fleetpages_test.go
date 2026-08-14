package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/myselfvivek17/pkgwatch/internal/repo"
)

// The hub reports what was blocked and points at the machine holding the chain.
//
// Install sessions and their per-package verdicts never sync, so the one thing
// this page must not do is imply it has the dependency tree. It has the refusal
// and the session id; the chain is on the agent.
func TestTheHubShowsBlockedInstallsWithoutClaimingTheChain(t *testing.T) {
	_, h := hubServerWith(t, func(s *Server) {
		s.FleetBlocks = func(int) ([]repo.FleetBlock, error) {
			return []repo.FleetBlock{{
				DeviceID: "dev-1", Hostname: "laptop", At: time.Now(), Tier: "critical",
				PURL: "pkg:npm/evil@1.0.0", AdvisoryID: "MAL-9",
				Detail: `{"reason":"malware","summary":"steals tokens",` +
					`"fixed_in":"","session_id":"abc123"}`,
			}}, nil
		}
	})
	body := get(t, h, "/sessions").Body.String()

	for _, want := range []string{"laptop", "pkg:npm/evil@1.0.0", "MAL-9", "steals tokens",
		"ssh -L 4875:127.0.0.1:4875 laptop", "/sessions/abc123"} {
		if !strings.Contains(body, want) {
			t.Errorf("%q is missing from the hub's block page", want)
		}
	}
	// No fix is a real answer and must read as one rather than as a blank cell.
	if !strings.Contains(body, "none yet") {
		t.Error("an advisory with no fix rendered as an empty column")
	}
	if !strings.Contains(body, "never synced") {
		t.Error("the page does not say the dependency chain is not here")
	}
	if !strings.Contains(body, "</html>") {
		t.Error("the page stopped before the end of the document")
	}
}

// An empty block list means two different things, and they are not both good.
func TestAnEmptyBlockListSaysWhetherAnyoneIsReporting(t *testing.T) {
	_, h := hubServerWith(t, func(s *Server) {
		s.FleetBlocks = func(int) ([]repo.FleetBlock, error) { return nil, nil }
		s.Devices = func() ([]repo.Device, error) { return nil, nil }
	})
	body := get(t, h, "/sessions").Body.String()

	if !strings.Contains(body, "No machine is reporting") {
		t.Error("an empty fleet rendered as a fleet with nothing blocked")
	}
}

// A machine the hub takes findings from sends no packages at all, and that must
// not render the same as a machine with none.
//
// The same trap as the credential list: absent from the page reads as clean.
func TestFleetInventoryNamesMachinesThatSendNoPackages(t *testing.T) {
	_, h := hubServerWith(t, func(s *Server) {
		s.FleetInventory = func(string, string, int) ([]repo.FleetInventoryRow, error) {
			return []repo.FleetInventoryRow{
				{DeviceID: "dev-1", Hostname: "laptop", SyncLevel: repo.SyncLevelFull,
					Ecosystem: "npm", Name: "lodash", Version: "4.17.21", Scope: "project"},
				// The LEFT JOIN placeholder: a machine, no package.
				{DeviceID: "dev-2", Hostname: "server", SyncLevel: repo.SyncLevelFindings},
			}, nil
		}
		s.FleetEcosystems = func() (map[string]int, error) {
			return map[string]int{"npm": 1, "alpine": 67}, nil
		}
		s.InventoryCoverage = func() ([]string, []string, error) {
			return []string{"npm"}, []string{"alpine"}, nil
		}
	})
	body := get(t, h, "/inventory").Body.String()

	if !strings.Contains(body, "lodash") {
		t.Error("a reported package is missing")
	}
	if !strings.Contains(body, "server") {
		t.Error("a machine sending no inventory vanished from the page")
	}
	if !strings.Contains(body, "accept inventory") {
		t.Error("a withheld inventory rendered as a machine with no packages")
	}
	// Held but matched against nothing is not the same as clean.
	if !strings.Contains(body, "NOT EXAMINED") {
		t.Error("an ecosystem with no bundle is not marked as unexamined")
	}
	if !strings.Contains(body, "agent-only") {
		t.Error("the page does not say the retirement audit and paths are not here")
	}
}

// The hub has no session report and no inventory writes. Both routes must be
// absent rather than answering with something empty.
func TestTheHubHasNoSessionReport(t *testing.T) {
	_, h := hubServerWith(t, func(s *Server) {
		s.FleetBlocks = func(int) ([]repo.FleetBlock, error) { return nil, nil }
	})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/sessions/abc123", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("/sessions/{id} answered %d on a hub, want 404 — the chain is not here", rec.Code)
	}
}
