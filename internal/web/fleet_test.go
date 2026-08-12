package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/myselfvivek17/pkgwatch/internal/repo"
)

// The fleet page's job is to refuse to render absent data as clean. These
// assertions are that refusal, not the layout.

func fleetServer(t *testing.T, devices []repo.Device, findings map[string]map[string]int) http.Handler {
	t.Helper()
	srv, err := New(ModeHub, "homelab")
	if err != nil {
		t.Fatal(err)
	}
	srv.Overview = func() (OverviewData, error) { return OverviewData{Mode: "hub"}, nil }
	srv.Devices = func() ([]repo.Device, error) { return devices, nil }
	srv.DeviceFindings = func(id string) (map[string]int, error) { return findings[id], nil }
	srv.SetDeviceStatus = func(string, string) error { return nil }

	r := chi.NewRouter()
	srv.Routes(r)
	return r
}

func device(id, host, status string, lastSeen time.Time) repo.Device {
	return repo.Device{
		ID: id, Hostname: host, OS: "linux", Arch: "amd64",
		Status: status, LastSeen: lastSeen, EnrolledAt: time.Now().Add(-24 * time.Hour),
	}
}

func page(t *testing.T, h http.Handler, path string) string {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d", path, rec.Code)
	}
	return rec.Body.String()
}

// The one that matters. A machine that stopped reporting yesterday must not
// show yesterday's numbers as though they were today's.
func TestASilentMachineShowsNoFindingCounts(t *testing.T) {
	stale := device("AAAA-BBBB", "nas", repo.DeviceStatusApproved, time.Now().Add(-3*24*time.Hour))
	body := fleetPage(t, []repo.Device{stale}, map[string]map[string]int{
		"AAAA-BBBB": {"critical": 4, "high": 9},
	})

	if strings.Contains(body, "×4") || strings.Contains(body, "×9") {
		t.Error("an offline machine is showing finding counts — those numbers describe a machine that may have been patched or compromised since")
	}
	if !strings.Contains(body, "NOT REPORTING") {
		t.Error("no NOT REPORTING treatment on a machine that has been silent for three days")
	}
	if !strings.Contains(body, "gate status unknown while offline") {
		t.Error("the card claims to know something about the gate on a machine it cannot reach")
	}
	if !strings.Contains(body, "3d") {
		t.Errorf("the card does not say how long it has been quiet:\n%s", body)
	}
}

// Three states, not two. An approved machine that has never sent anything is a
// different problem from one that stopped, and the naive COALESCE(last_seen,
// now) renders it as online — the exact lie this page exists to prevent.
func TestNeverReportedIsItsOwnState(t *testing.T) {
	fresh := device("CCCC-DDDD", "newbox", repo.DeviceStatusApproved, time.Time{})
	body := fleetPage(t, []repo.Device{fresh}, nil)

	if !strings.Contains(body, "NEVER REPORTED") {
		t.Error("a machine that has never reported is not marked as such")
	}
	if strings.Contains(body, "gate on") {
		t.Error("a machine that has never reported is rendered as healthy")
	}
	if !strings.Contains(body, "check the agent is running") {
		t.Error("the card does not say what to do about it")
	}
}

func TestAReportingMachineShowsItsFindings(t *testing.T) {
	live := device("EEEE-FFFF", "laptop", repo.DeviceStatusApproved, time.Now().Add(-2*time.Minute))
	body := fleetPage(t, []repo.Device{live}, map[string]map[string]int{
		"EEEE-FFFF": {"critical": 2},
	})

	if !strings.Contains(body, "×2") {
		t.Error("a reporting machine is not showing its findings")
	}
	if !strings.Contains(body, "gate on") {
		t.Error("a reporting machine is not shown as gating")
	}
	if strings.Contains(body, "NOT REPORTING") {
		t.Error("a machine that reported two minutes ago is marked offline")
	}
}

// A fleet where every agent has been killed must not read as healthy.
func TestSilentMachinesDriveTheSummaryWord(t *testing.T) {
	quiet := device("AAAA-BBBB", "nas", repo.DeviceStatusApproved, time.Now().Add(-8*time.Hour))
	body := fleetPage(t, []repo.Device{quiet}, nil)

	if strings.Contains(body, "All clear") {
		t.Error("a fleet with nothing reporting summarised as All clear")
	}
	if !strings.Contains(body, "1 not reporting") {
		t.Error("the summary does not count the silent machine")
	}
}

func TestCriticalFindingsRaiseTheBanner(t *testing.T) {
	live := device("EEEE-FFFF", "laptop", repo.DeviceStatusApproved, time.Now())
	body := fleetPage(t, []repo.Device{live}, map[string]map[string]int{
		"EEEE-FFFF": {"critical": 1},
	})
	if !strings.Contains(body, "Needs attention now") {
		t.Error("a critical finding did not raise the summary state")
	}
	if !strings.Contains(body, "machine with critical findings") {
		t.Error("no banner for a critical finding")
	}
}

// An empty fleet is not a clean fleet.
func TestAnEmptyFleetSaysSoWithoutClaimingHealth(t *testing.T) {
	body := fleetPage(t, nil, nil)
	if strings.Contains(body, "All clear") {
		t.Error("a hub with no devices claimed the fleet was clear")
	}
	if !strings.Contains(body, "still gates and still scans") {
		t.Error("the empty state does not say what an unpaired agent is still doing")
	}
}

func TestPendingDeviceIsNotCountedAsHealthy(t *testing.T) {
	waiting := device("1111-2222", "desktop", repo.DeviceStatusPending, time.Time{})
	body := fleetPage(t, []repo.Device{waiting}, nil)

	if strings.Contains(body, "gate on") {
		t.Error("an unapproved device rendered as gating")
	}
	if !strings.Contains(body, "waiting for approval") {
		t.Error("the summary does not mention the device waiting on a person")
	}
}

func TestDevicesPageOffersApprovalAndShowsTheFingerprint(t *testing.T) {
	waiting := device("1111-2222", "desktop", repo.DeviceStatusPending, time.Time{})
	h := fleetServer(t, []repo.Device{waiting}, nil)
	body := page(t, h, "/devices")

	if !strings.Contains(body, "1111-2222") {
		t.Error("the device ID is not shown — it is the fingerprint a person compares")
	}
	if !strings.Contains(body, "character for character") {
		t.Error("the page does not tell anyone to check the ID before approving")
	}
	if !strings.Contains(body, `value="approve"`) {
		t.Error("no approve control")
	}
	if !strings.Contains(body, ">never<") {
		t.Error("a device that has never reported shows something other than 'never'")
	}
}

// Approve and revoke change state. A cross-site page can POST a form here, and
// approving a device is the highest-privilege write in the product.
func TestDeviceActionsRefuseCrossSitePosts(t *testing.T) {
	waiting := device("1111-2222", "desktop", repo.DeviceStatusPending, time.Time{})
	h := fleetServer(t, []repo.Device{waiting}, nil)

	req := httptest.NewRequest(http.MethodPost, "/devices/action",
		strings.NewReader("device=1111-2222&action=approve"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "cross-site")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("cross-site approve = %d, want 403", rec.Code)
	}
}

func fleetPage(t *testing.T, devices []repo.Device, findings map[string]map[string]int) string {
	t.Helper()
	return page(t, fleetServer(t, devices, findings), "/")
}
