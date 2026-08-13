package hub

import (
	"testing"

	"github.com/myselfvivek17/pkgwatch/internal/fleet"
	"github.com/myselfvivek17/pkgwatch/internal/repo"
)

// Sending the full package list hands the hub a map of exploitable software on
// a machine (§3.3), so the hub's own record decides whether it is accepted. An
// agent announcing "full" is a request, not a switch it can throw.
func TestInventoryIsRefusedUntilTheHubIsSetToAcceptIt(t *testing.T) {
	h := newHarness(t)
	id, resp := h.enrol(t)
	if err := h.state.Repo.SetDeviceStatus(id.ID(), repo.DeviceStatusApproved, h.now); err != nil {
		t.Fatal(err)
	}
	client := h.client(id, resp.Token)

	push := fleet.SyncRequest{
		Version: "test", SyncLevel: repo.SyncLevelFull, FindingsComplete: true,
		Packages: []fleet.Package{
			{PURL: "pkg:npm/lodash@4.17.20", Ecosystem: "npm", Name: "lodash",
				Version: "4.17.20", Scope: "project", LastSeen: h.now},
		},
	}

	got, err := client.Push(push)
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	if got.Packages != 0 {
		t.Errorf("stored %d packages while the hub record said findings only", got.Packages)
	}
	if n := packageRows(t, h); n != 0 {
		t.Errorf("%d inventory rows held, want none", n)
	}

	// The decision a person takes on the pairing page.
	if err := h.state.Repo.SetDeviceSyncLevel(id.ID(), repo.SyncLevelFull); err != nil {
		t.Fatal(err)
	}
	got, err = client.Push(push)
	if err != nil {
		t.Fatalf("push after accepting: %v", err)
	}
	if got.Packages != 1 {
		t.Fatalf("stored %d packages after the hub accepted the inventory, want 1", got.Packages)
	}

	// Turning it back off drops what was collected. Keeping it would leave the
	// search page answering from an inventory this hub is no longer allowed to
	// receive, growing staler with every uninstall.
	if err := h.state.Repo.SetDeviceSyncLevel(id.ID(), repo.SyncLevelFindings); err != nil {
		t.Fatal(err)
	}
	if n := packageRows(t, h); n != 0 {
		t.Errorf("%d inventory rows survived being turned off, want none", n)
	}
}

func TestAnUnknownSyncLevelIsRefused(t *testing.T) {
	h := newHarness(t)
	id, _ := h.enrol(t)
	if err := h.state.Repo.SetDeviceSyncLevel(id.ID(), "everything"); err == nil {
		t.Error("a sync level nothing implements was accepted")
	}
}

func packageRows(t *testing.T, h *harness) int {
	t.Helper()
	var n int
	if err := h.state.DB.QueryRow("SELECT COUNT(*) FROM fleet_packages").Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
