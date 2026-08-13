package hub

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/myselfvivek17/pkgwatch/internal/db"
	"github.com/myselfvivek17/pkgwatch/internal/device"
	"github.com/myselfvivek17/pkgwatch/internal/fleet"
	"github.com/myselfvivek17/pkgwatch/internal/repo"
	"github.com/myselfvivek17/pkgwatch/internal/secret"
)

// The pairing and sync path is a trust boundary reachable from the whole LAN,
// so §12's rejection list gets exercised end to end over real HTTP: expired
// code, reused code, bad signature, clock skew, revoked token.

type harness struct {
	state *State
	url   string
	now   time.Time
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	handle, err := db.Open(filepath.Join(t.TempDir(), "hub.db"), db.SchemaHub)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { handle.Close() })

	h := &harness{
		state: &State{
			DB: handle, Repo: repo.Hub{DB: handle},
			Hostname: "test-hub", BundleDir: t.TempDir(),
		},
		now: time.Now(),
	}
	router := chi.NewRouter()
	h.state.API(router, func() time.Time { return h.now })

	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)
	h.url = srv.URL
	return h
}

// code issues a live pairing code.
func (h *harness) code(t *testing.T) string {
	t.Helper()
	code, err := secret.PairCode()
	if err != nil {
		t.Fatal(err)
	}
	if err := h.state.Repo.IssuePairCode(code, h.now); err != nil {
		t.Fatal(err)
	}
	return code
}

func (h *harness) client(id device.Identity, token string) *fleet.Client {
	return &fleet.Client{
		BaseURL: h.url, Token: token, Identity: id,
		Now: func() time.Time { return h.now },
	}
}

func (h *harness) enrollRequest(id device.Identity, code string) fleet.EnrollRequest {
	return fleet.EnrollRequest{
		DeviceID:  id.ID(),
		PublicKey: device.EncodePublic(id.Public),
		Code:      code,
		Hostname:  "laptop",
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		Version:   "test",
	}
}

// enrol pairs a fresh device and returns it, still pending.
func (h *harness) enrol(t *testing.T) (device.Identity, fleet.EnrollResponse) {
	t.Helper()
	id, err := device.Generate()
	if err != nil {
		t.Fatal(err)
	}
	resp, err := h.client(id, "").Enroll(h.enrollRequest(id, h.code(t)))
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	return id, resp
}

func apiError(t *testing.T, err error) fleet.APIError {
	t.Helper()
	var apiErr fleet.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("err = %v, want a refusal from the hub", err)
	}
	return apiErr
}

func TestEnrolmentLandsPendingNotApproved(t *testing.T) {
	h := newHarness(t)
	id, resp := h.enrol(t)

	if resp.DeviceID != id.ID() {
		t.Errorf("device ID = %q, want %q", resp.DeviceID, id.ID())
	}
	if resp.Status != repo.DeviceStatusPending {
		t.Errorf("status = %q — a device that approved itself makes the fingerprint check decorative", resp.Status)
	}
	if resp.Token == "" {
		t.Error("no token issued")
	}

	stored, err := h.state.Repo.Device(id.ID())
	if err != nil {
		t.Fatal(err)
	}
	if stored.TokenHash == resp.Token {
		t.Error("the token is stored in the clear")
	}
	if !secret.Verify(resp.Token, stored.TokenHash) {
		t.Error("the stored hash does not match the issued token")
	}
}

// Single use, and atomically so: the UPDATE ... WHERE used_at IS NULL is what
// stops two concurrent enrolments both succeeding.
func TestAPairingCodeWorksOnceOnly(t *testing.T) {
	h := newHarness(t)
	code := h.code(t)

	first, _ := device.Generate()
	if _, err := h.client(first, "").Enroll(h.enrollRequest(first, code)); err != nil {
		t.Fatalf("first enrolment: %v", err)
	}

	second, _ := device.Generate()
	_, err := h.client(second, "").Enroll(h.enrollRequest(second, code))
	if err == nil {
		t.Fatal("the same code enrolled a second device")
	}
	if got := apiError(t, err).Code; got != fleet.CodeAuth {
		t.Errorf("code = %q, want an auth refusal", got)
	}
}

func TestAnExpiredPairingCodeIsRefused(t *testing.T) {
	h := newHarness(t)
	code := h.code(t)

	h.now = h.now.Add(repo.PairCodeTTL + time.Minute)

	id, _ := device.Generate()
	if _, err := h.client(id, "").Enroll(h.enrollRequest(id, code)); err == nil {
		t.Fatal("an expired code still enrolled a device")
	}
}

func TestAnUnknownPairingCodeIsRefused(t *testing.T) {
	h := newHarness(t)
	id, _ := device.Generate()
	if _, err := h.client(id, "").Enroll(h.enrollRequest(id, "AAAA-BBBB")); err == nil {
		t.Fatal("a code that was never issued enrolled a device")
	}
}

// The signature is checked before the code is spent, so a caller who cannot
// prove key possession cannot burn somebody else's pairing code by guessing.
func TestAFailedSignatureDoesNotBurnTheCode(t *testing.T) {
	h := newHarness(t)
	code := h.code(t)

	attacker, _ := device.Generate()
	victim, _ := device.Generate()
	// Claims the victim's key while signing with its own.
	forged := h.enrollRequest(attacker, code)
	forged.PublicKey = device.EncodePublic(victim.Public)
	forged.DeviceID = victim.ID()
	if _, err := h.client(attacker, "").Enroll(forged); err == nil {
		t.Fatal("a request signed by one key enrolled another key")
	}

	// The code must still work for its rightful holder.
	if _, err := h.client(victim, "").Enroll(h.enrollRequest(victim, code)); err != nil {
		t.Errorf("the code was burned by a failed attempt: %v", err)
	}
}

// The ID is what a person compares by eye. A device that could pick one
// unrelated to its key would make that comparison meaningless.
func TestDeviceIDMustMatchTheKey(t *testing.T) {
	h := newHarness(t)
	id, _ := device.Generate()
	req := h.enrollRequest(id, h.code(t))
	req.DeviceID = "AAAA-BBBB-CCCC-DDDD"

	if _, err := h.client(id, "").Enroll(req); err == nil {
		t.Fatal("a device chose an ID unrelated to its key")
	}
}

func TestApprovedDeviceCanSync(t *testing.T) {
	h := newHarness(t)
	id, resp := h.enrol(t)
	if err := h.state.Repo.SetDeviceStatus(id.ID(), repo.DeviceStatusApproved, h.now); err != nil {
		t.Fatal(err)
	}

	out, err := h.client(id, resp.Token).Push(fleet.SyncRequest{
		Version: "test",
		Events: []fleet.Event{
			{AgentID: 1, At: h.now, Kind: "scan"},
			{AgentID: 2, At: h.now, Kind: "finding_new", Severity: "critical", PURL: "pkg:npm/lodash@4.17.20"},
		},
		Findings: []fleet.Finding{
			{PURL: "pkg:npm/lodash@4.17.20", AdvisoryID: "GHSA-x", Tier: "high", Score: 7.5, State: "new", DetectedAt: h.now},
		},
		FindingsComplete: true,
	})
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	if out.Events != 2 || out.Findings != 1 {
		t.Errorf("accepted %d events / %d findings, want 2 / 1", out.Events, out.Findings)
	}
	if out.AcceptedThrough != 2 {
		t.Errorf("AcceptedThrough = %d, want 2", out.AcceptedThrough)
	}

	stored, err := h.state.Repo.Device(id.ID())
	if err != nil {
		t.Fatal(err)
	}
	if !stored.EverReported() {
		t.Error("a successful push did not record a check-in")
	}
}

func TestPendingDeviceCannotSyncAndIsToldWhy(t *testing.T) {
	h := newHarness(t)
	id, resp := h.enrol(t)

	_, err := h.client(id, resp.Token).Push(fleet.SyncRequest{Version: "test"})
	apiErr := apiError(t, err)
	if !apiErr.Pending() {
		t.Errorf("code = %q, want %q — pending is a wait, and an agent needs to tell it from a stop",
			apiErr.Code, fleet.CodePending)
	}
}

// Revocation stops sync. It must be distinguishable from an unreachable hub, or
// the agent retries into a backoff forever and looks healthy while reporting
// nothing.
func TestRevokedDeviceIsRefusedWithAReasonItCanActOn(t *testing.T) {
	h := newHarness(t)
	id, resp := h.enrol(t)
	client := h.client(id, resp.Token)

	if err := h.state.Repo.SetDeviceStatus(id.ID(), repo.DeviceStatusApproved, h.now); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Push(fleet.SyncRequest{Version: "test"}); err != nil {
		t.Fatalf("approved push: %v", err)
	}

	if err := h.state.Repo.SetDeviceStatus(id.ID(), repo.DeviceStatusRevoked, h.now); err != nil {
		t.Fatal(err)
	}
	_, err := client.Push(fleet.SyncRequest{Version: "test"})
	if apiErr := apiError(t, err); !apiErr.Revoked() {
		t.Errorf("code = %q, want %q", apiErr.Code, fleet.CodeRevoked)
	}
}

func TestAWrongTokenIsRefused(t *testing.T) {
	h := newHarness(t)
	id, _ := h.enrol(t)
	if err := h.state.Repo.SetDeviceStatus(id.ID(), repo.DeviceStatusApproved, h.now); err != nil {
		t.Fatal(err)
	}

	_, err := h.client(id, "not the token").Push(fleet.SyncRequest{Version: "test"})
	if apiErr := apiError(t, err); apiErr.Code != fleet.CodeAuth {
		t.Errorf("code = %q, want an auth refusal", apiErr.Code)
	}
}

// A leaked token alone must not be enough (§4) — that is the whole reason the
// protocol carries a signature as well.
//
// Built by hand rather than through the client, because the client derives the
// device header from the identity it signs with. Going through it would send
// the thief's own ID and be refused as an unknown device, which is a different
// check passing and would still pass with signature verification deleted.
func TestALeakedTokenWithoutTheKeyIsUseless(t *testing.T) {
	h := newHarness(t)
	victim, resp := h.enrol(t)
	if err := h.state.Repo.SetDeviceStatus(victim.ID(), repo.DeviceStatusApproved, h.now); err != nil {
		t.Fatal(err)
	}

	body := []byte(`{"agent_version":"test"}`)
	req, err := http.NewRequest(http.MethodPost, h.url+fleet.PathSync, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+resp.Token)

	// The stolen token, the victim's device ID — and a signature from a key the
	// thief made up, because the victim's private key never left that machine.
	thief, _ := device.Generate()
	thief.Sign(req, body, h.now)
	req.Header.Set(device.HeaderDevice, victim.ID())

	got, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer got.Body.Close()
	if got.StatusCode == http.StatusOK {
		t.Fatal("a stolen token alone was enough to sync")
	}
	if got.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", got.StatusCode)
	}
}

func TestClockSkewIsRefusedInBothDirections(t *testing.T) {
	h := newHarness(t)
	id, resp := h.enrol(t)
	if err := h.state.Repo.SetDeviceStatus(id.ID(), repo.DeviceStatusApproved, h.now); err != nil {
		t.Fatal(err)
	}

	for _, drift := range []time.Duration{-device.MaxSkew - time.Minute, device.MaxSkew + time.Minute} {
		skewed := h.client(id, resp.Token)
		stamp := h.now.Add(drift)
		skewed.Now = func() time.Time { return stamp }

		if _, err := skewed.Push(fleet.SyncRequest{Version: "test"}); err == nil {
			t.Errorf("a request %v out of step was accepted", drift)
		}
	}
}

// Replay is absorbed by UNIQUE(device_id, agent_event_id), which is why there
// is no nonce store: a lost acknowledgement means the agent re-sends, and that
// has to be harmless rather than a duplicate.
func TestReplayingAPushDuplicatesNothing(t *testing.T) {
	h := newHarness(t)
	id, resp := h.enrol(t)
	if err := h.state.Repo.SetDeviceStatus(id.ID(), repo.DeviceStatusApproved, h.now); err != nil {
		t.Fatal(err)
	}
	client := h.client(id, resp.Token)

	push := fleet.SyncRequest{
		Version: "test",
		Events:  []fleet.Event{{AgentID: 7, At: h.now, Kind: "scan"}},
	}
	if _, err := client.Push(push); err != nil {
		t.Fatal(err)
	}
	again, err := client.Push(push)
	if err != nil {
		t.Fatal(err)
	}
	if again.Events != 0 {
		t.Errorf("a replayed push inserted %d events, want 0", again.Events)
	}
	// Still acknowledged through 7 — the agent must be able to advance its
	// cursor past events the hub already holds, or it re-sends them forever.
	if again.AcceptedThrough != 7 {
		t.Errorf("AcceptedThrough = %d, want 7", again.AcceptedThrough)
	}

	var stored int
	if err := h.state.DB.QueryRow("SELECT COUNT(*) FROM fleet_events").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != 1 {
		t.Errorf("%d rows stored, want 1", stored)
	}
}

// A partial snapshot applied as a replacement would delete every finding it
// left out, rendering the machine cleaner than it is.
func TestAnIncompleteFindingsSnapshotIsNotAppliedAsOne(t *testing.T) {
	h := newHarness(t)
	id, resp := h.enrol(t)
	if err := h.state.Repo.SetDeviceStatus(id.ID(), repo.DeviceStatusApproved, h.now); err != nil {
		t.Fatal(err)
	}
	client := h.client(id, resp.Token)

	full := []fleet.Finding{
		{PURL: "pkg:npm/a@1", AdvisoryID: "GHSA-1", Tier: "high", State: "new", DetectedAt: h.now},
		{PURL: "pkg:npm/b@1", AdvisoryID: "GHSA-2", Tier: "low", State: "new", DetectedAt: h.now},
	}
	if _, err := client.Push(fleet.SyncRequest{Version: "test", Findings: full, FindingsComplete: true}); err != nil {
		t.Fatal(err)
	}

	// A truncated push that does not claim completeness must change nothing.
	if _, err := client.Push(fleet.SyncRequest{
		Version:          "test",
		Findings:         full[:1],
		FindingsComplete: false,
	}); err != nil {
		t.Fatal(err)
	}

	counts, err := h.state.Repo.FleetFindingCounts(id.ID())
	if err != nil {
		t.Fatal(err)
	}
	if counts["high"]+counts["low"] != 2 {
		t.Errorf("findings = %v, want both still on file", counts)
	}
}

// Closure has to be able to reach the hub. A delta can only ever add, so a
// snapshot is the only shape that carries a finding going away.
func TestASnapshotCarriesClosure(t *testing.T) {
	h := newHarness(t)
	id, resp := h.enrol(t)
	if err := h.state.Repo.SetDeviceStatus(id.ID(), repo.DeviceStatusApproved, h.now); err != nil {
		t.Fatal(err)
	}
	client := h.client(id, resp.Token)

	if _, err := client.Push(fleet.SyncRequest{
		Version: "test",
		Findings: []fleet.Finding{
			{PURL: "pkg:npm/a@1", AdvisoryID: "GHSA-1", Tier: "critical", State: "new", DetectedAt: h.now},
		},
		FindingsComplete: true,
	}); err != nil {
		t.Fatal(err)
	}

	// The package was upgraded; the agent's next snapshot no longer holds it.
	if _, err := client.Push(fleet.SyncRequest{
		Version: "test", Findings: nil, FindingsComplete: true,
	}); err != nil {
		t.Fatal(err)
	}

	counts, err := h.state.Repo.FleetFindingCounts(id.ID())
	if err != nil {
		t.Fatal(err)
	}
	if counts["critical"] != 0 {
		t.Errorf("critical = %d, want 0 — the hub's counts can only climb otherwise", counts["critical"])
	}
}

// Inventory is volunteered by the agent but gated by the hub's record of the
// level, so a compromised agent cannot start sending a map of exploitable
// software on its machine (§3.3).
func TestPackagesAreIgnoredBelowFullSyncLevel(t *testing.T) {
	h := newHarness(t)
	id, resp := h.enrol(t)
	if err := h.state.Repo.SetDeviceStatus(id.ID(), repo.DeviceStatusApproved, h.now); err != nil {
		t.Fatal(err)
	}

	out, err := h.client(id, resp.Token).Push(fleet.SyncRequest{
		Version:   "test",
		SyncLevel: "full", // claimed by the agent
		Packages:  []fleet.Package{{PURL: "pkg:npm/a@1", Ecosystem: "npm", Name: "a", Version: "1"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Packages != 0 {
		t.Errorf("stored %d packages — the hub's own record of the level must decide", out.Packages)
	}
}

func TestAnUnknownDeviceIsRefused(t *testing.T) {
	h := newHarness(t)
	stranger, _ := device.Generate()

	_, err := h.client(stranger, "any token").Push(fleet.SyncRequest{Version: "test"})
	if apiErr := apiError(t, err); apiErr.Code != fleet.CodeUnknown {
		t.Errorf("code = %q, want %q", apiErr.Code, fleet.CodeUnknown)
	}
}
