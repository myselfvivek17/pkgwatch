package hub

import (
	"bytes"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/myselfvivek17/pkgwatch/internal/bundle"
	"github.com/myselfvivek17/pkgwatch/internal/device"
	"github.com/myselfvivek17/pkgwatch/internal/fleet"
	"github.com/myselfvivek17/pkgwatch/internal/repo"
)

// stageOnHub writes a bundle into the relay directory, with or without the
// manifest that carries its signature.
func stageOnHub(t *testing.T, h *harness, name, scope, version string, data []byte, withManifest bool) string {
	t.Helper()
	path := filepath.Join(h.state.BundleDir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if withManifest {
		manifest := bundle.Manifest{
			Version: version, Scope: scope,
			SHA256: bundle.Digest(data), Size: int64(len(data)), BuiltAt: h.now,
		}
		if err := bundle.SaveManifest(path, manifest, []byte("signature-bytes")); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

// approved enrols a device and approves it, which is what a person does on the
// hub's device page.
func (h *harness) approved(t *testing.T) *fleet.Client {
	t.Helper()
	id, resp := h.enrol(t)
	if err := h.state.Repo.SetDeviceStatus(id.ID(), repo.DeviceStatusApproved, h.now); err != nil {
		t.Fatal(err)
	}
	return h.client(id, resp.Token)
}

// The relay hands over exactly what it holds, and the manifest travels with it.
// Without the manifest the agent has no signature to check the bytes against,
// which would leave "the hub sent it" as the only reason to trust them.
func TestTheRelayOffersOnlyBundlesItCanProve(t *testing.T) {
	h := newHarness(t)
	payload := []byte("advisory-bundle-bytes")
	stageOnHub(t, h, "advisories-npm.db", "npm", "20260808", payload, true)
	stageOnHub(t, h, "advisories-debian-12.db", "Debian:12", "20260808", []byte("orphan"), false)

	client := h.approved(t)
	offers, err := client.Bundles()
	if err != nil {
		t.Fatalf("list bundles: %v", err)
	}
	if len(offers) != 1 {
		t.Fatalf("got %d offers, want the one bundle with a manifest: %+v", len(offers), offers)
	}
	if offers[0].Manifest.Scope != "npm" || offers[0].Manifest.Signature == "" {
		t.Errorf("offer = %+v, want the npm scope and a signature", offers[0].Manifest)
	}

	got, err := client.FetchBundle(offers[0].File)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("relayed %q, want %q", got, payload)
	}

	// The bundle with no manifest is not merely unlisted, it is unreachable.
	// Offering it by another route would hand over bytes nothing can check.
	if _, err := client.FetchBundle("advisories-debian-12.db"); err == nil {
		t.Error("a bundle with no manifest was served anyway")
	}
}

// Revoking a machine has to cut both directions with one decision. A device
// that could still pull bundles after being revoked would keep looking like a
// managed machine to whoever revoked it.
func TestTheRelayRefusesDevicesThatAreNotApproved(t *testing.T) {
	h := newHarness(t)
	stageOnHub(t, h, "advisories-npm.db", "npm", "20260808", []byte("bytes"), true)

	id, resp := h.enrol(t)
	pending := h.client(id, resp.Token)
	if _, err := pending.Bundles(); err == nil {
		t.Fatal("an unapproved device was handed the bundle list")
	} else if got := apiError(t, err).Code; got != fleet.CodePending {
		t.Errorf("code = %q, want %q", got, fleet.CodePending)
	}

	if err := h.state.Repo.SetDeviceStatus(id.ID(), repo.DeviceStatusApproved, h.now); err != nil {
		t.Fatal(err)
	}
	if _, err := pending.Bundles(); err != nil {
		t.Fatalf("approved device refused: %v", err)
	}

	if err := h.state.Repo.SetDeviceStatus(id.ID(), repo.DeviceStatusRevoked, h.now); err != nil {
		t.Fatal(err)
	}
	if _, err := pending.FetchBundle("advisories-npm.db"); err == nil {
		t.Fatal("a revoked device still pulled a bundle")
	} else if got := apiError(t, err).Code; got != fleet.CodeRevoked {
		t.Errorf("code = %q, want %q", got, fleet.CodeRevoked)
	}
}

// The name in the URL is matched against the list the hub built for itself, so
// there is no string an agent can send that names a file outside the bundle
// directory.
func TestTheRelayCannotBeWalkedOutOfItsDirectory(t *testing.T) {
	h := newHarness(t)
	stageOnHub(t, h, "advisories-npm.db", "npm", "20260808", []byte("bytes"), true)

	secret := filepath.Join(filepath.Dir(h.state.BundleDir), "hub.db")
	if err := os.WriteFile(secret, []byte("device tokens live here"), 0o600); err != nil {
		t.Fatal(err)
	}

	client := h.approved(t)
	for _, name := range []string{"../hub.db", "..", secret} {
		if body, err := client.FetchBundle(name); err == nil {
			t.Errorf("fetching %q returned %d bytes instead of a refusal", name, len(body))
		}
	}
}

// An unsigned read is refused for the same reason a push is: the token alone
// must not be enough, or a captured Authorization header is a working
// credential on its own.
func TestARelayFetchMustBeSigned(t *testing.T) {
	h := newHarness(t)
	stageOnHub(t, h, "advisories-npm.db", "npm", "20260808", []byte("bytes"), true)

	id, resp := h.enrol(t)
	if err := h.state.Repo.SetDeviceStatus(id.ID(), repo.DeviceStatusApproved, h.now); err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest(http.MethodGet, h.url+fleet.PathBundles, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+resp.Token)
	req.Header.Set(device.HeaderDevice, id.ID())
	// No timestamp, no signature: the token and nothing else.

	got, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer got.Body.Close()
	if got.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 for a token with no signature", got.StatusCode)
	}
}

// A signature is valid for the request it was made for. One captured from a
// list must not open the fetch.
func TestARelaySignatureDoesNotTransferToAnotherPath(t *testing.T) {
	h := newHarness(t)
	stageOnHub(t, h, "advisories-npm.db", "npm", "20260808", []byte("bytes"), true)

	id, resp := h.enrol(t)
	if err := h.state.Repo.SetDeviceStatus(id.ID(), repo.DeviceStatusApproved, h.now); err != nil {
		t.Fatal(err)
	}

	signed, err := http.NewRequest(http.MethodGet, h.url+fleet.PathBundles, nil)
	if err != nil {
		t.Fatal(err)
	}
	id.Sign(signed, nil, h.now)

	lifted, err := http.NewRequest(http.MethodGet, h.url+fleet.PathBundles+"/advisories-npm.db", nil)
	if err != nil {
		t.Fatal(err)
	}
	lifted.Header.Set("Authorization", "Bearer "+resp.Token)
	for _, header := range []string{device.HeaderDevice, device.HeaderTimestamp, device.HeaderSignature} {
		lifted.Header.Set(header, signed.Header.Get(header))
	}

	got, err := http.DefaultClient.Do(lifted)
	if err != nil {
		t.Fatal(err)
	}
	defer got.Body.Close()
	if got.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 — a signature for one path opened another", got.StatusCode)
	}
}
