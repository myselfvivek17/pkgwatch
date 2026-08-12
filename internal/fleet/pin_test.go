package fleet

import (
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/myselfvivek17/pkgwatch/internal/device"
)

// tlsHub starts an https server with its own self-signed certificate and
// returns the URL and the fingerprint of what it serves.
func tlsHub(t *testing.T, handler http.Handler) (string, string) {
	t.Helper()
	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)
	return srv.URL, Fingerprint(srv.Certificate().Raw)
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"accepted_through":0}`))
	})
}

func testClient(t *testing.T, url, fingerprint string) *Client {
	t.Helper()
	id, err := device.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return &Client{BaseURL: url, Identity: id, Fingerprint: fingerprint, Now: time.Now}
}

func TestTheRightCertificateIsAccepted(t *testing.T) {
	url, fingerprint := tlsHub(t, okHandler())
	if _, err := testClient(t, url, fingerprint).Push(SyncRequest{}); err != nil {
		t.Errorf("a pinned certificate was refused: %v", err)
	}
}

// The one that matters. InsecureSkipVerify without VerifyPeerCertificate is not
// weaker verification, it is none — and it looks identical from the outside, so
// this is the only thing that can tell them apart.
// otherFingerprint is a well-formed pin that belongs to no certificate here.
//
// Deliberately fabricated rather than taken from a second httptest server:
// httptest reuses one built-in certificate for every TLS server it starts, so
// two "different" hubs have identical fingerprints and the mismatch never
// happens. A test built that way passes with the pin check deleted.
const otherFingerprint = "1A2B-3C4D-5E6F-7081-92A3-B4C5-D6E7-F809-1A2B-3C4D-5E6F-7081-92A3-B4C5-D6E7-F809"

func TestADifferentCertificateIsRefused(t *testing.T) {
	url, served := tlsHub(t, okHandler())
	if SameFingerprint(served, otherFingerprint) {
		t.Fatal("the fabricated pin collides with the served certificate")
	}

	_, err := testClient(t, url, otherFingerprint).Push(SyncRequest{})
	var wrong ErrWrongCertificate
	if !errors.As(err, &wrong) {
		t.Fatalf("err = %v, want a certificate mismatch", err)
	}
	// The message has to name both, or nobody can tell a regenerated hub
	// certificate from something answering in its place.
	if !strings.Contains(wrong.Error(), "pinned:") || !strings.Contains(wrong.Error(), "presented:") {
		t.Errorf("the refusal does not show both fingerprints:\n%s", wrong.Error())
	}
	if !strings.Contains(wrong.Error(), "re-pair") {
		t.Error("the refusal does not say what to do about it")
	}
}

// A certificate mismatch must not be wrapped into an ordinary network error.
// "The hub is down" and "something is answering for the hub" are opposite
// situations, and the agent branches on the difference.
func TestAMismatchIsNotReportedAsUnreachable(t *testing.T) {
	url, _ := tlsHub(t, okHandler())

	err := testClient(t, url, otherFingerprint).post(PathSync, SyncRequest{}, nil)
	if err == nil {
		t.Fatal("a mismatched pin was accepted")
	}
	if strings.Contains(err.Error(), "reach hub at") {
		t.Errorf("a pin mismatch was reported as a connectivity problem: %v", err)
	}
}

// First contact records what was presented so a person can compare it. Nothing
// else in the flow ever runs with an empty pin.
func TestFirstContactCapturesTheFingerprint(t *testing.T) {
	url, fingerprint := tlsHub(t, okHandler())
	client := testClient(t, url, "")

	if _, err := client.Push(SyncRequest{}); err != nil {
		t.Fatalf("first contact failed: %v", err)
	}
	if client.SeenFingerprint != fingerprint {
		t.Errorf("captured %q, want %q", client.SeenFingerprint, fingerprint)
	}
}

// The fingerprint is compared by eye against what the hub printed, so both ends
// have to be the same shape — and a paste with the dashes stripped must still
// match.
func TestFingerprintFormattingIsForgiving(t *testing.T) {
	_, fingerprint := tlsHub(t, okHandler())

	if strings.Count(fingerprint, "-") != 15 {
		t.Errorf("fingerprint %q is not grouped in fours", fingerprint)
	}
	if !SameFingerprint(fingerprint, strings.ReplaceAll(fingerprint, "-", "")) {
		t.Error("the same fingerprint without dashes did not match")
	}
	if !SameFingerprint(fingerprint, strings.ToLower(fingerprint)) {
		t.Error("case changed the answer")
	}
	// An empty pin is never a match. "Nothing on file" must not mean "trusts
	// everything" anywhere a comparison is being made.
	if SameFingerprint("", fingerprint) {
		t.Error("an empty pin matched a real certificate")
	}
}

// Plain http gets no pinned transport, and must keep working — the loopback
// test setups and any hub with tls = false depend on it.
func TestPlainHTTPStillWorks(t *testing.T) {
	srv := httptest.NewServer(okHandler())
	t.Cleanup(srv.Close)

	if _, err := testClient(t, srv.URL, "").Push(SyncRequest{}); err != nil {
		t.Errorf("http push failed: %v", err)
	}
}

// The transport must not quietly fall back to the system trust store: a hub
// with a certificate from a real CA is still only trusted at its pinned
// fingerprint.
func TestAValidCAWouldNotSubstituteForThePin(t *testing.T) {
	url, _ := tlsHub(t, okHandler())
	client := testClient(t, url, otherFingerprint)

	transport, ok := client.client().Transport.(*http.Transport)
	if !ok {
		t.Fatal("https client is not using the pinned transport")
	}
	if transport.TLSClientConfig.VerifyPeerCertificate == nil {
		t.Fatal("InsecureSkipVerify is set with no VerifyPeerCertificate — that is no verification at all")
	}
	if transport.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Error("TLS floor is below 1.2")
	}
}
