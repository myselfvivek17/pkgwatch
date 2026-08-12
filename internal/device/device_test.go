package device_test

import (
	"bytes"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/myselfvivek17/pkgwatch/internal/device"
)

func signed(t *testing.T, id device.Identity, method, path string, body []byte, at time.Time) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, "https://hub.test"+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	id.Sign(req, body, at)
	return req
}

func TestIDIsAFunctionOfTheKey(t *testing.T) {
	a, err := device.Generate()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := device.Generate()

	if a.ID() != a.ID() {
		t.Error("the same key produced two different IDs")
	}
	if a.ID() == b.ID() {
		t.Error("two keys produced the same ID")
	}
	// A person reads this off one screen and compares it to another. That
	// comparison is the anti-MITM step, and an unbroken run of 26 characters is
	// where it stops being done honestly.
	if !strings.Contains(a.ID(), "-") || len(strings.Split(a.ID(), "-")) < 6 {
		t.Errorf("ID %q is not grouped for reading", a.ID())
	}
}

func TestRoundTripKeepsTheIdentity(t *testing.T) {
	original, _ := device.Generate()
	restored, err := device.Decode(original.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if restored.ID() != original.ID() {
		t.Error("a stored and reloaded key is a different device")
	}
}

func TestCorruptStoredKeyIsRefused(t *testing.T) {
	for _, encoded := range []string{"", "not base64 $$", "c2hvcnQ"} {
		if _, err := device.Decode(encoded); err == nil {
			t.Errorf("Decode(%q) succeeded", encoded)
		}
	}
}

func TestSignedRequestVerifies(t *testing.T) {
	id, _ := device.Generate()
	now := time.Now()
	req := signed(t, id, http.MethodPost, "/api/v1/sync", []byte(`{"events":[]}`), now)

	if err := device.Verify(req, []byte(`{"events":[]}`), id.Public, now); err != nil {
		t.Errorf("a freshly signed request did not verify: %v", err)
	}
}

func TestAnotherDevicesKeyDoesNotVerify(t *testing.T) {
	mine, _ := device.Generate()
	theirs, _ := device.Generate()
	now := time.Now()
	req := signed(t, mine, http.MethodPost, "/api/v1/sync", []byte("body"), now)

	if err := device.Verify(req, []byte("body"), theirs.Public, now); !errors.Is(err, device.ErrBadSignature) {
		t.Errorf("err = %v, want a bad-signature refusal", err)
	}
}

// A signature lifted off one request must not authorise a different one.
func TestSignatureIsBoundToMethodPathAndBody(t *testing.T) {
	id, _ := device.Generate()
	now := time.Now()
	body := []byte(`{"events":[]}`)

	t.Run("body swapped", func(t *testing.T) {
		req := signed(t, id, http.MethodPost, "/api/v1/sync", body, now)
		if err := device.Verify(req, []byte(`{"events":["forged"]}`), id.Public, now); err == nil {
			t.Error("a swapped body verified")
		}
	})

	t.Run("path swapped", func(t *testing.T) {
		req := signed(t, id, http.MethodPost, "/api/v1/sync", body, now)
		req.URL.Path = "/api/v1/devices/revoke"
		if err := device.Verify(req, body, id.Public, now); err == nil {
			t.Error("a signature for one path authorised another")
		}
	})

	t.Run("method swapped", func(t *testing.T) {
		req := signed(t, id, http.MethodGet, "/api/v1/sync", body, now)
		req.Method = http.MethodPost
		if err := device.Verify(req, body, id.Public, now); err == nil {
			t.Error("a signature for a read authorised a write")
		}
	})
}

// Both directions. A one-sided check accepts a timestamp years ahead, whose
// signature then stays valid for years.
func TestSkewIsRejectedInBothDirections(t *testing.T) {
	id, _ := device.Generate()
	now := time.Now()

	for _, tc := range []struct {
		name  string
		stamp time.Time
	}{
		{"too old", now.Add(-device.MaxSkew - time.Second)},
		{"too far ahead", now.Add(device.MaxSkew + time.Second)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := signed(t, id, http.MethodPost, "/api/v1/sync", nil, tc.stamp)
			if err := device.Verify(req, nil, id.Public, now); !errors.Is(err, device.ErrSkew) {
				t.Errorf("err = %v, want a skew refusal", err)
			}
		})
	}

	// Inside the window either way, because two machines are never in step.
	for _, stamp := range []time.Time{now.Add(-90 * time.Second), now.Add(90 * time.Second)} {
		req := signed(t, id, http.MethodPost, "/api/v1/sync", nil, stamp)
		if err := device.Verify(req, nil, id.Public, now); err != nil {
			t.Errorf("a request %v out was refused: %v", now.Sub(stamp), err)
		}
	}
}

func TestUnsignedRequestIsRefused(t *testing.T) {
	id, _ := device.Generate()
	req, _ := http.NewRequest(http.MethodPost, "https://hub.test/api/v1/sync", nil)
	if err := device.Verify(req, nil, id.Public, time.Now()); !errors.Is(err, device.ErrNoSignature) {
		t.Errorf("err = %v, want a not-signed refusal", err)
	}
}
