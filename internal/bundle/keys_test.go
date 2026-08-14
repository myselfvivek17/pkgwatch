package bundle

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
)

// Every embedded key must be a usable ed25519 public key.
//
// Default() logs a malformed constant and skips it rather than panicking inside
// the gate's process, which is the right behaviour at runtime and a terrible
// place to find out. A mistyped key would leave verification quietly weaker
// than the source implies — and in the case of a single-key list, would leave a
// verifier trusting nothing while every bundle failed for reasons nobody could
// see. This turns that into a build failure.
func TestEveryEmbeddedPublisherKeyIsUsable(t *testing.T) {
	if len(publisherKeysBase64) == 0 {
		t.Fatal("no publisher keys are embedded — nothing could verify a bundle")
	}

	seen := map[string]bool{}
	for i, encoded := range publisherKeysBase64 {
		raw, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			t.Errorf("key %d is not valid base64: %v", i, err)
			continue
		}
		if len(raw) != ed25519.PublicKeySize {
			// A private key pasted here would be 64 bytes, and is the mistake
			// worth catching loudest: it would put signing material in the
			// repository.
			t.Errorf("key %d is %d bytes, want %d%s", i, len(raw), ed25519.PublicKeySize,
				map[bool]string{true: " — that is the size of a PRIVATE key"}[len(raw) == ed25519.PrivateKeySize])
			continue
		}
		if seen[encoded] {
			t.Errorf("key %d is a duplicate; a rotation that pasted the same key twice "+
				"looks like two trusted keys and is one", i)
		}
		seen[encoded] = true
	}

	// And the verifier actually built from them carries every one.
	if got := len(Default().Keys); got != len(publisherKeysBase64) {
		t.Errorf("the verifier holds %d keys, the source lists %d — one was dropped as malformed",
			got, len(publisherKeysBase64))
	}
}
