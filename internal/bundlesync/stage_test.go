package bundlesync_test

import (
	"crypto/ed25519"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/myselfvivek17/pkgwatch/internal/bundle"
	"github.com/myselfvivek17/pkgwatch/internal/bundlesync"
	"github.com/myselfvivek17/pkgwatch/internal/config"
)

// Relayed bytes are checked exactly as hard as bytes from anywhere else. The
// hub saves the fleet a download and decides nothing: it cannot make a bundle
// trusted, and a hub that has been taken over must not be able to hand every
// agent an advisory set of its choosing (§0, hard rule 2).
func TestARelayedBundleIsNotTrustedBecauseTheHubSentIt(t *testing.T) {
	data := []byte("a signed advisory bundle")
	manifest := bundle.Manifest{
		Version: "20260808", Scope: "npm",
		SHA256: bundle.Digest(data), Size: int64(len(data)), BuiltAt: time.Now(),
	}

	// A signature that is well formed and made by the wrong key — what a hub
	// that decided to sign its own bundles would produce.
	_, impostor, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		sig     []byte
		payload []byte
		want    string
	}{
		{
			// The manifest is intact and the bytes are not. This is the shape of
			// a bundle modified in transit or in the hub's own directory.
			name:    "a flipped byte",
			payload: flip(data),
			sig:     bundle.Sign(impostor, manifest.Version, manifest.Scope, flip(data)),
			want:    "digest",
		},
		{
			// Bytes and digest agree, and nobody the agent trusts signed them.
			// A hub can produce this pair for any content it likes.
			name:    "a signature the publisher never made",
			payload: data,
			sig:     bundle.Sign(impostor, manifest.Version, manifest.Scope, data),
			want:    "does not verify",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Config{DataDir: t.TempDir()}

			err := bundlesync.Stage(cfg, tc.payload, manifest, tc.sig, bundlesync.Options{})
			if err == nil {
				t.Fatal("the bundle was installed")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want it to name the %s check", err, tc.want)
			}

			// Refused means nothing landed. A bundle that failed verification and
			// still replaced the file would be the worst of both.
			if _, err := os.Stat(cfg.ScopedBundlePath(manifest.Scope)); !os.IsNotExist(err) {
				t.Errorf("a refused bundle was written to %s", cfg.ScopedBundlePath(manifest.Scope))
			}
		})
	}
}

func flip(data []byte) []byte {
	out := append([]byte(nil), data...)
	out[0] ^= 0xff
	return out
}
