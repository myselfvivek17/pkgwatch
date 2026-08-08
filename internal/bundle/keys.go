package bundle

import (
	"crypto/ed25519"
	"encoding/base64"
	"log/slog"
)

// Publisher keys, compiled into the binary.
//
// This list is deliberately a slice, not a single key. Rotating the publisher
// key means publishing the new key here first, shipping a release, and only
// then signing with it — so agents running an older binary keep verifying
// through the transition instead of rejecting every bundle.
//
// Order is current, then next. Adding a key is a code change and a release,
// which is the point: no remote party can add one.
var publisherKeysBase64 = []string{
	// dev — used by `pkgwatch publish` for local bundles. Replaced by the
	// production key at M6, when the real key ceremony happens on hardware
	// the maintainer controls.
	"JqEkbCJnKyEQd8nmlp41JjFp+cdgwDYADiyO+GG0krU=",
}

// Default returns the verifier every agent uses.
func Default() Verifier {
	keys := make([]ed25519.PublicKey, 0, len(publisherKeysBase64))
	for _, encoded := range publisherKeysBase64 {
		raw, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			// A malformed constant is a build mistake. Skip it rather than
			// panic in the gate's process, but say so loudly — silently
			// dropping a key would weaken verification without a trace.
			slog.Error("ignoring malformed embedded publisher key", "key", encoded)
			continue
		}
		keys = append(keys, ed25519.PublicKey(raw))
	}
	return Verifier{Keys: keys}
}
