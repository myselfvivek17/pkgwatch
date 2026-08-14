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
	// dev — signs every bundle on this fleet today. Still trusted because the
	// corpus has not been re-signed yet; removing it before that would make
	// `sync --rebuild` reject bundles already on disk. It goes in the release
	// after the corpus moves to the production key, and that removal is what
	// actually revokes it.
	"JqEkbCJnKyEQd8nmlp41JjFp+cdgwDYADiyO+GG0krU=",

	// production — generated 2026-08-14 on the maintainer's own machine; the
	// private half has never been on the network and is not in this repository.
	// Listed second because it is the *next* key, not yet the signing one:
	// agents have to be able to verify it before anything is signed with it,
	// and shipping it here is what makes that true.
	"wb5p81lTC719T9xB/7tkwb/TUF67wkfKpepYaJycB5I=",
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
