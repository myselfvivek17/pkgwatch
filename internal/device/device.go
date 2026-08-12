// Package device holds an agent's identity and the request signing both sides
// of the sync protocol agree on (§4).
//
// The identity is an ed25519 keypair generated on first pair. Its public half
// is what the device ID is derived from, so the ID a person reads off the agent
// and the ID they approve on the hub are the same string only if no one sat in
// between — that comparison is the whole anti-MITM step, and it is worth
// nothing if the ID is anything other than a function of the key.
package device

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Headers carried by every signed request.
const (
	HeaderDevice    = "X-Pkgwatch-Device"
	HeaderTimestamp = "X-Pkgwatch-Timestamp"
	HeaderSignature = "X-Pkgwatch-Signature"
)

// MaxSkew bounds how far a request's timestamp may sit from the receiver's
// clock (§4). Checked in both directions: a one-sided check accepts an
// arbitrarily far-future timestamp, which stops bounding the replay window at
// all.
const MaxSkew = 120 * time.Second

var (
	b32 = base32.StdEncoding.WithPadding(base32.NoPadding)
	b64 = base64.RawURLEncoding
)

// ID derives the device ID from a public key: base32 of the first 16 bytes of
// its SHA-256, in four-character groups.
//
// Grouped because a person reads this off one screen and compares it to
// another, and an unbroken 26-character string is where that comparison stops
// being done honestly.
func ID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	encoded := b32.EncodeToString(sum[:16])

	var out strings.Builder
	for i, c := range encoded {
		if i > 0 && i%4 == 0 {
			out.WriteByte('-')
		}
		out.WriteRune(c)
	}
	return out.String()
}

// Identity is one agent's keypair.
type Identity struct {
	Private ed25519.PrivateKey
	Public  ed25519.PublicKey
}

func (i Identity) ID() string { return ID(i.Public) }

// Generate makes a new identity.
func Generate() (Identity, error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return Identity{}, fmt.Errorf("generate device key: %w", err)
	}
	return Identity{Private: priv, Public: pub}, nil
}

// Encode serialises the private key for storage. The public half is derived
// from it, so there is only ever one secret to keep.
func (i Identity) Encode() string { return b64.EncodeToString(i.Private) }

func Decode(encoded string) (Identity, error) {
	raw, err := b64.DecodeString(encoded)
	if err != nil || len(raw) != ed25519.PrivateKeySize {
		return Identity{}, fmt.Errorf("stored device key is unusable — unpair and pair again")
	}
	priv := ed25519.PrivateKey(raw)
	return Identity{Private: priv, Public: priv.Public().(ed25519.PublicKey)}, nil
}

// EncodePublic and DecodePublic move the public half over the wire.
func EncodePublic(pub ed25519.PublicKey) string { return b64.EncodeToString(pub) }

func DecodePublic(encoded string) (ed25519.PublicKey, error) {
	raw, err := b64.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("public key is not valid base64")
	}
	return PublicFromBytes(raw)
}

// PublicFromBytes wraps stored key bytes, checking the length.
//
// The check is not a formality: ed25519.Verify panics on a key of the wrong
// size, so a truncated row in the database would take the hub down rather than
// refuse one request.
func PublicFromBytes(raw []byte) (ed25519.PublicKey, error) {
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key is %d bytes, want %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// canonical is the string both sides sign: method, path, a hash of the body,
// and the timestamp.
//
// The body is included so a signature cannot be lifted off one request and
// replayed onto a different payload, and the timestamp so it cannot be replayed
// at all outside the skew window. The path is included because otherwise a
// signature for a read would authorise a write.
func canonical(method, path string, body []byte, ts int64) string {
	sum := sha256.Sum256(body)
	return strings.Join([]string{
		strings.ToUpper(method),
		path,
		hex.EncodeToString(sum[:]),
		strconv.FormatInt(ts, 10),
	}, "|")
}

// Sign stamps req with this identity's headers. body is what will be sent, and
// must be the same bytes the request carries.
//
// A bearer token alone would be enough to impersonate a device to anyone who
// captured it. The signature means a leaked token is not sufficient on its own,
// which is the point of carrying both (§4).
func (i Identity) Sign(req *http.Request, body []byte, now time.Time) {
	ts := now.Unix()
	req.Header.Set(HeaderDevice, i.ID())
	req.Header.Set(HeaderTimestamp, strconv.FormatInt(ts, 10))
	req.Header.Set(HeaderSignature,
		b64.EncodeToString(ed25519.Sign(i.Private, []byte(canonical(req.Method, req.URL.Path, body, ts)))))
}

// Verify errors describe why a request was refused. They are distinguished so
// the hub can log a clock problem as a clock problem rather than as an attack —
// a machine whose time drifted looks exactly like a replay otherwise.
type VerifyError struct{ Reason string }

func (e VerifyError) Error() string { return e.Reason }

var (
	ErrNoSignature  = VerifyError{"request is not signed"}
	ErrBadSignature = VerifyError{"signature does not match this device's key"}
	ErrSkew         = VerifyError{"timestamp is outside the accepted window — check the clock on both machines"}
)

// Verify checks a signed request against a known public key.
func Verify(req *http.Request, body []byte, pub ed25519.PublicKey, now time.Time) error {
	rawTS := req.Header.Get(HeaderTimestamp)
	rawSig := req.Header.Get(HeaderSignature)
	if rawTS == "" || rawSig == "" {
		return ErrNoSignature
	}

	ts, err := strconv.ParseInt(rawTS, 10, 64)
	if err != nil {
		return ErrNoSignature
	}
	// Both directions. Only checking the past accepts a timestamp years ahead,
	// whose signature then stays valid for years.
	if drift := now.Sub(time.Unix(ts, 0)); drift > MaxSkew || drift < -MaxSkew {
		return ErrSkew
	}

	sig, err := b64.DecodeString(rawSig)
	if err != nil {
		return ErrNoSignature
	}
	if !ed25519.Verify(pub, []byte(canonical(req.Method, req.URL.Path, body, ts)), sig) {
		return ErrBadSignature
	}
	return nil
}
