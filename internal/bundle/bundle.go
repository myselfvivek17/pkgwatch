// Package bundle verifies, installs and describes the signed advisory bundle.
//
// Rule 2 of the project lives here: a bundle is trusted because of who signed
// it, never because of who served it. Verification is identical and mandatory
// whether the bytes came from the publisher or from your own hub — a
// compromised hub must not be able to push "everything is safe" and blind the
// fleet.
package bundle

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// signaturePrefix domain-separates our signatures, and binding the version into
// the signed message means an old, validly signed bundle cannot be replayed as
// the current one to freeze an agent's view of the world.
// signaturePrefix is v2 because the signed message gained the scope. A v1
// signature does not verify under v2 and must not: the whole point of the
// change is that a bundle's identity now includes what it claims to cover.
const signaturePrefix = "pkgwatch-bundle-v2"

// ScopeAll is the scope of a bundle carrying every ecosystem.
const ScopeAll = "all"

// Manifest describes a published bundle. Signature covers SignedMessage, not
// this struct, so the manifest can gain fields without invalidating signatures.
type Manifest struct {
	Version string `json:"version"`

	// Scope is what this bundle claims to cover: "npm", "Debian:12", or "all".
	// It is signed, because it is a security-relevant claim — see SignedMessage.
	Scope string `json:"scope"`

	SHA256      string    `json:"sha256"`
	Size        int64     `json:"size"`
	BuiltAt     time.Time `json:"built_at"`
	RecordCount int       `json:"record_count"`
	URL         string    `json:"url,omitempty"`
	Signature   string    `json:"signature"` // hex-encoded ed25519 signature
}

// SignedMessage is the exact byte string a bundle signature covers: the
// protocol tag, the version, the scope, and the digest of the file.
//
// The scope is in here rather than only in the manifest because of what a
// per-ecosystem layout makes possible. Without it, a validly signed npm bundle
// could be served as the Debian one: every check passes — the key is trusted,
// the digest matches, the version is current — and the agent silently ends up
// with zero Debian advisories. It would then report every Debian package as
// having nothing on file, which is indistinguishable from safety. Binding the
// scope is what makes "this is the Debian bundle" a claim the publisher made
// rather than a claim the filename makes.
func SignedMessage(version, scope string, data []byte) []byte {
	sum := sha256.Sum256(data)
	return []byte(signaturePrefix + "\n" + version + "\n" + scope + "\n" + hex.EncodeToString(sum[:]))
}

// Sign produces a bundle signature. Used by the publisher; agents only verify.
func Sign(priv ed25519.PrivateKey, version, scope string, data []byte) []byte {
	return ed25519.Sign(priv, SignedMessage(version, scope, data))
}

// Verifier holds the publisher keys a binary trusts.
type Verifier struct {
	// Keys is current-then-next. Shipping both means rotating the publisher key
	// does not brick agents running an older binary.
	Keys []ed25519.PublicKey
}

// ErrNoKeys means the binary was built without a publisher key.
var ErrNoKeys = errors.New("bundle: no publisher keys compiled into this binary")

// Verify checks a bundle's signature against every trusted key.
func (v Verifier) Verify(version, scope string, data, sig []byte) error {
	if len(v.Keys) == 0 {
		return ErrNoKeys
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("bundle: signature is %d bytes, want %d", len(sig), ed25519.SignatureSize)
	}

	msg := SignedMessage(version, scope, data)
	for _, key := range v.Keys {
		if len(key) == ed25519.PublicKeySize && ed25519.Verify(key, msg, sig) {
			return nil
		}
	}
	return fmt.Errorf(
		"bundle: signature for version %q scope %q does not verify against any trusted publisher key",
		version, scope)
}

// ScopeFileName renders a scope as a filename component: "Debian:12" becomes
// "debian-12", "crates.io" stays "crates.io".
//
// The filename is a convenience only. Nothing trusts it — the scope that counts
// is the one inside the signature.
func ScopeFileName(scope string) string {
	safe := strings.ToLower(scope)
	for _, bad := range []string{":", "/", `\`, " "} {
		safe = strings.ReplaceAll(safe, bad, "-")
	}
	return safe
}

// ManifestPath is where a staged bundle's manifest is kept: beside the bundle,
// under the same name.
//
// Kept rather than discarded after verification, because a signature cannot be
// re-derived. A hub that threw the manifest away could still hand an agent the
// bytes, and the agent would have no way to check them against the publisher
// key — which would leave "trust it, the hub sent it" as the only option, and
// that is the exact thing hard rule 2 forbids.
func ManifestPath(bundlePath string) string { return bundlePath + ".json" }

// SaveManifest records a verified bundle's manifest beside it. The signature is
// written inline so the file is self-contained.
func SaveManifest(bundlePath string, m Manifest, sig []byte) error {
	m.Signature = hex.EncodeToString(sig)
	raw, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("bundle: encode manifest: %w", err)
	}
	if err := os.WriteFile(ManifestPath(bundlePath), raw, 0o600); err != nil {
		return fmt.Errorf("bundle: write manifest: %w", err)
	}
	return nil
}

// LoadManifest reads the manifest stored beside a bundle.
func LoadManifest(bundlePath string) (Manifest, error) {
	raw, err := os.ReadFile(ManifestPath(bundlePath))
	if err != nil {
		return Manifest{}, err
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return Manifest{}, fmt.Errorf("bundle: parse stored manifest: %w", err)
	}
	return m, nil
}

// Digest returns the hex SHA-256 of data, as published in the manifest.
func Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Install atomically replaces the advisory database at path.
//
// Write-then-rename, because a partially written advisories.db would silently
// disarm matching on the next start — and a bundle that fails to install must
// leave the previous one intact rather than leaving nothing.
func Install(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("bundle: create %s: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, ".advisories-*.tmp")
	if err != nil {
		return fmt.Errorf("bundle: create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename succeeds

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("bundle: write: %w", err)
	}
	// Durability before the rename: otherwise a crash can leave the new name
	// pointing at unwritten blocks.
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("bundle: sync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("bundle: close: %w", err)
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return fmt.Errorf("bundle: chmod: %w", err)
	}

	// On POSIX, rename over an existing path is atomic and the old file stays
	// readable until the instant it is replaced. Removing first would open a
	// window where advisories.db does not exist — and a crash in that window
	// leaves the agent with no bundle at all, which means the gate fails open.
	// A machine updating its advisories must never be able to disarm itself.
	//
	// Windows is the exception: it will not rename onto an existing file, so
	// there the unlink is unavoidable. Callers DETACH the advisory schema first
	// so no handle is held open across it.
	if runtime.GOOS == "windows" {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("bundle: remove previous bundle: %w", err)
		}
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("bundle: install: %w", err)
	}
	return nil
}
