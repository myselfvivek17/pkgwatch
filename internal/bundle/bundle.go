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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// signaturePrefix domain-separates our signatures, and binding the version into
// the signed message means an old, validly signed bundle cannot be replayed as
// the current one to freeze an agent's view of the world.
const signaturePrefix = "pkgwatch-bundle-v1"

// Manifest describes a published bundle. Signature covers SignedMessage, not
// this struct, so the manifest can gain fields without invalidating signatures.
type Manifest struct {
	Version     string    `json:"version"`
	SHA256      string    `json:"sha256"`
	Size        int64     `json:"size"`
	BuiltAt     time.Time `json:"built_at"`
	RecordCount int       `json:"record_count"`
	URL         string    `json:"url,omitempty"`
	Signature   string    `json:"signature"` // hex-encoded ed25519 signature
}

// SignedMessage is the exact byte string a bundle signature covers: the
// protocol tag, the version, and the digest of the file.
func SignedMessage(version string, data []byte) []byte {
	sum := sha256.Sum256(data)
	return []byte(signaturePrefix + "\n" + version + "\n" + hex.EncodeToString(sum[:]))
}

// Sign produces a bundle signature. Used by the publisher; agents only verify.
func Sign(priv ed25519.PrivateKey, version string, data []byte) []byte {
	return ed25519.Sign(priv, SignedMessage(version, data))
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
func (v Verifier) Verify(version string, data, sig []byte) error {
	if len(v.Keys) == 0 {
		return ErrNoKeys
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("bundle: signature is %d bytes, want %d", len(sig), ed25519.SignatureSize)
	}

	msg := SignedMessage(version, data)
	for _, key := range v.Keys {
		if len(key) == ed25519.PublicKeySize && ed25519.Verify(key, msg, sig) {
			return nil
		}
	}
	return fmt.Errorf("bundle: signature for version %q does not verify against any trusted publisher key", version)
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
