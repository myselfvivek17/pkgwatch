package bundle

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mustKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestVerifyAcceptsAGoodSignature(t *testing.T) {
	pub, priv := mustKeypair(t)
	data := []byte("advisory bundle bytes")

	sig := Sign(priv, "20260808", data)

	v := Verifier{Keys: []ed25519.PublicKey{pub}}
	if err := v.Verify("20260808", data, sig); err != nil {
		t.Errorf("Verify rejected a valid signature: %v", err)
	}
}

// Key rotation: binaries embed the current key and the next one, so a rotation
// does not brick every agent still running an older build.
func TestVerifyAcceptsTheNextKey(t *testing.T) {
	current, _ := mustKeypair(t)
	next, nextPriv := mustKeypair(t)
	data := []byte("bundle signed with the incoming key")

	sig := Sign(nextPriv, "20260901", data)

	v := Verifier{Keys: []ed25519.PublicKey{current, next}}
	if err := v.Verify("20260901", data, sig); err != nil {
		t.Errorf("Verify rejected a signature from the next key: %v", err)
	}
}

func TestVerifyRejectsAForeignKey(t *testing.T) {
	pub, _ := mustKeypair(t)
	_, attackerPriv := mustKeypair(t)
	data := []byte("bundle")

	sig := Sign(attackerPriv, "20260808", data)

	v := Verifier{Keys: []ed25519.PublicKey{pub}}
	if err := v.Verify("20260808", data, sig); err == nil {
		t.Error("Verify accepted a signature from a key we do not trust")
	}
}

// The whole point of signing: a hub that has been compromised must not be able
// to push a modified bundle that says everything is safe.
func TestVerifyRejectsTamperedBytes(t *testing.T) {
	pub, priv := mustKeypair(t)
	data := []byte("advisory bundle bytes")
	sig := Sign(priv, "20260808", data)

	tampered := append([]byte(nil), data...)
	tampered[0] ^= 0x01

	v := Verifier{Keys: []ed25519.PublicKey{pub}}
	if err := v.Verify("20260808", tampered, sig); err == nil {
		t.Error("Verify accepted a bundle whose bytes had been changed")
	}
}

// The signature covers the version too, so an old signed bundle cannot be
// replayed as a current one to freeze an agent's view of the world.
func TestVerifyRejectsAReplayedVersion(t *testing.T) {
	pub, priv := mustKeypair(t)
	data := []byte("last month's bundle")
	sig := Sign(priv, "20260701", data)

	v := Verifier{Keys: []ed25519.PublicKey{pub}}
	if err := v.Verify("20260901", data, sig); err == nil {
		t.Error("Verify accepted a bundle replayed under a different version")
	}
}

func TestVerifyWithNoKeysConfiguredFails(t *testing.T) {
	_, priv := mustKeypair(t)
	data := []byte("bundle")
	sig := Sign(priv, "20260808", data)

	v := Verifier{}
	err := v.Verify("20260808", data, sig)
	if err == nil {
		t.Fatal("Verify succeeded with no trusted keys")
	}
	if !strings.Contains(err.Error(), "no publisher keys") {
		t.Errorf("error should name the cause, got: %v", err)
	}
}

func TestVerifyRejectsAMalformedSignature(t *testing.T) {
	pub, _ := mustKeypair(t)
	v := Verifier{Keys: []ed25519.PublicKey{pub}}

	for _, sig := range [][]byte{nil, {}, []byte("short")} {
		if err := v.Verify("20260808", []byte("bundle"), sig); err == nil {
			t.Errorf("Verify accepted a %d-byte signature", len(sig))
		}
	}
}

// Installing must be atomic: an interrupted swap that leaves a truncated
// advisories.db would silently disarm matching on next start.
func TestInstallReplacesAtomically(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "advisories.db")

	if err := os.WriteFile(target, []byte("old bundle"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := Install(target, []byte("new bundle")); err != nil {
		t.Fatalf("Install: %v", err)
	}

	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new bundle" {
		t.Errorf("target = %q, want the new bundle", got)
	}

	// No temporary files left behind for the next scan to trip over.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("directory holds %v, want only advisories.db", names)
	}
}

func TestInstallCreatesWhenAbsent(t *testing.T) {
	target := filepath.Join(t.TempDir(), "advisories.db")

	if err := Install(target, []byte("first bundle")); err != nil {
		t.Fatalf("Install: %v", err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "first bundle" {
		t.Errorf("target = %q", got)
	}
}

// The rollback guard compares versions as strings, so only fixed-width
// lexicographically sortable versions may be signed.
func TestValidateVersion(t *testing.T) {
	valid := []string{"20260808", "20260809T1400", "19700101", "20991231T0000"}
	for _, v := range valid {
		if err := ValidateVersion(v); err != nil {
			t.Errorf("ValidateVersion(%q) = %v, want nil", v, err)
		}
	}

	invalid := []string{
		"",
		"2026-08-09",  // sorts below "20260808"
		"v20260809",   // sorts below every bare digit string
		"20260809.1",  // .10 would sort below .9
		"1",           // not fixed width
		"latest",      //
		"20260809T14", // truncated time
	}
	for _, v := range invalid {
		if err := ValidateVersion(v); err == nil {
			t.Errorf("ValidateVersion(%q) = nil, want an error", v)
		}
	}
}

// The embedded key list is what makes rule 2 real: bundles are trusted because
// of who signed them, never because of who served them.
func TestBuiltInVerifierIsWiredUp(t *testing.T) {
	v := Default()
	if len(v.Keys) == 0 {
		t.Skip("no publisher key compiled into this build yet")
	}
	for i, k := range v.Keys {
		if len(k) != ed25519.PublicKeySize {
			t.Errorf("embedded key %d is %d bytes, want %d", i, len(k), ed25519.PublicKeySize)
		}
	}
}
