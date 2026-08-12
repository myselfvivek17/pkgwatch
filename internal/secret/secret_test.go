package secret_test

import (
	"strings"
	"testing"

	"github.com/myselfvivek17/pkgwatch/internal/secret"
)

func TestHashVerifiesOnlyTheRightPassword(t *testing.T) {
	encoded, err := secret.Hash("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !secret.Verify("correct horse battery staple", encoded) {
		t.Error("the right password did not verify")
	}
	if secret.Verify("Correct horse battery staple", encoded) {
		t.Error("a near-miss verified")
	}
	if secret.Verify("", encoded) {
		t.Error("the empty password verified")
	}
}

func TestSaltMakesIdenticalPasswordsHashDifferently(t *testing.T) {
	a, _ := secret.Hash("same")
	b, _ := secret.Hash("same")
	if a == b {
		t.Error("two hashes of one password are identical — the salt is not random")
	}
}

// Nothing should ever mean "let them in". A truncated, empty or hand-edited
// value in the config is a broken deployment, and a broken deployment must fail
// closed.
func TestUnusableHashesNeverVerify(t *testing.T) {
	for _, encoded := range []string{
		"",
		"hunter2",
		"$argon2id$v=19$m=65536,t=1,p=4$$",
		"$argon2i$v=19$m=65536,t=1,p=4$c2FsdHNhbHRzYWx0$aGFzaA",
		"$argon2id$v=13$m=65536,t=1,p=4$c2FsdHNhbHRzYWx0$aGFzaA",
	} {
		if secret.Verify("anything", encoded) {
			t.Errorf("%q verified", encoded)
		}
	}
}

func TestParametersTravelWithTheHash(t *testing.T) {
	encoded, _ := secret.Hash("x")
	// Raising the cost later must not lock out credentials hashed at the old
	// cost, which only works if verify reads the parameters from the string.
	if !strings.HasPrefix(encoded, "$argon2id$v=19$m=65536,t=1,p=4$") {
		t.Errorf("encoded = %q, want the parameters inline", encoded)
	}
}

func TestPairCodeIsTranscribable(t *testing.T) {
	seen := map[string]bool{}
	for range 100 {
		code, err := secret.PairCode()
		if err != nil {
			t.Fatal(err)
		}
		if len(code) != 9 || code[4] != '-' {
			t.Fatalf("code = %q, want XXXX-XXXX", code)
		}
		// Someone reads this off one screen and types it into another.
		if strings.ContainsAny(code, "01OILUV") {
			t.Errorf("code %q contains a character that gets misread", code)
		}
		seen[code] = true
	}
	if len(seen) < 99 {
		t.Errorf("%d distinct codes in 100 draws — not random enough for single use", len(seen))
	}
}
