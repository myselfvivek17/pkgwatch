// Package secret hashes the two credentials pkgwatch stores: the hub
// dashboard's password and each device's sync token.
//
// argon2id rather than SHA-256, per §4.1 and §8. Both of these are bearer
// credentials sitting in a database on a machine whose whole purpose is to
// notice when it has been compromised, and a fast hash makes the file worth
// stealing. This is a trust boundary, so it does not get simplified.
package secret

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Parameters. 64 MiB and one pass is the argon2 RFC's second recommended
// profile — a login on a homelab server takes well under a tenth of a second,
// and an attacker with the database pays that per guess.
const (
	timeCost   = 1
	memoryCost = 64 * 1024
	threads    = 4
	keyLen     = 32
	saltLen    = 16
)

var b64 = base64.RawStdEncoding

// ErrMalformed means the stored hash is not something this code wrote.
var ErrMalformed = errors.New("stored hash is not a recognised argon2id string")

// Hash returns a PHC-format argon2id string, salt and parameters included.
//
// The parameters travel with the hash rather than being read from constants at
// verify time, so raising the cost later does not lock out every existing
// credential.
func Hash(plain string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("read salt: %w", err)
	}
	sum := argon2.IDKey([]byte(plain), salt, timeCost, memoryCost, threads, keyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, memoryCost, timeCost, threads,
		b64.EncodeToString(salt), b64.EncodeToString(sum)), nil
}

// Verify reports whether plain produced encoded.
//
// A malformed or empty stored hash verifies as false rather than as an error
// the caller might forget to check. There is no input for which "no usable
// hash on file" should mean "let them in".
func Verify(plain, encoded string) bool {
	salt, want, params, err := parse(encoded)
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(plain), salt, params.time, params.memory, params.threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

type costs struct {
	memory, time uint32
	threads      uint8
}

func parse(encoded string) (salt, sum []byte, c costs, err error) {
	parts := strings.Split(encoded, "$")
	// "", "argon2id", "v=19", "m=..,t=..,p=..", salt, hash
	if len(parts) != 6 || parts[1] != "argon2id" {
		return nil, nil, c, ErrMalformed
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return nil, nil, c, ErrMalformed
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &c.memory, &c.time, &c.threads); err != nil {
		return nil, nil, c, ErrMalformed
	}
	if salt, err = b64.DecodeString(parts[4]); err != nil {
		return nil, nil, c, ErrMalformed
	}
	if sum, err = b64.DecodeString(parts[5]); err != nil {
		return nil, nil, c, ErrMalformed
	}
	if len(salt) == 0 || len(sum) == 0 {
		return nil, nil, c, ErrMalformed
	}
	return salt, sum, c, nil
}

// Token returns a URL-safe random string of n bytes of entropy, for device
// tokens and session signing keys.
func Token(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("read random: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// PairCode returns an 8-character human-transcribable pairing code (§4).
//
// The alphabet drops the characters that get misread when someone reads a code
// off one screen and types it into another — no 0/O, no 1/I/L, no U next to V.
// 28 symbols over 8 characters is about 38 bits, which is far more than a
// single-use code with a ten-minute life needs.
const codeAlphabet = "ABCDEFGHJKMNPQRSTWXYZ23456789"

func PairCode() (string, error) {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("read random: %w", err)
	}
	out := make([]byte, 0, 9)
	for i, b := range buf {
		if i == 4 {
			out = append(out, '-')
		}
		// Modulo bias over a 29-symbol alphabet is under 2% on the worst symbol,
		// which costs a fraction of a bit against a code that lives ten minutes
		// and is single use. Rejection sampling here would be ceremony.
		out = append(out, codeAlphabet[int(b)%len(codeAlphabet)])
	}
	return string(out), nil
}
