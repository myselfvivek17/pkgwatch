package fleet

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ErrWrongCertificate is what a pin mismatch looks like.
//
// Its own type because the difference between this and an ordinary network
// error is the difference between "the hub is down" and "something is
// answering for the hub". Only one of those is worth waking someone for.
type ErrWrongCertificate struct{ Expected, Got string }

func (e ErrWrongCertificate) Error() string {
	return fmt.Sprintf(
		"the hub presented a different certificate than the one pinned at pairing\n"+
			"  pinned:    %s\n"+
			"  presented: %s\n"+
			"Either the hub's certificate was regenerated, or something is answering in its place.\n"+
			"If the hub was rebuilt, re-pair this agent; do not ignore this otherwise.",
		e.Expected, e.Got)
}

// Fingerprint is the SHA-256 of a certificate's DER bytes, grouped in fours.
//
// Grouped because a person compares it by eye against what the hub printed —
// the same reason the device ID is grouped. Both halves of that comparison have
// to be the same shape or nobody does it properly.
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	encoded := strings.ToUpper(hex.EncodeToString(sum[:]))

	var out strings.Builder
	for i := 0; i < len(encoded); i += 4 {
		if i > 0 {
			out.WriteByte('-')
		}
		out.WriteString(encoded[i : i+4])
	}
	return out.String()
}

// normaliseFingerprint lets a person paste one with or without the dashes.
func normaliseFingerprint(s string) string {
	return strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(s), "-", ""))
}

// SameFingerprint compares two fingerprints regardless of formatting.
func SameFingerprint(a, b string) bool {
	return a != "" && normaliseFingerprint(a) == normaliseFingerprint(b)
}

// pinnedTransport builds an HTTP transport that trusts exactly one certificate.
//
// InsecureSkipVerify AND VerifyPeerCertificate, never the first without the
// second. Skipping verification is what lets a self-signed certificate through;
// the callback is the only thing that then checks anything at all. Shipping the
// first alone is not weaker verification, it is none — and it looks identical
// from the outside, which is why they live in one function that cannot produce
// one without the other.
func pinnedTransport(expected string, seen *string) *http.Transport {
	return &http.Transport{
		TLSClientConfig: &tls.Config{
			// Name verification is deliberately not used. The hub is reached by
			// LAN hostname or bare IP, and its certificate is trusted because a
			// person compared its fingerprint — not because a CA vouched for a
			// name.
			InsecureSkipVerify: true, //nolint:gosec // VerifyPeerCertificate below is the check
			MinVersion:         tls.VersionTLS12,
			VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
				if len(rawCerts) == 0 {
					return errors.New("the hub presented no certificate")
				}
				got := Fingerprint(rawCerts[0])
				if seen != nil {
					*seen = got
				}
				// An empty pin means first contact, and the caller is capturing
				// the fingerprint to show a person. Every later request has one.
				if expected == "" {
					return nil
				}
				if !SameFingerprint(expected, got) {
					return ErrWrongCertificate{Expected: expected, Got: got}
				}
				return nil
			},
		},
		TLSHandshakeTimeout: 10 * time.Second,
	}
}
