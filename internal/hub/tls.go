package hub

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/myselfvivek17/pkgwatch/internal/config"
)

// certLifetime is deliberately long.
//
// This certificate is not trusted by a CA and never will be — it is trusted
// because its fingerprint was compared by a person at pairing time. Expiry
// therefore buys nothing except a day when every agent in the fleet
// simultaneously stops syncing until each one is re-paired by hand. Rotation is
// a deliberate act here, not a calendar event.
const certLifetime = 10 * 365 * 24 * time.Hour

// Fingerprint is the SHA-256 of a certificate's DER bytes, grouped for reading.
//
// Grouped for the same reason the device ID is: this is compared by eye against
// what the agent printed, and an unbroken 64-character hex string is where that
// comparison stops being done honestly.
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

// CertPaths are where a generated keypair lives. Both are inside the data
// directory, which is created 0700.
func CertPaths(cfg config.Config) (certPath, keyPath string) {
	if cfg.Hub.TLSCert != "" && cfg.Hub.TLSKey != "" {
		return cfg.Hub.TLSCert, cfg.Hub.TLSKey
	}
	return filepath.Join(cfg.DataDir, "hub-cert.pem"), filepath.Join(cfg.DataDir, "hub-tls.key")
}

// LoadOrCreateCert returns the hub's certificate, generating a self-signed one
// on first run.
//
// Generated rather than demanded, because a hub that will not start until
// someone has produced a certificate is a hub nobody runs. A real certificate
// can be supplied through hub.tls_cert and hub.tls_key; agents pin whatever is
// presented at pairing either way, so the distinction matters to browsers and
// not to the sync protocol.
func LoadOrCreateCert(cfg config.Config) (tls.Certificate, error) {
	certPath, keyPath := CertPaths(cfg)

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err == nil {
		return cert, nil
	}
	if !os.IsNotExist(err) && !os.IsNotExist(underlying(err)) {
		// A keypair that exists and will not load is a real problem. Silently
		// generating a replacement would change the fingerprint every agent in
		// the fleet has pinned, and they would all fail to sync with no clue why.
		return tls.Certificate{}, fmt.Errorf("read hub certificate %s: %w", certPath, err)
	}
	if cfg.Hub.TLSCert != "" {
		return tls.Certificate{}, fmt.Errorf(
			"hub.tls_cert is set to %s but it could not be read: %w", cfg.Hub.TLSCert, err)
	}
	return generateCert(certPath, keyPath)
}

// underlying unwraps the *fs.PathError tls.LoadX509KeyPair returns.
func underlying(err error) error {
	type unwrapper interface{ Unwrap() error }
	if u, ok := err.(unwrapper); ok {
		return u.Unwrap()
	}
	return err
}

func generateCert(certPath, keyPath string) (tls.Certificate, error) {
	// ECDSA P-256 rather than Ed25519: browsers still handle Ed25519
	// certificates inconsistently, and this same certificate serves the
	// dashboard a person opens in one.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate hub key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

	host := hostname()
	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: host, Organization: []string{"pkgwatch hub"}},
		NotBefore:             time.Now().Add(-time.Hour), // tolerate a little clock skew
		NotAfter:              time.Now().Add(certLifetime),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
		DNSNames:              dnsNames(host),
		IPAddresses:           localIPs(),
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create hub certificate: %w", err)
	}

	if err := writePEM(certPath, "CERTIFICATE", der, 0o644); err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	// 0600. The certificate is public by definition; the key is not.
	if err := writePEM(keyPath, "EC PRIVATE KEY", keyDER, 0o600); err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: mustParse(der)}, nil
}

func mustParse(der []byte) *x509.Certificate {
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil
	}
	return parsed
}

func writePEM(path, blockType string, der []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	defer file.Close()
	return pem.Encode(file, &pem.Block{Type: blockType, Bytes: der})
}

// dnsNames covers the ways someone might address this hub.
//
// Only a convenience: agents pin the fingerprint and skip name verification
// entirely, so a missing name costs a browser warning rather than a broken
// fleet.
func dnsNames(host string) []string {
	names := []string{"localhost"}
	if host != "" && host != "localhost" {
		names = append(names, host)
		// Windows hostnames are frequently used in lowercase in URLs.
		if lower := strings.ToLower(host); lower != host {
			names = append(names, lower)
		}
	}
	return names
}

func localIPs() []net.IP {
	ips := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ips
	}
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
			ips = append(ips, ipNet.IP)
		}
	}
	return ips
}

// TLSConfig is what the hub listens with.
func TLSConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		// 1.2 floor. Everything in this fleet is this binary or a current
		// browser, so there is nothing old enough to need less.
		MinVersion: tls.VersionTLS12,
	}
}
