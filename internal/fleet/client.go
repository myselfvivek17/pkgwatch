package fleet

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/myselfvivek17/pkgwatch/internal/device"
)

// Client is the agent's side of the sync protocol.
type Client struct {
	BaseURL  string
	Token    string
	Identity device.Identity

	// Fingerprint is the hub certificate pinned at pairing. Empty means first
	// contact: the certificate is accepted and recorded in SeenFingerprint for
	// a person to compare, which is the only moment that trust is established.
	//
	// After pairing this is never empty in normal operation. An agent that lost
	// it would silently accept any certificate, so `agent pair` writes it in
	// the same step that writes the token.
	Fingerprint string

	// SeenFingerprint is what the hub actually presented on the last request.
	SeenFingerprint string

	HTTP *http.Client
	Now  func() time.Time
}

// usesTLS reports whether this client will speak https.
func (c *Client) usesTLS() bool { return strings.HasPrefix(c.BaseURL, "https://") }

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Client) client() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	if !c.usesTLS() {
		return &http.Client{Timeout: 30 * time.Second}
	}
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: pinnedTransport(c.Fingerprint, &c.SeenFingerprint),
	}
}

// APIError is a refusal the hub explained.
//
// Code is kept separate from the message so the agent can act on it: pending is
// a wait, revoked is a stop, and an agent that retried through a revocation
// forever would look healthy while reporting nothing.
type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e APIError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return fmt.Sprintf("hub refused the request (%d)", e.Status)
}

// Revoked and Pending are what a caller actually branches on.
func (e APIError) Revoked() bool { return e.Code == CodeRevoked }
func (e APIError) Pending() bool { return e.Code == CodePending }

// Unknown means the hub has no record of this device — its database was
// restored from before the pairing, or the device was deleted outright.
func (e APIError) Unknown() bool { return e.Code == CodeUnknown }

// post sends one signed request.
//
// The body is marshalled once and both signed and sent, because the signature
// covers a hash of the bytes: re-encoding between the two would produce a
// signature for a payload that never travelled.
func (c *Client) post(path string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}

	url := strings.TrimRight(c.BaseURL, "/") + path
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	c.Identity.Sign(req, body, c.now())

	resp, err := c.client().Do(req)
	if err != nil {
		// A pin mismatch travels out intact rather than wrapped into "could not
		// reach the hub". They are opposite situations: one means the hub is
		// down, the other means something is answering in its place.
		var wrongCert ErrWrongCertificate
		if errors.As(err, &wrongCert) {
			return wrongCert
		}
		return fmt.Errorf("reach hub at %s: %w", c.BaseURL, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read hub response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		apiErr := APIError{Status: resp.StatusCode}
		var parsed ErrorResponse
		if json.Unmarshal(raw, &parsed) == nil {
			apiErr.Code, apiErr.Message = parsed.Code, parsed.Message
		}
		return apiErr
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(raw, out)
}

// get sends one signed read and returns the raw response body.
//
// Signed the same way a push is, over an empty body. The path is part of what
// is signed, so a signature captured from a sync cannot be replayed onto a
// fetch — and the hub applies exactly the same device check to both, which is
// why a revoked machine stops receiving bundles as well as sending events.
func (c *Client) get(path string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, strings.TrimRight(c.BaseURL, "/")+path, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	c.Identity.Sign(req, nil, c.now())

	resp, err := c.client().Do(req)
	if err != nil {
		var wrongCert ErrWrongCertificate
		if errors.As(err, &wrongCert) {
			return nil, wrongCert
		}
		return nil, fmt.Errorf("reach hub at %s: %w", c.BaseURL, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBundleBytes))
	if err != nil {
		return nil, fmt.Errorf("read hub response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		apiErr := APIError{Status: resp.StatusCode}
		var parsed ErrorResponse
		if json.Unmarshal(raw, &parsed) == nil {
			apiErr.Code, apiErr.Message = parsed.Code, parsed.Message
		}
		return nil, apiErr
	}
	return raw, nil
}

// maxBundleBytes bounds a relayed bundle. The published corpus is tens of
// megabytes; this leaves room to grow and still refuses to read forever from
// something answering on the hub's address.
const maxBundleBytes = 256 << 20

// Bundles lists what the hub is willing to relay.
func (c *Client) Bundles() ([]BundleOffer, error) {
	raw, err := c.get(PathBundles)
	if err != nil {
		return nil, err
	}
	var out BundleListResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("parse the hub's bundle list: %w", err)
	}
	return out.Bundles, nil
}

// FetchBundle downloads one bundle's bytes. The caller verifies them; nothing
// about having asked the hub for them makes them trustworthy.
func (c *Client) FetchBundle(file string) ([]byte, error) {
	return c.get(PathBundles + "/" + url.PathEscape(file))
}

// Enroll exchanges a pairing code for a device token.
func (c *Client) Enroll(req EnrollRequest) (EnrollResponse, error) {
	var out EnrollResponse
	err := c.post(PathEnroll, req, &out)
	return out, err
}

// Push sends one batch of events and the current findings snapshot.
func (c *Client) Push(req SyncRequest) (SyncResponse, error) {
	var out SyncResponse
	err := c.post(PathSync, req, &out)
	return out, err
}
