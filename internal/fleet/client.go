package fleet

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/myselfvivek17/pkgwatch/internal/device"
)

// Client is the agent's side of the sync protocol.
type Client struct {
	BaseURL  string
	Token    string
	Identity device.Identity

	HTTP *http.Client
	Now  func() time.Time
}

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
	return &http.Client{Timeout: 30 * time.Second}
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
