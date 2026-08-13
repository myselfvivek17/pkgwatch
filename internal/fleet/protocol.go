// Package fleet holds the wire contract between an agent and its hub, and the
// agent-side client that speaks it.
//
// Both sides import these types so the payload has one definition rather than
// two that drift. Sync is outbound only (§7): an agent pushes and never pulls
// instructions, which is what keeps hard rule 1 true — a hub that has been
// taken over can stop receiving, and cannot tell an agent to stop gating.
package fleet

import (
	"time"

	"github.com/myselfvivek17/pkgwatch/internal/bundle"
)

// APIBase is the versioned prefix every endpoint sits under. Versioned from
// the start because an agent and its hub are upgraded on different days.
const APIBase = "/api/v1"

// Endpoints.
const (
	PathEnroll  = APIBase + "/enroll"
	PathSync    = APIBase + "/sync"
	PathBundles = APIBase + "/bundles"
)

// BundleOffer is one advisory bundle the hub holds and will serve.
//
// The manifest travels with it, signature included, because that is what the
// agent verifies against its own compiled-in publisher key. The hub relaying it
// is a bandwidth cache and nothing more: it cannot make a bundle trusted, and a
// hub that has been taken over cannot use this to push "everything is safe"
// (§0, hard rule 2).
type BundleOffer struct {
	// File names the bundle for the fetch that follows. It is a convenience
	// only — placement follows the scope inside the signed manifest, so a hub
	// serving the npm bundle under a Debian name still lands as npm.
	File     string          `json:"file"`
	Manifest bundle.Manifest `json:"manifest"`
}

// BundleListResponse is what the hub offers. Empty is a normal answer: a hub
// with no bundle of its own has nothing to relay, and says so rather than
// leaving the agent to infer it from a 404.
type BundleListResponse struct {
	Bundles []BundleOffer `json:"bundles"`
}

// EnrollRequest pairs an agent with a hub.
//
// Carries the public key rather than only the derived ID so the hub can verify
// the signature on this very request — proof the caller holds the key it is
// enrolling, rather than one it copied off someone else's screen.
type EnrollRequest struct {
	DeviceID  string `json:"device_id"`
	PublicKey string `json:"public_key"`
	Code      string `json:"code"`
	Hostname  string `json:"hostname"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	Version   string `json:"version"`
	SyncLevel string `json:"sync_level"`
}

// EnrollResponse hands back the device token.
//
// Status is always pending: approval is a person comparing the device ID shown
// here with the one on the hub, and an enrolment that approved itself would
// make that comparison decorative.
type EnrollResponse struct {
	DeviceID string `json:"device_id"`
	Token    string `json:"token"`
	Status   string `json:"status"`
}

// Event is one timeline row on its way to the hub.
type Event struct {
	AgentID    int64     `json:"agent_event_id"`
	At         time.Time `json:"ts"`
	Kind       string    `json:"kind"`
	Severity   string    `json:"severity,omitempty"`
	PURL       string    `json:"purl,omitempty"`
	AdvisoryID string    `json:"advisory_id,omitempty"`
	Detail     string    `json:"detail_json,omitempty"`
}

// Finding is one open finding on its way to the hub.
type Finding struct {
	PURL       string    `json:"purl"`
	AdvisoryID string    `json:"advisory_id"`
	Tier       string    `json:"tier"`
	Score      float64   `json:"score"`
	State      string    `json:"state"`
	DetectedAt time.Time `json:"detected_at"`
}

// Package is one inventory row, sent only at sync_level = full.
type Package struct {
	PURL      string    `json:"purl"`
	Ecosystem string    `json:"ecosystem"`
	Name      string    `json:"name"`
	Version   string    `json:"version"`
	Scope     string    `json:"scope"`
	LastSeen  time.Time `json:"last_seen"`
}

// SyncRequest is one push.
//
// Events are incremental against the agent's own cursor. Findings are a full
// snapshot every time, and deliberately so: the agent's findings table has no
// updated_at, and more importantly a delta can only ever add. A snapshot is the
// only shape that carries a closure — without it the hub's counts climb forever
// and a fleet that is getting better looks like one getting worse.
type SyncRequest struct {
	Version   string    `json:"agent_version"`
	SyncLevel string    `json:"sync_level"`
	Events    []Event   `json:"events"`
	Findings  []Finding `json:"findings"`
	Packages  []Package `json:"packages,omitempty"`

	// FindingsComplete says whether Findings is the whole set. A truncated
	// snapshot must not be treated as one, or the hub deletes everything the
	// push happened to leave out.
	FindingsComplete bool `json:"findings_complete"`
}

// SyncResponse acknowledges a push.
//
// AcceptedThrough is the highest agent event ID the hub has durably stored. The
// agent marks its cursor from this rather than from what it sent, so a push
// that half-succeeded is re-sent rather than silently skipped.
type SyncResponse struct {
	AcceptedThrough int64 `json:"accepted_through"`
	Events          int   `json:"events"`
	Findings        int   `json:"findings"`
	Packages        int   `json:"packages"`
}

// ErrorResponse is what every refusal carries.
//
// Code is machine-readable so the agent can tell "not approved yet" from
// "revoked" — one is a wait and the other is a stop, and an agent that retried
// through a revocation forever would look healthy while reporting nothing.
type ErrorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Refusal codes.
const (
	CodePending    = "device_pending"
	CodeRevoked    = "device_revoked"
	CodeUnknown    = "device_unknown"
	CodeAuth       = "device_auth"
	CodeBadRequest = "bad_request"
)
