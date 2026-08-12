package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/myselfvivek17/pkgwatch/internal/buildinfo"
	"github.com/myselfvivek17/pkgwatch/internal/config"
	"github.com/myselfvivek17/pkgwatch/internal/db"
	"github.com/myselfvivek17/pkgwatch/internal/device"
	"github.com/myselfvivek17/pkgwatch/internal/fleet"
	"github.com/myselfvivek17/pkgwatch/internal/repo"
)

// Backoff bounds, and the steady-state interval between pushes (§7).
const (
	syncInterval    = 5 * time.Minute
	backoffInitial  = 30 * time.Second
	backoffMax      = 30 * time.Minute
	eventBatchLimit = 2_000
)

// runSync pushes to the hub until ctx ends.
//
// Everything here is best-effort by construction. The agent gates installs,
// scans and matches whether or not any of this succeeds — that is hard rule 1,
// and it is why no error in this file is ever returned to the caller as fatal.
func runSync(ctx context.Context, cfg config.Config) {
	// "off" is a real choice, not a misconfiguration: sending the full
	// inventory hands a hub a map of exploitable software on every machine, and
	// some people want none of it leaving the box (§3.3).
	if cfg.Agent.SyncLevel == "off" {
		slog.Info("fleet sync disabled (sync_level = off)")
		return
	}

	backoff := backoffInitial

	for {
		outcome := syncOnce(cfg)

		wait := syncInterval
		switch outcome {
		case syncHalted:
			// Revoked, or unknown to the hub. Retrying cannot fix either — both
			// need a person — and an agent that kept trying would sit in a
			// backoff loop looking healthy while reporting nothing.
			//
			// Halted for this process only. Restarting the agent retries once,
			// which is what makes re-approving on the hub actually recoverable.
			slog.Warn("fleet sync stopped until this agent is restarted; " +
				"gating and scanning are unaffected")
			return
		case syncFailed:
			wait = backoff
			backoff = min(backoff*2, backoffMax)
		default:
			backoff = backoffInitial
		}

		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return
		}
	}
}

type syncOutcome int

const (
	syncOK syncOutcome = iota
	syncFailed
	syncSkipped
	syncHalted
)

// syncOnce runs one push on its own database handle, for the same reason a
// scheduled scan does: db.Open pins a handle to one connection, and a push that
// waits on the network must not be holding the connection an install needs.
func syncOnce(cfg config.Config) syncOutcome {
	handle, err := db.Open(cfg.AgentDBPath(), db.SchemaAgent)
	if err != nil {
		slog.Error("fleet sync could not open the database", "error", err)
		return syncFailed
	}
	defer handle.Close()

	store := repo.Agent{DB: handle}
	client, err := clientFor(store)
	if err != nil {
		slog.Error("fleet sync could not load the pairing", "error", err)
		return syncFailed
	}
	if client == nil {
		return syncSkipped
	}
	level := cfg.Agent.SyncLevel

	now := time.Now()

	// Trim before reading the batch, so an agent that has been offline for a
	// fortnight sends the events that matter rather than the oldest 2,000 scan
	// rows over and over.
	dropped, err := store.TrimQueue(repo.EventQueueCap, now)
	if err != nil {
		slog.Warn("could not trim the sync queue", "error", err)
	}
	if len(dropped) > 0 {
		total := 0
		for _, n := range dropped {
			total += n
		}
		// Recorded, not merely logged. A silently capped queue leaves a hole in
		// the fleet timeline that reads as a quiet week, and this row is itself
		// synced — so the gap arrives with an explanation attached.
		slog.Warn("sync queue over cap, gave up on the least important events",
			"dropped", total, "by_severity", dropped)
		if err := store.RecordEvent(repo.EventSyncDropped, "", "", "",
			map[string]any{"dropped": total, "cap": repo.EventQueueCap}, now); err != nil {
			slog.Warn("could not record the queue drop", "error", err)
		}
	}

	queued, err := store.QueuedEvents(eventBatchLimit)
	if err != nil {
		slog.Error("could not read the sync queue", "error", err)
		return syncFailed
	}
	findings, err := store.SyncableFindings()
	if err != nil {
		slog.Error("could not read findings for sync", "error", err)
		return syncFailed
	}

	push := fleet.SyncRequest{
		Version:   buildinfo.Version,
		SyncLevel: level,
		Events:    make([]fleet.Event, 0, len(queued)),
		Findings:  make([]fleet.Finding, 0, len(findings)),
		// The snapshot is read in full above, so it can be applied as one. If
		// this ever becomes paginated, this flag must go false — the hub deletes
		// whatever a complete snapshot leaves out.
		FindingsComplete: true,
	}
	for _, e := range queued {
		push.Events = append(push.Events, fleet.Event{
			AgentID: e.ID, At: e.At, Kind: e.Kind, Severity: e.Severity,
			PURL: e.PURL, AdvisoryID: e.AdvisoryID, Detail: e.Detail,
		})
	}
	for _, f := range findings {
		push.Findings = append(push.Findings, fleet.Finding{
			PURL: f.PURL, AdvisoryID: f.AdvisoryID, Tier: f.Tier,
			Score: f.Score, State: f.State, DetectedAt: f.DetectedAt,
		})
	}

	if level == "full" {
		packages, err := store.SyncablePackages()
		if err != nil {
			slog.Warn("could not read packages for sync", "error", err)
		}
		for _, p := range packages {
			push.Packages = append(push.Packages, fleet.Package{
				PURL: p.PURL, Ecosystem: p.Ecosystem, Name: p.Name,
				Version: p.Version, Scope: p.Scope, LastSeen: p.LastSeen,
			})
		}
	}

	resp, err := client.Push(push)
	if err != nil {
		return handlePushError(store, err, now)
	}

	// Cleared on success, so an agent re-approved on the hub stops reporting
	// itself as revoked without needing to be paired again.
	if err := store.SetHubState(repo.HubRevoked, ""); err != nil {
		slog.Warn("could not clear the revoked marker", "error", err)
	}

	// The cursor moves to what the hub acknowledged, never to what was sent. A
	// push that half-landed is re-sent; the UNIQUE constraint on the hub side
	// absorbs the overlap.
	marked, err := store.MarkEventsSynced(resp.AcceptedThrough)
	if err != nil {
		slog.Warn("could not advance the sync cursor", "error", err)
	}
	if err := store.SetHubState(repo.HubLastSync, time.Now().UTC().Format(time.RFC3339)); err != nil {
		slog.Warn("could not record the sync time", "error", err)
	}

	slog.Info("synced to hub",
		"events_sent", len(push.Events), "events_stored", resp.Events,
		"cursor_advanced", marked, "findings", resp.Findings, "packages", resp.Packages)
	return syncOK
}

// handlePushError decides whether to retry, and records the refusals a person
// has to act on.
func handlePushError(store repo.Agent, err error, now time.Time) syncOutcome {
	// A pin mismatch is not a network problem and must not be filed as one.
	// "The hub is down" and "something is answering for the hub" are opposite
	// situations, and only one of them is routine.
	var wrongCert fleet.ErrWrongCertificate
	if errors.As(err, &wrongCert) {
		slog.Error("REFUSING to sync: the hub's certificate does not match the one pinned at pairing",
			"pinned", wrongCert.Expected, "presented", wrongCert.Got)
		if err := store.RecordEvent(repo.EventSyncRefused, "critical", "", "",
			map[string]any{
				"reason":    "certificate_mismatch",
				"pinned":    wrongCert.Expected,
				"presented": wrongCert.Got,
			}, now); err != nil {
			slog.Warn("could not record the certificate mismatch", "error", err)
		}
		// Halted rather than retried. Retrying would hand the same credentials
		// to whatever is on the other end, once every thirty seconds.
		return syncHalted
	}

	var apiErr fleet.APIError
	if !errors.As(err, &apiErr) {
		// A network error. Normal, and not worth an event every thirty seconds —
		// the hub being unreachable is the state this tool is built to be fine in.
		slog.Debug("fleet sync could not reach the hub", "error", err)
		return syncFailed
	}

	switch {
	case apiErr.Revoked(), apiErr.Unknown():
		// Persisted so `pkgwatch status` and the dashboard can say which of
		// "revoked" and "cannot reach the hub" is true. Without it a revoked
		// agent is indistinguishable from a healthy one on a quiet network.
		if err := store.SetHubState(repo.HubRevoked, now.UTC().Format(time.RFC3339)); err != nil {
			slog.Warn("could not record the revocation", "error", err)
		}
		if err := store.RecordEvent(repo.EventSyncRefused, "high", "", "",
			map[string]any{"reason": apiErr.Code, "message": apiErr.Message}, now); err != nil {
			slog.Warn("could not record the refusal", "error", err)
		}
		slog.Error("the hub refused this device", "reason", apiErr.Code, "message", apiErr.Message)
		return syncHalted

	case apiErr.Pending():
		// Waiting on a person to approve it. Not an error, and not worth a
		// backoff that would then delay the first real push by half an hour.
		slog.Info("waiting for approval on the hub", "message", apiErr.Message)
		return syncSkipped

	default:
		slog.Warn("hub refused a push", "code", apiErr.Code, "message", apiErr.Message)
		return syncFailed
	}
}

// clientFor builds the sync client from stored pairing state, or returns nil
// when this agent has no hub — which is the normal, supported case.
func clientFor(store repo.Agent) (*fleet.Client, error) {
	token, err := store.HubState(repo.HubToken)
	if err != nil {
		return nil, err
	}
	hubURL, err := store.HubState(repo.HubURL)
	if err != nil {
		return nil, err
	}
	encodedKey, err := store.HubState(repo.HubDeviceKey)
	if err != nil {
		return nil, err
	}
	if token == "" || hubURL == "" || encodedKey == "" {
		return nil, nil
	}

	// The stored revocation marker is deliberately NOT consulted here.
	//
	// It records what the hub last said, for `pkgwatch status` and the
	// dashboard to report. Treating it as a gate would be a one-way door: the
	// marker is only cleared by a successful push, and a client that refuses to
	// be built cannot make one — so re-approving a device on the hub could
	// never bring it back, on this or any later run. Halting is per-process
	// instead, which makes a restart the recovery path.
	id, err := device.Decode(encodedKey)
	if err != nil {
		return nil, err
	}

	fingerprint, err := store.HubState(repo.HubCertFP)
	if err != nil {
		return nil, err
	}
	// An https hub with no pin on file is refused rather than trusted. It means
	// the pairing predates pinning, or the row was lost — and an agent that
	// carried on would accept any certificate at all while looking healthy,
	// which is worse than not syncing.
	if strings.HasPrefix(hubURL, "https://") && fingerprint == "" {
		return nil, fmt.Errorf(
			"no hub certificate is pinned for %s — run `pkgwatch agent unpair` and pair again "+
				"so the certificate can be recorded", hubURL)
	}

	return &fleet.Client{
		BaseURL: hubURL, Token: token, Identity: id, Fingerprint: fingerprint,
	}, nil
}
