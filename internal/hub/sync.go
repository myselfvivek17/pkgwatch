package hub

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/myselfvivek17/pkgwatch/internal/fleet"
	"github.com/myselfvivek17/pkgwatch/internal/repo"
)

// handleSync takes one push from an approved device.
func (s *State) handleSync(now func() time.Time) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		dev := deviceFrom(r.Context())

		body, err := io.ReadAll(r.Body)
		if err != nil {
			refuse(w, http.StatusBadRequest, fleet.CodeBadRequest, "could not read the request")
			return
		}
		var req fleet.SyncRequest
		if err := json.Unmarshal(body, &req); err != nil {
			refuse(w, http.StatusBadRequest, fleet.CodeBadRequest, "could not parse the request")
			return
		}

		var resp fleet.SyncResponse

		events := make([]repo.FleetEvent, 0, len(req.Events))
		for _, e := range req.Events {
			events = append(events, repo.FleetEvent{
				DeviceID: dev.ID, AgentID: e.AgentID, At: e.At, Kind: e.Kind,
				Severity: e.Severity, PURL: e.PURL, AdvisoryID: e.AdvisoryID, Detail: e.Detail,
			})
		}
		accepted, through, err := s.Repo.IngestEvents(dev.ID, events, now())
		if err != nil {
			// No partial acknowledgement. Reporting a cursor the hub does not
			// actually hold would have the agent mark those events synced and
			// never send them again.
			slog.Error("could not store fleet events", "device", dev.ID, "error", err)
			refuse(w, http.StatusInternalServerError, fleet.CodeBadRequest, "could not store events")
			return
		}
		resp.Events = accepted
		resp.AcceptedThrough = through

		// Findings replace only when the agent says the snapshot is complete. A
		// truncated set applied as a replacement deletes every finding it left
		// out, which would render the machine cleaner than it is — the one
		// direction this tool must never fail in.
		if req.FindingsComplete {
			findings := make([]repo.FleetFinding, 0, len(req.Findings))
			for _, f := range req.Findings {
				findings = append(findings, repo.FleetFinding{
					PURL: f.PURL, AdvisoryID: f.AdvisoryID, Tier: f.Tier,
					Score: f.Score, State: f.State, DetectedAt: f.DetectedAt,
				})
			}
			if resp.Findings, err = s.Repo.ReplaceFindings(dev.ID, findings, now()); err != nil {
				slog.Error("could not store fleet findings", "device", dev.ID, "error", err)
				refuse(w, http.StatusInternalServerError, fleet.CodeBadRequest, "could not store findings")
				return
			}
		} else if len(req.Findings) > 0 {
			slog.Warn("ignored a partial findings snapshot",
				"device", dev.ID, "count", len(req.Findings))
		}

		// Inventory only at sync_level = full, and only when this device is
		// actually set to it on the hub. Sending the full package list hands the
		// hub a map of exploitable software on every machine (§3.3); the hub's
		// record of the level is authoritative so a compromised agent cannot
		// start volunteering it.
		if dev.SyncLevel != repo.SyncLevelFull && len(req.Packages) > 0 {
			// An agent set to full whose hub row still says findings sends its
			// whole inventory and has it dropped on the floor. Both sides read
			// as working — the agent reports packages sent, the search page
			// reports the machine as findings-only — and nothing connects the
			// two. Said once per push, on the side that made the decision.
			slog.Warn("dropped an inventory this hub is not set to accept",
				"device", dev.ID, "packages", len(req.Packages),
				"hub_level", dev.SyncLevel,
				"fix", "press \"accept inventory\" for this device on the pairing page")
		}
		if dev.SyncLevel == repo.SyncLevelFull && len(req.Packages) > 0 {
			packages := make([]repo.FleetPackage, 0, len(req.Packages))
			for _, p := range req.Packages {
				packages = append(packages, repo.FleetPackage{
					PURL: p.PURL, Ecosystem: p.Ecosystem, Name: p.Name,
					Version: p.Version, Scope: p.Scope, LastSeen: p.LastSeen,
				})
			}
			if resp.Packages, err = s.Repo.ReplacePackages(dev.ID, packages); err != nil {
				slog.Error("could not store fleet packages", "device", dev.ID, "error", err)
				refuse(w, http.StatusInternalServerError, fleet.CodeBadRequest, "could not store packages")
				return
			}
		}

		// Touched last, and only on success. last_seen_at is what the fleet page
		// reads to decide a machine is reporting; setting it on a push that then
		// failed to store anything would render a broken agent as healthy.
		if err := s.Repo.TouchDevice(dev.ID, req.Version, now()); err != nil {
			slog.Warn("could not record device check-in", "device", dev.ID, "error", err)
		}

		writeJSON(w, http.StatusOK, resp)
	}
}
