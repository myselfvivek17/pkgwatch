package hub

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/myselfvivek17/pkgwatch/internal/device"
	"github.com/myselfvivek17/pkgwatch/internal/fleet"
	"github.com/myselfvivek17/pkgwatch/internal/repo"
	"github.com/myselfvivek17/pkgwatch/internal/secret"
)

// maxBody caps a sync push. The queue is bounded at 50k events (§7), which at a
// few hundred bytes each lands well under this; the cap is here so a device
// that has gone wrong cannot make the hub allocate without limit.
const maxBody = 32 << 20

// tokenBytes is the entropy in a device token. Long enough that the token is
// never the weak half of the pair.
const tokenBytes = 32

// deviceKey carries the authenticated device to the handler.
type ctxKey struct{}

func deviceFrom(ctx context.Context) repo.Device {
	d, _ := ctx.Value(ctxKey{}).(repo.Device)
	return d
}

// API mounts the endpoints agents talk to.
//
// Outside the dashboard's session guard, and correctly so: agents authenticate
// with a device token and a signature, not with the hub password. They are
// separate credentials for separate callers, which is why revoking one machine
// does not sign a person out of the dashboard.
func (s *State) API(r chi.Router, now func() time.Time) {
	r.Post(fleet.PathEnroll, s.handleEnroll(now))
	r.Post(fleet.PathSync, s.requireDevice(now, s.handleSync(now)))
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(body)
}

func refuse(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, fleet.ErrorResponse{Code: code, Message: message})
}

// handleEnroll turns a valid pairing code into a device token.
func (s *State) handleEnroll(now func() time.Time) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
		if err != nil {
			refuse(w, http.StatusBadRequest, fleet.CodeBadRequest, "could not read the request")
			return
		}
		var req fleet.EnrollRequest
		if err := json.Unmarshal(body, &req); err != nil {
			refuse(w, http.StatusBadRequest, fleet.CodeBadRequest, "could not parse the request")
			return
		}

		pub, err := device.DecodePublic(req.PublicKey)
		if err != nil {
			refuse(w, http.StatusBadRequest, fleet.CodeBadRequest, err.Error())
			return
		}
		// The ID is a function of the key, and a person is about to compare it by
		// eye against what the agent printed. A device that could choose its own
		// ID independently of its key would make that comparison meaningless.
		if device.ID(pub) != req.DeviceID {
			refuse(w, http.StatusBadRequest, fleet.CodeBadRequest,
				"device ID does not match the public key it was sent with")
			return
		}

		// Signature before code redemption, so a caller who cannot prove key
		// possession cannot burn somebody's pairing code by guessing at it.
		if err := device.Verify(r, body, pub, now()); err != nil {
			refuse(w, http.StatusUnauthorized, fleet.CodeAuth, err.Error())
			return
		}

		if err := s.Repo.RedeemPairCode(req.Code, now()); err != nil {
			if errors.Is(err, repo.ErrBadPairCode) {
				refuse(w, http.StatusForbidden, fleet.CodeAuth, err.Error())
				return
			}
			refuse(w, http.StatusInternalServerError, fleet.CodeBadRequest, "could not redeem the code")
			return
		}

		token, err := secret.Token(tokenBytes)
		if err != nil {
			refuse(w, http.StatusInternalServerError, fleet.CodeBadRequest, "could not issue a token")
			return
		}
		hash, err := secret.Hash(token)
		if err != nil {
			refuse(w, http.StatusInternalServerError, fleet.CodeBadRequest, "could not store the token")
			return
		}

		enrolled := repo.Device{
			ID: req.DeviceID, PublicKey: pub, TokenHash: hash,
			Hostname: req.Hostname, OS: req.OS, Arch: req.Arch,
			SyncLevel: req.SyncLevel, Version: req.Version,
		}
		if err := s.Repo.Enroll(enrolled, now()); err != nil {
			refuse(w, http.StatusInternalServerError, fleet.CodeBadRequest, "could not enrol the device")
			return
		}

		// The token is logged nowhere, here or anywhere else. It is written once
		// into this response and never read back — only its hash is stored.
		slog.Info("device enrolled, awaiting approval",
			"device", req.DeviceID, "hostname", req.Hostname, "os", req.OS)

		writeJSON(w, http.StatusOK, fleet.EnrollResponse{
			DeviceID: req.DeviceID,
			Token:    token,
			Status:   repo.DeviceStatusPending,
		})
	}
}

// requireDevice authenticates a signed, token-bearing request.
//
// Order matters and is not the obvious one. The signature is checked before the
// token even though the token is the "primary" credential, because verifying a
// token means an argon2id hash — 64 MiB and a few milliseconds by design. An
// attacker who can make the hub do that for free has a memory-exhaustion lever
// on an endpoint reachable from the whole LAN. Checking the ed25519 signature
// first costs microseconds and already requires the device's private key, so
// nothing unauthenticated ever reaches the expensive half.
func (s *State) requireDevice(now func() time.Time, next func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(device.HeaderDevice)
		if id == "" {
			refuse(w, http.StatusUnauthorized, fleet.CodeAuth, "request names no device")
			return
		}

		known, err := s.Repo.Device(id)
		if err != nil {
			if errors.Is(err, repo.ErrNoSuchDevice) {
				refuse(w, http.StatusUnauthorized, fleet.CodeUnknown,
					"this hub has no record of that device — pair it again")
				return
			}
			refuse(w, http.StatusInternalServerError, fleet.CodeAuth, "could not look up the device")
			return
		}

		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
		if err != nil {
			refuse(w, http.StatusRequestEntityTooLarge, fleet.CodeBadRequest, "request body too large")
			return
		}

		pub, err := device.PublicFromBytes(known.PublicKey)
		if err != nil {
			refuse(w, http.StatusInternalServerError, fleet.CodeAuth, "stored key for this device is unusable")
			return
		}
		if err := device.Verify(r, body, pub, now()); err != nil {
			// Logged with the reason so a drifted clock reads as a clock problem
			// rather than as an attack — the two look identical otherwise.
			slog.Warn("refused a device request", "device", id, "reason", err)
			refuse(w, http.StatusUnauthorized, fleet.CodeAuth, err.Error())
			return
		}

		// Status is checked after the signature and before the token, so a
		// revoked device gets a straight answer without the hub paying argon2
		// for a credential it is going to reject anyway.
		switch known.Status {
		case repo.DeviceStatusApproved:
		case repo.DeviceStatusRevoked:
			refuse(w, http.StatusForbidden, fleet.CodeRevoked,
				"this device has been revoked on the hub — it will keep gating installs locally, but will not sync")
			return
		default:
			refuse(w, http.StatusForbidden, fleet.CodePending,
				"this device is enrolled but not approved yet — approve it on the hub's device page")
			return
		}

		if !secret.Verify(bearer(r), known.TokenHash) {
			refuse(w, http.StatusUnauthorized, fleet.CodeAuth, "device token does not match")
			return
		}

		r.Body = io.NopCloser(bytes.NewReader(body))
		next(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, known)))
	}
}

func bearer(r *http.Request) string {
	const prefix = "Bearer "
	value := r.Header.Get("Authorization")
	if len(value) <= len(prefix) {
		return ""
	}
	return value[len(prefix):]
}
