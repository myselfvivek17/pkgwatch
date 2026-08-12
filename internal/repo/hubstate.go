package repo

import (
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/myselfvivek17/pkgwatch/internal/secret"
)

// Keys in the hub's own state bag.
const (
	hubSessionKey = "session_key"
)

// State reads one key from the hub's state bag. A missing key is "" with no
// error.
func (h Hub) State(key string) (string, error) {
	var v string
	err := h.DB.QueryRow("SELECT v FROM hub_state WHERE k = ?", key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v, err
}

func (h Hub) SetState(key, value string) error {
	_, err := h.DB.Exec(`INSERT INTO hub_state (k, v) VALUES (?, ?)
		ON CONFLICT(k) DO UPDATE SET v = excluded.v`, key, value)
	return err
}

// SessionKey returns the hub's session signing key, generating one on first
// call.
//
// Generated rather than derived from the password hash, and stored here rather
// than in the config file. Deriving it would mean anyone who learned the
// password could forge session cookies without logging in, and would make
// changing the password silently sign every user out — which reads as a bug and
// teaches people not to change it.
//
// INSERT OR IGNORE then read back, so two hub processes starting at once agree
// on one key instead of each writing its own and invalidating the other's
// sessions.
func (h Hub) SessionKey() ([]byte, error) {
	fresh, err := secret.Token(32)
	if err != nil {
		return nil, err
	}
	if _, err := h.DB.Exec("INSERT OR IGNORE INTO hub_state (k, v) VALUES (?, ?)",
		hubSessionKey, fresh); err != nil {
		return nil, fmt.Errorf("store session key: %w", err)
	}

	stored, err := h.State(hubSessionKey)
	if err != nil {
		return nil, err
	}
	key, err := base64.RawURLEncoding.DecodeString(stored)
	if err != nil || len(key) < 32 {
		// A key too short to be one we wrote must not be used. Signing with it
		// would produce cookies that verify, which is the failure mode where
		// everything looks fine and nothing is protected.
		return nil, fmt.Errorf("hub session key in %s is unusable — delete the row to have a new one generated", hubSessionKey)
	}
	return key, nil
}
