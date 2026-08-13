package agent

import (
	"database/sql"
	"log/slog"
	"sync"

	"github.com/myselfvivek17/pkgwatch/internal/db"
)

// Lease coordinates the one moment the merged advisory database is replaced.
//
// The daemon is the process that holds that file open — the dashboard, both
// registry gates and every scan read through it — which is exactly why the
// daemon is the one that can replace it. On Windows a rename over a file with
// an open handle fails outright, so a swap has to happen with every reader in
// this process stood down and reattached afterwards.
//
// Readers take Read, which is a read lock: any number at once, and none while a
// swap is in progress. Nothing here is a substitute for the file being replaced
// atomically; it is what stops this process being the reason it cannot be.
type Lease struct {
	mu   sync.RWMutex
	path string

	handlesMu sync.Mutex
	handles   []*sql.DB
}

func NewLease(advisoryPath string) *Lease { return &Lease{path: advisoryPath} }

// Register adds a long-lived handle that has the advisory database attached, so
// the swap can detach and reattach it.
//
// A handle that reads advisories and is not registered is the failure this type
// exists to prevent: the swap succeeds everywhere else and that one handle
// keeps answering out of a file that no longer exists.
func (l *Lease) Register(handle *sql.DB) {
	if l == nil || handle == nil {
		return
	}
	l.handlesMu.Lock()
	defer l.handlesMu.Unlock()
	l.handles = append(l.handles, handle)
}

// Read runs fn with the advisory database guaranteed not to be swapped under it.
func (l *Lease) Read(fn func() error) error {
	if l == nil {
		return fn()
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	return fn()
}

// Swap stands every registered reader down, runs replace, and brings them back.
//
// Reattachment is attempted for every handle even if one fails, and a failure
// is loud: a handle left detached still answers queries, with no advisories in
// them, which is the shape of "nothing found" that this project keeps refusing
// to let mean "nothing wrong".
func (l *Lease) Swap(replace func() error) error {
	if l == nil {
		return replace()
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	l.handlesMu.Lock()
	handles := append([]*sql.DB(nil), l.handles...)
	l.handlesMu.Unlock()

	for _, handle := range handles {
		if err := db.DetachAdvisories(handle); err != nil {
			slog.Warn("could not release the advisory database before swapping it", "error", err)
		}
	}

	replaceErr := replace()

	for _, handle := range handles {
		attached, err := db.AttachAdvisories(handle, l.path)
		if err != nil || !attached {
			// Said at error level even though the process keeps running. Matching
			// is disarmed on this handle until the agent is restarted, and a
			// disarmed gate that looks healthy is worse than one that is down.
			slog.Error("advisory database is NOT attached after a bundle swap — "+
				"restart the agent; matching on this connection is disarmed until then",
				"path", l.path, "attached", attached, "error", err)
		}
	}
	return replaceErr
}
