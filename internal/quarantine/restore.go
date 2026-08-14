package quarantine

import (
	"fmt"
	"os"
	"time"

	"github.com/myselfvivek17/pkgwatch/internal/repo"
)

// Restore puts a quarantined package back where it was and checks that what
// came back is what was taken.
//
// It lives here rather than in the CLI because the dashboard restores too, and
// the verification is the feature: two copies of this would eventually be two
// different definitions of "restored". The caller prints; every outcome is
// recorded here so the answer survives whoever asked.
func Restore(store repo.Agent, id string, now time.Time) (repo.QuarantineItem, error) {
	item, err := store.QuarantineItem(id)
	if err != nil {
		return item, err
	}
	if !item.Restorable() {
		return item, fmt.Errorf("%s is in state %q, not %q — nothing to restore",
			id, item.State, repo.QuarantineActive)
	}

	if _, err := os.Stat(item.ArchivePath); err != nil {
		// Its own state rather than a passing error: an archive that has been
		// deleted means this package can never come back, and that fact should
		// outlive the command that discovered it.
		if markErr := store.MarkQuarantineMissing(id); markErr != nil {
			return item, fmt.Errorf("the archive for %s is gone (%s), and the record could not be "+
				"updated: %w", id, item.ArchivePath, markErr)
		}
		return item, fmt.Errorf("the archive for %s is gone (%s) — this package cannot be restored",
			id, item.ArchivePath)
	}
	if _, err := os.Stat(item.OriginPath); err == nil {
		return item, fmt.Errorf("%s already exists — refusing to unpack over it. Move it aside first",
			item.OriginPath)
	}

	digest, err := Unpack(item.ArchivePath, item.OriginPath)
	if err != nil {
		if markErr := store.MarkRestored(id, repo.QuarantineFailed, "", now); markErr != nil {
			return item, fmt.Errorf("%w (and the failure could not be recorded: %v)", err, markErr)
		}
		return item, err
	}

	if digest != item.SHA256 {
		if markErr := store.MarkRestored(id, repo.QuarantineFailed, digest, now); markErr != nil {
			return item, markErr
		}
		return item, fmt.Errorf("RESTORED FILES DO NOT MATCH: took %s, put back %s. "+
			"The files are at %s and are not what was removed", item.SHA256, digest, item.OriginPath)
	}
	if err := store.MarkRestored(id, repo.QuarantineRestored, digest, now); err != nil {
		return item, err
	}

	// The files are back, so the finding is back. Without this the row keeps the
	// 'quarantined' state it was given when the package was taken away, and goes
	// on claiming the package is contained while it sits on disk. The scan's
	// present-packages pass reaches the same conclusion, but hours later.
	if _, err := store.ReopenFindingsForRestored(item.PURL); err != nil {
		return item, fmt.Errorf("restored, but its findings could not be reopened — "+
			"they still read as quarantined: %w", err)
	}

	if err := store.RecordEvent(repo.EventRestore, "high", item.PURL, item.AdvisoryID,
		map[string]any{"id": id, "path": item.OriginPath}, now); err != nil {
		// The files are back; only the timeline row is missing. Reported rather
		// than returned, so a logging failure cannot look like a failed restore.
		return item, fmt.Errorf("restored, but the event could not be recorded: %w", err)
	}
	return item, nil
}
