package repo_test

import (
	"testing"
	"time"

	"github.com/myselfvivek17/pkgwatch/internal/match"
	"github.com/myselfvivek17/pkgwatch/internal/repo"
)

// Rotation follows from code having run, not from a package being vulnerable.
// The distinction is the advisory's kind, which lives in the bundle rather than
// on the finding — so a machine with no bundle cannot answer this at all, and
// must not answer it as "none".
func TestOnlyMalwareFindingsWarrantARotation(t *testing.T) {
	handle := buildTestBundle(t) // carries GHSA-35jh-r3h4-6jhm and MAL-2025-47141
	store := repo.Agent{DB: handle}
	now := time.Now()

	if _, err := store.RecordFindings([]repo.Finding{
		{PURL: "pkg:npm/lodash@4.17.20", AdvisoryID: "GHSA-35jh-r3h4-6jhm",
			Tier: match.TierHigh, Score: 7.4, State: repo.StateNew, DetectedAt: now},
		{PURL: "pkg:npm/%40ctrl/tinycolor@4.1.2", AdvisoryID: "MAL-2025-47141",
			Tier: match.TierCritical, Score: 10, State: repo.StateNew, DetectedAt: now},
	}, now); err != nil {
		t.Fatal(err)
	}

	findings, err := store.MalwareFindings(true, 50)
	if err != nil {
		t.Fatalf("malware findings: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want only the malware one: %+v", len(findings), findings)
	}
	if findings[0].AdvisoryID != "MAL-2025-47141" {
		t.Errorf("got %s, want the MAL record", findings[0].AdvisoryID)
	}

	// Without a bundle the question cannot be answered. Returning the whole
	// findings table would send someone rotating every key they own because a
	// dependency has a medium CVE.
	if unattached, err := store.MalwareFindings(false, 50); err != nil || len(unattached) != 0 {
		t.Errorf("unattached returned %d findings (err %v), want none", len(unattached), err)
	}
}

// Progress is stored per finding, not per machine: two malicious packages a
// month apart are two exposures with two checklists, and ticking an item on one
// says nothing about the other.
func TestRotationProgressIsKeptPerFinding(t *testing.T) {
	handle := buildTestBundle(t)
	store := repo.Agent{DB: handle}
	now := time.Now()

	const first, second = "pkg:npm/one@1.0.0", "pkg:npm/two@2.0.0"
	if err := store.SetRotationChecked(first, "MAL-1", "ssh", now); err != nil {
		t.Fatal(err)
	}

	checked, err := store.RotationChecked(first, "MAL-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, done := checked["ssh"]; !done {
		t.Error("the ticked item did not come back")
	}

	other, err := store.RotationChecked(second, "MAL-2")
	if err != nil {
		t.Fatal(err)
	}
	if len(other) != 0 {
		t.Errorf("a tick on one exposure marked another as done: %v", other)
	}

	// Unticking clears the timestamp and keeps the row, so changing your mind
	// is recorded rather than erased.
	if err := store.SetRotationChecked(first, "MAL-1", "ssh", time.Time{}); err != nil {
		t.Fatal(err)
	}
	checked, err = store.RotationChecked(first, "MAL-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(checked) != 0 {
		t.Errorf("unticking left %v ticked", checked)
	}
}
