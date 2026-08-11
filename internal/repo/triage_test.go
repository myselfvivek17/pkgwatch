package repo_test

import (
	"errors"
	"testing"
	"time"

	"github.com/myselfvivek17/pkgwatch/internal/repo"
)

// score matters as much as tier here: announcement decisions key on the
// contextual score, so a fixture with a low tier and a score of 9 would be
// announced and look like a bug in the code rather than in the fixture.
func seedFinding(t *testing.T, store repo.Agent, purl, advisory, tier string, score float64) {
	t.Helper()
	if _, err := store.RecordFindings([]repo.Finding{{
		PURL: purl, AdvisoryID: advisory, Score: score, Tier: tier, State: repo.StateNew,
	}}, time.Now()); err != nil {
		t.Fatal(err)
	}
}

func openPURLs(t *testing.T, store repo.Agent) map[string]string {
	t.Helper()
	rows, err := store.OpenFindings(false, repo.FindingFilter{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, row := range rows {
		out[row.PURL] = row.State
	}
	return out
}

// --days is the whole point of ignore. If nothing enforces the expiry then
// "hide this for a week" silently means "never mention it again", which is how
// a deferred decision becomes a forgotten one.
func TestIgnoreExpiresOnItsOwn(t *testing.T) {
	store := newAgentDB(t)
	seedFinding(t, store, "pkg:npm/lodash@4.17.20", "GHSA-x", "critical", 9.8)
	seedFinding(t, store, "pkg:npm/chalk@5.0.0", "GHSA-y", "low", 2.0)

	until := time.Now().Add(24 * time.Hour)
	for _, purl := range []string{"pkg:npm/lodash@4.17.20", "pkg:npm/chalk@5.0.0"} {
		if err := store.IgnoreFinding(purl, map[string]string{
			"pkg:npm/lodash@4.17.20": "GHSA-x", "pkg:npm/chalk@5.0.0": "GHSA-y",
		}[purl], "waiting on upstream", until); err != nil {
			t.Fatal(err)
		}
	}
	if len(openPURLs(t, store)) != 0 {
		t.Fatal("ignored findings are still listed")
	}

	// Still inside the window: nothing comes back.
	n, err := store.ExpireIgnores(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("ExpireIgnores brought back %d findings before their window ended", n)
	}

	// Past it.
	n, err = store.ExpireIgnores(until.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("ExpireIgnores = %d, want 2", n)
	}

	open := openPURLs(t, store)
	if len(open) != 2 {
		t.Fatalf("open findings = %+v, want both back", open)
	}
	// Back at the weight a first scan would have given them: an expiring ignore
	// must not produce the alert storm baseline mode exists to prevent.
	if open["pkg:npm/lodash@4.17.20"] != repo.StateNew {
		t.Errorf("critical came back as %q, want new", open["pkg:npm/lodash@4.17.20"])
	}
	if open["pkg:npm/chalk@5.0.0"] != repo.StateAcknowledged {
		t.Errorf("low came back as %q, want acknowledged", open["pkg:npm/chalk@5.0.0"])
	}
}

// Acknowledging keeps a finding listed. Confusing the two would mean a person
// who meant "I have seen this" silently hid it instead.
func TestAcknowledgeKeepsItListed(t *testing.T) {
	store := newAgentDB(t)
	seedFinding(t, store, "pkg:npm/lodash@4.17.20", "GHSA-x", "critical", 9.8)

	if err := store.AcknowledgeFinding("pkg:npm/lodash@4.17.20", "GHSA-x", "known, fix next sprint"); err != nil {
		t.Fatal(err)
	}
	open := openPURLs(t, store)
	if open["pkg:npm/lodash@4.17.20"] != repo.StateAcknowledged {
		t.Fatalf("state = %q, want acknowledged and still listed", open["pkg:npm/lodash@4.17.20"])
	}
}

// A typo must not read as "handled".
func TestTriageRefusesUnknownFindings(t *testing.T) {
	store := newAgentDB(t)
	err := store.AcknowledgeFinding("pkg:npm/nope@1.0.0", "GHSA-z", "")
	if !errors.Is(err, repo.ErrNoSuchFinding) {
		t.Errorf("err = %v, want ErrNoSuchFinding", err)
	}
}
