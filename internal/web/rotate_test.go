package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/myselfvivek17/pkgwatch/internal/repo"
	"github.com/myselfvivek17/pkgwatch/internal/rotate"
)

// rotationServer wires the rotation page over fixed data.
func rotationServer(t *testing.T, ticked map[string]time.Time) (*Server, http.Handler) {
	t.Helper()
	srv, err := New(ModeAgent, "test-host")
	if err != nil {
		t.Fatal(err)
	}
	srv.Overview = func() (OverviewData, error) { return OverviewData{Mode: "agent"}, nil }
	srv.Exposures = func() ([]repo.Finding, bool, error) {
		return []repo.Finding{{
			PURL: "pkg:npm/%40ctrl/tinycolor@4.1.2", AdvisoryID: "MAL-2025-47141",
			Summary: "Malicious code in @ctrl/tinycolor (npm)", DetectedAt: time.Now(),
		}}, true, nil
	}
	srv.Credentials = func() []rotate.Item {
		return []rotate.Item{
			{ID: "aws", Label: "AWS access keys", Category: rotate.CategoryCloud, Path: "/home/x/.aws/credentials"},
			{ID: "github-cli", Label: "GitHub CLI token", Category: rotate.CategoryVCS, Path: "/home/x/.config/gh/hosts.yml"},
			{ID: "ssh", Label: "SSH private keys", Category: rotate.CategorySSH, Path: "/home/x/.ssh/id_ed25519"},
		}
	}
	srv.RotationChecked = func(string, string) (map[string]time.Time, error) { return ticked, nil }
	srv.SetRotationChecked = func(string, string, string, time.Time) error { return nil }

	r := chi.NewRouter()
	srv.Routes(r)
	return srv, r
}

// Every credential gets a row, and the count says how many are done.
//
// This is the test the page needed: the first version rendered one row instead
// of three and stopped mid-tag, because the inner range referred to the page
// root rather than the exposure. The status code was 200 throughout.
func TestTheChecklistRendersEveryCredential(t *testing.T) {
	_, h := rotationServer(t, map[string]time.Time{"ssh": time.Now()})
	body := get(t, h, "/rotate").Body.String()

	if got := strings.Count(body, `class="pw-check`); got < 3 {
		t.Errorf("found %d checklist markers, want a row per credential", got)
	}
	for _, want := range []string{"AWS access keys", "GitHub CLI token", "SSH private keys"} {
		if !strings.Contains(body, want) {
			t.Errorf("%q is missing from the page", want)
		}
	}
	if !strings.Contains(body, "1 / 3 rotated") {
		t.Error("the progress count is wrong or missing")
	}
	// A truncated render is the failure mode that a 200 hides, so assert the
	// page actually finished.
	if !strings.Contains(body, "</html>") {
		t.Error("the page stopped before the end of the document")
	}
	// The purl is case-sensitive on npm and must not be uppercased anywhere.
	if !strings.Contains(body, "pkg:npm/%40ctrl/tinycolor@4.1.2") {
		t.Error("the package identifier is not rendered as written")
	}
}

// The checklist is grouped under its category headings, worst blast radius
// first.
//
// The order alone does not survive being read: a flat list sorted by an
// invisible rank looks arbitrary, and the headings are what tell someone
// working down it under pressure that stopping halfway still means the cloud
// keys are done.
func TestTheChecklistIsGroupedByBlastRadius(t *testing.T) {
	_, h := rotationServer(t, nil)
	body := get(t, h, "/rotate").Body.String()

	var seen []string
	for _, category := range []string{rotate.CategoryCloud, rotate.CategoryVCS, rotate.CategorySSH} {
		at := strings.Index(body, `class="pw-cred-group">`+category)
		if at < 0 {
			t.Errorf("no heading for %q", category)
			continue
		}
		seen = append(seen, category)
	}
	if len(seen) != 3 {
		t.Fatalf("found %d of 3 category headings", len(seen))
	}
	// Cloud reaches every other system; ssh reaches the hosts that trust it.
	// Rendering them the other way round inverts the advice.
	cloud := strings.Index(body, `class="pw-cred-group">`+rotate.CategoryCloud)
	ssh := strings.Index(body, `class="pw-cred-group">`+rotate.CategorySSH)
	if cloud > ssh {
		t.Error("ssh is listed above cloud keys — the ordering is the advice")
	}
}

// A tick on something this machine does not have would record work nobody
// could have done, so the item is checked against the detected list.
func TestAnUnknownChecklistItemIsRefused(t *testing.T) {
	var wrote bool
	srv, h := rotationServer(t, nil)
	srv.SetRotationChecked = func(string, string, string, time.Time) error {
		wrote = true
		return nil
	}

	form := url.Values{
		"purl":     {"pkg:npm/x@1"},
		"advisory": {"MAL-1"},
		"item":     {"nonsense"},
	}
	req := httptest.NewRequest(http.MethodPost, "/rotate/check", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if wrote {
		t.Error("a tick was recorded for a credential this machine does not have")
	}
}

// The hub shows both pages and can write to neither.
//
// The write paths are the assertion that matters. Sync is outbound-only, so a
// tick or a restore entered on the hub has no channel to reach the machine that
// owns the files — a control that appeared to work would be recording rotations
// nobody performed.
func TestTheHubServesBothPagesReadOnly(t *testing.T) {
	h := hubServer(t)

	for _, path := range []string{"/rotate", "/quarantine"} {
		if code := get(t, h, path).Code; code != http.StatusOK {
			t.Errorf("GET %s answered %d on a hub, want 200", path, code)
		}
	}

	for _, path := range []string{"/rotate/check", "/quarantine/restore"} {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(""))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code == http.StatusOK || rec.Code == http.StatusSeeOther {
			t.Errorf("POST %s answered %d on a hub — the write path must not exist", path, rec.Code)
		}
	}
}

// The hub renders whose machine it is and how to get there, and never a bare
// link: agent dashboards bind loopback, so an anchor would be dead from the hub.
func TestTheHubSaysWhichMachineOwesTheWork(t *testing.T) {
	h := hubServer(t)
	body := get(t, h, "/rotate").Body.String()

	for _, want := range []string{"laptop", "ssh -L 4875:127.0.0.1:4875 laptop"} {
		if !strings.Contains(body, want) {
			t.Errorf("%q is missing from the hub's rotation page", want)
		}
	}
	// One ticked, one not: the count is evidence about a machine this hub
	// cannot see, so it has to come from the replicated rows.
	if !strings.Contains(body, "1 / 2 rotated") {
		t.Error("the replicated progress count is wrong or missing")
	}
	if strings.Contains(body, `action="/rotate/check"`) {
		t.Error("the hub rendered a form that posts to a route it does not serve")
	}
	if !strings.Contains(body, "</html>") {
		t.Error("the page stopped before the end of the document")
	}
}

// A quarantine row replicated at findings level carries no path, and the page
// must not render that as a package taken from nowhere.
func TestAWithheldPathSaysSoOnTheHub(t *testing.T) {
	h := hubServer(t)
	body := get(t, h, "/quarantine").Body.String()

	if !strings.Contains(body, "not replicated at this sync level") {
		t.Error("a withheld origin path rendered as an empty cell")
	}
	if strings.Contains(body, ">restore<") {
		t.Error("the hub offered a restore it cannot perform")
	}
}

// The credential list is shown with no malware anywhere, and a machine that
// does not send one is distinguished from a machine that has none.
//
// These two render identically if nobody thinks about it — an empty table — and
// only one of them is good news. "No credentials on that box" and "this hub is
// not set to receive them" are opposite facts.
func TestTheHubListsCredentialsWithoutAnyMalware(t *testing.T) {
	srv, h := hubServerWith(t, func(s *Server) {
		s.FleetExposures = func() ([]repo.FleetExposure, bool, error) { return nil, true, nil }
	})
	_ = srv

	body := get(t, h, "/rotate").Body.String()

	if !strings.Contains(body, "Nothing to rotate") {
		t.Error("expected the no-malware state")
	}
	// ...and the credential list all the same, which is the point.
	for _, want := range []string{"What could be read on each machine", "laptop",
		"SSH private keys", "/home/x/.ssh/id_ed25519"} {
		if !strings.Contains(body, want) {
			t.Errorf("%q is missing — the list must not depend on a malware finding", want)
		}
	}
	// The findings-level machine says why it is empty.
	if !strings.Contains(body, "server") {
		t.Error("a machine that reports no credentials vanished from the list")
	}
	if !strings.Contains(body, "accept inventory") {
		t.Error("a withheld credential list rendered as a machine holding none")
	}
	if !strings.Contains(body, "</html>") {
		t.Error("the page stopped before the end of the document")
	}
}

// Without a bundle nothing can tell malware from a vulnerability, and the page
// says that rather than rendering an empty list that reads as "nothing ran".
func TestTheRotationPageSaysWhenItCannotTell(t *testing.T) {
	srv, h := rotationServer(t, nil)
	srv.Exposures = func() ([]repo.Finding, bool, error) { return nil, false, nil }

	body := get(t, h, "/rotate").Body.String()
	if !strings.Contains(body, "No advisory bundle is installed") {
		t.Error("an unattached bundle rendered as though there were nothing to rotate")
	}
}
