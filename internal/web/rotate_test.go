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

// A hub has none of these files, so it has no business serving either page.
// Disabling the nav item is not enough on its own — a disabled link still
// leaves the route reachable by typing it — so the routes are registered from
// the same hooks the nav is derived from, and both must be absent together.
func TestTheHubServesNeitherPage(t *testing.T) {
	srv, err := New(ModeHub, "hub")
	if err != nil {
		t.Fatal(err)
	}
	srv.Overview = func() (OverviewData, error) { return OverviewData{Mode: "hub"}, nil }

	r := chi.NewRouter()
	srv.Routes(r)

	for _, path := range []string{"/rotate", "/quarantine"} {
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s answered %d on a hub, want 404", path, rec.Code)
		}
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
