package gate_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/myselfvivek17/pkgwatch/internal/gate"
	"github.com/myselfvivek17/pkgwatch/internal/match"
)

// requestsAdvisory stands in for a real PyPI record. OSV has no PyPI fixture in
// this repo, and a synthetic advisory is enough to exercise the index filter —
// the matching itself is covered against real data elsewhere.
func requestsAdvisory() match.Advisory {
	score := 8.1
	return match.Advisory{
		ID:           "GHSA-test-pypi-0001",
		Kind:         match.KindVulnerability,
		Ecosystem:    match.EcosystemPyPI,
		PackageName:  "requests",
		Summary:      "Synthetic advisory for the PyPI gate tests",
		SeverityCVSS: &score,
		Ranges:       []match.Range{{Introduced: "0", Fixed: "2.31.0"}},
		Source:       "osv",
		Published:    time.Now().Add(-365 * 24 * time.Hour),
		Modified:     time.Now().Add(-365 * 24 * time.Hour),
	}
}

// hyphenatedAdvisory covers a project whose own name contains hyphens, which is
// where source-distribution filenames stop being unambiguous.
func hyphenatedAdvisory() match.Advisory {
	score := 8.1
	return match.Advisory{
		ID:           "GHSA-test-pypi-0002",
		Kind:         match.KindVulnerability,
		Ecosystem:    match.EcosystemPyPI,
		PackageName:  "backports-ssl-match-hostname",
		SeverityCVSS: &score,
		Ranges:       []match.Range{{Introduced: "0", Fixed: "3.6.0"}},
		Source:       "osv",
		Published:    time.Now().Add(-365 * 24 * time.Hour),
		Modified:     time.Now().Add(-365 * 24 * time.Hour),
	}
}

func newPyPIProxy(t *testing.T, upstream *upstreamRecorder, extra ...match.Advisory) *httptest.Server {
	t.Helper()

	g := newGateWith(t, true, extra...)
	g.Cooldown = 0

	parsed, err := gate.ParseUpstream(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := &gate.PyPI{Gate: g, Upstream: parsed}

	server := httptest.NewServer(proxy.Handler())
	t.Cleanup(server.Close)
	return server
}

// htmlIndex serves a PEP 503 simple page with the given filenames.
func htmlIndex(project string, filenames ...string) func(string) (int, string) {
	var page strings.Builder
	page.WriteString("<!DOCTYPE html><html><body><h1>Links for " + project + "</h1>\n")
	for _, name := range filenames {
		page.WriteString(`<a href="https://files.pythonhosted.org/packages/` + name +
			`#sha256=abc">` + name + "</a><br/>\n")
	}
	page.WriteString("</body></html>")
	body := page.String()
	return func(string) (int, string) { return http.StatusOK, body }
}

func fetch(t *testing.T, url string, accept string) (int, string) {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(body)
}

// pip only ever learns about a file from the index page, including when a
// requirements file pins the version. Removing the file removes it from every
// resolution path pip has.
func TestHTMLIndexWithholdsAffectedFiles(t *testing.T) {
	upstream := newUpstream(t, htmlIndex("requests",
		"requests-2.30.0-py3-none-any.whl",
		"requests-2.30.0.tar.gz",
		"requests-2.31.0-py3-none-any.whl",
		"requests-2.31.0.tar.gz",
	))
	// PyPI serves text/html for the classic simple index.
	upstream.contentType = "text/html; charset=utf-8"
	proxy := newPyPIProxy(t, upstream, requestsAdvisory())

	status, body := fetch(t, proxy.URL+"/simple/requests/", "text/html")
	if status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}
	if strings.Contains(body, "requests-2.30.0") {
		t.Error("2.30.0 is affected and must not be listed, in either distribution form")
	}
	if !strings.Contains(body, "requests-2.31.0-py3-none-any.whl") ||
		!strings.Contains(body, "requests-2.31.0.tar.gz") {
		t.Error("2.31.0 carries the fix and must still be listed")
	}
	// The page around the links has to survive: pip reads the base URL and the
	// data-requires-python attributes off it.
	if !strings.Contains(body, "Links for requests") {
		t.Error("the page structure was destroyed, not filtered")
	}
}

func TestJSONIndexWithholdsAffectedFiles(t *testing.T) {
	payload := map[string]any{
		"meta": map[string]any{"api-version": "1.1"},
		"name": "requests",
		"files": []map[string]any{
			{"filename": "requests-2.30.0-py3-none-any.whl", "url": "https://x/1", "upload-time": "2023-05-03T00:00:00Z"},
			{"filename": "requests-2.31.0-py3-none-any.whl", "url": "https://x/2", "upload-time": "2023-05-22T00:00:00Z"},
		},
	}
	encoded, _ := json.Marshal(payload)

	upstream := newUpstream(t, func(string) (int, string) { return http.StatusOK, string(encoded) })
	upstream.contentType = "application/vnd.pypi.simple.v1+json"
	proxy := newPyPIProxy(t, upstream, requestsAdvisory())

	status, body := fetch(t, proxy.URL+"/simple/requests/", "application/vnd.pypi.simple.v1+json")
	if status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}

	var doc struct {
		Name  string           `json:"name"`
		Meta  map[string]any   `json:"meta"`
		Files []map[string]any `json:"files"`
	}
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("response is not JSON: %v\n%s", err, body)
	}
	if len(doc.Files) != 1 {
		t.Fatalf("got %d files, want 1", len(doc.Files))
	}
	if doc.Files[0]["filename"] != "requests-2.31.0-py3-none-any.whl" {
		t.Errorf("wrong file survived: %v", doc.Files[0])
	}
	if doc.Meta["api-version"] != "1.1" {
		t.Error("meta was dropped — pip needs it to know how to read the page")
	}
}

// PEP 427 escapes the project name in wheel filenames, so the first hyphen is
// always the version boundary. Source distributions carry the raw name, which
// may itself contain hyphens — and getting that boundary wrong means the
// advisory silently never matches.
func TestHyphenatedProjectNameVersionBoundary(t *testing.T) {
	upstream := newUpstream(t, htmlIndex("backports.ssl-match-hostname",
		"backports.ssl_match_hostname-3.5.0.1.tar.gz",
		"backports.ssl_match_hostname-3.7.0.1.tar.gz",
		"backports.ssl_match_hostname-3.5.0.1-py3-none-any.whl",
	))
	upstream.contentType = "text/html"
	proxy := newPyPIProxy(t, upstream, hyphenatedAdvisory())

	_, body := fetch(t, proxy.URL+"/simple/backports.ssl-match-hostname/", "text/html")

	if strings.Contains(body, "3.5.0.1") {
		t.Error("3.5.0.1 is below the 3.6.0 fix and must be withheld, sdist and wheel alike")
	}
	if !strings.Contains(body, "3.7.0.1") {
		t.Error("3.7.0.1 is above the fix and must survive")
	}
}

// Egg filenames are hyphen-delimited fields like wheels, not name-then-version
// like sdists. Reading requests-2.23.0-py2.7.egg as version "2.23.0-py2.7"
// meant no comparator could parse it, every advisory errored out, and the file
// was served as unevaluated — a hole in the middle of a covered package that
// announced itself only as a log warning.
func TestEggFilenameVersionBoundary(t *testing.T) {
	upstream := newUpstream(t, htmlIndex("requests",
		"requests-2.19.1-py2.7.egg",
		"requests-2.31.0-py2.7.egg",
	))
	upstream.contentType = "text/html"
	proxy := newPyPIProxy(t, upstream, requestsAdvisory())

	_, body := fetch(t, proxy.URL+"/simple/requests/", "text/html")
	if strings.Contains(body, "requests-2.19.1-py2.7.egg") {
		t.Error("2.19.1 is below the 2.31.0 fix and must be withheld in egg form too")
	}
	if !strings.Contains(body, "requests-2.31.0-py2.7.egg") {
		t.Error("2.31.0 carries the fix and must survive")
	}
}

// The full index listing names no project, so there is nothing to evaluate
// against and it passes straight through.
func TestFullIndexPassesThrough(t *testing.T) {
	upstream := newUpstream(t, func(string) (int, string) {
		return http.StatusOK, `<html><body><a href="/simple/requests/">requests</a></body></html>`
	})
	upstream.contentType = "text/html"
	proxy := newPyPIProxy(t, upstream)

	status, body := fetch(t, proxy.URL+"/simple/", "text/html")
	if status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}
	if !strings.Contains(body, `<a href="/simple/requests/">requests</a>`) {
		t.Errorf("the project listing was filtered: %s", body)
	}
}

// A filename shape we cannot parse must not be silently dropped from the index
// — that would break an install for a reason we could not state.
func TestUnrecognisedFilenameIsAllowed(t *testing.T) {
	upstream := newUpstream(t, htmlIndex("requests", "some-mystery-artifact.bin"))
	upstream.contentType = "text/html"
	proxy := newPyPIProxy(t, upstream, requestsAdvisory())

	_, body := fetch(t, proxy.URL+"/simple/requests/", "text/html")
	if !strings.Contains(body, "some-mystery-artifact.bin") {
		t.Error("an unevaluated file must still be offered")
	}
}

// PyPI names normalize per PEP 503, so a request for Requests must find an
// advisory filed against requests.
func TestProjectNameIsNormalized(t *testing.T) {
	upstream := newUpstream(t, htmlIndex("Requests",
		"requests-2.30.0-py3-none-any.whl",
		"requests-2.31.0-py3-none-any.whl",
	))
	upstream.contentType = "text/html"
	proxy := newPyPIProxy(t, upstream, requestsAdvisory())

	_, body := fetch(t, proxy.URL+"/simple/Requests/", "text/html")
	if strings.Contains(body, "requests-2.30.0") {
		t.Error("PEP 503 folds Requests and requests to one project; the advisory must still apply")
	}
}
