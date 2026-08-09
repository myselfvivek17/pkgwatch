package gate_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/myselfvivek17/pkgwatch/internal/gate"
)

// packument builds a minimal but realistically shaped npm packument, with
// dist-tags.latest on the newest version listed.
func packument(name string, versions ...string) string {
	return packumentTagged(name, versions[len(versions)-1], versions...)
}

// packumentTagged is the same, with latest pointed wherever the test needs it.
func packumentTagged(name, latest string, versions ...string) string {
	entries := map[string]any{}
	times := map[string]string{}
	for _, v := range versions {
		entries[v] = map[string]any{
			"name":    name,
			"version": v,
			"dist": map[string]any{
				"tarball": fmt.Sprintf("https://registry.npmjs.org/%s/-/%s-%s.tgz",
					name, unscoped(name), v),
				"shasum": "0000000000000000000000000000000000000000",
			},
		}
		times[v] = "2020-01-01T00:00:00.000Z"
	}
	doc := map[string]any{
		"name":      name,
		"dist-tags": map[string]string{"latest": latest},
		"versions":  entries,
		"time":      times,
		// A field pkgwatch knows nothing about. It must survive the round trip:
		// npm reads plenty we have no reason to model.
		"readme": "# " + name,
	}
	encoded, _ := json.Marshal(doc)
	return string(encoded)
}

func unscoped(name string) string {
	if _, after, found := strings.Cut(strings.TrimPrefix(name, "@"), "/"); found {
		return after
	}
	return name
}

// upstreamRecorder is a stand-in npm registry that remembers what it was sent.
type upstreamRecorder struct {
	*httptest.Server

	// contentType overrides the response content type, which is what decides
	// whether the PyPI gate parses a page as HTML or as PEP 691 JSON.
	contentType string

	mu      sync.Mutex
	paths   []string
	headers []http.Header
}

func newUpstream(t *testing.T, body func(path string) (int, string)) *upstreamRecorder {
	t.Helper()

	rec := &upstreamRecorder{}
	rec.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.mu.Lock()
		rec.paths = append(rec.paths, r.URL.Path)
		rec.headers = append(rec.headers, r.Header.Clone())
		rec.mu.Unlock()

		status, payload := body(r.URL.Path)
		contentType := rec.contentType
		if contentType == "" {
			contentType = "application/json"
		}
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(status)
		io.WriteString(w, payload)
	}))
	t.Cleanup(rec.Close)
	return rec
}

func (u *upstreamRecorder) lastHeader() http.Header {
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.headers) == 0 {
		return nil
	}
	return u.headers[len(u.headers)-1]
}

// newNPMProxy fronts upstream with a gate holding the real fixture advisories.
func newNPMProxy(t *testing.T, upstream *upstreamRecorder) *httptest.Server {
	t.Helper()

	g := newGate(t, true)
	g.Cooldown = 0 // the fixtures are years old; the buffer is tested separately
	return proxyOver(t, g, upstream)
}

// proxyOver fronts upstream with a gate the caller has configured.
func proxyOver(t *testing.T, g *gate.Gate, upstream *upstreamRecorder) *httptest.Server {
	t.Helper()

	parsed, err := gate.ParseUpstream(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := &gate.NPM{Gate: g, Upstream: parsed}

	server := httptest.NewServer(proxy.Handler())
	t.Cleanup(server.Close)
	proxy.SelfURL = server.URL
	return server
}

// packumentWithTimes builds a packument whose publish times the test controls,
// which is what the publish buffer reads.
func packumentWithTimes(name string, times map[string]string) string {
	versions := make([]string, 0, len(times))
	for version := range times {
		versions = append(versions, version)
	}
	sort.Strings(versions)

	var doc map[string]any
	json.Unmarshal([]byte(packument(name, versions...)), &doc)
	doc["time"] = times
	encoded, _ := json.Marshal(doc)
	return string(encoded)
}

// captureLogs redirects slog for the duration of one test and returns the sink.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()

	var sink bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&sink, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return &sink
}

func getJSON(t *testing.T, url string) (int, map[string]any) {
	t.Helper()

	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if len(body) > 0 {
		if err := json.Unmarshal(body, &doc); err != nil {
			t.Fatalf("response from %s is not JSON: %v\n%s", url, err, body)
		}
	}
	return resp.StatusCode, doc
}

// The invisible happy path: the affected version is simply not offered, so npm
// resolves to a safe one and the install succeeds with no drama.
func TestPackumentWithholdsAffectedVersion(t *testing.T) {
	upstream := newUpstream(t, func(string) (int, string) {
		return http.StatusOK, packument("lodash", "4.17.19", "4.17.20", "4.17.21")
	})
	proxy := newNPMProxy(t, upstream)

	status, doc := getJSON(t, proxy.URL+"/lodash")
	if status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}

	versions, _ := doc["versions"].(map[string]any)
	if _, present := versions["4.17.20"]; present {
		t.Error("4.17.20 is affected by GHSA-35jh-r3h4-6jhm and must not be offered")
	}
	if _, present := versions["4.17.21"]; !present {
		t.Error("4.17.21 is fixed and must still be offered")
	}
	if doc["readme"] != "# lodash" {
		t.Error("fields pkgwatch does not model were dropped from the packument")
	}
}

// Dropping the tag instead of moving it would fail `npm install lodash` with a
// registry error that says nothing about why.
func TestDistTagMovesToNewestSafeVersion(t *testing.T) {
	upstream := newUpstream(t, func(string) (int, string) {
		// latest points at an affected version; 4.17.21 carries the fix.
		return http.StatusOK, packumentTagged("lodash", "4.17.20", "4.17.20", "4.17.21")
	})
	proxy := newNPMProxy(t, upstream)

	_, doc := getJSON(t, proxy.URL+"/lodash")
	tags, _ := doc["dist-tags"].(map[string]any)
	if tags["latest"] != "4.17.21" {
		t.Errorf("dist-tags.latest = %v, want 4.17.21", tags["latest"])
	}
}

// When nothing survives there is no safe version to point at, and a tag
// pointing at a version that is no longer listed would make npm fail with a
// resolution error instead of a missing-tag one.
func TestDistTagIsDroppedWhenNothingSurvives(t *testing.T) {
	upstream := newUpstream(t, func(string) (int, string) {
		return http.StatusOK, packument("lodash", "4.17.19", "4.17.20")
	})
	proxy := newNPMProxy(t, upstream)

	_, doc := getJSON(t, proxy.URL+"/lodash")
	versions, _ := doc["versions"].(map[string]any)
	if len(versions) != 0 {
		t.Fatalf("every listed version is affected; got %d left", len(versions))
	}
	tags, _ := doc["dist-tags"].(map[string]any)
	if _, present := tags["latest"]; present {
		t.Errorf("dist-tags.latest points at a version that is no longer offered: %v", tags)
	}
}

// Without this rewrite npm downloads tarballs straight from the upstream
// registry and the lockfile interception point never fires.
func TestTarballLinksPointBackThroughTheProxy(t *testing.T) {
	upstream := newUpstream(t, func(string) (int, string) {
		return http.StatusOK, packument("lodash", "4.17.21")
	})
	proxy := newNPMProxy(t, upstream)

	_, doc := getJSON(t, proxy.URL+"/lodash")
	versions, _ := doc["versions"].(map[string]any)
	entry, _ := versions["4.17.21"].(map[string]any)
	dist, _ := entry["dist"].(map[string]any)

	tarball, _ := dist["tarball"].(string)
	if !strings.HasPrefix(tarball, proxy.URL) {
		t.Errorf("tarball = %q, should be rewritten through %s", tarball, proxy.URL)
	}
	if !strings.HasSuffix(tarball, "/lodash/-/lodash-4.17.21.tgz") {
		t.Errorf("tarball path was mangled: %q", tarball)
	}
}

// `npm ci` reads exact versions and tarball URLs out of package-lock.json and
// never requests a packument. Filtering alone would miss it entirely.
func TestTarballRequestIsBlocked(t *testing.T) {
	upstream := newUpstream(t, func(string) (int, string) {
		return http.StatusOK, `"tarball bytes"`
	})
	proxy := newNPMProxy(t, upstream)

	status, doc := getJSON(t, proxy.URL+"/lodash/-/lodash-4.17.20.tgz")
	if status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 — npm surfaces the status and exits non-zero", status)
	}
	if doc["advisory"] != "GHSA-35jh-r3h4-6jhm" {
		t.Errorf("block body should name the advisory, got %v", doc["advisory"])
	}
	if len(upstream.paths) != 0 {
		t.Errorf("a blocked tarball must not be fetched from upstream, requested %v", upstream.paths)
	}
}

func TestCleanTarballPassesThrough(t *testing.T) {
	upstream := newUpstream(t, func(string) (int, string) {
		return http.StatusOK, `"tarball bytes"`
	})
	proxy := newNPMProxy(t, upstream)

	resp, err := http.Get(proxy.URL + "/lodash/-/lodash-4.17.21.tgz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if len(upstream.paths) != 1 || upstream.paths[0] != "/lodash/-/lodash-4.17.21.tgz" {
		t.Errorf("upstream saw %v", upstream.paths)
	}
}

// Scoped packages are requested with the slash percent-encoded on packument
// paths and literal on tarball paths. Getting either wrong means the malware
// record for @ctrl/tinycolor is never consulted.
func TestScopedPackageIsBlockedOnBothPaths(t *testing.T) {
	upstream := newUpstream(t, func(string) (int, string) {
		return http.StatusOK, packument("@ctrl/tinycolor", "4.1.1", "4.1.2")
	})
	proxy := newNPMProxy(t, upstream)

	_, doc := getJSON(t, proxy.URL+"/@ctrl%2ftinycolor")
	versions, _ := doc["versions"].(map[string]any)
	if _, present := versions["4.1.2"]; present {
		t.Error("@ctrl/tinycolor 4.1.2 is malware and must not be offered")
	}

	status, _ := getJSON(t, proxy.URL+"/@ctrl/tinycolor/-/tinycolor-4.1.2.tgz")
	if status != http.StatusForbidden {
		t.Errorf("scoped tarball status = %d, want 403", status)
	}
}

// A private registry token passing through this proxy is the user's credential.
// It has to reach upstream, and it must not reach a log file — a security tool
// that leaks it has created the breach it exists to prevent.
func TestAuthorizationIsForwardedAndNeverLogged(t *testing.T) {
	const secret = "npm_SUPERSECRETTOKENVALUE"

	upstream := newUpstream(t, func(string) (int, string) {
		return http.StatusOK, packument("lodash", "4.17.20", "4.17.21")
	})
	proxy := newNPMProxy(t, upstream)

	logs := captureLogs(t)

	req, err := http.NewRequest(http.MethodGet, proxy.URL+"/lodash", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	if got := upstream.lastHeader().Get("Authorization"); got != "Bearer "+secret {
		t.Errorf("upstream Authorization = %q — a private registry would reject this request", got)
	}
	if strings.Contains(logs.String(), secret) {
		t.Fatalf("the auth token reached the log output:\n%s", logs.String())
	}
}

// Anything that is not a package request is none of the gate's business.
func TestRegistryAPIsPassThrough(t *testing.T) {
	upstream := newUpstream(t, func(string) (int, string) {
		return http.StatusOK, `{"objects":[]}`
	})
	proxy := newNPMProxy(t, upstream)

	status, _ := getJSON(t, proxy.URL+"/-/v1/search?text=lodash")
	if status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}
	if len(upstream.paths) != 1 || upstream.paths[0] != "/-/v1/search" {
		t.Errorf("upstream saw %v, want the search API untouched", upstream.paths)
	}
}

// An upstream that returns something unparseable must not break the install.
func TestUnparseablePackumentFailsOpen(t *testing.T) {
	upstream := newUpstream(t, func(string) (int, string) {
		return http.StatusOK, `<html>proxy interception page</html>`
	})
	proxy := newNPMProxy(t, upstream)

	resp, err := http.Get(proxy.URL + "/lodash")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want the original response passed through", resp.StatusCode)
	}
	if !strings.Contains(string(body), "proxy interception page") {
		t.Errorf("body was not passed through: %s", body)
	}
}

func TestUpstreamErrorsArePassedThrough(t *testing.T) {
	upstream := newUpstream(t, func(string) (int, string) {
		return http.StatusNotFound, `{"error":"Not found"}`
	})
	proxy := newNPMProxy(t, upstream)

	status, doc := getJSON(t, proxy.URL+"/no-such-package")
	if status != http.StatusNotFound {
		t.Errorf("status = %d, want 404", status)
	}
	if doc["error"] != "Not found" {
		t.Errorf("body = %v", doc)
	}
}
