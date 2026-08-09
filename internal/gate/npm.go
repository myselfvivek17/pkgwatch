package gate

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"

	"github.com/myselfvivek17/pkgwatch/internal/match"
	"github.com/myselfvivek17/pkgwatch/internal/repo"
)

// DefaultNPMUpstream is the registry proxied when nothing else is configured.
const DefaultNPMUpstream = "https://registry.npmjs.org"

// NPM is a filtering proxy in front of an npm registry.
//
// It intercepts at two points, and both are necessary:
//
//   - The packument (GET /{name}) is the resolution path. Removing an affected
//     version here means npm never chooses it, and a clean install shows no sign
//     anything happened. This is the invisible happy path.
//   - The tarball (GET /{name}/-/{file}.tgz) is the lockfile path. `npm ci`
//     reads exact versions and tarball URLs straight out of package-lock.json and
//     never asks for a packument at all. Filtering alone would miss it entirely.
type NPM struct {
	Gate     *Gate
	Upstream *url.URL
	Client   *http.Client

	// SessionID attributes decisions when this proxy serves exactly one install
	// — which is how the `pkgwatch npm` wrapper runs it, on its own ephemeral
	// port. The agent's shared :4873 leaves it empty.
	SessionID string

	// SelfURL is where this proxy is reachable, used to rewrite tarball links in
	// packuments back through here. Without the rewrite npm fetches tarballs
	// straight from the upstream registry and the second interception point
	// never fires.
	SelfURL string
}

func (n *NPM) client() *http.Client {
	if n.Client != nil {
		return n.Client
	}
	return http.DefaultClient
}

func (n *NPM) upstream() *url.URL {
	if n.Upstream != nil {
		return n.Upstream
	}
	parsed, _ := url.Parse(DefaultNPMUpstream)
	return parsed
}

func (n *NPM) Handler() http.Handler { return http.HandlerFunc(n.serve) }

func (n *NPM) serve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		n.passthrough(w, r)
		return
	}

	name, file, isTarball := splitNPMPath(r.URL.EscapedPath())
	switch {
	case isTarball && name != "":
		n.serveTarball(w, r, name, file)
	case !isTarball && name != "":
		n.servePackument(w, r, name)
	default:
		n.passthrough(w, r)
	}
}

// splitNPMPath decomposes an npm registry path into a package name and, for
// tarball requests, the filename.
//
// npm URL-encodes the scope separator on packument requests (@ctrl%2ftinycolor)
// but not on tarball requests (@ctrl/tinycolor/-/tinycolor-4.1.2.tgz), so the
// split happens on the escaped path and the name is unescaped afterwards.
func splitNPMPath(escapedPath string) (name, file string, isTarball bool) {
	trimmed := strings.TrimPrefix(escapedPath, "/")
	if trimmed == "" {
		return "", "", false
	}
	// /-/v1/search and friends are registry APIs, not packages.
	if strings.HasPrefix(trimmed, "-/") {
		return "", "", false
	}

	if before, after, found := strings.Cut(trimmed, "/-/"); found {
		decoded, err := url.PathUnescape(before)
		if err != nil {
			return "", "", false
		}
		return decoded, after, true
	}

	decoded, err := url.PathUnescape(trimmed)
	if err != nil {
		return "", "", false
	}
	// A packument path is the bare name — one segment, or two for a scoped
	// package. Anything deeper (/{name}/{version}) is a different endpoint and
	// is passed through untouched.
	rest := decoded
	if strings.HasPrefix(decoded, "@") {
		_, after, found := strings.Cut(decoded[1:], "/")
		if !found {
			return "", "", false // "@scope" alone is not a package
		}
		rest = after
	}
	if strings.Contains(rest, "/") {
		return "", "", false
	}
	return decoded, "", false
}

func (n *NPM) servePackument(w http.ResponseWriter, r *http.Request, name string) {
	upstreamReq, err := n.request(r)
	if err != nil {
		httpError(w, http.StatusBadGateway, err.Error())
		return
	}

	// The abbreviated packument npm asks for by default carries no publish
	// times, and the cooldown check is the only defence during the window
	// between a malicious release and its advisory. Asking for the full document
	// buys that at the cost of a larger response; set cooldown_hours = 0 to keep
	// the small one.
	if n.Gate.Cooldown > 0 {
		upstreamReq.Header.Set("Accept", "application/json")
	}
	// Read the body ourselves, so ask for it uncompressed rather than carrying a
	// gzip decoder around.
	upstreamReq.Header.Del("Accept-Encoding")

	resp, err := n.client().Do(upstreamReq)
	if err != nil {
		httpError(w, http.StatusBadGateway, "upstream registry unreachable: "+err.Error())
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		copyHeaders(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		httpError(w, http.StatusBadGateway, "reading packument: "+err.Error())
		return
	}

	filtered, err := n.filterPackument(name, body)
	if err != nil {
		// An unparseable packument is not grounds to break the install. Pass the
		// original through and record that this request went unevaluated.
		n.Gate.degrade(Request{SessionID: n.SessionID, Ecosystem: match.EcosystemNPM, Name: name},
			"packument could not be filtered: "+err.Error())
		filtered = body
	}

	header := w.Header()
	copyHeaders(header, resp.Header)
	header.Del("Content-Length")
	header.Del("Content-Encoding")
	header.Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(filtered)
}

// filterPackument removes affected versions and repoints any dist-tag left
// pointing at one.
//
// The document is decoded into a generic map rather than a struct: npm reads
// fields we have no reason to know about, and a struct round-trip would silently
// drop every one of them.
func (n *NPM) filterPackument(name string, body []byte) ([]byte, error) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}

	var versions map[string]json.RawMessage
	if raw, ok := doc["versions"]; ok {
		if err := json.Unmarshal(raw, &versions); err != nil {
			return nil, err
		}
	}
	if len(versions) == 0 {
		return body, nil
	}

	published := map[string]time.Time{}
	if raw, ok := doc["time"]; ok {
		var times map[string]string
		if err := json.Unmarshal(raw, &times); err == nil {
			for version, stamp := range times {
				if at, err := time.Parse(time.RFC3339, stamp); err == nil {
					published[version] = at
				}
			}
		}
	}

	// Evaluate the whole list in one call. The publish buffer can only be
	// decided with every version in hand — holding back a fresh release is safe
	// only if an older one survives.
	order := make([]string, 0, len(versions))
	for version := range versions {
		order = append(order, version)
	}
	sort.Strings(order) // deterministic, so a rebuilt packument is reproducible

	reqs := make([]Request, len(order))
	for i, version := range order {
		reqs[i] = Request{
			SessionID: n.SessionID,
			Ecosystem: match.EcosystemNPM,
			Name:      name,
			Version:   version,
			Point:     PointResolve,
			Published: published[version],
		}
	}

	removed := map[string]Verdict{}
	for i, verdict := range n.Gate.EvaluateSet(reqs) {
		version := order[i]
		if verdict.Blocked {
			removed[version] = verdict
			delete(versions, version)
			continue
		}
		if rewritten, ok := n.rewriteTarball(versions[version]); ok {
			versions[version] = rewritten
		}
	}

	if len(removed) == 0 && n.SelfURL == "" {
		return body, nil
	}
	// One line per package, not per version. An ordinary install withholds
	// dozens of long-abandoned versions nobody asked for, and printing each one
	// buries npm's own output under the gate's bookkeeping.
	if len(removed) > 0 {
		advisories := map[string]struct{}{}
		buffered := 0
		for _, verdict := range removed {
			if verdict.Reason == ReasonCooldown {
				buffered++
				continue
			}
			advisories[verdict.AdvisoryID] = struct{}{}
		}
		slog.Info("npm gate: versions withheld from resolution",
			"package", name, "withheld", len(removed), "offered", len(versions),
			"advisories", len(advisories), "too_new", buffered)

		ids := make([]string, 0, len(advisories))
		for id := range advisories {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		n.Gate.event(repo.EventPackageFiltered, "", match.PURLBase(match.EcosystemNPM, name), "",
			map[string]any{
				"withheld":   len(removed),
				"offered":    len(versions),
				"advisories": ids,
				"too_new":    buffered,
				"session_id": n.SessionID,
			})
	}

	encoded, err := json.Marshal(versions)
	if err != nil {
		return nil, err
	}
	doc["versions"] = encoded

	if err := repointDistTags(doc, versions); err != nil {
		return nil, err
	}
	return json.Marshal(doc)
}

// repointDistTags moves any tag pointing at a removed version down to the
// highest version that survived.
//
// Dropping the tag instead would be worse than useless: `npm install lodash`
// resolves through `latest`, and a missing `latest` fails with a registry error
// that says nothing about why. Moving it to the newest safe release is the
// answer the user would have picked.
func repointDistTags(doc map[string]json.RawMessage, versions map[string]json.RawMessage) error {
	raw, ok := doc["dist-tags"]
	if !ok {
		return nil
	}
	var tags map[string]string
	if err := json.Unmarshal(raw, &tags); err != nil {
		return err
	}

	newest := highestVersion(versions)
	changed := false
	for tag, version := range tags {
		if _, alive := versions[version]; alive {
			continue
		}
		if newest == "" {
			delete(tags, tag)
		} else {
			tags[tag] = newest
		}
		changed = true
	}
	if !changed {
		return nil
	}

	encoded, err := json.Marshal(tags)
	if err != nil {
		return err
	}
	doc["dist-tags"] = encoded
	return nil
}

// highestVersion picks the greatest stable release present, falling back to
// prereleases only if that is all there is. A dist-tag repointed at a
// prerelease would hand `npm install` a beta.
//
// Parsing is lenient here, unlike everywhere else. This only chooses which of
// several already-cleared versions a tag points at — no advisory decision rests
// on it — and old npm packages carry versions ("1.0", "v2.1.3") that strict
// semver rejects. Being strict would drop every survivor on such a package and
// delete the tag as if nothing were safe.
func highestVersion(versions map[string]json.RawMessage) string {
	var best, fallback *semver.Version
	var bestRaw, fallbackRaw, anyRaw string

	for version := range versions {
		if anyRaw == "" || version > anyRaw {
			anyRaw = version
		}
		parsed, err := semver.NewVersion(version)
		if err != nil {
			continue
		}
		if parsed.Prerelease() != "" {
			if fallback == nil || parsed.GreaterThan(fallback) {
				fallback, fallbackRaw = parsed, version
			}
			continue
		}
		if best == nil || parsed.GreaterThan(best) {
			best, bestRaw = parsed, version
		}
	}

	switch {
	case bestRaw != "":
		return bestRaw
	case fallbackRaw != "":
		return fallbackRaw
	default:
		// Nothing parsed at all. Every survivor is still a version the gate
		// cleared, so pointing the tag at one beats deleting it and failing the
		// install outright.
		return anyRaw
	}
}

// rewriteTarball points a version's download link back through this proxy.
func (n *NPM) rewriteTarball(entry json.RawMessage) (json.RawMessage, bool) {
	if n.SelfURL == "" {
		return nil, false
	}

	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(entry, &decoded); err != nil {
		return nil, false
	}
	rawDist, ok := decoded["dist"]
	if !ok {
		return nil, false
	}
	var dist map[string]json.RawMessage
	if err := json.Unmarshal(rawDist, &dist); err != nil {
		return nil, false
	}
	var tarball string
	if err := json.Unmarshal(dist["tarball"], &tarball); err != nil {
		return nil, false
	}
	parsed, err := url.Parse(tarball)
	if err != nil {
		return nil, false
	}

	rewritten, err := json.Marshal(strings.TrimSuffix(n.SelfURL, "/") + parsed.EscapedPath())
	if err != nil {
		return nil, false
	}
	dist["tarball"] = rewritten

	if decoded["dist"], err = json.Marshal(dist); err != nil {
		return nil, false
	}
	out, err := json.Marshal(decoded)
	if err != nil {
		return nil, false
	}
	return out, true
}

func (n *NPM) serveTarball(w http.ResponseWriter, r *http.Request, name, file string) {
	version := versionFromTarball(name, file)
	if version == "" {
		// Cannot tell what this is, so cannot judge it. Recorded, not silent.
		n.Gate.degrade(Request{SessionID: n.SessionID, Ecosystem: match.EcosystemNPM, Name: name},
			"tarball filename "+file+" does not encode a version")
		n.passthrough(w, r)
		return
	}

	verdict := n.Gate.Evaluate(Request{
		SessionID: n.SessionID,
		Ecosystem: match.EcosystemNPM,
		Name:      name,
		Version:   version,
		Point:     PointDownload,
	})
	if verdict.Blocked {
		writeBlocked(w, match.EcosystemNPM, name, version, verdict)
		return
	}
	n.passthrough(w, r)
}

// versionFromTarball recovers a version from an npm tarball filename.
//
// The filename uses the unscoped name: @ctrl/tinycolor ships
// tinycolor-4.1.2.tgz. Registries that publish under a different filename
// convention return "" and the request is passed through as unevaluated rather
// than guessed at.
func versionFromTarball(name, file string) string {
	base := path.Base(file)
	if !strings.HasSuffix(base, ".tgz") {
		return ""
	}
	base = strings.TrimSuffix(base, ".tgz")

	unscoped := name
	if _, after, found := strings.Cut(strings.TrimPrefix(name, "@"), "/"); found {
		unscoped = after
	}
	if !strings.HasPrefix(base, unscoped+"-") {
		return ""
	}
	return strings.TrimPrefix(base, unscoped+"-")
}

// passthrough forwards a request to the upstream registry unchanged.
func (n *NPM) passthrough(w http.ResponseWriter, r *http.Request) {
	upstreamReq, err := n.request(r)
	if err != nil {
		httpError(w, http.StatusBadGateway, err.Error())
		return
	}

	resp, err := n.client().Do(upstreamReq)
	if err != nil {
		httpError(w, http.StatusBadGateway, "upstream registry unreachable: "+err.Error())
		return
	}
	defer resp.Body.Close()

	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// request builds the upstream request.
//
// Authorization is copied through verbatim and never logged, inspected or
// persisted: a private registry token passing through this proxy is the user's
// credential, and a security tool that leaks it into a log file has created the
// breach it exists to prevent.
func (n *NPM) request(r *http.Request) (*http.Request, error) {
	// Concatenate the escaped path rather than assigning URL.Path: npm encodes
	// the scope separator (@ctrl%2ftinycolor) and re-encoding a decoded path
	// would change the request the registry sees.
	raw := strings.TrimSuffix(n.upstream().String(), "/") + r.URL.EscapedPath()
	if r.URL.RawQuery != "" {
		raw += "?" + r.URL.RawQuery
	}

	upstreamReq, err := http.NewRequestWithContext(r.Context(), r.Method, raw, r.Body)
	if err != nil {
		return nil, fmt.Errorf("build upstream request: %w", err)
	}
	copyHeaders(upstreamReq.Header, r.Header)
	upstreamReq.Header.Del("Host")
	return upstreamReq, nil
}

// hopByHop headers must not be forwarded (RFC 9110 §7.6.1).
var hopByHop = map[string]bool{
	"Connection": true, "Keep-Alive": true, "Proxy-Authenticate": true,
	"Proxy-Authorization": true, "Te": true, "Trailer": true,
	"Transfer-Encoding": true, "Upgrade": true,
}

func copyHeaders(dst, src http.Header) {
	for key, values := range src {
		if hopByHop[http.CanonicalHeaderKey(key)] {
			continue
		}
		for _, v := range values {
			dst.Add(key, v)
		}
	}
}

func httpError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// writeBlocked answers a blocked download.
//
// 403 rather than 404: npm surfaces the status and exits non-zero, which is what
// hands control back to the wrapper. The body is for a human reading npm's
// error output, and repeats what the wrapper will say properly afterwards.
func writeBlocked(w http.ResponseWriter, ecosystem, name, version string, v Verdict) {
	detail := map[string]any{
		"error":     fmt.Sprintf("pkgwatch blocked %s %s@%s", ecosystem, name, version),
		"reason":    v.Reason,
		"advisory":  v.AdvisoryID,
		"tier":      v.Tier,
		"summary":   v.Summary,
		"fixed_in":  v.FixedIn,
		"resolve":   "run the install through `pkgwatch npm` / `pkgwatch pip` to review and override",
		"pkgwatch":  true,
		"purl":      match.PURL(ecosystem, name, version),
		"malicious": v.Reason == ReasonMalware,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	json.NewEncoder(w).Encode(detail)
}
