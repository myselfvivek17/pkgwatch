package gate

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/myselfvivek17/pkgwatch/internal/match"
)

// DefaultPyPIUpstream is the index proxied when nothing else is configured.
const DefaultPyPIUpstream = "https://pypi.org/simple"

// PyPI is a filtering proxy in front of a PEP 503 simple index.
//
// There is one interception point rather than npm's two, and that is not an
// oversight: pip only ever learns about a file from the index page, including
// when versions are pinned in a requirements file. Removing a file from the
// listing removes it from every resolution path pip has.
//
// The exception is `pip install <url>` and `pip install ./local.whl`, which
// never touch an index at all. Nothing a proxy can do reaches those.
type PyPI struct {
	Gate     *Gate
	Upstream *url.URL
	Client   *http.Client

	SessionID string
}

func (p *PyPI) client() *http.Client {
	if p.Client != nil {
		return p.Client
	}
	return http.DefaultClient
}

func (p *PyPI) upstream() *url.URL {
	if p.Upstream != nil {
		return p.Upstream
	}
	parsed, _ := url.Parse(DefaultPyPIUpstream)
	return parsed
}

func (p *PyPI) Handler() http.Handler { return http.HandlerFunc(p.serve) }

func (p *PyPI) serve(w http.ResponseWriter, r *http.Request) {
	name := projectFromPath(r.URL.Path)
	if r.Method != http.MethodGet || name == "" {
		p.proxy(w, r, "")
		return
	}
	p.proxy(w, r, name)
}

// projectFromPath extracts the project name from a simple-index path.
// "/simple/requests/" and "/requests/" both name requests; "/simple/" names
// nothing and is the full index listing.
func projectFromPath(path string) string {
	trimmed := strings.Trim(path, "/")
	trimmed = strings.TrimPrefix(trimmed, "simple")
	trimmed = strings.Trim(trimmed, "/")
	if trimmed == "" || strings.Contains(trimmed, "/") {
		return ""
	}
	decoded, err := url.PathUnescape(trimmed)
	if err != nil {
		return ""
	}
	return decoded
}

func (p *PyPI) proxy(w http.ResponseWriter, r *http.Request, name string) {
	target := *p.upstream()
	target.Path = strings.TrimSuffix(target.Path, "/") + "/" + strings.TrimPrefix(r.URL.Path, "/simple/")
	target.RawQuery = r.URL.RawQuery

	upstreamReq, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), r.Body)
	if err != nil {
		httpError(w, http.StatusBadGateway, err.Error())
		return
	}
	// Authorization travels verbatim and is never logged — see NPM.request.
	copyHeaders(upstreamReq.Header, r.Header)
	upstreamReq.Header.Del("Host")
	upstreamReq.Header.Del("Accept-Encoding")
	upstreamReq.Host = target.Host

	resp, err := p.client().Do(upstreamReq)
	if err != nil {
		httpError(w, http.StatusBadGateway, "upstream index unreachable: "+err.Error())
		return
	}
	defer resp.Body.Close()

	if name == "" || resp.StatusCode != http.StatusOK {
		copyHeaders(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		httpError(w, http.StatusBadGateway, "reading index: "+err.Error())
		return
	}

	contentType := resp.Header.Get("Content-Type")
	filtered, err := p.filter(name, contentType, body)
	if err != nil {
		p.Gate.degrade(Request{SessionID: p.SessionID, Ecosystem: match.EcosystemPyPI, Name: name},
			"index page could not be filtered: "+err.Error())
		filtered = body
	}

	header := w.Header()
	copyHeaders(header, resp.Header)
	header.Del("Content-Length")
	header.Del("Content-Encoding")
	w.WriteHeader(http.StatusOK)
	w.Write(filtered)
}

func (p *PyPI) filter(name, contentType string, body []byte) ([]byte, error) {
	if strings.Contains(contentType, "json") {
		return p.filterJSON(name, body)
	}
	return p.filterHTML(name, body), nil
}

// simpleJSON is the PEP 691 index response. Only the fields that get rewritten
// are typed; everything else rides along in the generic map.
type simpleJSON struct {
	Files []map[string]any `json:"files"`
}

func (p *PyPI) filterJSON(name string, body []byte) ([]byte, error) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	raw, ok := doc["files"]
	if !ok {
		return body, nil
	}

	var listing simpleJSON
	if err := json.Unmarshal(raw, &listing.Files); err != nil {
		return nil, err
	}

	kept := make([]map[string]any, 0, len(listing.Files))
	dropped := 0
	for _, file := range listing.Files {
		filename, _ := file["filename"].(string)
		// PEP 700 publishes upload-time, which is what makes the cooldown check
		// possible on the Python side at all.
		var published time.Time
		if stamp, ok := file["upload-time"].(string); ok {
			if at, err := time.Parse(time.RFC3339, stamp); err == nil {
				published = at
			}
		}
		if p.blocks(name, filename, published) {
			dropped++
			continue
		}
		kept = append(kept, file)
	}
	if dropped == 0 {
		return body, nil
	}

	encoded, err := json.Marshal(kept)
	if err != nil {
		return nil, err
	}
	doc["files"] = encoded
	return json.Marshal(doc)
}

// anchorPattern matches one <a …>filename</a> element. PEP 503 pages are a flat
// list of anchors with no nesting, so this does not need a parser — and reaching
// for one would mean a ninth dependency for a document shape defined by a spec
// that forbids anything more complicated.
var anchorPattern = regexp.MustCompile(`(?is)<a\s[^>]*>.*?</a>`)

// anchorText pulls the link text, which PEP 503 defines as the filename.
var anchorText = regexp.MustCompile(`(?is)<a\s[^>]*>(.*?)</a>`)

func (p *PyPI) filterHTML(name string, body []byte) []byte {
	return anchorPattern.ReplaceAllFunc(body, func(anchor []byte) []byte {
		groups := anchorText.FindSubmatch(anchor)
		if len(groups) < 2 {
			return anchor
		}
		filename := strings.TrimSpace(string(groups[1]))
		// The HTML listing carries no upload time, so cooldown does not apply
		// here. PEP 691's JSON does.
		if p.blocks(name, filename, time.Time{}) {
			return nil
		}
		return anchor
	})
}

// blocks evaluates one distribution file and reports whether to withhold it.
func (p *PyPI) blocks(name, filename string, published time.Time) bool {
	version := versionFromPyPIFile(name, filename)
	if version == "" {
		// Unrecognised filename shape. Withholding it would break installs for a
		// reason we cannot state; allowing it silently would be a hole. Allow,
		// and record that this file went unevaluated.
		p.Gate.degrade(Request{SessionID: p.SessionID, Ecosystem: match.EcosystemPyPI, Name: name},
			"filename "+filename+" does not encode a version")
		return false
	}

	// The index is the only place pip learns what exists, so this is a listing
	// decision even when the version was pinned in a requirements file.
	verdict := p.Gate.Evaluate(Request{
		SessionID: p.SessionID,
		Ecosystem: match.EcosystemPyPI,
		Name:      name,
		Version:   version,
		Point:     PointResolve,
		Published: published,
	})
	return verdict.Blocked
}

// pypiExtensions are the distribution suffixes a simple index lists, longest
// first so .tar.gz is stripped before .gz would be.
var pypiExtensions = []string{".tar.gz", ".tar.bz2", ".tar.xz", ".whl", ".egg", ".zip", ".tar"}

// positionalExtensions name the formats whose filenames are hyphen-delimited
// fields, so the version is always the second one.
//
// Wheels escape the project name (PEP 427) and eggs do the same, which is what
// makes the position reliable. Getting this wrong is not a parse failure that
// announces itself: requests-2.23.0-py2.7.egg read as version "2.23.0-py2.7",
// which no comparator accepts, so every advisory errored out and the file was
// offered as unevaluated — a silent hole in the middle of a covered package.
var positionalExtensions = map[string]bool{".whl": true, ".egg": true}

// versionFromPyPIFile recovers a version from a distribution filename.
//
// Source distributions are the hard case: the project name may itself contain
// hyphens (backports-ssl-match-hostname-3.5.0.1.tar.gz), so the boundary is
// found by growing a prefix until it normalizes to the project name we already
// know from the URL.
func versionFromPyPIFile(project, filename string) string {
	base := strings.TrimSpace(filename)
	if idx := strings.IndexAny(base, "#?"); idx >= 0 {
		base = base[:idx]
	}

	trimmed, positional := "", false
	for _, ext := range pypiExtensions {
		if strings.HasSuffix(base, ext) {
			trimmed = strings.TrimSuffix(base, ext)
			positional = positionalExtensions[ext]
			break
		}
	}
	if trimmed == "" {
		return ""
	}

	if positional {
		parts := strings.Split(trimmed, "-")
		if len(parts) < 2 {
			return ""
		}
		return parts[1]
	}

	want := match.NormalizeName(match.EcosystemPyPI, project)
	for idx, char := range trimmed {
		if char != '-' {
			continue
		}
		if match.NormalizeName(match.EcosystemPyPI, trimmed[:idx]) == want {
			return trimmed[idx+1:]
		}
	}
	return ""
}
