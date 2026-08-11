// Package web serves the dashboard shell shared by both modes.
//
// One template set serves the agent and the hub, parameterized by Mode: §8 asks
// for "same codebase, same design system", and a second layout would need
// hand-syncing every time a page is added.
package web

import (
	"embed"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/myselfvivek17/pkgwatch/internal/repo"
)

//go:embed templates static
var assets embed.FS

type Mode string

const (
	ModeAgent Mode = "agent"
	ModeHub   Mode = "hub"
)

// NavItem mirrors the design's nav list. Items whose page does not exist yet
// render disabled rather than hidden — the design already models this state,
// and hiding them would misrepresent what the tool does.
type NavItem struct {
	Key     string
	Label   string
	Href    string
	Enabled bool
	Active  bool
}

// nav is the design's nine items in order. Enabled flips on as milestones land.
func nav(mode Mode, active string) []NavItem {
	first := NavItem{Key: "overview", Label: "Fleet overview", Href: "/", Enabled: true}
	if mode == ModeAgent {
		first.Label = "Overview"
	}
	items := []NavItem{
		first,
		{Key: "timeline", Label: "Timeline", Href: "/timeline", Enabled: true},
		{Key: "findings", Label: "Findings triage", Href: "/findings", Enabled: true},
		{Key: "block", Label: "Install block", Href: "/sessions"},
		{Key: "credentials", Label: "Credential rotation", Href: "/rotate"},
		{Key: "inventory", Label: "Inventory", Href: "/inventory", Enabled: true},
		{Key: "pairing", Label: "Device pairing", Href: "/devices"},
		{Key: "settings", Label: "Settings", Href: "/settings"},
		{Key: "quarantine", Label: "Quarantine", Href: "/quarantine"},
	}
	for i := range items {
		items[i].Active = items[i].Key == active
	}
	return items
}

// Page is the data every template receives.
type Page struct {
	Mode            Mode
	Title           string
	Identity        string
	Connected       bool
	ConnectionLabel string
	Nav             []NavItem
	Data            any
}

// Badge is the severity-badge partial's input.
type Badge struct {
	Tier  string
	Size  string
	Count int
}

// Server renders the shell. Callers supply the facts that differ per mode.
type Server struct {
	Mode     Mode
	Hostname string
	// HubLabel names the hub an agent is paired with, or "" when unpaired.
	// On a hub it names the hub itself.
	HubLabel string
	Paired   bool

	Overview func() (OverviewData, error)

	// Events and OldestEvent back the timeline. They are funcs rather than a
	// repo handle so the hub can supply fleet events from its own tables
	// without this package knowing which database it is reading.
	Events      func(repo.EventFilter) ([]repo.Event, error)
	OldestEvent func() (time.Time, error)

	// Findings backs the triage page. It returns whether the advisory bundle was
	// attached alongside the rows, because "no fix listed" and "we could not
	// look" are the same empty column and opposite meanings.
	Findings func(repo.FindingFilter) ([]repo.Finding, bool, error)

	// Acknowledge and Ignore are the page's only writes. Both are optional: the
	// hub renders findings from its agents read-only, because the agent is
	// authoritative for its own data (§3.3) and sync is outbound-only.
	Acknowledge func(purl, advisoryID, note string) error
	Ignore      func(purl, advisoryID, note string, days int) error

	// Inventory returns present packages, or retired ones when retired is true.
	// Ecosystems returns the per-ecosystem counts alongside what the bundle
	// actually covers, because a package list with no statement of what was
	// examined is the failure this project keeps hitting.
	Inventory  func(retired bool, limit int) ([]repo.PackageRow, error)
	Ecosystems func() (map[string]int, []string, error)

	// RetirementSummary counts every retired row rather than the page on
	// screen, so the audit's totals do not depend on where pagination fell.
	RetirementSummary func() (total, orphaned, renamed int, err error)

	// HistoryDays is the retention window, shown so a timeline that stops is
	// distinguishable from a machine that did nothing.
	HistoryDays int

	// StreamInterval is how often the live feed polls for new rows. Zero means
	// the default; tests set it low.
	StreamInterval time.Duration

	templates map[string]*template.Template
}

// OverviewData is what the overview page shows until real pages land.
//
// Packages and Devices are deliberately separate fields. They are different
// facts, and rendering one under the other's label is exactly the kind of
// quiet mislabelling this tool exists to not do.
type OverviewData struct {
	Mode     string
	Version  string
	Commit   string
	DataDir  string
	Listen   string
	Packages int // agent: packages in the local inventory
	Devices  int // hub: approved devices
	Bundle   repo.BundleInfo
	Findings map[string]int
}

func (o OverviewData) IsHub() bool { return o.Mode == "hub" }

func (o OverviewData) HasFindings() bool {
	for _, n := range o.Findings {
		if n > 0 {
			return true
		}
	}
	return false
}

// FindingTiers returns badge inputs in descending severity so the most urgent
// tier is always leftmost.
func (o OverviewData) FindingTiers() []Badge {
	out := make([]Badge, 0, len(repo.Tiers))
	for _, tier := range repo.Tiers {
		out = append(out, Badge{Tier: tier, Size: "sm", Count: o.Findings[tier]})
	}
	return out
}

type designData struct {
	Sizes  []badgeRow
	Tokens []token
}

// token carries a pre-built declaration because html/template's CSS sanitizer
// rejects `background: var({{.Name}})` — an interpolated custom property is not
// a value it recognises, so the attribute is dropped and the chip renders blank.
// The names are compile-time constants, so template.CSS is safe here.
type token struct {
	Name  string
	Style template.CSS
}

func tokens(names ...string) []token {
	out := make([]token, 0, len(names))
	for _, n := range names {
		out = append(out, token{Name: n, Style: template.CSS("background: var(" + n + ")")})
	}
	return out
}

type badgeRow struct {
	Label  string
	Badges []Badge
}

// New parses the embedded templates. A parse failure is a programming error, so
// it surfaces at construction rather than on the first request.
func New(mode Mode, hostname string) (*Server, error) {
	s := &Server{Mode: mode, Hostname: hostname, templates: map[string]*template.Template{}}
	for _, page := range []string{"overview", "design", "timeline", "findings", "inventory"} {
		tpl, err := template.ParseFS(assets,
			"templates/layout.html",
			"templates/partials/*.html",
			"templates/pages/"+page+".html",
		)
		if err != nil {
			return nil, fmt.Errorf("parse page %s: %w", page, err)
		}
		s.templates[page] = tpl
	}
	return s, nil
}

// Routes mounts the shell onto r. The /static/* wildcard is chi syntax — chi
// patterns are exact matches unless a wildcard says otherwise.
func (s *Server) Routes(r chi.Router) {
	r.Handle("/static/*", http.FileServer(http.FS(assets)))
	r.Get("/", s.handleOverview)
	r.Get("/design", s.handleDesign)
	if s.Events != nil {
		r.Get("/timeline", s.handleTimeline)
		r.Get("/events/stream", s.handleStream)
	}
	if s.Inventory != nil && s.Ecosystems != nil {
		r.Get("/inventory", s.handleInventory)
	}
	if s.Findings != nil {
		r.Get("/findings", s.handleFindings)
		if s.Acknowledge != nil && s.Ignore != nil {
			r.Post("/findings/triage", guard(s.handleTriage))
		}
	}
}

// renderPartial renders one partial on its own, for the live stream to push
// pre-rendered HTML instead of JSON the browser would have to template again.
// Any page's template set carries the partials, so the first one serves.
func (s *Server) renderPartial(name string, data any) (string, error) {
	tpl, ok := s.templates["timeline"]
	if !ok {
		return "", fmt.Errorf("templates not loaded")
	}
	var buf strings.Builder
	if err := tpl.ExecuteTemplate(&buf, name, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	data, err := s.Overview()
	if err != nil {
		http.Error(w, "overview unavailable: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.render(w, "overview", "Overview", "overview", data)
}

func (s *Server) handleDesign(w http.ResponseWriter, _ *http.Request) {
	s.render(w, "design", "Design system", "", designData{
		Sizes: []badgeRow{
			{Label: "md", Badges: badgesOfSize("md")},
			{Label: "sm", Badges: badgesOfSize("sm")},
		},
		Tokens: tokens(
			"--bg", "--bg-elevated", "--bg-sunken", "--bg-hover",
			"--border", "--border-strong",
			"--text", "--text-dim", "--text-faint",
			"--accent", "--accent-fg",
			"--sev-critical-bg", "--sev-critical-fg", "--sev-critical-bg-subtle",
			"--sev-high-bg", "--sev-high-fg", "--sev-high-border",
			"--sev-medium-bg", "--sev-medium-fg", "--sev-medium-border",
		),
	})
}

func badgesOfSize(size string) []Badge {
	out := make([]Badge, 0, len(repo.Tiers))
	for _, tier := range repo.Tiers {
		out = append(out, Badge{Tier: tier, Size: size})
	}
	return out
}

func (s *Server) render(w http.ResponseWriter, page, title, active string, data any) {
	tpl, ok := s.templates[page]
	if !ok {
		http.Error(w, "unknown page", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tpl.ExecuteTemplate(w, "layout", Page{
		Mode:            s.Mode,
		Title:           title,
		Identity:        s.identity(),
		Connected:       s.connected(),
		ConnectionLabel: s.connectionLabel(),
		Nav:             nav(s.Mode, active),
		Data:            data,
	}); err != nil {
		// Headers are already sent by now, so there is nothing useful to send
		// the browser; the daemon's logger picks this up via the http.Server.
		return
	}
}

func (s *Server) identity() string {
	if s.Mode == ModeHub {
		return "hub · " + s.Hostname
	}
	return "agent · " + s.Hostname
}

func (s *Server) connected() bool {
	if s.Mode == ModeHub {
		return true
	}
	return s.Paired
}

// connectionLabel never claims a healthy link the agent does not have. An
// unpaired agent says so plainly — the agent works fine without a hub (§0), and
// implying otherwise would be the same lie as rendering an offline machine as clean.
func (s *Server) connectionLabel() string {
	if s.Mode == ModeHub {
		return "hub · serving fleet"
	}
	if s.Paired {
		if s.HubLabel != "" {
			return "connected to " + s.HubLabel
		}
		return "connected to hub"
	}
	return "local only — no hub paired"
}
