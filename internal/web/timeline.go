package web

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/myselfvivek17/pkgwatch/internal/repo"
)

// TimelineData is the timeline page's view model.
type TimelineData struct {
	Days            []TimelineDay
	KindOptions     []Option
	SeverityOptions []Option

	// Cursor is the newest event id on the page, which the live stream resumes
	// from. Zero when the page is empty.
	Cursor int64

	Horizon     string
	HistoryDays int
}

// TimelineDay groups rows under one date heading.
type TimelineDay struct {
	Key    string
	Label  string
	Events []TimelineRow
}

// Option is one entry in a filter select.
type Option struct {
	Value    string
	Label    string
	Selected bool
}

// Field is one row of an expanded event's detail grid.
type Field struct {
	Key   string
	Value string
}

// TimelineRow is one event, shaped for display.
//
// The template gets finished strings rather than the event itself: deciding
// what an event *says* is a judgement about severity and wording, and that
// belongs in Go where it can be tested, not spread across template conditionals.
type TimelineRow struct {
	ID          int64
	Time        string
	Kind        string
	KindLabel   string
	Summary     string
	PURL        string
	Tier        string
	Routine     bool
	Alarming    bool
	Fields      []Field
	SessionHref string

	// Members are the rows this one stands in for when a batch of the same kind
	// landed in the same minute. Empty on an ordinary row.
	Members []TimelineRow
}

func (r TimelineRow) HasDetail() bool { return len(r.Fields) > 0 || len(r.Members) > 0 }

func (r TimelineRow) Grouped() bool { return len(r.Members) > 0 }

func (r TimelineRow) Count() int {
	if len(r.Members) == 0 {
		return 1
	}
	return len(r.Members)
}

func (r TimelineRow) Badge() Badge { return Badge{Tier: r.Tier, Size: "sm"} }

// collapseAfter is how many same-kind events in the same minute it takes before
// they are folded into one row.
//
// Three, because two rows are still readable and worth seeing separately. The
// numbers this is defending against are not marginal: one bundle sync wrote 156
// finding_new events in a single second, and one npm install wrote 115
// install_blocked. A page that renders those one per line is a page nobody
// scrolls, which means the one row that mattered that day is never seen.
const collapseAfter = 3

// collapse folds runs of same-kind events sharing a minute into one row.
//
// Nothing is discarded: the members hang off the group and the row expands to
// them. This is a rendering decision, not a retention one, and the underlying
// events still sync and still make up the audit trail.
func collapse(rows []TimelineRow) []TimelineRow {
	var out []TimelineRow
	for start := 0; start < len(rows); {
		end := start + 1
		for end < len(rows) &&
			rows[end].Kind == rows[start].Kind &&
			rows[end].Time == rows[start].Time {
			end++
		}

		run := rows[start:end]
		if len(run) < collapseAfter {
			out = append(out, run...)
			start = end
			continue
		}
		out = append(out, groupRow(run))
		start = end
	}
	return out
}

// groupRow builds the stand-in for a run.
//
// It takes the worst tier in the run, not the first: a batch containing one
// critical among a hundred mediums has to read as critical, or collapsing would
// hide exactly the row that collapsing must never hide.
func groupRow(run []TimelineRow) TimelineRow {
	group := TimelineRow{
		ID:        run[0].ID,
		Time:      run[0].Time,
		Kind:      run[0].Kind,
		KindLabel: run[0].KindLabel,
		Routine:   run[0].Routine,
		Members:   run,
	}

	packages := map[string]bool{}
	for _, row := range run {
		if row.PURL != "" {
			packages[row.PURL] = true
		}
		if row.Alarming {
			group.Alarming = true
		}
		if worseTier(row.Tier, group.Tier) {
			group.Tier = row.Tier
		}
	}

	group.Summary = fmt.Sprintf("%d × %s", len(run), run[0].KindLabel)
	if n := len(packages); n > 0 && n < len(run) {
		// The distinct-package count is the fact that makes a burst legible:
		// 156 rows over 27 packages is a bundle sync, not 156 problems.
		group.Summary += fmt.Sprintf(" across %d package%s", n, plural(n))
	}
	return group
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// worseTier reports whether a is more severe than b. An empty tier is the least
// severe thing there is.
func worseTier(a, b string) bool {
	return tierRank(a) < tierRank(b)
}

func tierRank(tier string) int {
	for i, known := range repo.Tiers {
		if known == tier {
			return i
		}
	}
	return len(repo.Tiers)
}

// kindLabels are what each event kind is called on screen. An unknown kind
// falls back to its raw name rather than being hidden — an event this build
// does not recognise was still recorded for a reason.
var kindLabels = map[string]string{
	repo.EventScan:            "scan",
	repo.EventFeedSync:        "bundle sync",
	repo.EventFindingNew:      "new finding",
	repo.EventFindingBack:     "finding back",
	repo.EventFindingFixed:    "finding closed",
	repo.EventInstallBlocked:  "install blocked",
	repo.EventGateDegraded:    "gate degraded",
	repo.EventPackageFiltered: "version withheld",
	repo.EventSyncDropped:     "queue trimmed",
	repo.EventSyncRefused:     "sync refused",
}

// buildRow turns a stored event into a display row.
func buildRow(e repo.Event) TimelineRow {
	row := TimelineRow{
		ID:        e.ID,
		Time:      e.At.Format("15:04"),
		Kind:      e.Kind,
		KindLabel: kindLabels[e.Kind],
		PURL:      e.PURL,
		Tier:      e.Severity,
		Routine:   e.Routine(),
		Alarming:  e.Alarming(),
		Summary:   summarise(e),
	}
	if row.KindLabel == "" {
		row.KindLabel = e.Kind
	}

	if e.PURL != "" {
		row.Fields = append(row.Fields, Field{Key: "package", Value: e.PURL})
	}
	if e.AdvisoryID != "" {
		row.Fields = append(row.Fields, Field{Key: "advisory", Value: e.AdvisoryID})
	}
	keys := make([]string, 0, len(e.Detail))
	for key := range e.Detail {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if key == "session_id" {
			row.SessionHref = "/sessions/" + e.Detail[key]
			continue
		}
		row.Fields = append(row.Fields, Field{Key: key, Value: e.Detail[key]})
	}
	return row
}

// summarise is the one-line description shown before a row is expanded.
//
// A scan row says what it found, including nothing: "no change" is the answer
// that proves the agent ran, and replacing it with a blank line would make a
// working watchdog indistinguishable from a stopped one.
func summarise(e repo.Event) string {
	switch e.Kind {
	case repo.EventScan:
		parts := []string{e.Detail["packages"] + " packages"}
		if e.Detail["new"] != "" && e.Detail["new"] != "0" {
			parts = append(parts, e.Detail["new"]+" new")
		}
		if e.Detail["gone"] != "" && e.Detail["gone"] != "0" {
			parts = append(parts, e.Detail["gone"]+" retired")
		}
		if e.Detail["findings"] != "" && e.Detail["findings"] != "0" {
			parts = append(parts, e.Detail["findings"]+" findings")
		}
		if len(parts) == 1 {
			parts = append(parts, "no change")
		}
		if e.Detail["unmatched"] == "true" {
			parts = append(parts, "NOT matched — no bundle")
		}
		return strings.Join(parts, " · ")
	case repo.EventFeedSync:
		return "bundle " + e.Detail["bundle"] + " · " + e.Detail["records"] + " records"
	case repo.EventGateDegraded:
		// Never softened. This is the gate allowing an install it could not
		// evaluate, which is the one failure that cannot be found afterwards.
		return "allowed without evaluation — " + e.Detail["detail"]

	case repo.EventFindingNew, repo.EventFindingBack:
		// The advisory leads, because it is the part that varies. One package
		// routinely carries several advisories, and a row showing only the purl
		// renders them as three identical lines — which reads as a duplication
		// bug rather than as three different problems.
		if e.AdvisoryID != "" {
			return e.AdvisoryID + " · " + e.PURL
		}
		return e.PURL

	case repo.EventFindingFixed:
		return countSummary(e, "closed")
	case repo.EventSyncDropped:
		return e.Detail["dropped"] + " event(s) never sent — the outbound queue hit its cap"
	case repo.EventSyncRefused:
		return "the hub refused this device: " + e.Detail["reason"]

	default:
		if e.PURL != "" {
			return e.PURL
		}
		return e.Kind
	}
}

// countSummary describes a batch event: how many, and of what.
func countSummary(e repo.Event, verb string) string {
	parts := []string{e.Detail["count"] + " " + verb}
	for _, tier := range repo.Tiers {
		if n := e.Detail[tier]; n != "" && n != "0" {
			parts = append(parts, n+" "+tier)
		}
	}
	if len(parts) == 1 {
		return parts[0]
	}
	return parts[0] + " · " + strings.Join(parts[1:], ", ")
}

// group folds rows into day headings, newest day first.
func group(events []repo.Event, now time.Time) []TimelineDay {
	var days []TimelineDay
	var current *TimelineDay
	for _, event := range events {
		key := event.Day()
		if current == nil || current.Key != key {
			days = append(days, TimelineDay{Key: key, Label: dayLabel(event.At, now)})
			current = &days[len(days)-1]
		}
		current.Events = append(current.Events, buildRow(event))
	}
	for i := range days {
		days[i].Events = collapse(days[i].Events)
	}
	return days
}

func dayLabel(at, now time.Time) string {
	today := now.Truncate(24 * time.Hour)
	switch {
	case at.After(today):
		return "Today"
	case at.After(today.AddDate(0, 0, -1)):
		return "Yesterday"
	default:
		return at.Format("Mon 2 Jan 2006")
	}
}

func options(selected string, pairs ...string) []Option {
	out := make([]Option, 0, len(pairs)/2)
	for i := 0; i+1 < len(pairs); i += 2 {
		out = append(out, Option{
			Value: pairs[i], Label: pairs[i+1], Selected: pairs[i] == selected,
		})
	}
	return out
}

func (s *Server) handleTimeline(w http.ResponseWriter, r *http.Request) {
	kind := r.URL.Query().Get("kind")
	severity := r.URL.Query().Get("severity")

	events, err := s.Events(repo.EventFilter{Kind: kind, Severity: severity, Limit: 300})
	if err != nil {
		http.Error(w, "timeline unavailable: "+err.Error(), http.StatusInternalServerError)
		return
	}

	data := TimelineData{
		Days: group(events, time.Now()),
		KindOptions: options(kind,
			"", "everything",
			"actionable", "actionable only",
			"routine", "routine only",
			repo.EventInstallBlocked, "install blocked",
			repo.EventFindingNew, "new findings"),
		SeverityOptions: options(severity,
			"", "any severity",
			"critical", "critical",
			"high", "high",
			"medium", "medium",
			"low", "low"),
		HistoryDays: s.HistoryDays,
	}
	if len(events) > 0 {
		data.Cursor = events[0].ID
	}
	if oldest, err := s.OldestEvent(); err == nil && !oldest.IsZero() {
		data.Horizon = oldest.Format("2 Jan 2006")
	}

	s.render(w, "timeline", "Timeline", "timeline", data)
}

// handleStream is the live feed: server-sent events, one message per new row.
//
// It polls the events table rather than receiving from an in-process channel,
// because the writer is usually a different process. `pkgwatch scan` runs in the
// CLI while the daemon serves this page, and a channel would only ever carry the
// daemon's own events — the page would sit silent through exactly the activity a
// person ran a command to watch.
func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	cursor := int64(0)
	fmt.Sscan(r.URL.Query().Get("since"), &cursor)

	ticker := time.NewTicker(s.streamInterval())
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			events, err := s.Events(repo.EventFilter{SinceID: cursor, Limit: 50})
			if err != nil {
				// A transient DB error must not kill the stream; the next tick
				// retries and the browser never sees a reconnect.
				continue
			}
			for _, event := range events {
				cursor = event.ID
				row := buildRow(event)
				html, err := s.renderPartial("timeline-row", row)
				if err != nil {
					continue
				}
				// SSE frames are line-delimited, so the HTML has to arrive as
				// one logical line and be unpacked by the client.
				fmt.Fprintf(w, "event: row\ndata: %s\ndata: %s\n\n",
					event.Day(), strings.ReplaceAll(html, "\n", " "))
			}
			flusher.Flush()
		}
	}
}

func (s *Server) streamInterval() time.Duration {
	if s.StreamInterval > 0 {
		return s.StreamInterval
	}
	return 2 * time.Second
}
