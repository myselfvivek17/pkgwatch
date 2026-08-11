package web

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/myselfvivek17/pkgwatch/internal/repo"
)

// SessionsData lists recent gated installs.
type SessionsData struct {
	Rows  []SessionRow
	Empty bool
}

// SessionRow is one run in the list.
type SessionRow struct {
	ID        string
	When      string
	Ecosystem string
	Argv      string
	CWD       string
	Context   string
	Outcome   string
	Blocked   int
	Withheld  int
	Allowed   int
	Elapsed   string
}

// Interesting marks a run that did something other than let everything through.
func (r SessionRow) Interesting() bool { return r.Blocked > 0 }

// ReportData is one install's report.
type ReportData struct {
	Session  SessionRow
	Blocked  []DecisionRow
	Withheld []WithheldRow
	Allowed  int
	NotFound bool
}

// DecisionRow is one refused version.
type DecisionRow struct {
	PURL     string
	Reason   string
	Advisory string
	At       string
}

// WithheldRow is one package whose listing was filtered.
type WithheldRow struct {
	Package    string
	Count      int
	Advisories []string
	TooNew     int
}

func sessionRow(s repo.Session) SessionRow {
	row := SessionRow{
		ID:        s.ID,
		When:      s.StartedAt.Format("2006-01-02 15:04"),
		Ecosystem: s.Ecosystem,
		Argv:      s.Argv,
		CWD:       s.CWD,
		Context:   s.Context,
		Outcome:   s.Outcome,
		Blocked:   s.Blocked,
		Withheld:  s.Withheld,
		Allowed:   s.Allowed,
	}
	if row.Outcome == "" {
		// A session with no outcome never had one written, which usually means
		// the package manager is still running or was killed. Saying "clean"
		// would be inventing the half of the story that matters.
		row.Outcome = "unfinished"
	}
	if !s.EndedAt.IsZero() {
		row.Elapsed = s.EndedAt.Sub(s.StartedAt).Round(time.Second).String()
	}
	return row
}

func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	sessions, err := s.Sessions(100)
	if err != nil {
		http.Error(w, "sessions unavailable: "+err.Error(), http.StatusInternalServerError)
		return
	}
	data := SessionsData{Empty: len(sessions) == 0}
	for _, session := range sessions {
		data.Rows = append(data.Rows, sessionRow(session))
	}
	s.render(w, "sessions", "Install sessions", "block", data)
}

func (s *Server) handleSessionReport(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	session, decisions, withheld, err := s.SessionReport(id)
	if err != nil {
		http.Error(w, "session unavailable: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if session.ID == "" {
		s.render(w, "session-report", "Install session", "block", ReportData{NotFound: true})
		return
	}

	data := ReportData{Session: sessionRow(session)}
	for _, decision := range decisions {
		if decision.Decision != repo.DecisionBlocked {
			continue
		}
		data.Blocked = append(data.Blocked, DecisionRow{
			PURL:     decision.PURL,
			Reason:   decision.Reason,
			Advisory: decision.AdvisoryID,
			At:       decision.At.Format("15:04:05"),
		})
	}
	for _, item := range withheld {
		data.Withheld = append(data.Withheld, WithheldRow{
			Package:    item.PURLBase,
			Count:      item.Count,
			Advisories: item.Advisories,
			TooNew:     item.TooNew,
		})
	}
	data.Allowed = session.Allowed

	s.render(w, "session-report", "Install session", "block", data)
}
