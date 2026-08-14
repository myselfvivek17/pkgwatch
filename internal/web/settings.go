package web

import (
	"net/http"
	"os"

	"github.com/myselfvivek17/pkgwatch/internal/config"
)

// SettingsData backs the settings page.
//
// Read-only, and the page says so rather than leaving it to be discovered. The
// agent's dashboard has no login — it is safe on loopback precisely because it
// cannot change how this machine is protected, and a form here that could edit
// `bind` would turn "anything running on this box" into "anything on the LAN".
type SettingsData struct {
	Sections []config.Section

	// Path is the file these came from, and Exists says whether it is there at
	// all. A machine running entirely on defaults has no file, which is normal
	// and needs saying — otherwise the page looks like it failed to load one.
	Path   string
	Exists bool

	DataDir string
}

// SettingsFrom describes a running configuration for the page.
//
// Lives here rather than in either daemon because the page is one page (§8) and
// both modes need the same two facts a merged Config cannot carry: which file
// it came from, and whether that file exists at all.
//
// Called per request rather than captured once. It is a stat and a parse of a
// file measured in lines, and a page showing the configuration as it was at
// boot would be wrong in exactly the situation someone opens it in — just after
// editing the file, wondering whether the edit took.
func SettingsFrom(cfg config.Config, mode string) SettingsData {
	path := cfg.Path
	if path == "" {
		path = config.DefaultPath()
	}
	_, err := os.Stat(path)

	return SettingsData{
		Sections: config.Explain(cfg, path, mode),
		Path:     path,
		Exists:   err == nil,
		DataDir:  cfg.DataDir,
	}
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	s.render(w, "settings", "Settings", "settings", s.Settings())
}
