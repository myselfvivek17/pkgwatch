package web

import (
	"errors"
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

	// Unreadable is set when the file could not be examined at all — neither
	// present nor absent, so nothing below can be called a default with a
	// straight face.
	Unreadable string

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

	data := SettingsData{
		Sections: config.Explain(cfg, path, mode),
		Path:     path,
		DataDir:  cfg.DataDir,
	}

	// Only "it is not there" means the machine is running on defaults. A
	// permission error or an unreadable mount is a third state, and reporting
	// it as a missing file would tell someone every value below is a default
	// when the file may say otherwise.
	switch _, err := os.Stat(path); {
	case err == nil:
		data.Exists = true
	case errors.Is(err, os.ErrNotExist):
	default:
		data.Unreadable = err.Error()
	}
	return data
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	s.render(w, "settings", "Settings", "settings", s.Settings())
}
