package hub

import (
	"log/slog"
	"net/http"
	"os"
	"path/filepath"

	"github.com/go-chi/chi/v5"

	"github.com/myselfvivek17/pkgwatch/internal/bundle"
	"github.com/myselfvivek17/pkgwatch/internal/fleet"
)

// Bundle relay: the hub hands out the advisory bundles it already holds so that
// one machine on the LAN downloads the corpus and the rest copy it from there.
//
// It is a bandwidth cache and nothing else. Every byte an agent receives here is
// verified against the publisher key compiled into that agent, exactly as if it
// had come from upstream — a hub cannot make a bundle trustworthy, and one that
// has been taken over cannot use this to hand the fleet an empty advisory set
// and blind it (§0, hard rule 2).

// offers enumerates the bundles this hub can relay.
//
// A bundle with no manifest beside it is skipped: the manifest carries the
// signature, and bytes nobody can check are worse than no offer at all. It is
// logged rather than passed over silently, because the difference between "this
// hub has no npm bundle" and "this hub has one it cannot prove" is exactly the
// kind of thing that otherwise reads as coverage.
func (s *State) offers() []fleet.BundleOffer {
	entries, err := os.ReadDir(s.BundleDir)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("could not read the bundle directory", "dir", s.BundleDir, "error", err)
		}
		return nil
	}

	var out []fleet.BundleOffer
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".db" {
			continue
		}
		path := filepath.Join(s.BundleDir, entry.Name())
		manifest, err := bundle.LoadManifest(path)
		if err != nil {
			slog.Warn("holding a bundle with no usable manifest, so it is not offered",
				"bundle", entry.Name(), "error", err)
			continue
		}
		if manifest.Signature == "" || manifest.Scope == "" || manifest.Version == "" {
			slog.Warn("stored manifest is incomplete, so the bundle is not offered",
				"bundle", entry.Name())
			continue
		}
		out = append(out, fleet.BundleOffer{File: entry.Name(), Manifest: manifest})
	}
	return out
}

// handleBundleList tells an agent what is on offer.
func (s *State) handleBundleList(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, fleet.BundleListResponse{Bundles: s.offers()})
}

// handleBundleFile serves one bundle's bytes.
//
// The requested name is matched against the enumerated offers rather than
// joined onto a directory. Filtering for "..", separators or absolute paths
// would be a blocklist over an attacker-controlled string; comparing against a
// list this hub built itself cannot escape the directory at all.
func (s *State) handleBundleFile(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "file")
	for _, offer := range s.offers() {
		if offer.File != name {
			continue
		}

		file, err := os.Open(filepath.Join(s.BundleDir, offer.File))
		if err != nil {
			refuse(w, http.StatusInternalServerError, fleet.CodeBadRequest, "could not read the bundle")
			return
		}
		defer file.Close()

		info, err := file.Stat()
		if err != nil {
			refuse(w, http.StatusInternalServerError, fleet.CodeBadRequest, "could not read the bundle")
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		// ServeContent over io.Copy for the range support: a bundle is tens of
		// megabytes and an agent on a flaky link should be able to resume.
		http.ServeContent(w, r, offer.File, info.ModTime(), file)
		return
	}

	refuse(w, http.StatusNotFound, fleet.CodeBadRequest, "this hub holds no bundle by that name")
}
