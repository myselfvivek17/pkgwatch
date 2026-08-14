package web

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/myselfvivek17/pkgwatch/internal/config"
)

// settingsServer serves the settings page over a config file written for the
// test, so "set in config" and "default" are both really exercised.
func settingsServer(t *testing.T, body string) (string, chi.Router) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "pkgwatch.toml")
	if body != "" {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}

	srv, err := New(ModeAgent, "test-host")
	if err != nil {
		t.Fatal(err)
	}
	srv.Overview = func() (OverviewData, error) { return OverviewData{Mode: "agent"}, nil }
	srv.Settings = func() SettingsData { return SettingsFrom(cfg, "agent") }

	r := chi.NewRouter()
	srv.Routes(r)
	return path, r
}

// The column the page exists for: a value somebody chose reads differently from
// one nobody has touched.
//
// A sparse config over code defaults makes the effective value of anything
// unanswerable without reading the source, and "72 hours" says nothing about
// whether 72 was a decision.
func TestSettingsSaysWhichValuesWereChosen(t *testing.T) {
	_, h := settingsServer(t, "[agent]\nblock_tier = \"critical\"\n")
	body := get(t, h, "/settings").Body.String()

	// The chosen value, and marked as chosen.
	if !strings.Contains(body, "critical") {
		t.Error("the configured block_tier is missing")
	}
	if strings.Count(body, "set in config") != 1 {
		t.Errorf("found %d settings marked as configured, want exactly the one that is",
			strings.Count(body, "set in config"))
	}
	// And an untouched one, still shown, marked as a default.
	if !strings.Contains(body, "72 hours") || !strings.Contains(body, "default") {
		t.Error("defaults are not shown as defaults")
	}
	if !strings.Contains(body, "</html>") {
		t.Error("the page stopped before the end of the document")
	}
}

// A machine with no config file runs entirely on defaults. That is a normal way
// to run, and the page must not render it as a file it failed to read.
func TestSettingsSaysWhenThereIsNoFile(t *testing.T) {
	_, h := settingsServer(t, "")
	body := get(t, h, "/settings").Body.String()

	if !strings.Contains(body, "There is no config file") {
		t.Error("a missing config file is not explained")
	}
	if strings.Contains(body, "set in config") {
		t.Error("something claims to be configured with no file to configure it")
	}
}

// The page never writes, and must never print credential material.
//
// The agent's dashboard has no login of its own — it is safe on loopback only
// because it cannot change how the machine is protected.
func TestSettingsNeitherWritesNorPrintsSecrets(t *testing.T) {
	const hash = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$hunter2hunter2"
	path := filepath.Join(t.TempDir(), "pkgwatch.toml")
	if err := os.WriteFile(path,
		[]byte("[hub]\npassword_hash = \""+hash+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}

	srv, err := New(ModeHub, "hub")
	if err != nil {
		t.Fatal(err)
	}
	srv.Overview = func() (OverviewData, error) { return OverviewData{Mode: "hub"}, nil }
	srv.Settings = func() SettingsData { return SettingsFrom(cfg, "hub") }

	r := chi.NewRouter()
	srv.Routes(r)

	body := get(t, r, "/settings").Body.String()
	if strings.Contains(body, hash) || strings.Contains(body, "hunter2") {
		t.Error("the password hash was rendered into the page")
	}
	if !strings.Contains(body, "set") {
		t.Error("the page does not say whether a password is configured at all")
	}

	// No write path, by any method.
	for _, method := range []string{"POST", "PUT"} {
		req := httptest.NewRequest(method, "/settings", strings.NewReader(""))
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code == 200 || rec.Code == 303 {
			t.Errorf("%s /settings answered %d — this page must not write", method, rec.Code)
		}
	}
}
