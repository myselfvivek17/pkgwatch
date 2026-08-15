package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// A forged POST fails even when the headers look perfect.
//
// This is the case the header checks cannot cover: a client that omits
// Sec-Fetch-Site and Origin — a privacy extension that strips them, an old
// embedded WebView that never sent them — was previously allowed through, and
// the agent's dashboard has no session to fall back on. The token does not
// depend on the browser volunteering anything.
func TestAStateChangeWithoutTheTokenIsRefused(t *testing.T) {
	var applied []string
	token, h := triageServer(t, &applied)

	form := url.Values{
		"purl": {"pkg:npm/lodash@4.17.20"}, "advisory": {"GHSA-x"}, "action": {"ack"},
	}
	for _, tc := range []struct {
		name    string
		csrf    string
		headers map[string]string
	}{
		{"no token at all", "", nil},
		{"no token, headers a browser would send", "",
			map[string]string{"Sec-Fetch-Site": "same-origin", "Origin": "http://127.0.0.1:4875"}},
		{"a guessed token", "not-the-token",
			map[string]string{"Sec-Fetch-Site": "same-origin"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := url.Values{}
			for k, v := range form {
				body[k] = v
			}
			body.Set("csrf", tc.csrf)

			req := httptest.NewRequest(http.MethodPost, "/findings/triage",
				strings.NewReader(body.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Host = "127.0.0.1:4875"
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Errorf("code = %d, want 403", rec.Code)
			}
		})
	}

	// The write path is the real assertion: a refusal that still changed
	// something would be no refusal at all.
	if len(applied) != 0 {
		t.Errorf("a forged request reached the write path: %v", applied)
	}

	// And the genuine token still works, so this is a lock rather than a wall.
	rec := postTriage(h, token, form,
		map[string]string{"Sec-Fetch-Site": "same-origin"})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("a real submission got %d, want 303", rec.Code)
	}
	if len(applied) != 1 {
		t.Errorf("the real submission applied %v, want one change", applied)
	}
}

// Every form the dashboard renders carries the field.
//
// A form that forgets it fails closed — but only when somebody clicks it, which
// is a poor way to find out. Counting fields against forms catches it at build
// time instead.
func TestEveryRenderedFormCarriesTheToken(t *testing.T) {
	rotation, rotateHandler := rotationServer(t, nil)

	checked := 0
	for _, tc := range []struct {
		path  string
		token string
		h     http.Handler
	}{
		{"/rotate", rotation.csrf, rotateHandler},
	} {
		body := get(t, tc.h, tc.path).Body.String()

		forms := strings.Count(body, `<form method="post"`)
		fields := strings.Count(body, `name="csrf" value="`+tc.token+`"`)
		if forms == 0 {
			t.Errorf("%s renders no post form, so this proves nothing", tc.path)
			continue
		}
		if fields != forms {
			t.Errorf("%s: %d post form(s) but %d csrf field(s)", tc.path, forms, fields)
		}
		checked += forms
	}
	if checked == 0 {
		t.Error("no form was actually inspected")
	}
}
