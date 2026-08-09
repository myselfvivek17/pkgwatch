package gate

import (
	"encoding/json"
	"testing"
)

// Filename parsing is where a gate goes quiet. A version it cannot read is not
// a version it blocks: the request is recorded as unevaluated and passed
// through. Both parsers therefore get a table of their own rather than being
// exercised only through the proxies.

func TestVersionFromTarball(t *testing.T) {
	cases := []struct{ name, file, want string }{
		{"lodash", "lodash-4.17.20.tgz", "4.17.20"},
		{"@ctrl/tinycolor", "tinycolor-4.1.2.tgz", "4.1.2"},

		// A hyphen-then-digit inside the package name is the shape that breaks
		// positional parsing. It is safe here only because the name is known
		// from the request path rather than guessed from the filename.
		{"foo-2", "foo-2-1.0.0.tgz", "1.0.0"},
		{"socket.io-client", "socket.io-client-4.7.5.tgz", "4.7.5"},

		{"pkg", "pkg-1.0.0-beta.1.tgz", "1.0.0-beta.1"},
		{"pkg", "pkg-1.0.0+build.5.tgz", "1.0.0+build.5"},

		// Registries that publish under a different convention return nothing,
		// which the caller records as unevaluated rather than guessing.
		{"lodash", "something-else-1.0.0.tgz", ""},
		{"lodash", "lodash-4.17.20.tar.gz", ""},
		{"lodash", "lodash.tgz", ""},
	}

	for _, tc := range cases {
		if got := versionFromTarball(tc.name, tc.file); got != tc.want {
			t.Errorf("versionFromTarball(%q, %q) = %q, want %q", tc.name, tc.file, got, tc.want)
		}
	}
}

func TestVersionFromPyPIFile(t *testing.T) {
	cases := []struct{ project, file, want string }{
		{"requests", "requests-2.19.1-py2.py3-none-any.whl", "2.19.1"},
		{"requests", "requests-2.19.1.tar.gz", "2.19.1"},

		// Eggs are hyphen-delimited fields like wheels. Reading this one as
		// "2.23.0-py2.7" made every advisory error out and served the file
		// unevaluated.
		{"requests", "requests-2.23.0-py2.7.egg", "2.23.0"},

		// Source distributions carry the raw project name, which may itself
		// contain the separator.
		{"backports.ssl-match-hostname", "backports.ssl_match_hostname-3.5.0.1.tar.gz", "3.5.0.1"},
		{"zope.interface", "zope.interface-5.4.0.tar.gz", "5.4.0"},

		// PEP 440 shapes that must survive intact.
		{"pkg", "pkg-1.0.post1.tar.gz", "1.0.post1"},
		{"pkg", "pkg-1!2.0.tar.gz", "1!2.0"},
		{"pkg", "pkg-1.0+local.tar.gz", "1.0+local"},

		// A fragment or query on the link must not end up inside the version.
		{"requests", "requests-2.31.0.tar.gz#sha256=deadbeef", "2.31.0"},

		{"requests", "mystery-artifact.bin", ""},
		{"requests", "somethingelse-1.0.tar.gz", ""},
	}

	for _, tc := range cases {
		if got := versionFromPyPIFile(tc.project, tc.file); got != tc.want {
			t.Errorf("versionFromPyPIFile(%q, %q) = %q, want %q", tc.project, tc.file, got, tc.want)
		}
	}
}

// A package whose surviving versions are all too old to be strict semver must
// still get a usable dist-tag. Deleting it fails `npm install <pkg>` outright,
// as if nothing were safe, when in fact every survivor was cleared.
func TestHighestVersionToleratesLegacyVersions(t *testing.T) {
	versions := map[string]json.RawMessage{
		"1.0":   json.RawMessage(`{}`),
		"1.2":   json.RawMessage(`{}`),
		"0.9.1": json.RawMessage(`{}`),
	}
	if got := highestVersion(versions); got != "1.2" {
		t.Errorf("highestVersion = %q, want 1.2", got)
	}
}

func TestHighestVersionPrefersStableOverPrerelease(t *testing.T) {
	versions := map[string]json.RawMessage{
		"2.0.0-beta.1": json.RawMessage(`{}`),
		"1.9.0":        json.RawMessage(`{}`),
	}
	if got := highestVersion(versions); got != "1.9.0" {
		t.Errorf("highestVersion = %q — a repointed tag must not hand npm a beta", got)
	}
}

func TestHighestVersionFallsBackToPrerelease(t *testing.T) {
	versions := map[string]json.RawMessage{"2.0.0-beta.1": json.RawMessage(`{}`)}
	if got := highestVersion(versions); got != "2.0.0-beta.1" {
		t.Errorf("highestVersion = %q, want the prerelease when it is all there is", got)
	}
}

func TestSplitNPMPath(t *testing.T) {
	cases := []struct {
		path       string
		name, file string
		tarball    bool
	}{
		{"/lodash", "lodash", "", false},
		{"/@ctrl%2ftinycolor", "@ctrl/tinycolor", "", false},
		{"/@ctrl/tinycolor", "@ctrl/tinycolor", "", false},
		{"/lodash/-/lodash-4.17.20.tgz", "lodash", "lodash-4.17.20.tgz", true},
		{"/@ctrl/tinycolor/-/tinycolor-4.1.2.tgz", "@ctrl/tinycolor", "tinycolor-4.1.2.tgz", true},

		// Registry APIs and per-version endpoints are not packages.
		{"/-/v1/search", "", "", false},
		{"/lodash/4.17.20", "", "", false},
		{"/@ctrl", "", "", false},
		{"/", "", "", false},
	}

	for _, tc := range cases {
		name, file, tarball := splitNPMPath(tc.path)
		if name != tc.name || file != tc.file || tarball != tc.tarball {
			t.Errorf("splitNPMPath(%q) = (%q, %q, %v), want (%q, %q, %v)",
				tc.path, name, file, tarball, tc.name, tc.file, tc.tarball)
		}
	}
}
