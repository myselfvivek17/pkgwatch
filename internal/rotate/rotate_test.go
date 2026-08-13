package rotate

import (
	"os"
	"path/filepath"
	"testing"
)

// The rule this package exists for: only what is actually on the machine. A
// generic checklist reads as a form to fill in, and the person reading it has
// just found out that something ran as them.
func TestOnlyCredentialsThatExistAreListed(t *testing.T) {
	home := t.TempDir()
	write(t, filepath.Join(home, ".aws", "credentials"), "[default]\naws_access_key_id=AKIA…\n")
	write(t, filepath.Join(home, ".ssh", "id_ed25519"), "-----BEGIN OPENSSH PRIVATE KEY-----\n")

	items := Detect(home)
	if len(items) != 2 {
		t.Fatalf("found %d items, want the two that exist: %+v", len(items), ids(items))
	}
	// Blast radius order: a cloud key reaches everything, an SSH key reaches
	// the hosts that trust it.
	if items[0].ID != "aws" || items[1].ID != "ssh" {
		t.Errorf("order = %v, want cloud before ssh", ids(items))
	}
	if items[0].Path == "" || items[0].RotateURL == "" {
		t.Error("an item without a path or a rotation link is advice, not a task")
	}
}

// An .npmrc without a token is a registry preference. Listing it would pad the
// checklist with something nobody needs to rotate, and every padded line makes
// the real ones less likely to be done.
func TestAConfigFileWithNoCredentialInItIsNotListed(t *testing.T) {
	home := t.TempDir()
	write(t, filepath.Join(home, ".npmrc"), "registry=http://127.0.0.1:4873\n")

	if items := Detect(home); len(items) != 0 {
		t.Errorf("listed %v for an .npmrc with no auth token", ids(items))
	}

	write(t, filepath.Join(home, ".npmrc"), "//registry.npmjs.org/:_authToken=npm_xxx\n")
	items := Detect(home)
	if len(items) != 1 || items[0].ID != "npm" {
		t.Errorf("got %v, want the npm token once a token is in the file", ids(items))
	}
}

// One entry per credential kind, whichever of its paths exists. Two rows for
// the same token would be two things to tick and one thing to rotate.
func TestOneEntryPerCredentialKind(t *testing.T) {
	home := t.TempDir()
	write(t, filepath.Join(home, ".ssh", "id_ed25519"), "key\n")
	write(t, filepath.Join(home, ".ssh", "id_rsa"), "key\n")

	if items := Detect(home); len(items) != 1 {
		t.Errorf("got %v, want one ssh entry", ids(items))
	}
}

// An empty home is an empty list, and the caller says what that does and does
// not mean. Detect must not invent an item so the page has something on it.
func TestNothingFoundIsAnEmptyList(t *testing.T) {
	if items := Detect(t.TempDir()); len(items) != 0 {
		t.Errorf("found %v in an empty home directory", ids(items))
	}
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func ids(items []Item) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, item.ID)
	}
	return out
}
