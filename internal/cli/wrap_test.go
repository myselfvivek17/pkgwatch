package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/myselfvivek17/pkgwatch/internal/repo"
)

// promptCmd wires a command to scripted input and captured output, standing in
// for the terminal this path normally reads from.
func promptCmd(input string) (*cobra.Command, *bytes.Buffer) {
	cmd := &cobra.Command{}
	out := &bytes.Buffer{}
	cmd.SetIn(strings.NewReader(input))
	cmd.SetOut(out)
	cmd.SetErr(out)
	return cmd, out
}

var blockedLodash = []repo.Decision{{
	PURL: "pkg:npm/lodash@4.17.20", Decision: repo.DecisionBlocked,
	Reason: "vulnerability", AdvisoryID: "GHSA-35jh-r3h4-6jhm",
}}

var withheldExpress = []repo.Withheld{{
	PURLBase: "pkg:npm/express", Count: 42, Advisories: []string{"GHSA-aaaa-bbbb-cccc"},
}}

// The default is abort. Anyone hitting enter to make a prompt go away must not
// thereby install a package the gate refused.
func TestPromptDefaultsToAbort(t *testing.T) {
	cmd, _ := promptCmd("\n")

	approved, err := promptOverride(cmd, blockedLodash, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(approved) != 0 {
		t.Errorf("a bare newline approved %v", approved)
	}
}

// A closed stdin is not consent.
func TestPromptOnEOFAborts(t *testing.T) {
	cmd, _ := promptCmd("")

	approved, err := promptOverride(cmd, blockedLodash, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(approved) != 0 {
		t.Errorf("EOF approved %v", approved)
	}
}

// Choosing override is not itself an approval — every item is still named and
// answered individually, so nobody waves through a package they did not read.
func TestOverrideStillAsksPerItem(t *testing.T) {
	cmd, out := promptCmd("o\nn\n")

	approved, err := promptOverride(cmd, blockedLodash, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(approved) != 0 {
		t.Errorf("declining the per-package question still approved %v", approved)
	}
	if !strings.Contains(out.String(), "pkg:npm/lodash@4.17.20") {
		t.Error("the prompt must name what is being approved")
	}
}

func TestOverrideApprovesWhatWasAccepted(t *testing.T) {
	// Blocked download: yes. Withheld package: no.
	cmd, _ := promptCmd("o\ny\nn\n")

	approved, err := promptOverride(cmd, blockedLodash, withheldExpress)
	if err != nil {
		t.Fatal(err)
	}
	if len(approved) != 1 || approved[0] != "pkg:npm/lodash@4.17.20" {
		t.Fatalf("approved = %v, want just the accepted download", approved)
	}
}

// Withheld versions are approved per package, because there is no way to know
// which of forty-two filtered versions the resolver would have picked.
func TestWithheldIsApprovedAtPackageLevel(t *testing.T) {
	cmd, out := promptCmd("o\ny\n")

	approved, err := promptOverride(cmd, nil, withheldExpress)
	if err != nil {
		t.Fatal(err)
	}
	if len(approved) != 1 || approved[0] != "pkg:npm/express" {
		t.Fatalf("approved = %v, want the versionless package identifier", approved)
	}
	if !strings.Contains(out.String(), "42") {
		t.Error("the prompt should say how many versions it covers")
	}
}

// View prints the detail and returns to the menu rather than deciding anything.
func TestViewThenAbort(t *testing.T) {
	cmd, out := promptCmd("v\na\n")

	approved, err := promptOverride(cmd, blockedLodash, withheldExpress)
	if err != nil {
		t.Fatal(err)
	}
	if len(approved) != 0 {
		t.Errorf("viewing details approved %v", approved)
	}
	printed := out.String()
	if !strings.Contains(printed, "GHSA-35jh-r3h4-6jhm") {
		t.Error("view should show the advisory behind a blocked download")
	}
	if !strings.Contains(printed, "GHSA-aaaa-bbbb-cccc") {
		t.Error("view should show the advisories behind withheld versions too")
	}
}

// Unrecognised input re-asks. It must never fall through to approval.
func TestUnrecognisedInputReAsks(t *testing.T) {
	cmd, out := promptCmd("what?\na\n")

	approved, err := promptOverride(cmd, blockedLodash, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(approved) != 0 {
		t.Errorf("approved %v", approved)
	}
	if !strings.Contains(out.String(), "didn't catch that") {
		t.Error("expected the prompt to re-ask")
	}
}

func TestShellInitRefusesUnknownShell(t *testing.T) {
	cmd := shellInitCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"tcsh"})

	if err := cmd.Execute(); err == nil {
		t.Error("an unsupported shell must fail loudly, not print nothing")
	}
}

// The integration shadows npm with a function that calls pkgwatch, which runs
// npm — so every snippet needs the guard, or an install script that shells out
// to npm recurses until something gives.
func TestShellSnippetsCarryTheRecursionGuard(t *testing.T) {
	for shell, snippet := range shellSnippets {
		if !strings.Contains(snippet, gateEnvMarker) {
			t.Errorf("%s integration has no %s guard and will recurse", shell, gateEnvMarker)
		}
	}
}
