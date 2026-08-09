package gate_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/myselfvivek17/pkgwatch/internal/gate"
	"github.com/myselfvivek17/pkgwatch/internal/match"
)

// The publish buffer is the only defence that needs no knowledge at all, and it
// covers the window nothing else can: every advisory postdates the attack it
// describes, so a compromised release looks exactly like a good one for its
// first hours — which is when it is being installed.

func request(name, version string, published time.Time) gate.Request {
	return gate.Request{
		Ecosystem: match.EcosystemNPM, Name: name, Version: version,
		Point: gate.PointResolve, Published: published,
	}
}

func TestBufferWithholdsFreshVersion(t *testing.T) {
	g := newGate(t, true)
	g.Cooldown = 72 * time.Hour
	now := time.Now()

	verdicts := g.EvaluateSet([]gate.Request{
		request("some-package", "1.0.0", now.Add(-30*24*time.Hour)),
		request("some-package", "1.1.0", now.Add(-2*time.Hour)), // published today
	})

	if verdicts[0].Blocked {
		t.Error("the settled version must stay available — it is what we fall back to")
	}
	if !verdicts[1].Blocked {
		t.Fatal("a version published two hours ago should be held back")
	}
	if verdicts[1].Reason != gate.ReasonCooldown {
		t.Errorf("Reason = %q, want cooldown", verdicts[1].Reason)
	}
}

// This is the case that makes the buffer safe to switch on. A security patch is
// also a brand new release. Holding it back would leave the resolver on the
// version it fixes — which the gate then withholds as vulnerable, so nothing
// survives and the install fails outright.
func TestBufferNeverLeavesNothingInstallable(t *testing.T) {
	g := newGate(t, true)
	g.Cooldown = 72 * time.Hour
	now := time.Now()

	// 4.17.20 is affected by the real lodash advisory; 4.17.21 carries the fix
	// and, in this scenario, shipped an hour ago.
	verdicts := g.EvaluateSet([]gate.Request{
		request("lodash", "4.17.20", now.Add(-2*365*24*time.Hour)),
		request("lodash", "4.17.21", now.Add(-1*time.Hour)),
	})

	if !verdicts[0].Blocked {
		t.Error("4.17.20 is vulnerable and must still be withheld")
	}
	if verdicts[1].Blocked {
		t.Fatal("the buffer must not withhold the only installable version — " +
			"a fresh security patch has to get through")
	}
}

// A package whose every release is recent — a new dependency, or one under
// active development — must still be installable.
func TestBufferAllowsPackageWithOnlyFreshVersions(t *testing.T) {
	g := newGate(t, true)
	g.Cooldown = 72 * time.Hour
	now := time.Now()

	verdicts := g.EvaluateSet([]gate.Request{
		request("brand-new-package", "0.1.0", now.Add(-3*time.Hour)),
		request("brand-new-package", "0.1.1", now.Add(-1*time.Hour)),
	})

	for i, v := range verdicts {
		if v.Blocked {
			t.Errorf("verdict %d blocked; with nothing older to fall back to the buffer must stand down", i)
		}
	}
}

// The buffer belongs to resolution. A lockfile pinning a fresh version is a
// record of a decision already made, and refusing it would break `npm ci` and
// every CI job that depends on it.
func TestBufferDoesNotApplyToASingleRequest(t *testing.T) {
	g := newGate(t, true)
	g.Cooldown = 72 * time.Hour

	verdict := g.Evaluate(gate.Request{
		Ecosystem: match.EcosystemNPM, Name: "some-package", Version: "1.1.0",
		Point: gate.PointDownload, Published: time.Now().Add(-time.Hour),
	})
	if verdict.Blocked {
		t.Fatal("the buffer must not fire on the download path")
	}
	if !verdict.Warn || verdict.Reason != gate.ReasonCooldown {
		t.Errorf("it should still warn, got %+v", verdict)
	}
}

func TestBufferOffWhenCooldownIsZero(t *testing.T) {
	g := newGate(t, true)
	g.Cooldown = 0
	now := time.Now()

	verdicts := g.EvaluateSet([]gate.Request{
		request("some-package", "1.0.0", now.Add(-30*24*time.Hour)),
		request("some-package", "1.1.0", now.Add(-time.Hour)),
	})
	for i, v := range verdicts {
		if v.Blocked || v.Warn {
			t.Errorf("verdict %d = %+v; cooldown_hours = 0 disables the buffer entirely", i, v)
		}
	}
}

// A buffered version is recorded as withheld with its own reason, so the report
// can tell "we know this is bad" apart from "this is too new for anyone to
// know yet".
func TestBufferedVersionsAreRecordedSeparately(t *testing.T) {
	g := newGate(t, true)
	g.Cooldown = 72 * time.Hour
	const session = "5555555555555555"
	now := time.Now()

	if err := g.Repo.StartSession(session, match.EcosystemNPM, ".", "npm i", "interactive", now); err != nil {
		t.Fatal(err)
	}
	reqs := []gate.Request{
		request("some-package", "1.0.0", now.Add(-30*24*time.Hour)),
		request("some-package", "1.1.0", now.Add(-time.Hour)),
	}
	for i := range reqs {
		reqs[i].SessionID = session
	}
	g.EvaluateSet(reqs)

	withheld, err := g.Repo.SessionWithheld(session)
	if err != nil {
		t.Fatal(err)
	}
	if len(withheld) != 1 {
		t.Fatalf("got %d withheld packages, want 1", len(withheld))
	}
	if withheld[0].TooNew != 1 {
		t.Errorf("TooNew = %d, want 1", withheld[0].TooNew)
	}
	if len(withheld[0].Advisories) != 0 {
		t.Errorf("a buffered version has no advisory, got %v", withheld[0].Advisories)
	}
}

// End to end through the packument filter: npm is offered the settled release
// and never sees the one published an hour ago.
func TestBufferThroughThePackumentFilter(t *testing.T) {
	upstream := newUpstream(t, func(string) (int, string) {
		return http.StatusOK, packumentWithTimes("some-package",
			map[string]string{
				"1.0.0": time.Now().Add(-30 * 24 * time.Hour).UTC().Format(time.RFC3339),
				"1.1.0": time.Now().Add(-1 * time.Hour).UTC().Format(time.RFC3339),
			})
	})

	g := newGate(t, true)
	g.Cooldown = 72 * time.Hour
	proxy := proxyOver(t, g, upstream)

	_, doc := getJSON(t, proxy.URL+"/some-package")
	versions, _ := doc["versions"].(map[string]any)

	if _, present := versions["1.1.0"]; present {
		t.Error("1.1.0 was published an hour ago and should not be offered yet")
	}
	if _, present := versions["1.0.0"]; !present {
		t.Fatal("1.0.0 is settled and must remain installable")
	}

	// And the tag has to follow, or npm resolves to a version that is no longer
	// listed and fails with an unrelated error.
	tags, _ := doc["dist-tags"].(map[string]any)
	if tags["latest"] != "1.0.0" {
		t.Errorf("dist-tags.latest = %v, want 1.0.0", tags["latest"])
	}
}

// The publish buffer cannot run against a PEP 503 HTML listing, which carries no
// upload times. Silently skipping it would be the same mistake as reporting an
// uncovered ecosystem as clean.
func TestPyPIHTMLIndexSaysTheBufferCannotApply(t *testing.T) {
	upstream := newUpstream(t, htmlIndex("requests", "requests-2.31.0-py3-none-any.whl"))
	upstream.contentType = "text/html"

	g := newGateWith(t, true, requestsAdvisory())
	g.Cooldown = 72 * time.Hour

	logs := captureLogs(t)
	proxy := pypiProxyOver(t, g, upstream)
	fetch(t, proxy.URL+"/simple/requests/", "text/html")

	if !strings.Contains(logs.String(), "publish buffer not applied") {
		t.Errorf("an index that cannot support the buffer must say so:\n%s", logs.String())
	}
}
