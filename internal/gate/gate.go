// Package gate decides whether a package version may be installed, and records
// why.
//
// Two rules shape everything here.
//
// The gate fails OPEN. A locked database, a missing bundle or a panic in the
// matcher must not stop you installing software — a security tool that bricks
// your toolchain gets uninstalled by Friday. But it fails open LOUDLY: every
// degraded evaluation writes a gate_degraded event, because a gate that is
// silently not gating reads as protection and is worse than no gate at all.
//
// The gate never prompts. It answers HTTP requests from npm and pip, which have
// no terminal attached and no way to ask a human anything. Blocking is a 403
// and a recorded decision; the wrapper reads those decisions after the package
// manager exits and does the prompting (§5.1).
package gate

import (
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	"github.com/myselfvivek17/pkgwatch/internal/match"
	"github.com/myselfvivek17/pkgwatch/internal/repo"
)

// Reasons a verdict carries. Empty means nothing was found.
const (
	ReasonMalware       = "malware"
	ReasonVulnerability = "vulnerability"
	ReasonCooldown      = "cooldown"
	ReasonDegraded      = "degraded"
)

// Interception points. Which one a request came from does not change the
// verdict, only what refusing it means.
const (
	// PointResolve is a listing: the resolver is being told what exists.
	// Refusing here removes a version from the menu and nothing more.
	PointResolve = "resolve"
	// PointDownload is the bytes themselves. Refusing here stops an install
	// that had already decided what it wanted.
	PointDownload = "download"
)

// Request is one concrete package version the gate is asked about.
type Request struct {
	SessionID string
	Ecosystem string
	Name      string
	Version   string

	// Point is where in the install this was asked. Defaults to PointDownload,
	// the stricter reading — an unlabelled request is treated as one that
	// actually stopped something.
	Point string

	// Published is when this exact version was released upstream, when the
	// registry told us. Zero means unknown, which disables the cooldown check
	// rather than guessing.
	Published time.Time
}

// Verdict is the gate's answer.
type Verdict struct {
	Blocked    bool
	Reason     string
	AdvisoryID string
	Summary    string
	Tier       string
	Score      float64
	FixedIn    string

	// Warn marks something worth telling the user about that is not grounds to
	// block — a version published minutes ago, for instance.
	Warn bool

	// Degraded means the gate could not evaluate this request and allowed it by
	// default. Not the same as "clean".
	Degraded bool
}

// tierRank orders tiers so a configured threshold can be compared against.
var tierRank = map[string]int{
	match.TierLow: 1, match.TierMedium: 2, match.TierHigh: 3, match.TierCritical: 4,
}

// Gate evaluates requests against the advisory bundle.
//
// ponytail: DB is the gate's OWN handle, not the dashboard's. db.Open pins each
// handle to a single connection (ATTACH is per-connection state), so sharing one
// would serialise every packument lookup behind whatever the dashboard is doing.
// A separate handle costs one open file and removes the contention entirely. If
// the per-request query ever shows up in latency, the upgrade path is an
// in-memory malware set loaded at startup — measure before building it.
type Gate struct {
	DB   *sql.DB
	Repo repo.Agent

	// BundleAttached is false on a machine that has never synced. Every request
	// is then degraded, which is the honest answer: we do not know.
	BundleAttached bool

	// Covered is what the attached bundle actually carries records for. An
	// ecosystem missing from it returns zero rows for every lookup, which is
	// indistinguishable from "nothing wrong" — so it is reported as degraded
	// instead. Empty means unknown coverage and disables the check.
	Covered []string

	// BlockTier is the lowest tier that blocks an install. Malware always blocks
	// regardless — it is not on the same scale.
	BlockTier string

	// Cooldown treats a version published more recently than this as worth
	// mentioning. Advisories lag attacks by hours to days, so "brand new" is the
	// only signal available during the window that matters most (§5.1).
	Cooldown time.Duration

	Now func() time.Time

	// Guard, when set, wraps every advisory lookup so the daemon can replace the
	// merged database underneath a long-running gate. Nil means run directly,
	// which is right for a one-shot process — there is nothing to coordinate
	// with, and a gate that needed a coordinator to answer would be a gate that
	// fails closed for want of one.
	Guard func(func() error) error
}

// guarded runs fn under Guard if there is one.
func (g *Gate) guarded(fn func() error) error {
	if g.Guard == nil {
		return fn()
	}
	return g.Guard(fn)
}

func (g *Gate) now() time.Time {
	if g.Now != nil {
		return g.Now()
	}
	return time.Now()
}

// Evaluate answers one request and records the decision.
//
// It never returns an error: there is no caller that could do anything useful
// with one. Anything that goes wrong becomes a degraded verdict.
//
// A single request can never trigger the publish buffer — holding a fresh
// release back is only safe when an older one survives to fall back to, and one
// request is not a version list. That is deliberate: it is what keeps the buffer
// off the download path, where a lockfile has already recorded a decision.
func (g *Gate) Evaluate(req Request) Verdict {
	return g.EvaluateSet([]Request{req})[0]
}

// EvaluateSet answers for a whole package's version list at once and records
// every decision.
//
// Some rules cannot be decided one version at a time. The publish buffer is
// one: a release published an hour ago is worth holding back, but only if
// something older survives to install instead — otherwise the buffer becomes
// the reason nothing can be installed at all. Only a caller holding the full
// list can know that, so the rule lives here rather than in each proxy.
func (g *Gate) EvaluateSet(reqs []Request) []Verdict {
	started := make([]time.Time, len(reqs))
	verdicts := make([]Verdict, len(reqs))
	for i, req := range reqs {
		started[i] = g.now()
		verdicts[i] = g.decide(req)
	}

	applyBuffer(verdicts)

	for i, req := range reqs {
		g.record(req, verdicts[i], started[i])
	}
	return verdicts
}

// applyBuffer turns cooldown warnings into withholdings, but only when the
// version list has something clean and settled to fall back to.
//
// The case this guards against is a security patch, which is also a brand new
// release. Holding it back would leave the resolver on the version it fixes —
// which the gate then withholds as vulnerable, so nothing survives and the
// install fails. A buffer must never be the reason there is nothing left.
func applyBuffer(verdicts []Verdict) {
	fallback := false
	for _, v := range verdicts {
		if !v.Blocked && v.Reason != ReasonCooldown {
			fallback = true
			break
		}
	}
	if !fallback {
		return
	}

	for i, v := range verdicts {
		if !v.Blocked && v.Reason == ReasonCooldown {
			verdicts[i].Blocked = true
			verdicts[i].Warn = false
		}
	}
}

func (g *Gate) record(req Request, verdict Verdict, started time.Time) {
	purl := match.PURL(req.Ecosystem, req.Name, req.Version)
	decision := repo.DecisionAllowed
	switch {
	case verdict.Blocked && req.Point == PointResolve:
		decision = repo.DecisionWithheld
	case verdict.Blocked:
		decision = repo.DecisionBlocked
	case verdict.Reason == repo.DecisionOverride:
		decision = repo.DecisionOverride
	}

	latency := int(g.now().Sub(started) / time.Millisecond)
	if err := g.Repo.RecordDecision(repo.Decision{
		SessionID:  req.SessionID,
		PURL:       purl,
		Decision:   decision,
		Reason:     verdict.Reason,
		AdvisoryID: verdict.AdvisoryID,
		LatencyMS:  latency,
		At:         started,
	}); err != nil {
		// Losing the audit trail is not grounds to change the answer.
		slog.Warn("gate: could not record decision", "purl", purl, "error", err)
	}

	// Only a refusal at the download point earns a timeline entry. A packument
	// filter withholds dozens of ancient versions on an ordinary install; an
	// event apiece would drown the timeline in things that stopped nothing.
	// npm.go records one summary event per filtered package instead.
	if verdict.Blocked && decision == repo.DecisionBlocked {
		g.event(repo.EventInstallBlocked, verdict.Tier, purl, verdict.AdvisoryID, map[string]any{
			"reason":     verdict.Reason,
			"session_id": req.SessionID,
			"summary":    verdict.Summary,
			"fixed_in":   verdict.FixedIn,
		})
	}
}

// decide is the evaluation proper, with recording left to EvaluateSet.
func (g *Gate) decide(req Request) (verdict Verdict) {
	// A panic in a version comparator must not take the install down with it.
	// Fail open, and say so.
	defer func() {
		if r := recover(); r != nil {
			slog.Error("gate: matcher panicked, allowing", "package", req.Name, "panic", r)
			g.degrade(req, fmt.Sprintf("matcher panic: %v", r))
			verdict = Verdict{Degraded: true, Reason: ReasonDegraded}
		}
	}()

	// An explicit override for this session wins over everything. The user was
	// shown what they were approving and named it; that is a local, deliberate
	// loosening, which is the only direction loosening is allowed to travel.
	if approved, err := g.Repo.IsApproved(req.SessionID,
		match.PURL(req.Ecosystem, req.Name, req.Version),
		match.PURLBase(req.Ecosystem, req.Name)); err == nil && approved {
		return Verdict{Reason: repo.DecisionOverride}
	}

	if !g.BundleAttached {
		g.degrade(req, "no advisory bundle installed")
		return Verdict{Degraded: true, Reason: ReasonDegraded}
	}

	// A bundle built without this ecosystem's feed answers "no advisories" for
	// every package in it. That is the one wrong answer this tool must never
	// give, so say we do not know instead.
	if len(g.Covered) > 0 && !covers(g.Covered, req.Ecosystem) {
		g.degrade(req, "the installed bundle carries no "+
			match.BaseEcosystem(req.Ecosystem)+" advisories at all")
		return Verdict{Degraded: true, Reason: ReasonDegraded}
	}

	var advisories []match.Advisory
	err := g.guarded(func() error {
		var err error
		advisories, err = repo.LookupAdvisories(g.DB, req.Ecosystem, req.Name)
		return err
	})
	if err != nil {
		g.degrade(req, "advisory lookup failed: "+err.Error())
		return Verdict{Degraded: true, Reason: ReasonDegraded}
	}

	pkg := match.Package{
		Ecosystem: req.Ecosystem,
		Name:      req.Name,
		Version:   req.Version,
		// An install is by definition current, and the gate has no inventory to
		// consult — M3 owns scope. Treating it as project scope keeps the score
		// free of the global-install multiplier the gate cannot verify.
		Scope:    match.ScopeProject,
		LastSeen: g.now(),
	}

	worst := Verdict{}
	for _, adv := range advisories {
		hit, err := match.Affects(adv, pkg)
		if err != nil {
			// One unparseable version in one advisory is not a reason to stop
			// evaluating the rest, but it does mean coverage is incomplete.
			slog.Warn("gate: could not evaluate advisory",
				"advisory", adv.ID, "package", req.Name, "error", err)
			continue
		}
		if !hit {
			continue
		}

		score, tier := match.Score(adv, pkg, g.now())
		candidate := Verdict{
			Blocked:    adv.Kind == match.KindMalware || tierRank[tier] >= tierRank[g.blockTier()],
			Reason:     reasonFor(adv),
			AdvisoryID: adv.ID,
			Summary:    adv.Summary,
			Tier:       tier,
			Score:      score,
			FixedIn:    fixedIn(adv),
		}
		if beats(candidate, worst) {
			worst = candidate
		}
	}
	if worst.AdvisoryID != "" {
		return worst
	}

	// Nothing on file — which is exactly the state a compromised release is in
	// for its first hours. Every advisory postdates the attack it describes, so
	// "nothing known" is the strongest signal available during the window that
	// matters most, and the only defence that needs no knowledge at all is to
	// wait (§5.1).
	//
	// This returns a warning, not a block. Whether it becomes a withholding is
	// decided in applyBuffer, which can see whether anything older survives.
	if g.Cooldown > 0 && !req.Published.IsZero() && g.now().Sub(req.Published) < g.Cooldown {
		return Verdict{
			Warn:   true,
			Reason: ReasonCooldown,
			Summary: fmt.Sprintf("published %s ago, inside the %s publish buffer",
				roundDuration(g.now().Sub(req.Published)), roundDuration(g.Cooldown)),
		}
	}
	return Verdict{}
}

// covers matches the full ecosystem identifier, release included. A bundle
// holding Debian:12 does not answer for Debian:13 — different fixed versions,
// different feed — and treating it as if it did turns "found nothing" into
// "nothing is wrong".
func covers(covered []string, ecosystem string) bool {
	for _, item := range covered {
		if item == ecosystem {
			return true
		}
	}
	return false
}

func (g *Gate) blockTier() string {
	if _, ok := tierRank[g.BlockTier]; ok {
		return g.BlockTier
	}
	return match.TierHigh
}

// degrade records that the gate allowed something it could not evaluate.
func (g *Gate) degrade(req Request, detail string) {
	slog.Warn("gate degraded — allowing without evaluation",
		"ecosystem", req.Ecosystem, "package", req.Name, "version", req.Version, "detail", detail)
	g.event(repo.EventGateDegraded, "", match.PURL(req.Ecosystem, req.Name, req.Version), "", map[string]any{
		"detail":     detail,
		"session_id": req.SessionID,
	})
}

func (g *Gate) event(kind, severity, purl, advisoryID string, detail any) {
	if err := g.Repo.RecordEvent(kind, severity, purl, advisoryID, detail, g.now()); err != nil {
		slog.Warn("gate: could not record event", "kind", kind, "error", err)
	}
}

// beats orders verdicts so the most serious finding is the one reported.
// Malware outranks any score, because it is a different product.
func beats(candidate, current Verdict) bool {
	if current.AdvisoryID == "" {
		return true
	}
	if candidate.Reason == ReasonMalware && current.Reason != ReasonMalware {
		return true
	}
	if current.Reason == ReasonMalware && candidate.Reason != ReasonMalware {
		return false
	}
	return candidate.Score > current.Score
}

func reasonFor(adv match.Advisory) string {
	if adv.Kind == match.KindMalware {
		return ReasonMalware
	}
	return ReasonVulnerability
}

// fixedIn reports the first fixed version, when the advisory names one. Malware
// is never "fixed" by upgrading — the release itself is the payload — so the
// field is left empty rather than pointing at a later version as if that
// undoes the code that already ran.
func fixedIn(adv match.Advisory) string {
	if adv.Kind == match.KindMalware {
		return ""
	}
	for _, r := range adv.Ranges {
		if r.Fixed != "" {
			return r.Fixed
		}
	}
	return ""
}

func roundDuration(d time.Duration) time.Duration {
	if d < time.Hour {
		return d.Round(time.Minute)
	}
	return d.Round(time.Hour)
}
