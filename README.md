# pkgwatch

A cross-platform supply-chain watchdog for a small fleet of personal machines, shipped as a single static binary that runs in one of two modes.

**Agent** — runs a local registry proxy that gates `npm` and `pip` installs, keeps an inventory of everything installed on the machine, matches it against a local advisory database, and serves a machine-local dashboard. Fully functional with no network.

**Hub** — aggregates events and findings from paired agents, serves the fleet dashboard, and relays signed advisory bundles. Never required for an agent to work.

One machine can run both.

## The three hard rules

1. **The agent never depends on the hub.** Hub down, hub unreachable, hub never configured — installs still get gated, findings still get detected.
2. **Advisory bundles are verified against a publisher key compiled into the binary**, not trusted because the hub sent them. A compromised hub must not be able to push "everything is safe" and blind the fleet.
3. **Policy flows in the strict direction only.** An agent may be configured stricter than the hub tells it, never looser. Loosening is a local action.

## Status

**M0 through M2 complete.** Installs are gated. Nothing is scanned yet — pkgwatch does not know what is already on the machine until M3.

| Milestone | State |
|---|---|
| M0 — skeleton, config, DB, CLI, `/health`, CI | done |
| M0.5 — design system, dashboard shell | done |
| M1 — advisory bundle pipeline, PEP 440 + semver matching, `check` | done |
| M1b — Debian, Alpine, Go, Rust matching | done |
| M1b — Ubuntu matching | comparator done, **feed not in the bundle** |
| M1b — Java, Ruby, PHP, .NET matching | remaining |
| M2 — npm and PyPI gates | done |
| M3 — inventory, Docker collector, retroactive watcher | |
| M4 — agent dashboard pages | |
| M5 — hub, pairing, sync | |
| M6 — quarantine, credential rotation, packaging | |

Commands whose milestone has not landed exist and say so rather than being absent:

```
$ pkgwatch scan
Error: not implemented yet — lands in M3
```

## Checking a package

```
$ pkgwatch check pkg:npm/lodash@4.17.20
npm lodash (4.17.20)
bundle 20260808 · 5 records · 1 advisories on file for this package

HIGH  GHSA-35jh-r3h4-6jhm  score 7.2
      Command Injection in lodash
      fixed in 4.17.21

$ pkgwatch check "pkg:npm/%40ctrl/tinycolor@4.1.2"
CRITICAL · MALWARE  MAL-2025-47141  score 20.0
                    Malicious code in @ctrl/tinycolor (npm)
                    remove this package — malicious releases are not fixed by upgrading
```

Malware is floored at critical regardless of its CVSS score. Active malware and a latent CVE are different products and do not share a scale.

## Gating an install

```sh
pkgwatch npm install express        # or: pkgwatch npm ci
pkgwatch pip install -r requirements.txt
eval "$(pkgwatch shell-init bash)"  # shadow npm and pip permanently
```

The wrapper starts a filtering proxy on a loopback port for the lifetime of one
command. Nothing is written to your `.npmrc` or `pip.conf`, and the agent daemon
does not need to be running.

**npm is intercepted at two points, because either one alone leaves a hole.**

Filtering the *packument* (`GET /{name}`) removes affected versions before the
resolver ever sees them, so a clean install shows no sign anything happened —
`npm install lodash express` pulls 68 packages, withholds 350 affected versions
across 9 of them, and resolves to clean releases. That is the invisible happy
path, and it is where the gate does almost all of its work.

Refusing the *tarball* (`GET /{name}/-/*.tgz`) catches the other half. `npm ci`
reads exact versions and download URLs straight out of `package-lock.json` and
never requests a packument at all; filtering alone would miss it completely.
Packument tarball links are rewritten back through the proxy so this point
actually fires.

**PyPI has one interception point, and that is not an oversight.** pip only ever
learns a file exists from the index page, including when a requirements file
pins the version — so removing a file from the listing removes it from every
resolution path pip has. `pip install <url>` and a local wheel touch no index
and nothing a proxy can do reaches them.

**Withholding a version and blocking a download are different events.** The
first is routine and silent — the resolver picks another. The second stopped
something. They are reported separately, and withheld versions only surface when
resolution actually failed, which is what makes the npm error legible:

```
$ pkgwatch npm install lodash@4.17.20
npm error notarget No matching version found for lodash@4.17.20.

pkgwatch withheld 115 affected version(s) from resolution:

  PACKAGE         WITHHELD  ADVISORIES
  pkg:npm/lodash  115       GHSA-jf85-cpcp-j695, GHSA-r5fr-rjxr-66jc

  If the version you asked for could not be found, this is why.
```

**The gate never prompts.** It answers HTTP requests from tools with no terminal
attached, so blocking is a 403 and a recorded decision. The wrapper reads those
decisions after the package manager exits — when stdin is ours again — and does
the asking. Overrides are named individually and apply to that one install
session; withheld versions are approved per package, since there is no way to
know which of a hundred filtered versions the resolver would have picked.

**It fails open, loudly.** A locked database, a missing bundle, an unparseable
packument or a panic in a comparator allows the install and writes a
`gate_degraded` event. A gate that is silently not gating reads as protection and
is worse than no gate at all.

`block_tier` defaults to `high`. npm's corpus has a low or medium advisory
against a large share of transitive dependencies, and a gate that fires on all of
them gets switched off within a week. Malware always blocks regardless of the
setting — it is an active attack, not a latent weakness, and the two do not share
a scale.

Gate evaluation costs **2.3 ms on average and 37 ms at worst** across 3,310 real
decisions. `Authorization` headers travel to the upstream registry verbatim and
are never logged, inspected or persisted; a test asserts the token does not reach
log output.

## The advisory bundle

Advisories are compiled centrally and distributed as one signed SQLite file, replicated to every agent. Compiling once and shipping a file beats every machine parsing hundreds of megabytes of upstream JSON.

```sh
pkgwatch publish build-bundle --input npm-all.zip --out advisories.db --key publisher.key
pkgwatch sync --file advisories.db
```

The whole npm ecosystem — 228,957 advisories from a 208 MB OSV archive — compiles in about 13 seconds into a **49 MB** bundle. That is well above the 15–25 MB the design anticipated, and the reason is worth stating: **219,308 of the 227,080 rows are malware records**, not vulnerabilities. The `ossf/malicious-packages` feed has grown by more than an order of magnitude, which is itself the argument for this tool existing.

Adding PyPI, Debian, Alpine, Go and crates.io brings it to 522,525 records and **117 MB**, down from 313 MB by two changes that lose nothing:

- **Enumerated versions are dropped when the advisory also gives ranges.** Debian enumerates every affected version across four releases; the range already says the same thing. That alone was 7 million rows and 160 MB. Malware records keep their enumeration even when a range exists — a range spanning a non-contiguous set would mark clean versions in the gap as malicious, and "this package is malware" must never be reached by inference.
- **Summaries are stored once per advisory id**, not once per affected package. One CVE lands in four Debian releases with identical prose averaging ~245 characters.

117 MB is still more than a fleet-wide bundle should be, and per-ecosystem bundles are the obvious next step — an agent with no Debian packages has no use for 200,000 Debian rows. That is no longer only an optimisation: **Ubuntu is missing because it cannot fit.** Its OSV archive alone is 573 MB of input, several times Debian's, and there is no room for it in a file every agent downloads whole. Ubuntu coverage is blocked on this decision.

**When per-ecosystem bundles land, the ecosystem has to go into the signed message**, or a validly signed npm bundle served as `advisories-debian.db` silently zeroes Debian coverage — signature intact, agent blind.

### A bundle says what it covers

Every bundle records the ecosystems it carries, and the agent refuses to answer
questions about the ones it does not:

```
$ pkgwatch status
advisories  20260809 · 522525 records · built 0s ago
covers      Alpine, Debian, Go, PyPI, crates.io, npm
```

This exists because of a live gap. A bundle was built with 496,740 records and no
PyPI feed at all, so every lookup for a Python package returned zero rows — and
zero rows is the same query result as *nothing wrong*. `check pkg:pypi/requests@2.19.1`
answered "no advisories match this version" for a package that had ten, one of
them a credential leak. The bundle was large, recent and correctly signed. It was
simply blind, and nothing said so.

An ecosystem absent from `covers` is now reported as unknown by the gate, refused
outright by `check`, and warned about by `status` if it is one of the gated two.
"We never looked" and "we looked and it was clean" must never be the same answer.

A bundle is trusted because of who signed it, never because of where it came from. Verification is identical and mandatory whether the bytes came from the publisher or from your own hub, and `sync` refuses:

- bytes that do not match the manifest digest
- a signature from any key not compiled into the binary
- a bundle relabelled to a version it was not signed for
- a bundle older than the one already installed, without `--allow-downgrade`
- a bundle with no signature at all

The version and digest are read from the manifest, never from the candidate file — otherwise the file would get to choose what it is signed as, which is no binding at all. Publisher keys are a **list**, current plus next, so rotating one does not brick agents running an older binary.

## Version matching

Version comparison is where correctness actually lives — both false positives and false negatives are silent.

The **PEP 440** parser is hand-written, because no Go library handles epochs (`1!2.0`), post-releases, dev releases and local versions correctly together. It is checked two ways: a hand-written table encoding what the specification says, and a differential test against CPython's own `packaging` library covering **9,634 versions** for normalization and **6,511** for total ordering. The golden file is committed, so CI needs no Python.

**npm** versions go through `Masterminds/semver` in strict mode, pinned to the behaviour advisory matching depends on: a prerelease sorts below its own release, so `1.0.0-beta.1` never falls inside a range introduced at `1.0.0`.

**Debian and Ubuntu** share a hand-written `deb-version(7)` comparator, checked against Debian's own `apt_pkg.version_compare` across 852 versions and 402 equality pairs. Two of its rules are unlike anything else: `~` sorts *before* the end of a string (which is how Debian spells a pre-release, so `1.0~rc1` precedes `1.0`), and letters sort before all non-letters rather than in ASCII order. The comparator is exercised against Debian data; the Ubuntu feed is not currently in the bundle, so Ubuntu packages come back as *unknown* rather than clean.

**Alpine** uses a hand-written apk comparator, checked against `apk version -t` across all 1,600 pairwise comparisons of its corpus. Its quirks were read off apk itself rather than from documentation: trailing components are significant (`1.0 < 1.0.0`, the opposite of PEP 440), a component with a leading zero compares as a fraction (`1.01 < 1.1`), and an absent suffix number sorts below zero (`1.0_p < 1.0_p0`).

**Distribution advisories keep their release qualifier.** A CVE lands in `Debian:11`, `Debian:12`, `Debian:13` and `Debian:14` with a *different fixed version in each*, so collapsing them would match against the wrong distribution's bounds. `check` requires the release:

```sh
pkgwatch check "pkg:deb/debian/openssl@3.0.11-1~deb12u2?distro=debian-12"
```

Verified against a live `debian:12-slim` container: all 88 of its real installed packages parsed without error, 8 flagged with findings consistent with Debian's tracker, and the fix boundary holds — `3.0.11-1~deb12u2` is flagged for a CVE that `3.0.19-1~deb12u2` is clean for.

CVSS base scores are computed from the vector strings OSV publishes, falling back to the qualitative rating when no vector is present.

## Build

Requires the Go version in `go.mod` (currently 1.25, raised by `golang.org/x/sys`, not by anything here). Everything builds with `CGO_ENABLED=0` — that is what keeps cross-compiling all six targets from one machine trivial, and it is why the SQLite driver is `modernc.org/sqlite` rather than `mattn/go-sqlite3`.

```sh
CGO_ENABLED=0 go build -o dist/pkgwatch ./cmd/pkgwatch
go test ./...
```

## Try it

```sh
pkgwatch status          # health, feed freshness, coverage, findings, pairing
pkgwatch agent           # dashboard on :4875, npm gate on :4873, PyPI on :4874
pkgwatch npm ci          # one gated install, no daemon needed
```

Then open `/design` for the full design system — every token and component the dashboards are built from, in both themes.

The hub refuses to start on a non-loopback bind without a configured password. That is deliberate: the dashboard approves package installs and deletes files, so unauthenticated on a LAN it is a remote code execution primitive. Tailscale is the recommended exposure path.

Both modes serve `/health` for the service manager to watch.

## Dependency discipline

This tool watches for supply-chain attacks. Its own dependency tree is a target, so direct dependencies are capped at 8 and `govulncheck` runs in CI.

Currently in use: `modernc.org/sqlite`, `go-chi/chi/v5`, `spf13/cobra`, `BurntSushi/toml`, `Masterminds/semver/v3`, `package-url/packageurl-go`. Reserved: `golang.org/x/crypto` for argon2id (M5) and `fyne.io/systray` behind the `tray` build tag (M6). That accounts for all 8 — anything else has to be stdlib or hand-written, which is why the PEP 440 parser, the CVSS calculator and the OSV reader are in-tree.

**On vendoring:** the build spec calls for committing `vendor/`. We don't. `go mod vendor` weighs 134 MB, 125 MB of which is machine-generated `modernc.org/{libc,sqlite}` — one file set per GOOS/GOARCH, the cost of pure-Go SQLite. `go.sum` already pins every dependency by cryptographic hash, so tampering is covered; what we forgo is availability if a module is yanked upstream. Worth revisiting if pkgwatch moves to its own repository.

The dashboards ship **zero JavaScript dependencies**. Server-rendered `html/template`, hand-written CSS, and about forty lines of vanilla JS. A supply-chain security tool that pulled four hundred npm packages to render a table would be a self-own.

## Ports

| Port | Purpose |
|---|---|
| 4873 | npm gate |
| 4874 | PyPI gate |
| 4875 | dashboard — hub, or agent when running alone |
| 4877 | agent dashboard when a hub already holds 4875 |

The agent detects the conflict, logs it, and shifts. It does not crash.

## Data locations

| Platform | Path |
|---|---|
| Linux | `~/.local/share/pkgwatch/` |
| macOS | `~/Library/Application Support/pkgwatch/` |
| Windows | `%LOCALAPPDATA%\pkgwatch\` |

`agent.db` and `hub.db` hold machine and fleet state. `advisories.db` is a separate, replaceable file attached read-only, so a bundle update is an atomic file swap rather than a migration.

## Running as a service

See `contrib/` — a systemd **user** unit, a launchd plist, and a Windows Scheduled Task registered at logon. All three watch `/health`.

On Windows, unsigned binaries trip SmartScreen and may be flagged by Defender. On macOS they need `xattr -d com.apple.quarantine`.
