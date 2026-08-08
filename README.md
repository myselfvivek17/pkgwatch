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

**M0, M0.5 and M1 complete.** Advisory matching works; nothing is gated or scanned yet.

| Milestone | State |
|---|---|
| M0 — skeleton, config, DB, CLI, `/health`, CI | done |
| M0.5 — design system, dashboard shell | done |
| M1 — advisory bundle pipeline, PEP 440 + semver matching, `check` | done |
| M1b — Go, Rust, Java, Ruby, PHP, .NET, Debian/Alpine/Ubuntu matching | next |
| M2 — npm and PyPI gates | |
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

## The advisory bundle

Advisories are compiled centrally and distributed as one signed SQLite file, replicated to every agent. Compiling once and shipping a file beats every machine parsing hundreds of megabytes of upstream JSON.

```sh
pkgwatch publish build-bundle --input npm-all.zip --out advisories.db --key publisher.key
pkgwatch sync --file advisories.db
```

The whole npm ecosystem — 228,957 advisories from a 208 MB OSV archive — compiles in about 13 seconds into a **49 MB** bundle. That is well above the 15–25 MB the design anticipated, and the reason is worth stating: **219,308 of the 227,080 rows are malware records**, not vulnerabilities. The `ossf/malicious-packages` feed has grown by more than an order of magnitude, which is itself the argument for this tool existing.

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

CVSS base scores are computed from the vector strings OSV publishes, falling back to the qualitative rating when no vector is present.

## Build

Requires Go 1.23+. Everything builds with `CGO_ENABLED=0` — that is what keeps cross-compiling all six targets from one machine trivial, and it is why the SQLite driver is `modernc.org/sqlite` rather than `mattn/go-sqlite3`.

```sh
CGO_ENABLED=0 go build -o dist/pkgwatch ./cmd/pkgwatch
go test ./...
```

## Try it

```sh
pkgwatch status          # health, feed freshness, findings, pairing state
pkgwatch agent           # local dashboard on http://127.0.0.1:4875
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
| 4873 | npm gate (M2) |
| 4874 | PyPI gate (M2) |
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
