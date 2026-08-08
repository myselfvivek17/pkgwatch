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

**M0 + M0.5 complete.** Skeleton and design system. Nothing is being watched yet.

| Milestone | State |
|---|---|
| M0 — skeleton, config, DB, CLI, `/health`, CI | done |
| M0.5 — design system, dashboard shell | done |
| M1 — advisory bundle pipeline, PEP 440 + semver matching | next |
| M1b — Go, Rust, Java, Ruby, PHP, .NET, Debian/Alpine/Ubuntu matching | |
| M2 — npm and PyPI gates | |
| M3 — inventory, Docker collector, retroactive watcher | |
| M4 — agent dashboard pages | |
| M5 — hub, pairing, sync | |
| M6 — quarantine, credential rotation, packaging | |

Commands whose milestone has not landed exist and say so rather than being absent:

```
$ pkgwatch check pkg:npm/lodash@4.17.20
Error: not implemented yet — lands in M1
```

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

Currently in use: `modernc.org/sqlite`, `go-chi/chi/v5`, `spf13/cobra`, `BurntSushi/toml`. Reserved for later milestones: `Masterminds/semver/v3` (M1), `packageurl-go` (M1), `golang.org/x/crypto` for argon2id (M5), and `fyne.io/systray` behind the `tray` build tag (M6). That accounts for all 8 — anything else has to be stdlib or hand-written.

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
