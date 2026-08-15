# pkgwatch

A supply-chain watchdog for a small fleet of personal machines. One static Go binary, no agent-side services to host, no account to create, and nothing about your machines leaves your network.

It does two things that are usually sold separately:

- **Stops a bad install as it happens.** A local registry proxy sits in front of `npm` and `pip`. Known-malicious and known-vulnerable versions are removed from the version listing before your package manager ever sees them, so the resolver quietly picks something safe. Nothing to approve, nothing to read.
- **Finds the one you already installed.** The package you added six months ago that became known-bad this morning is found by a scan nobody triggered, matched against an advisory database that updates itself.

```
$ pkgwatch check "pkg:npm/%40ctrl/tinycolor@4.1.2"
CRITICAL · MALWARE  MAL-2025-47141  score 20.0
                    Malicious code in @ctrl/tinycolor (npm)
                    remove this package — malicious releases are not fixed by upgrading
```

**No AI, no telemetry, no cloud.** Matching is deterministic version-range comparison against a signed SQLite database you hold. The only network traffic is to the package registries it proxies and, optionally, to your own hub.

---

## Agent and hub

The binary runs in one of two modes. Most people only ever need the first.

**Agent** — runs on a machine you use. It gates `npm` and `pip` installs, inventories what is installed, matches that against the advisory database, and serves a dashboard on `127.0.0.1`. **Fully functional with no network and no hub.** If you have one laptop, this is the whole product.

**Hub** — runs on one machine and aggregates findings from paired agents, so you can answer "which of my machines has this package" from one page. It also relays advisory bundles, so one machine downloads the corpus and the rest copy it across the LAN instead of each fetching hundreds of megabytes.

One machine can run both. **The hub is a convenience and never a dependency:** kill it and every agent keeps gating, scanning and matching exactly as before.

### The three hard rules

1. **The agent never depends on the hub.** Hub down, unreachable, or never configured — installs still get gated and findings still get detected.
2. **Advisory bundles are verified against a publisher key compiled into the binary**, not trusted because the hub sent them. A compromised hub cannot push "everything is safe" and blind the fleet.
3. **Policy flows in the strict direction only.** A hub may tell an agent to be stricter, never looser. Loosening is always a local action.

---

## Install

No published releases yet, so you build it or point the installer at a binary you built. The installers download nothing: a supply-chain tool whose install script piped an unsigned build from the internet would be a poor advertisement for itself.

**Linux / macOS**

```sh
git clone https://github.com/myselfvivek17/pkgwatch && cd pkgwatch
sh contrib/install.sh              # agent + service, verified by /health
sh contrib/install.sh --hub        # a hub as well
sh contrib/install.sh --no-service # binary only
```

**Windows**

```powershell
git clone https://github.com/myselfvivek17/pkgwatch; cd pkgwatch
powershell -ExecutionPolicy Bypass -File contrib\windows\install.ps1
```

Run that one **elevated** if you can: it registers the agent as a windowless scheduled task. Unelevated it falls back to an interactive task, which works but leaves a console window that stops the agent when closed — and it tells you so rather than leaving you to find out.

**Build it yourself**

```sh
CGO_ENABLED=0 go build -o dist/pkgwatch ./cmd/pkgwatch
go test ./...
```

Everything builds with `CGO_ENABLED=0`, which is what makes cross-compiling all six targets from one machine trivial, and why the SQLite driver is `modernc.org/sqlite`.

On Windows, unsigned binaries trip SmartScreen and may be flagged by Defender. On macOS they need `xattr -d com.apple.quarantine`.

---

## Quick start

```sh
pkgwatch sync --dir ./bundles   # install advisory bundles (see below)
pkgwatch scan                   # take the first inventory
pkgwatch findings               # what is wrong, worst first
pkgwatch agent                  # daemon: gates, scheduled scans, dashboard
```

Then open **http://127.0.0.1:4875**.

To gate installs in your shell:

```sh
eval "$(pkgwatch shell-init)"    # npm and pip now go through the gate
```

or gate a single command without any daemon:

```sh
pkgwatch npm ci
pkgwatch pip install -r requirements.txt
```

**Full walkthrough, including pairing and the hub: [docs/USAGE.md](docs/USAGE.md).**

---

## What it does

### Gating an install

The npm gate has two interception points, because one is not enough:

- **The packument** (`GET /{name}`) is the resolution path. Affected versions are removed from the listing and any dist-tag pointing at one is repointed, so npm's own resolver settles on a safe version. This is the invisible happy path — no prompt, no failure.
- **The tarball** (`GET /{name}/-/*.tgz`) is the download path. A lockfile-pinned install never asks for a listing, so filtering alone would miss it entirely. That one is refused outright, with a readable report.

The gate **fails open**. A locked database, a stale bundle or a matcher panic logs `gate_degraded` and lets the install through. A security tool that bricks `npm install` gets uninstalled the same afternoon.

`Authorization` headers are forwarded verbatim and never logged or persisted, with a test asserting no auth value reaches log output.

### The publish buffer

A version published more recently than `cooldown_hours` (default 72) is withheld from resolution, so the resolver takes the previous one.

This is the only defence that needs no knowledge at all, and it covers the window nothing else can: every advisory postdates the attack it describes, so a compromised release is indistinguishable from a good one for its first hours — which is exactly when it is being installed. The buffer never applies when nothing older survives, so a brand new package and a security patch both still install.

### Finding what is already installed

Inventory covers npm (global and every `node_modules`), Python (`site-packages` metadata, parsed directly — never by invoking each interpreter), lockfiles for Go, Rust, Ruby, PHP and .NET, the host's own distribution packages, and **every running Docker container** — read over the Docker socket, with nothing executed inside the container.

Rows are never deleted when a package goes away; a retired row is timeline history. Findings close themselves when a package is removed and reopen if it comes back.

**First run is a baseline.** Pre-existing low-severity findings are recorded acknowledged without notifying, because day one is otherwise hundreds of alerts about six-year-old dev dependencies and notifications get switched off in week one.

### Responding

- **Quarantine** — archive a package, verify the archive reads back, and only then delete the original. `restore` refuses to claim success unless every file, link and executable bit comes back byte-identical. System and container packages are refused, with an explanation of what would have been destroyed.
- **Credential rotation** — after malware, a checklist of the credentials that **actually exist on that machine**, worst blast radius first (cloud → VCS → registry → SSH → app). Progress is stored per finding, so it survives a reboot. A generic checklist reads as a form to fill in; a short true one gets finished.
- **Script guard** — `enable-script-guard` turns npm lifecycle scripts off for every install you run, and `allow-scripts <pkg>` permits one package by name. Install scripts are arbitrary code running as you, before any advisory has had a chance to describe them.

### The dashboard

Server-rendered, **zero JavaScript dependencies** — hand-written CSS and about forty lines of vanilla JS. A supply-chain tool that pulled four hundred npm packages to render a table would be a self-own.

Agent pages: overview, timeline (live via SSE), findings triage, install-block reports, inventory with a retirement audit, credential rotation, quarantine, settings. Hub pages: fleet overview with trend charts, fleet timeline, findings, blocked installs, fleet inventory, package search, device pairing.

Open `/design` on either for the full design system in both themes.

---

## Security model

**What the hub can and cannot do.** It receives findings and events. It cannot make an agent trust a bundle (they are verified against the compiled-in publisher key regardless of who served them), cannot loosen an agent's policy, and cannot read a machine's package inventory unless *both* the agent's config and the hub's own record of that device say so — the hub's record is authoritative, so a compromised agent cannot start volunteering a map of its installed software.

**Pairing** is deliberately not a shared secret: ed25519 keypair per device, an 8-character code with a 10-minute single-use TTL, explicit approval on the hub showing the device fingerprint, and a device token hashed with argon2id. Every request afterwards carries the token *and* an ed25519 signature over `(method|path|body-sha256|timestamp)` with 120-second skew rejection, so a leaked token alone is not enough. TLS is on by default with the certificate fingerprint pinned at pairing — a mismatch halts rather than retrying, because retrying hands credentials to whatever is answering.

**The hub refuses to start** bound to a non-loopback address without a configured password. The dashboard approves installs and deletes files; unauthenticated on a LAN it is a remote code execution primitive, not a convenience.

**Bundle signing.** Advisory bundles are ed25519-signed and the signature covers the scope as well as the version, so a bundle cannot be served as one it was not signed to be. The trusted keys are a list compiled into the binary — rotation means shipping a build that trusts the new key *before* anything is signed with it, and revocation means shipping a build that no longer lists the old one.

---

## Honest limitations

- **npm and pip are gated. Everything else is matched, not gated.** Go, Rust, Maven, RubyGems, Packagist, NuGet, Debian, Ubuntu and Alpine packages are inventoried and matched against advisories, but nothing stands in front of those installs.
- **Java, Ruby, PHP and .NET version comparators are not written yet**, so advisories for those ecosystems will not match even though the packages are inventoried.
- **No dependency chain in the block report.** npm resolves the tree client-side and asks the proxy for each package independently, so the gate sees requests with no parent. Drawing a plausible chain would mean inventing the one part of that report you would most rely on; `npm ls <package>` answers it instead.
- **Auto-quarantine is deliberately unbuilt.** Deleting files off a machine without a person in the loop is not a default this project wants.
- **No published binaries, no code signing, no system tray.**
- **An ecosystem with no advisory bundle reports as NOT EXAMINED, never as clean.** That distinction is enforced throughout: "we found nothing" and "we never looked" are the same query result and opposite answers, and this tool is built to never confuse the two.

---

## Configuration, ports, data

Settings live in `pkgwatch.toml` in the data directory; the dashboard's **Settings** page shows every value, whether it came from the file or a built-in default, and where it takes effect. It is read-only by design — the agent dashboard has no login, and a form there that could edit `bind` would turn "anything running on this box" into "anything on the network".

| Port | Purpose |
|---|---|
| 4873 | npm gate |
| 4874 | PyPI gate |
| 4875 | agent dashboard |
| 4876 | hub |
| 4877 | agent dashboard when a hub already holds 4875 |

The agent detects a port conflict, logs it, and shifts. It does not crash.

| Platform | Data directory |
|---|---|
| Linux | `~/.local/share/pkgwatch/` |
| macOS | `~/Library/Application Support/pkgwatch/` |
| Windows | `%LOCALAPPDATA%\pkgwatch\` |

`agent.db` and `hub.db` hold machine and fleet state. `advisories.db` is a separate, replaceable file attached read-only, so a bundle update is an atomic file swap rather than a migration.

Both modes serve `/health`, and `pkgwatch health` asks that socket rather than the database — a check that reads the database reports a healthy machine while the listener is dead.

---

## Dependency discipline

This tool watches for supply-chain attacks, so its own dependency tree is a target. Direct dependencies are capped at **8**, and `govulncheck` runs in CI.

In use: `modernc.org/sqlite`, `go-chi/chi/v5`, `spf13/cobra`, `BurntSushi/toml`, `Masterminds/semver/v3`, `package-url/packageurl-go`, `golang.org/x/crypto` (argon2id). That is 7; the eighth is reserved for `fyne.io/systray` behind a build tag. Anything else has to be stdlib or hand-written — which is why the PEP 440 parser, the CVSS calculator, the dpkg/apk comparators and the OSV reader are all in-tree.

**On vendoring:** `vendor/` is deliberately not committed. `go mod vendor` weighs 134 MB, 125 MB of it machine-generated `modernc.org/{libc,sqlite}` — one file set per GOOS/GOARCH, the cost of pure-Go SQLite. `go.sum` pins every module by cryptographic hash, which covers tampering; what is forgone is availability if a module is yanked upstream.

---

## Status

Complete and running on a two-machine fleet: gating, inventory, matching, the retroactive watcher, both dashboards, hub pairing and sync, bundle relay, quarantine, credential rotation, the script guard, and packaging.

Not built: the system tray, published release binaries, and the Java/Ruby/PHP/.NET comparators.

## License

[Apache License 2.0](LICENSE). Use it, fork it, ship it — including commercially.

Apache rather than MIT for one substantive reason: it grants patent rights explicitly, and MIT is silent on them. That silence is where adoption of a security tool stalls inside a company. It also matches the licence of the ecosystem this reads from — osv-scanner, Trivy, Syft and Grype are all Apache-2.0.

The licence covers the code and does not grant rights to the name. A fork is welcome; a fork presenting itself as official pkgwatch, or distributing advisory bundles as though they came from this project's publisher key, is a different thing.
