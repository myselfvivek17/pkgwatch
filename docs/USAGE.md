# Using pkgwatch

A walkthrough from one machine to a fleet. Read the first section and stop if
you only have one computer — everything after it is optional.

- [One machine](#one-machine)
- [Advisory bundles](#advisory-bundles)
- [Gating installs](#gating-installs)
- [Running unattended](#running-unattended)
- [Adding a hub](#adding-a-hub)
- [Pairing a machine](#pairing-a-machine)
- [Responding to a finding](#responding-to-a-finding)
- [The script guard](#the-script-guard)
- [Troubleshooting](#troubleshooting)

---

## One machine

Install with `contrib/install.sh` (Linux/macOS) or
`contrib\windows\install.ps1` (Windows), then:

```sh
pkgwatch status
```

That prints health, how old the advisory database is, coverage, findings and
pairing state. On a fresh machine it will tell you there is no bundle, which
brings us to the thing that has to happen first.

### Take an inventory

```sh
pkgwatch scan
pkgwatch inventory
```

`scan` walks global installs, the host's own distribution packages, every
running container, and any project trees listed in `scan_paths`. That last one
is empty by default — there is no safe guess at where your projects live, and
walking a home directory to find out is slow enough that nobody would leave it
switched on. Set it once:

```toml
[agent]
scan_paths = ["/home/you/code", "/home/you/work"]
```

The first match against a bundle is a **baseline**: pre-existing low-severity
findings are recorded as acknowledged without notifying. Day one is otherwise
hundreds of alerts about six-year-old dev dependencies, and notifications that
noisy get switched off in week one.

---

## Advisory bundles

pkgwatch matches against a local SQLite database of advisories, not a web
service. Nothing about your machines is sent anywhere to do it.

A bundle is signed with an ed25519 key whose public half is compiled into the
binary. **The signature covers the scope as well as the version**, so a bundle
cannot be served as one it was not signed to be, and it is verified the same way
no matter where the bytes came from — a hub relaying it cannot make it trusted.

```sh
pkgwatch sync --file advisories-npm.db     # one bundle
pkgwatch sync --dir ./bundles              # every bundle in a directory
pkgwatch sync                              # pull from the paired hub
```

A machine takes only the scopes it needs: a Windows laptop with no Ubuntu
packages does not download the 132 MB Ubuntu bundle, and says so rather than
silently skipping it.

### Building bundles

If you are publishing your own:

```sh
pkgwatch publish keygen --out ~/.pkgwatch-keys/publisher.key
```

Add the printed **public** half to `publisherKeysBase64` in
`internal/bundle/keys.go`, ship a build carrying it, and **only then** sign with
it. Agents must be able to verify a key before anything is signed with it;
reverse that order and every agent rejects every bundle at once.

```sh
pkgwatch publish build-bundle --input ./osv-all.zip --out ./bundles --split \
    --key ~/.pkgwatch-keys/publisher.key
```

`--split` emits one signed bundle per ecosystem and release. To re-sign bundles
you already have — during a key rotation, say — use `publish sign --file`, which
reads the version and scope out of the bundle itself and rewrites only the
manifest and signature.

### Coverage is not the same as clean

An ecosystem you have packages for but no bundle for is reported **NOT
EXAMINED**, never as clean. "We found nothing" and "we never looked" are the
same query result and opposite answers, and every page in this tool is built to
keep them apart.

---

## Gating installs

The gate is a local registry proxy. It needs no daemon for a single command:

```sh
pkgwatch npm ci
pkgwatch npm install left-pad
pkgwatch pip install -r requirements.txt
```

To gate everything in your shell:

```sh
eval "$(pkgwatch shell-init)"      # bash/zsh
pkgwatch shell-init | Out-String | Invoke-Expression   # PowerShell
```

Most of the time you will see nothing. Affected versions are removed from the
version listing before npm sees them, so its own resolver picks something safe —
no prompt, no failure. You only get a report when a **lockfile-pinned** install
asks for a specific bad tarball, because there was no listing to filter.

Two settings decide how strict it is:

```toml
[agent]
block_tier = "high"      # lowest tier that stops an install; malware always blocks
cooldown_hours = 72      # withhold versions published more recently than this
```

`cooldown_hours` is the publish buffer, and it is the only defence here that
needs no knowledge at all: every advisory postdates the attack it describes, so
a compromised release looks fine for its first hours — exactly when it is being
installed. It never applies when nothing older survives, so a brand new package
still installs.

The gate **fails open**. A locked database or a stale bundle logs
`gate_degraded` and lets the install through.

---

## Running unattended

The gate protects an install as it happens. The other half — the package you
installed six months ago that became known-bad this morning — only works if
something runs without being asked.

```sh
pkgwatch agent
```

or install it as a service (the installers do this for you). The daemon
re-scans and re-matches every `scan_interval_hours` (default 6), and pulls fresh
bundles from its hub every `bundle_interval_hours` (default 6). Both matter: a
current inventory matched against a corpus that stopped ageing three weeks ago
produces the same clean report as a machine with nothing wrong.

Check it is actually serving:

```sh
pkgwatch health
```

That asks the socket. `pkgwatch status` reads the database and would report a
healthy machine while the listener was dead.

---

## Adding a hub

Only worth it with more than one machine. The hub aggregates findings, answers
"which of my machines has this package", and relays bundles so one machine
downloads the corpus for everyone.

**It is never required.** Kill it and every agent keeps gating and scanning.

On the machine that will host it:

```sh
pkgwatch hub set-password        # prints a password_hash line
```

Put that line in `pkgwatch.toml`:

```toml
[hub]
bind = "192.0.2.10"      # this host's LAN address, not 0.0.0.0
port = 4876
password_hash = "$argon2id$v=19$..."
```

Then start it (`pkgwatch hub`, or the systemd unit in `contrib/systemd/`).

**The hub refuses to start** on a non-loopback address without a password. That
is deliberate: the dashboard approves package installs and deletes files, so
unauthenticated on a LAN it is a remote code execution primitive.

Bind to one address rather than `0.0.0.0`. On a machine running Docker,
`0.0.0.0` also means every container bridge and any VPN interface — a wider
audience than "my network" and not one anybody pictures. If a firewall is
running, scope the rule to the LAN:

```sh
sudo ufw allow from 192.0.2.0/24 to any port 4876 proto tcp
```

A dropped port times out rather than refusing, which is the tell if pairing
hangs.

---

## Pairing a machine

Pairing is deliberately not a shared secret. Each device has its own ed25519
keypair, and the hub stores a token hashed with argon2id.

**1. On the hub**, generate a single-use code and print the certificate
fingerprint:

```sh
pkgwatch hub pair-code       # 8 characters, single use, 10-minute TTL
pkgwatch hub fingerprint     # e.g. FB93-57EB-...-9B70
```

**2. On the agent**, pair — passing the fingerprint you just read:

```sh
pkgwatch agent pair --hub https://192.0.2.10:4876 --code ABCD1234 \
    --fingerprint FB93-57EB-...-9B70
```

The fingerprint is checked during the handshake, so a mismatch fails *before*
the pairing code is spent. Without `--fingerprint`, whatever certificate is
presented now is trusted and printed for you to compare — first-use trust,
which is weaker.

The agent prints a **device ID** derived from its own key.

**3. Back on the hub**, approve it — after comparing that ID:

```sh
pkgwatch hub devices list
pkgwatch hub devices approve G3WC-QNL4-...-Q4
```

That comparison is the anti-MITM step. Approving without looking is what the
whole ceremony exists to prevent.

### Choosing what the machine sends

```toml
[agent]
sync_level = "findings"   # findings | full | off
```

`findings` is the default and sends findings and timeline events. `full` also
sends the package inventory, which is what makes cross-machine package search
work — and it needs **both** switches: the agent's config *and* the hub's own
record of that device (the "accept inventory" button on the pairing page). The
hub's record is authoritative, so a compromised agent cannot start volunteering
a map of its installed software.

`off` sends nothing. Sync is outbound-only: the hub has no channel to write
anything back down.

### Revoking

```sh
pkgwatch hub devices revoke G3WC-QNL4-...-Q4
```

The agent stops syncing and **keeps gating locally**.

---

## Responding to a finding

```sh
pkgwatch findings                       # worst first
pkgwatch check pkg:npm/lodash@4.17.20   # one package, in detail
pkgwatch ack <purl> <advisory>          # seen it, not acting yet
pkgwatch ignore <purl> <advisory> --days 30
```

An ignore expires on its own. "Hide this for a week" silently meaning "never
mention it again" is how a deferred decision becomes a forgotten one.

### Quarantine

```sh
pkgwatch quarantine pkg:npm/evil@1.0.0 --yes
pkgwatch restore <id>
```

The archive is written and read back and the digest compared *before* the
original is deleted, and `restore` refuses to claim success unless every file,
link and executable bit comes back identical. Findings stay open while a package
is quarantined — it is one command from being back, and a count that dropped
would show the machine clean while the malware sits in the archive.

System and container packages are refused: a system package's recorded path is
the package manager's own database, and a container package does not live on
this filesystem at all.

### Credential rotation

After malware — code that *ran as you* — the question is what it could read.

```sh
pkgwatch rotate                     # findings that warrant a rotation
pkgwatch rotate <purl>              # the checklist for one
pkgwatch rotate --credentials       # what exists here, with nothing wrong
```

Only credentials that actually exist on the machine are listed, worst blast
radius first: cloud, then version control, then registries, then SSH, then
application secrets. Progress is stored per finding and survives a reboot.

The same checklist is on the dashboard at `/rotate`, with tick boxes.

---

## The script guard

npm lifecycle scripts are arbitrary code running as you at install time, before
any advisory has had a chance to describe them — the mechanism most npm
supply-chain attacks actually use. npm runs them by default.

```sh
pkgwatch enable-script-guard        # ignore-scripts=true for every npm you run
pkgwatch allow-scripts esbuild      # permit one package, and build it now
pkgwatch allow-scripts list         # the guard, and everything allowed
pkgwatch allow-scripts esbuild --revoke
pkgwatch enable-script-guard --off
```

This edits your **user npm config**, not just pkgwatch's behaviour, because a
guard that only applied when you remembered to type `pkgwatch npm` would not be
a guard.

npm has no per-package allowlist of its own, so an allowance is the guard
staying on everywhere plus `npm rebuild <pkg> --ignore-scripts=false` for that
one package. Nothing is allowed automatically: allowing everything that already
runs code would grant the permission to exactly the set this shrinks.

Native modules (`esbuild`, `sharp`, `node-gyp`, `keytar`…) will need an
allowance or they come up unbuilt after a clean reinstall. `enable-script-guard`
lists which ones you have.

---

## Troubleshooting

**`pkgwatch health` says nothing is answering.** The daemon is not running, or
is bound somewhere else. On Windows check the scheduled task is actually
running rather than merely "Ready" — a task whose action exits 0 reads as
healthy while nothing is listening.

**A console window appears at logon on Windows, and closing it stops the
agent.** The task was registered interactive. Re-run
`contrib\windows\install-task.ps1` from an **elevated** PowerShell to register
it windowless.

**Pairing hangs.** A dropped firewall port times out; a closed one refuses.
Timeouts usually mean a firewall rule, not a wrong address.

**Pairing refuses with a certificate mismatch.** It halts rather than retrying,
because retrying hands credentials to whatever is answering. Check
`pkgwatch hub fingerprint` on the hub against what you passed.

**An ecosystem shows NOT EXAMINED.** There is no bundle for it. Those packages
are counted and absent from every finding, which is not the same as clean.

**`pkgwatch sync` says the running agent will pick it up.** On Windows nothing
outside the daemon can replace `advisories.db` while it is open, so the CLI
stages the bundle and the daemon merges it on its next pass.

**Package search returns nothing on the hub.** It needs `sync_level = "full"` on
the agent *and* "accept inventory" for that device on the pairing page. The page
says which machines are contributing and which are not.
