# Per-ecosystem bundles — deferred, with conditions

**Status: not started. Deliberately blocked on M3.**

The idea: an agent downloads advisories only for ecosystems it actually has.
A Windows machine with no Python has no use for 25,860 PyPI records; a laptop
with no containers has no use for 211,926 Debian ones.

This document exists so the decision is made on measurements rather than on how
appealing the idea sounds. **Detection has to be proven to work before any of the
distribution machinery is built.** If detection is wrong, per-ecosystem bundles
do not save space — they create blind spots, which is a strictly worse outcome
than a bundle that is merely too large.

## What it would save

Measured by splitting the real 117 MB bundle and vacuuming, not estimated.

| Profile | Size | Records |
|---|---|---|
| Everything (today) | 117.0 MB | 522,525 |
| Laptop — npm + PyPI | 59.3 MB | 252,888 |
| Server — whole ecosystems (Debian + Alpine + Go) | 57.0 MB | 266,385 |
| **Server — only the releases it runs** (Debian 12, Alpine 3.23/3.24, Go) | **24.6 MB** | 66,570 |
| npm only | 53.0 MB | 227,028 |
| PyPI only | 6.4 MB | 25,860 |

Two things fall out of this that were not obvious before measuring.

**npm is the floor.** 53 MB, and every machine here needs it. Splitting by
ecosystem alone therefore cannot reach the 50 MB target — the target is
unreachable this way. Going below it would mean splitting npm itself, most
plausibly separating its 227,028 malware records (96% of the corpus) from its
vulnerabilities, which is a different and larger design question.

**The split unit is ecosystem *plus release*, not ecosystem.** Debian appears as
13 separate releases in the bundle, because the same CVE carries a different
fixed version in each — `Debian:11` through `Debian:14` are ~24% of Debian's
records apiece. An agent running Debian 12 containers can never match the other
twelve. Splitting at release level takes the server from 57.0 MB to 24.6 MB,
which is a bigger saving than the ecosystem split that precedes it. Alpine is the
same shape: 23 releases, no one runs more than two or three.

## The gate: detection has to be proven first

Per-ecosystem bundles are only worth building if the agent can reliably answer
*"which ecosystems and releases does this machine actually have?"* That answer
comes from the M3 inventory, which does not exist yet.

**Do not build the distribution side before the detection side is measured.**
The order is:

1. **M3 lands the inventory** — npm/PyPI collectors, lockfile collectors, and the
   Docker collector that reads `/var/lib/dpkg/status` and `/lib/apk/db/installed`
   out of running containers.
2. **Measure detection against ground truth** on each real machine, not in
   tests. For every machine in the fleet, compare what detection claims against
   what is actually installed.
3. **Only then decide.** If detection is accurate, build it. If it is not, say so
   and keep the fleet-wide bundle — an oversized bundle is a bandwidth problem,
   a wrong bundle is a security one.

### What "detection works" has to mean

Falsifiable, per machine:

- Every ecosystem present is detected. Zero false negatives is the bar, because a
  false negative is a silent blind spot. A false positive only costs bandwidth.
- Every distro release in every running container is detected, including
  containers that are stopped and started later.
- Detection survives change: installing Python, pulling a Debian 13 image, or
  cloning a Rust project must all be noticed, not just what was there on the day
  the agent was set up.
- The Windows machine, the Linux laptop and the Ubuntu home server each get
  checked separately. They have different shapes and the server is the one with
  containers.

Concretely, the check is: run the collector, then compare against
`docker exec <c> dpkg -l`, `pip list`, `npm ls -g`, and the actual contents of
`/etc/os-release` in each image. Any ecosystem present in reality and absent from
detection is a failure, and it fails the whole idea, not just that case.

## Safety properties any implementation must have

These are not optional and none of them can be traded for size.

**The ecosystem must be bound into the signed message.** Today `SignedMessage`
covers a protocol tag, the version, and the file digest. With per-ecosystem
bundles, a validly signed npm bundle served as `advisories-debian.db` would pass
every check and silently zero Debian coverage — signature intact, agent blind.
The ecosystem (and release, if that is the split unit) has to be inside what the
signature covers.

**Absent detection must never mean silent no-coverage.** This is the same trap
that produced the PyPI gap: a bundle with no PyPI feed returned zero rows for
every Python package, which reads identically to "nothing wrong". The mechanism
that fixes it already exists — bundles declare what they cover, and the gate
reports an uncovered ecosystem as degraded rather than clean. The composition to
aim for:

    detect → subscribe → gate degrades loudly on anything uncovered
           → that degrade event marks the ecosystem for the next sync

That is self-healing and honest in the meantime: if you install Python on a
machine that never had it, the first `pip install` is degraded and says so, and
the next sync fetches the feed.

**"No Python detected" and "Python present, no data" must stay distinguishable**
in `status`, in `check`, and in the timeline. They are opposite situations that
produce the same empty query result.

## Knock-on effects

- **M5's relay contract changes.** The hub currently expects to cache and relay
  one bundle. It would need to hold a set and serve subsets, and an agent's
  subscription becomes part of what it tells the hub — which is inventory
  information, so it interacts with `sync_level = findings` (the default exists
  precisely so the hub does not get a map of exploitable software on every
  machine). Subscribing by ecosystem leaks less than a full inventory, but it is
  not nothing, and that should be a conscious choice rather than a side effect.
- **The publisher pipeline** (M6) builds one artifact today and would build N,
  with N manifests and N signatures.

## Recommendation

Keep the fleet-wide bundle until M3's inventory is real and its detection has
been measured on all three machines. Revisit then, with the numbers above and
whatever the detection audit says.

If detection turns out to be reliable, split at **ecosystem + release**, not
ecosystem — that is where most of the saving is.
