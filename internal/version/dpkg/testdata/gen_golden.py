"""Generate a golden ordering for pkgwatch's dpkg comparator using Debian's own
apt_pkg.version_compare — the same C implementation dpkg and apt use.

Run inside a debian container with python3-apt installed. Output is committed so
CI needs no Debian."""
import functools
import itertools
import sys

import apt_pkg

apt_pkg.init_system()

epochs = ["", "0:", "1:", "2:"]
upstreams = ["1.0", "1.0.0", "1.09", "1.9", "1.10", "2.0", "1.0~rc1", "1.0~~", "1.0~",
             "1.0a", "1.0A", "1.0+deb1", "1.0.1", "7.4.052", "1.1.1f", "3.0.2",
             "2.4.52", "0.9.8", "1.0-beta", "1.0~beta1", "1.0+really1.0"]
revisions = ["", "-0", "-1", "-2", "-10", "-1ubuntu1", "-1ubuntu4.6", "-1~bpo1",
             "-0ubuntu1.10", "-1+deb12u1"]

corpus = set()
for e, u, r in itertools.product(epochs, upstreams, revisions):
    corpus.add(f"{e}{u}{r}")

# Real versions from an Ubuntu system, where the awkward shapes actually occur.
corpus.update([
    "1:2.4.52-1ubuntu4.6", "2:7.4.052-1ubuntu3.1", "1.1.1f-1ubuntu2.16",
    "3.0.2-0ubuntu1.10", "2.34-0ubuntu3.2", "5.4.0-150.167", "1:8.2.3995-1ubuntu2.15",
    "0.2.5-1", "2.4.6-2ubuntu1.1", "1:1.2.11.dfsg-2ubuntu9.2", "8.2~rc1-1",
    "247.3-3ubuntu3.11", "1:4.8.1-2ubuntu1", "2.31-0ubuntu9.9",
])

valid = sorted(corpus)
ordered = sorted(valid, key=functools.cmp_to_key(apt_pkg.version_compare))

with open(sys.argv[1], "w", encoding="utf-8", newline="\n") as fh:
    fh.write("# Generated with apt_pkg.version_compare (Debian's own implementation).\n")
    fh.write("# Do not edit by hand; regenerate with testdata/gen_golden.sh\n")
    fh.write("SORTED\n")
    for v in ordered:
        fh.write(v + "\n")

    # Explicit equality classes: apt considers these the same version, which is
    # where a naive string comparison goes wrong.
    fh.write("EQUAL\n")
    for a, b in itertools.combinations(valid, 2):
        if apt_pkg.version_compare(a, b) == 0:
            fh.write(f"{a}\t{b}\n")

print(f"{len(valid)} versions")
