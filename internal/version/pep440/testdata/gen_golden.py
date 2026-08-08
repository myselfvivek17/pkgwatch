"""Generate a golden file for pkgwatch's PEP 440 parser from packaging's own
implementation. Run once; the output is committed so CI needs no Python."""
import itertools
import sys
from packaging.version import Version, InvalidVersion

corpus = []

# Systematic cross-product of the interesting grammar pieces.
# Kept deliberately small: the cross-product's value saturates once every
# component and separator spelling appears alongside every other component.
epochs = ["", "1!"]
releases = ["1.0", "1.0.0", "1.10", "01.2"]
pres = ["", "a1", "b2", "rc3", "alpha4", "c6", "preview8", "-alpha.9", "_rc3", "a"]
posts = ["", ".post1", "-2", ".rev3", ".r4", ".post"]
devs = ["", ".dev0", "dev", "-dev-7"]
locals_ = ["", "+abc.5", "+5", "+UBUNTU-1", "+foo_bar.2"]

for e, r, p, po, d, l in itertools.product(epochs, releases, pres, posts, devs, locals_):
    corpus.append(f"{e}{r}{p}{po}{d}{l}")

# Real versions seen in the wild, plus the PEP's own ordering example.
corpus += [
    "1.dev0", "1.0.dev456", "1.0a1", "1.0a2.dev456", "1.0a12.dev456", "1.0a12",
    "1.0b1.dev456", "1.0b2", "1.0b2.post345.dev456", "1.0b2.post345",
    "1.0rc1.dev456", "1.0rc1", "1.0", "1.0+abc.5", "1.0+abc.7", "1.0+5",
    "1.0.post456.dev34", "1.0.post456", "1.1.dev1",
    "2.0.1", "1.11.0", "0.0.1", "23.1", "4.0.0b1", "1.0.0.post20240101",
    "2024.2.2", "0.1.0.dev1", "3.12.0rc2", "1!0.5", "1.0.0+cpu",
    "2.31.0", "1.26.4", "4.66.2", "0.4.6", "1.2.3.4.5.6",
    "v1.0", " 1.0 ", "1.0.0-beta", "1.0.0_alpha_1",
]

# Deduplicate, keep only what packaging accepts.
seen, valid = set(), []
for raw in corpus:
    if raw in seen:
        continue
    seen.add(raw)
    try:
        valid.append((raw, str(Version(raw))))
    except InvalidVersion:
        pass

with open(sys.argv[1], "w", encoding="utf-8", newline="\n") as fh:
    fh.write("# Generated from packaging %s — do not edit by hand.\n"
             % __import__("packaging").__version__)
    fh.write("# Section NORMALIZE: input<TAB>normalized\n")
    fh.write("NORMALIZE\n")
    for raw, norm in valid:
        fh.write(f"{raw}\t{norm}\n")

    # One total ordering of every distinct version, as packaging sorts them.
    fh.write("SORTED\n")
    ordered = sorted({norm for _, norm in valid}, key=Version)
    for norm in ordered:
        fh.write(f"{norm}\n")

print(f"{len(valid)} versions, {len(set(n for _, n in valid))} distinct")
