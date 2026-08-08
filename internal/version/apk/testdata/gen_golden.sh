#!/bin/sh
# Emit apk's own verdict for every pair in the corpus, using `apk version -t`,
# which is apk-tools' comparison entry point.
set -eu

CORPUS="
1.0
1.0.0
1.0.1
1.0.10
1.0.2
1.1
2.0
0.9
1.0a
1.0b
1.0_alpha1
1.0_alpha2
1.0_beta1
1.0_pre1
1.0_rc1
1.0_rc2
1.0_cvs1
1.0_svn1
1.0_git1
1.0_hg1
1.0_p1
1.0_p2
1.0-r0
1.0-r1
1.0-r2
1.0-r10
1.0.1-r0
1.0_rc1-r1
1.0_p1-r1
1.0a-r1
3.1.4-r0
1.2.3_alpha
1.2.3_beta_p1
2.4.52-r0
1.1.1f-r0
3.0.2-r1
1.0_alpha
1.0_p
0.9.8
1.0.0.0
"

OUT="$1"
: > "$OUT"
echo "# Generated with 'apk version -t' inside alpine. Do not edit by hand." >> "$OUT"
echo "# regenerate with testdata/gen_golden.sh" >> "$OUT"
echo "PAIRS" >> "$OUT"

for a in $CORPUS; do
  for b in $CORPUS; do
    op=$(apk version -t "$a" "$b")
    printf '%s\t%s\t%s\n' "$a" "$b" "$op" >> "$OUT"
  done
done

echo "wrote $(wc -l < "$OUT") lines"
