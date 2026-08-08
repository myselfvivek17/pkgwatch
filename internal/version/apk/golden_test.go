package apk

import (
	"bufio"
	"os"
	"strings"
	"testing"
)

// Differential test against apk-tools itself: every pair in the corpus, with
// the verdict `apk version -t` gave inside Alpine. The table next door records
// the rules; this records what apk actually does. The golden file is generated
// by testdata/gen_golden.sh and committed, so CI needs no Alpine.
func TestComparisonsMatchApk(t *testing.T) {
	fh, err := os.Open("testdata/apk_golden.txt")
	if err != nil {
		t.Fatalf("open golden: %v", err)
	}
	defer fh.Close()

	checked := 0
	scanner := bufio.NewScanner(fh)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") || line == "PAIRS" {
			continue
		}

		fields := strings.Split(line, "\t")
		if len(fields) != 3 {
			t.Fatalf("malformed line: %q", line)
		}
		lhs, rhs, want := fields[0], fields[1], fields[2]

		a, err := Parse(lhs)
		if err != nil {
			t.Errorf("Parse(%q) failed but apk accepted it: %v", lhs, err)
			continue
		}
		b, err := Parse(rhs)
		if err != nil {
			t.Errorf("Parse(%q) failed but apk accepted it: %v", rhs, err)
			continue
		}

		got := symbol(Compare(a, b))
		if got != want {
			t.Errorf("%s %s %s — apk says %s", lhs, got, rhs, want)
		}
		checked++
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("read golden: %v", err)
	}
	if checked == 0 {
		t.Fatal("golden file is empty — regenerate it")
	}
	t.Logf("agrees with apk on %d comparisons", checked)
}

func symbol(c int) string {
	switch {
	case c < 0:
		return "<"
	case c > 0:
		return ">"
	default:
		return "="
	}
}
