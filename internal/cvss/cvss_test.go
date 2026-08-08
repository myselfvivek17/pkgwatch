package cvss

import "testing"

// Vectors and their published base scores. Most are the worked examples from
// the CVSS v3.1 specification and its calculator; the rest are real advisories.
func TestBaseScore(t *testing.T) {
	tests := []struct {
		vector string
		want   float64
	}{
		// The classic "worst case": remote, no privileges, no interaction.
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
		// Reflected XSS shape: user interaction, scope change, partial impact.
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1},
		// Local, low privileges, confidentiality only.
		{"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.5},
		// High attack complexity pulls the score down.
		{"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9},
		// Availability-only denial of service.
		{"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H", 6.5},
		// No impact at all scores zero regardless of how easy it is.
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0},
		// Hardest possible access, no impact.
		{"CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", 0.0},
		// Scope change raises privilege weights.
		{"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9},
		// Physical access, full impact.
		{"CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 6.8},
		// Adjacent network.
		{"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.8},
		// v3.0 vectors appear in older records and use the same base formula.
		{"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
		// Prototype pollution, the shape a lot of npm advisories take.
		{"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N", 5.9},
	}

	for _, tt := range tests {
		t.Run(tt.vector, func(t *testing.T) {
			got, err := BaseScore(tt.vector)
			if err != nil {
				t.Fatalf("BaseScore(%q): %v", tt.vector, err)
			}
			if got != tt.want {
				t.Errorf("BaseScore(%q) = %v, want %v", tt.vector, got, tt.want)
			}
		})
	}
}

// Temporal and environmental metrics may trail the base ones. They do not
// change the base score, and their presence must not make the vector unreadable.
func TestBaseScoreIgnoresTrailingMetrics(t *testing.T) {
	got, err := BaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:C")
	if err != nil {
		t.Fatalf("BaseScore: %v", err)
	}
	if got != 9.8 {
		t.Errorf("BaseScore = %v, want 9.8", got)
	}
}

func TestBaseScoreRejectsMalformed(t *testing.T) {
	for _, vector := range []string{
		"",
		"not a vector",
		"CVSS:3.1/AV:N",                       // missing metrics
		"CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P", // v2 uses a different formula
		"CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // bad metric value
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",     // A missing
	} {
		if score, err := BaseScore(vector); err == nil {
			t.Errorf("BaseScore(%q) = %v, want an error", vector, score)
		}
	}
}

// OSV records that carry no vector still carry a qualitative rating. Mapping it
// keeps those advisories scoreable instead of defaulting them all to 5.0.
func TestFromQualitative(t *testing.T) {
	tests := []struct {
		in    string
		want  float64
		found bool
	}{
		{"CRITICAL", 9.8, true},
		{"critical", 9.8, true},
		{"HIGH", 7.5, true},
		{"MODERATE", 5.0, true},
		{"MEDIUM", 5.0, true},
		{"LOW", 3.1, true},
		{"", 0, false},
		{"UNKNOWN", 0, false},
	}

	for _, tt := range tests {
		got, ok := FromQualitative(tt.in)
		if ok != tt.found {
			t.Errorf("FromQualitative(%q) ok = %v, want %v", tt.in, ok, tt.found)
			continue
		}
		if ok && got != tt.want {
			t.Errorf("FromQualitative(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}
