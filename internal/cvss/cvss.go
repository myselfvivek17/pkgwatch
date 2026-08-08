// Package cvss computes CVSS v3.x base scores from vector strings.
//
// OSV records carry severity as a vector, not a number, and pkgwatch's scoring
// needs a number. The base-score formula is fully specified and deterministic,
// so this is arithmetic rather than judgement.
//
// Reference: https://www.first.org/cvss/v3.1/specification-document (§8.1)
package cvss

import (
	"fmt"
	"math"
	"strings"
)

// Metric weights from the specification's lookup tables.
var (
	attackVector = map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
	attackCplx   = map[string]float64{"L": 0.77, "H": 0.44}
	userInteract = map[string]float64{"N": 0.85, "R": 0.62}
	impact       = map[string]float64{"H": 0.56, "L": 0.22, "N": 0.0}

	// Privileges Required is the one metric whose weight depends on Scope:
	// changing scope makes holding privileges less of a barrier.
	privRequiredUnchanged = map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	privRequiredChanged   = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}
)

// BaseScore computes the CVSS v3.0/v3.1 base score for a vector string.
// Temporal and environmental metrics, if present, are ignored — they do not
// affect the base score.
func BaseScore(vector string) (float64, error) {
	parts := strings.Split(strings.TrimSpace(vector), "/")
	if len(parts) < 9 {
		return 0, fmt.Errorf("cvss: %q is too short to be a v3 base vector", vector)
	}
	if parts[0] != "CVSS:3.1" && parts[0] != "CVSS:3.0" {
		return 0, fmt.Errorf("cvss: %q is not a CVSS v3 vector", vector)
	}

	metrics := map[string]string{}
	for _, part := range parts[1:] {
		key, value, ok := strings.Cut(part, ":")
		if !ok {
			return 0, fmt.Errorf("cvss: malformed metric %q in %q", part, vector)
		}
		metrics[key] = value
	}

	scope, ok := metrics["S"]
	if !ok || (scope != "U" && scope != "C") {
		return 0, fmt.Errorf("cvss: missing or invalid Scope in %q", vector)
	}
	scopeChanged := scope == "C"

	privRequired := privRequiredUnchanged
	if scopeChanged {
		privRequired = privRequiredChanged
	}

	av, err := lookup(metrics, "AV", attackVector, vector)
	if err != nil {
		return 0, err
	}
	ac, err := lookup(metrics, "AC", attackCplx, vector)
	if err != nil {
		return 0, err
	}
	pr, err := lookup(metrics, "PR", privRequired, vector)
	if err != nil {
		return 0, err
	}
	ui, err := lookup(metrics, "UI", userInteract, vector)
	if err != nil {
		return 0, err
	}
	c, err := lookup(metrics, "C", impact, vector)
	if err != nil {
		return 0, err
	}
	i, err := lookup(metrics, "I", impact, vector)
	if err != nil {
		return 0, err
	}
	a, err := lookup(metrics, "A", impact, vector)
	if err != nil {
		return 0, err
	}

	iscBase := 1 - ((1 - c) * (1 - i) * (1 - a))

	var impactSubscore float64
	if scopeChanged {
		impactSubscore = 7.52*(iscBase-0.029) - 3.25*math.Pow(iscBase-0.02, 15)
	} else {
		impactSubscore = 6.42 * iscBase
	}

	// No impact means no vulnerability, however easy the access.
	if impactSubscore <= 0 {
		return 0, nil
	}

	exploitability := 8.22 * av * ac * pr * ui

	score := impactSubscore + exploitability
	if scopeChanged {
		score *= 1.08
	}
	if score > 10 {
		score = 10
	}

	return roundUp1(score), nil
}

func lookup(metrics map[string]string, key string, table map[string]float64, vector string) (float64, error) {
	raw, ok := metrics[key]
	if !ok {
		return 0, fmt.Errorf("cvss: missing metric %s in %q", key, vector)
	}
	weight, ok := table[raw]
	if !ok {
		return 0, fmt.Errorf("cvss: invalid value %s:%s in %q", key, raw, vector)
	}
	return weight, nil
}

// roundUp1 is the specification's Roundup: the smallest number to one decimal
// place that is greater than or equal to the input. Plain rounding gives the
// wrong answer on scores that land exactly on a boundary, so this works in
// integer space as the spec's reference implementation does.
func roundUp1(f float64) float64 {
	scaled := int(math.Round(f * 100000))
	if scaled%10000 == 0 {
		return float64(scaled) / 100000.0
	}
	return (math.Floor(float64(scaled)/10000) + 1) / 10.0
}

// qualitative maps the severity words OSV and GHSA use onto representative
// scores, for records that carry no vector.
var qualitative = map[string]float64{
	"CRITICAL": 9.8,
	"HIGH":     7.5,
	"MODERATE": 5.0,
	"MEDIUM":   5.0,
	"LOW":      3.1,
}

// FromQualitative converts a severity word to a score. The bool reports whether
// the word was recognised — an unknown rating must not silently become zero.
func FromQualitative(severity string) (float64, bool) {
	score, ok := qualitative[strings.ToUpper(strings.TrimSpace(severity))]
	return score, ok
}
