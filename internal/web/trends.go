package web

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/myselfvivek17/pkgwatch/internal/repo"
)

// TrendDays is the window the design's charts cover.
const TrendDays = 14

// Trends is the fleet page's chart block.
type Trends struct {
	// Findings is one column per day, oldest first, including the days nothing
	// happened. Empty days are the point: a fortnight with two busy afternoons
	// should look like a fortnight with two busy afternoons.
	Findings []FindingDay
	Legend   []Badge
	Total    int

	// Blocks is the sparkline. The hub counts installs it refused, not installs
	// it evaluated — see BlockedNote.
	Blocks     []int
	BlockTotal int
	BlockLine  string
	BlockArea  string
	FirstDay   string
	LastDay    string

	// Ecosystems is "packages watched", carrying the same covered/not-examined
	// distinction the inventory page makes. A full-length bar for an ecosystem
	// nothing has advisories for would be the same false all-clear.
	Ecosystems []EcosystemBar
}

// FindingDay is one column of the stacked bar chart.
type FindingDay struct {
	Label    string
	Tick     string
	Total    int
	Segments []FindingSegment
}

// FindingSegment is one severity's share of a day's column.
type FindingSegment struct {
	Tier    string
	Count   int
	Percent int
}

// EcosystemBar is one row of the packages-watched list.
type EcosystemBar struct {
	Name    string
	Count   int
	Percent int
	Covered bool
}

// buildTrends turns raw daily counts into the chart's view model.
//
// The day axis is generated here rather than taken from the query, so a day
// with no events is a gap in the chart instead of a day that never existed.
func buildTrends(counts []repo.EventDay, ecosystems map[string]int, covered []string,
	now time.Time) Trends {

	findings := map[string]map[string]int{}
	blocks := map[string]int{}
	for _, c := range counts {
		switch c.Kind {
		case repo.EventFindingNew:
			if findings[c.Day] == nil {
				findings[c.Day] = map[string]int{}
			}
			tier := c.Severity
			if tier == "" {
				tier = "low"
			}
			findings[c.Day][tier] += c.Count
		case repo.EventInstallBlocked:
			blocks[c.Day] += c.Count
		}
	}

	var out Trends
	// Oldest first, left to right, so the newest day is where the eye lands
	// last — the same direction the timeline reads.
	for i := TrendDays - 1; i >= 0; i-- {
		day := now.AddDate(0, 0, -i)
		key := day.Format("2006-01-02")

		column := FindingDay{Label: day.Format("2 Jan"), Tick: day.Format("2")}
		for _, tier := range repo.Tiers {
			if n := findings[key][tier]; n > 0 {
				column.Segments = append(column.Segments,
					FindingSegment{Tier: tier, Count: n})
				column.Total += n
			}
		}
		out.Findings = append(out.Findings, column)
		out.Total += column.Total

		out.Blocks = append(out.Blocks, blocks[key])
		out.BlockTotal += blocks[key]
	}

	// Heights are per-column shares of the busiest day, so one enormous day
	// does not flatten the rest into invisibility.
	tallest := 0
	for _, d := range out.Findings {
		if d.Total > tallest {
			tallest = d.Total
		}
	}
	for i := range out.Findings {
		for j := range out.Findings[i].Segments {
			if tallest > 0 {
				out.Findings[i].Segments[j].Percent =
					out.Findings[i].Segments[j].Count * 100 / tallest
			}
		}
	}

	for _, tier := range repo.Tiers {
		out.Legend = append(out.Legend, Badge{Tier: tier, Size: "sm"})
	}

	out.BlockLine, out.BlockArea = sparkline(out.Blocks)
	if len(out.Findings) > 0 {
		out.FirstDay = out.Findings[0].Label
		out.LastDay = out.Findings[len(out.Findings)-1].Label
	}

	coveredSet := map[string]bool{}
	for _, name := range covered {
		coveredSet[name] = true
	}
	biggest := 0
	for _, n := range ecosystems {
		if n > biggest {
			biggest = n
		}
	}
	for _, name := range sortedKeys(ecosystems) {
		bar := EcosystemBar{Name: name, Count: ecosystems[name], Covered: coveredSet[name]}
		if biggest > 0 {
			bar.Percent = bar.Count * 100 / biggest
		}
		out.Ecosystems = append(out.Ecosystems, bar)
	}
	return out
}

// sparkline builds the two path strings for the blocks chart.
//
// Hand-rolled rather than pulled in: a supply-chain tool that added a charting
// dependency to draw fourteen points would be making its own argument for it.
// The viewBox is fixed at 240×56 and the path is scaled to it, so the SVG
// stretches to whatever width the card gives it.
func sparkline(values []int) (line, area string) {
	if len(values) < 2 {
		return "", ""
	}
	const w, h = 240.0, 56.0

	peak := 0
	for _, v := range values {
		if v > peak {
			peak = v
		}
	}

	step := w / float64(len(values)-1)
	var points []string
	for i, v := range values {
		x := float64(i) * step
		// A flat line at the bottom when nothing happened, rather than a
		// division by zero or a line through the middle suggesting activity.
		y := h - 1
		if peak > 0 {
			y = h - 1 - (float64(v)/float64(peak))*(h-2)
		}
		points = append(points, fmt.Sprintf("%.1f,%.1f", x, y))
	}

	line = "M" + strings.Join(points, " L")
	area = fmt.Sprintf("%s L%.1f,%.1f L0,%.1f Z", line, w, h, h)
	return line, area
}

func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
