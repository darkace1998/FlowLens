package analysis

import (
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/darkace1998/FlowLens/internal/config"
	"github.com/darkace1998/FlowLens/internal/storage"
)

// FlowAsymmetry analyzes flow data to detect asymmetric routing patterns.
// For each communicating pair (A↔B), it compares the byte volume in each
// direction and flags pairs with a large disparity.
type FlowAsymmetry struct{}

func (FlowAsymmetry) Name() string { return "Flow Asymmetry" }

// asymmetryThreshold is the minimum ratio between the larger and smaller
// direction to trigger an advisory. A ratio of 10 means one direction
// carries 10x more traffic than the other.
const asymmetryThreshold = 10.0

// asymmetryMinBytes is the minimum byte count in the larger direction
// for a pair to be considered. Filters out noise from tiny flows.
const asymmetryMinBytes = 100000 // 100 KB

// pairKey canonicalizes a pair of IPs so A→B and B→A map to the same key.
type pairKey struct {
	low  string // lexicographically smaller IP
	high string
}

type pairStats struct {
	LowToHighBytes  uint64 // bytes from low IP → high IP
	HighToLowBytes  uint64 // bytes from high IP → low IP
	LowToHighPkts   uint64
	HighToLowPkts   uint64
	LowToHighFlows  int
	HighToLowFlows  int
}

func makePairKey(a, b string) pairKey {
	if a < b {
		return pairKey{low: a, high: b}
	}
	return pairKey{low: b, high: a}
}

// Analyze returns advisories about asymmetric traffic patterns.
func (FlowAsymmetry) Analyze(store *storage.RingBuffer, cfg config.AnalysisConfig) []Advisory {
	flows, _ := store.Recent(10*time.Minute, 0)
	if len(flows) == 0 {
		return nil
	}

	pairs := make(map[pairKey]*pairStats)

	for _, f := range flows {
		src := f.SrcAddr.String()
		dst := f.DstAddr.String()
		pk := makePairKey(src, dst)

		stats, ok := pairs[pk]
		if !ok {
			stats = &pairStats{}
			pairs[pk] = stats
		}

		if src == pk.low {
			stats.LowToHighBytes += f.Bytes
			stats.LowToHighPkts += f.Packets
			stats.LowToHighFlows++
		} else {
			stats.HighToLowBytes += f.Bytes
			stats.HighToLowPkts += f.Packets
			stats.HighToLowFlows++
		}
	}

	now := time.Now()
	var advisories []Advisory

	// Collect asymmetric pairs for sorting.
	type asymResult struct {
		pk       pairKey
		ratio    float64
		larger   uint64
		smaller  uint64
		largeDir string
		smallDir string
	}
	var results []asymResult

	for pk, stats := range pairs {
		larger := stats.LowToHighBytes
		smaller := stats.HighToLowBytes
		largeDir := fmt.Sprintf("%s → %s", pk.low, pk.high)
		smallDir := fmt.Sprintf("%s → %s", pk.high, pk.low)

		if stats.HighToLowBytes > stats.LowToHighBytes {
			larger = stats.HighToLowBytes
			smaller = stats.LowToHighBytes
			largeDir = fmt.Sprintf("%s → %s", pk.high, pk.low)
			smallDir = fmt.Sprintf("%s → %s", pk.low, pk.high)
		}

		if larger < asymmetryMinBytes {
			continue
		}

		var ratio float64
		if smaller == 0 {
			ratio = math.Inf(1)
		} else {
			ratio = float64(larger) / float64(smaller)
		}

		if ratio >= asymmetryThreshold {
			results = append(results, asymResult{
				pk:       pk,
				ratio:    ratio,
				larger:   larger,
				smaller:  smaller,
				largeDir: largeDir,
				smallDir: smallDir,
			})
		}
	}

	// Sort by ratio descending.
	sort.Slice(results, func(i, j int) bool {
		return results[i].ratio > results[j].ratio
	})

	// Limit to top 10 most asymmetric pairs.
	if len(results) > 10 {
		results = results[:10]
	}

	for _, r := range results {
		sev := WARNING
		if r.ratio >= 100 || math.IsInf(r.ratio, 1) {
			sev = CRITICAL
		}

		ratioStr := fmt.Sprintf("%.0f:1", r.ratio)
		if math.IsInf(r.ratio, 1) {
			ratioStr = "∞:1 (unidirectional)"
		}

		advisories = append(advisories, Advisory{
			Severity:  sev,
			Timestamp: now,
			Title:     fmt.Sprintf("Asymmetric Flow: %s ↔ %s", r.pk.low, r.pk.high),
			Description: fmt.Sprintf(
				"Traffic ratio %s. %s: %s, %s: %s. "+
					"May indicate asymmetric routing, data exfiltration, or backup traffic.",
				ratioStr,
				r.largeDir, formatBytesShort(r.larger),
				r.smallDir, formatBytesShort(r.smaller),
			),
			Action: asymmetryAction(sev),
		})
	}

	return advisories
}

func asymmetryAction(sev Severity) string {
	switch sev {
	case CRITICAL:
		return "Investigate immediately — extreme traffic asymmetry may indicate data exfiltration or routing issue."
	default:
		return "Review traffic pattern — significant asymmetry detected. Verify if expected (e.g., backup, streaming)."
	}
}
