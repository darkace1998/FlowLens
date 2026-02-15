package analysis

import (
	"fmt"
	"sort"
	"time"

	"github.com/darkace1998/FlowLens/internal/config"
	"github.com/darkace1998/FlowLens/internal/storage"
)

// UnreachableDetector identifies destinations receiving many short-lived flows
// with tiny byte counts, which often indicates an unreachable host or service.
type UnreachableDetector struct{}

func (UnreachableDetector) Name() string { return "Unreachable Host Detector" }

// unreachableMinFlows is the minimum number of tiny flows to a single
// destination before flagging it as potentially unreachable.
const unreachableMinFlows = 20

// unreachableMaxBytes is the maximum bytes per flow to be considered "tiny"
// (connection attempts that fail immediately produce very small flows).
const unreachableMaxBytes = 200

// Analyze returns advisories about destinations that appear unreachable.
func (UnreachableDetector) Analyze(store *storage.RingBuffer, cfg config.AnalysisConfig) []Advisory {
	flows, _ := store.Recent(10*time.Minute, 0)
	if len(flows) == 0 {
		return nil
	}

	// Track destinations receiving many tiny flows.
	type dstKey struct {
		ip   string
		port uint16
	}
	type dstStats struct {
		tinyFlows  int
		totalFlows int
		sources    map[string]struct{}
	}

	dsts := make(map[dstKey]*dstStats)

	for _, f := range flows {
		// Only TCP and UDP — ICMP doesn't have ports.
		if f.Protocol != 6 && f.Protocol != 17 {
			continue
		}

		dk := dstKey{ip: f.DstAddr.String(), port: f.DstPort}
		s, ok := dsts[dk]
		if !ok {
			s = &dstStats{sources: make(map[string]struct{})}
			dsts[dk] = s
		}
		s.totalFlows++
		s.sources[f.SrcAddr.String()] = struct{}{}

		if f.Bytes <= unreachableMaxBytes {
			s.tinyFlows++
		}
	}

	type result struct {
		dk         dstKey
		tinyFlows  int
		totalFlows int
		sources    int
		tinyPct    float64
	}
	var results []result

	for dk, s := range dsts {
		if s.tinyFlows < unreachableMinFlows {
			continue
		}
		pct := float64(s.tinyFlows) / float64(s.totalFlows) * 100
		if pct < 70 {
			// If fewer than 70% of flows are tiny, the service is likely responding normally
			// for some connections — not unreachable.
			continue
		}
		results = append(results, result{
			dk: dk, tinyFlows: s.tinyFlows, totalFlows: s.totalFlows,
			sources: len(s.sources), tinyPct: pct,
		})
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].tinyFlows > results[j].tinyFlows
	})

	if len(results) > 10 {
		results = results[:10]
	}

	now := time.Now()
	var advisories []Advisory

	for _, r := range results {
		sev := WARNING
		if r.sources >= 3 && r.tinyPct >= 90 {
			sev = CRITICAL
		}

		advisories = append(advisories, Advisory{
			Severity:  sev,
			Timestamp: now,
			Title:     fmt.Sprintf("Unreachable: %s:%d", r.dk.ip, r.dk.port),
			Description: fmt.Sprintf(
				"%d of %d flows (%.0f%%) to %s:%d are tiny (≤%d bytes) from %d sources. "+
					"Host or service may be down.",
				r.tinyFlows, r.totalFlows, r.tinyPct,
				r.dk.ip, r.dk.port, unreachableMaxBytes, r.sources,
			),
			Action: unreachableAction(sev),
		})
	}

	return advisories
}

func unreachableAction(sev Severity) string {
	switch sev {
	case CRITICAL:
		return "Investigate immediately — multiple sources failing to reach this service strongly suggests it is down."
	default:
		return "Check service availability — many failed connection attempts detected."
	}
}
