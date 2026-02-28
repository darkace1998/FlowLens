package analysis

import (
	"fmt"
	"sort"
	"time"

	"github.com/darkace1998/FlowLens/internal/config"
	"github.com/darkace1998/FlowLens/internal/logging"
	"github.com/darkace1998/FlowLens/internal/model"
	"github.com/darkace1998/FlowLens/internal/storage"
)

// PortConcentrationDetector identifies destination ports being hit by many
// distinct sources, which may indicate service overload, brute-force attempts,
// or a popular service under stress.
type PortConcentrationDetector struct{}

func (PortConcentrationDetector) Name() string { return "Port Concentration Detector" }

// portConcentrationMinSources is the minimum number of unique sources
// hitting a single destination port to generate an advisory.
const portConcentrationMinSources = 20

// Analyze returns advisories about ports receiving connections from many sources.
func (PortConcentrationDetector) Analyze(store *storage.RingBuffer, cfg config.AnalysisConfig) []Advisory {
	flows, err := store.Recent(queryWindow(cfg), 0)
	if err != nil {
		logging.Default().Error("PortConcentrationDetector: failed to query recent flows: %v", err)
		return nil
	}
	if len(flows) == 0 {
		return nil
	}

	// Track unique sources per (dstIP, dstPort).
	type portKey struct {
		dstIP   string
		dstPort uint16
	}
	type portStats struct {
		sources map[string]struct{}
		bytes   uint64
		packets uint64
	}

	ports := make(map[portKey]*portStats)

	for _, f := range flows {
		if f.Protocol != 6 && f.Protocol != 17 {
			continue
		}

		pk := portKey{dstIP: model.SafeIPString(f.DstAddr), dstPort: f.DstPort}
		s, ok := ports[pk]
		if !ok {
			s = &portStats{sources: make(map[string]struct{})}
			ports[pk] = s
		}
		s.sources[model.SafeIPString(f.SrcAddr)] = struct{}{}
		s.bytes += f.Bytes
		s.packets += f.Packets
	}

	type result struct {
		pk      portKey
		sources int
		bytes   uint64
		packets uint64
	}
	var results []result

	for pk, s := range ports {
		srcCount := len(s.sources)
		if srcCount < portConcentrationMinSources {
			continue
		}
		results = append(results, result{pk: pk, sources: srcCount, bytes: s.bytes, packets: s.packets})
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].sources > results[j].sources
	})

	if len(results) > 10 {
		results = results[:10]
	}

	now := time.Now()
	var advisories []Advisory

	for _, r := range results {
		sev := WARNING
		if r.sources >= portConcentrationMinSources*3 {
			sev = CRITICAL
		}

		advisories = append(advisories, Advisory{
			Severity:  sev,
			Timestamp: now,
			Title:     fmt.Sprintf("Port Concentration: %s:%d", r.pk.dstIP, r.pk.dstPort),
			Description: fmt.Sprintf(
				"%d unique sources connecting to %s:%d (%s bytes, %s packets). "+
					"May indicate service overload, brute-force, or DDoS.",
				r.sources, r.pk.dstIP, r.pk.dstPort,
				formatBytesShort(r.bytes), formatCountShort(r.packets),
			),
			Action: portConcentrationAction(sev),
		})
	}

	return advisories
}

func portConcentrationAction(sev Severity) string {
	switch sev {
	case CRITICAL:
		return "Investigate immediately — very high source concentration may indicate DDoS or brute-force attack."
	default:
		return "Monitor service health — elevated source count hitting this port."
	}
}
