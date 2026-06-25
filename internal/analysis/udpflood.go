package analysis

import (
	"fmt"
	"sort"
	"time"

	"github.com/darkace1998/FlowLens/internal/config"
	"github.com/darkace1998/FlowLens/internal/logging"
	"github.com/darkace1998/FlowLens/internal/model"
	"github.com/darkace1998/FlowLens/internal/storage"
	"github.com/darkace1998/FlowLens/internal/util"
)

// UDPFloodDetector identifies destinations receiving a large number of UDP
// packets, which could indicate a UDP flood attack.
type UDPFloodDetector struct{}

func (UDPFloodDetector) Name() string { return "UDP Flood Detector" }

const udpFloodMinPackets = 10000

// Analyze returns advisories about potential UDP flood attacks.
func (UDPFloodDetector) Analyze(store storage.Storage, cfg config.AnalysisConfig) []Advisory {
	flows, err := store.Recent(queryWindow(cfg), 0)
	if err != nil {
		logging.Default().Error("UDPFloodDetector: failed to query recent flows: %v", err)
		return nil
	}
	if len(flows) == 0 {
		return nil
	}

	type targetStats struct {
		bytes   uint64
		packets uint64
		sources map[string]struct{}
	}

	targets := make(map[string]*targetStats)

	for _, f := range flows {
		// Only consider UDP flows
		if f.Protocol != 17 {
			continue
		}

		dstIP := model.SafeIPString(f.DstAddr)
		s, ok := targets[dstIP]
		if !ok {
			s = &targetStats{sources: make(map[string]struct{})}
			targets[dstIP] = s
		}
		s.bytes += f.Bytes
		s.packets += f.Packets
		s.sources[model.SafeIPString(f.SrcAddr)] = struct{}{}
	}

	type result struct {
		dstIP string
		stats *targetStats
	}
	results := make([]result, 0, len(targets))

	for dstIP, s := range targets {
		if s.packets < udpFloodMinPackets {
			continue
		}
		results = append(results, result{
			dstIP: dstIP,
			stats: s,
		})
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].stats.packets > results[j].stats.packets
	})

	if len(results) > 10 {
		results = results[:10]
	}

	now := time.Now()
	advisories := make([]Advisory, 0, len(results))

	for _, r := range results {
		sev := WARNING
		if r.stats.packets >= udpFloodMinPackets*5 {
			sev = CRITICAL
		}

		advisories = append(advisories, Advisory{
			Severity:  sev,
			Timestamp: now,
			Title:     fmt.Sprintf("UDP Flood Attack: %s", r.dstIP),
			Description: fmt.Sprintf(
				"%s received %s UDP packets (%s bytes) from %d unique sources. "+
					"This strongly indicates a UDP flood attack.",
				r.dstIP, util.FormatCount(r.stats.packets), util.FormatBytes(r.stats.bytes), len(r.stats.sources),
			),
			Action: udpFloodAction(sev),
		})
	}

	return advisories
}

func udpFloodAction(sev Severity) string {
	switch sev {
	case CRITICAL:
		return "Investigate immediately — target is actively under a severe UDP flood attack."
	default:
		return "Monitor destination — elevated UDP traffic detected, possibly a UDP flood."
	}
}
