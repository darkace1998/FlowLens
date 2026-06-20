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

// ICMPFloodDetector identifies destinations receiving a large number of ICMP packets,
// which could indicate a ping flood or smurf attack.
type ICMPFloodDetector struct{}

func (ICMPFloodDetector) Name() string { return "ICMP Flood Detector" }

const icmpFloodMinPackets = 10000

// Analyze returns advisories about potential ICMP flood attacks.
func (ICMPFloodDetector) Analyze(store storage.Storage, cfg config.AnalysisConfig) []Advisory {
	flows, err := store.Recent(queryWindow(cfg), 0)
	if err != nil {
		logging.Default().Error("ICMPFloodDetector: failed to query recent flows: %v", err)
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
		// Only consider ICMP and ICMPv6 flows
		if f.Protocol != 1 && f.Protocol != 58 {
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
		if s.packets < icmpFloodMinPackets {
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
		if r.stats.packets >= icmpFloodMinPackets*5 {
			sev = CRITICAL
		}

		advisories = append(advisories, Advisory{
			Severity:  sev,
			Timestamp: now,
			Title:     fmt.Sprintf("ICMP Flood Attack: %s", r.dstIP),
			Description: fmt.Sprintf(
				"%s received %s ICMP packets (%s bytes) from %d unique sources. "+
					"This strongly indicates an ICMP flood (ping flood) attack.",
				r.dstIP, util.FormatCount(r.stats.packets), util.FormatBytes(r.stats.bytes), len(r.stats.sources),
			),
			Action: icmpFloodAction(sev),
		})
	}

	return advisories
}

func icmpFloodAction(sev Severity) string {
	switch sev {
	case CRITICAL:
		return "Investigate immediately — target is actively under a severe ICMP flood attack."
	default:
		return "Monitor destination — elevated ICMP traffic detected, possibly a ping flood."
	}
}
