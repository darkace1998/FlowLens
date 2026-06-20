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

// SYNFloodDetector identifies destinations receiving a large number of TCP SYN
// packets, which could indicate a SYN flood attack.
type SYNFloodDetector struct{}

func (SYNFloodDetector) Name() string { return "SYN Flood Detector" }

const synFloodMinPackets = 10000

// Analyze returns advisories about potential SYN flood attacks.
func (SYNFloodDetector) Analyze(store storage.Storage, cfg config.AnalysisConfig) []Advisory {
	flows, err := store.Recent(queryWindow(cfg), 0)
	if err != nil {
		logging.Default().Error("SYNFloodDetector: failed to query recent flows: %v", err)
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
		// Only consider TCP flows
		if f.Protocol != 6 {
			continue
		}

		// Check for TCP SYN flag (0x02) without ACK (0x10) or other flags that would imply established state
		// A pure SYN packet is 0x02. NetFlow might aggregate flags over the flow, but in a SYN flood
		// we often see flows that only have SYN, or many small flows with only SYN.
		if f.TCPFlags&0x02 != 0 && f.TCPFlags&0x10 == 0 {
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
	}

	type result struct {
		dstIP string
		stats *targetStats
	}
	results := make([]result, 0, len(targets))

	for dstIP, s := range targets {
		if s.packets < synFloodMinPackets {
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
		if r.stats.packets >= synFloodMinPackets*5 {
			sev = CRITICAL
		}

		advisories = append(advisories, Advisory{
			Severity:  sev,
			Timestamp: now,
			Title:     fmt.Sprintf("SYN Flood Attack: %s", r.dstIP),
			Description: fmt.Sprintf(
				"%s received %s TCP SYN packets (%s bytes) from %d unique sources. "+
					"This strongly indicates a TCP SYN flood attack.",
				r.dstIP, util.FormatCount(r.stats.packets), util.FormatBytes(r.stats.bytes), len(r.stats.sources),
			),
			Action: synFloodAction(sev),
		})
	}

	return advisories
}

func synFloodAction(sev Severity) string {
	switch sev {
	case CRITICAL:
		return "Investigate immediately — target is actively under a severe TCP SYN flood attack."
	default:
		return "Monitor destination — elevated TCP SYN traffic detected, possibly a SYN flood."
	}
}
