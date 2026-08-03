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

// ElephantFlowDetector identifies extremely large, long-running flows that consume
// significant bandwidth, known as "elephant flows".
type ElephantFlowDetector struct{}

func (ElephantFlowDetector) Name() string { return "Elephant Flow Detector" }

// Analyze returns advisories about flows exceeding the elephant flow threshold.
func (ElephantFlowDetector) Analyze(store storage.Storage, cfg config.AnalysisConfig) []Advisory {
	flows, err := store.Recent(queryWindow(cfg), 0)
	if err != nil {
		logging.Default().Error("ElephantFlowDetector: failed to query recent flows: %v", err)
		return nil
	}
	if len(flows) == 0 {
		return nil
	}

	threshold := cfg.ElephantBytesThreshold
	if threshold <= 0 {
		threshold = 104857600 // 100 MB default
	}

	type flowKey struct {
		src, dst         string
		srcPort, dstPort uint16
		proto            uint8
	}

	type flowStats struct {
		bytes   uint64
		packets uint64
	}

	flowMap := make(map[flowKey]*flowStats)

	for _, f := range flows {
		// Only consider TCP and UDP
		if f.Protocol != 6 && f.Protocol != 17 {
			continue
		}

		fk := flowKey{
			src: model.SafeIPString(f.SrcAddr), dst: model.SafeIPString(f.DstAddr),
			srcPort: f.SrcPort, dstPort: f.DstPort, proto: f.Protocol,
		}

		if s, ok := flowMap[fk]; ok {
			s.bytes += f.Bytes
			s.packets += f.Packets
		} else {
			flowMap[fk] = &flowStats{
				bytes:   f.Bytes,
				packets: f.Packets,
			}
		}
	}

	type result struct {
		fk    flowKey
		stats *flowStats
	}
	results := make([]result, 0, len(flowMap))
	for k, v := range flowMap {
		if v.bytes >= threshold {
			results = append(results, result{fk: k, stats: v})
		}
	}

	if len(results) == 0 {
		return nil
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].stats.bytes > results[j].stats.bytes
	})

	if len(results) > 10 {
		results = results[:10]
	}

	now := time.Now()
	advisories := make([]Advisory, 0, len(results))

	for _, r := range results {
		protoName := model.ProtocolName(r.fk.proto)

		sev := WARNING
		if r.stats.bytes >= threshold*5 {
			sev = CRITICAL
		}

		desc := fmt.Sprintf(
			"Elephant flow detected: %s connection transferred %s in %d packets.",
			protoName, util.FormatBytes(r.stats.bytes), r.stats.packets,
		)

		advisories = append(advisories, Advisory{
			Severity:    sev,
			Timestamp:   now,
			Title:       fmt.Sprintf("Elephant Flow: %s:%d → %s:%d", r.fk.src, r.fk.srcPort, r.fk.dst, r.fk.dstPort),
			Description: desc,
			Action:      elephantFlowAction(sev),
		})
	}

	return advisories
}

func elephantFlowAction(sev Severity) string {
	switch sev {
	case CRITICAL:
		return "Investigate immediately — massive elephant flow may cause network congestion or indicate data exfiltration."
	default:
		return "Review connection — large flow detected. Verify if expected (e.g., backup, large file transfer)."
	}
}
