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

// ElephantFlowDetector identifies single network connections that consume
// a massive amount of bandwidth. These "elephant flows" can cause network
// congestion and degrade the performance of other, smaller flows (mice flows).
type ElephantFlowDetector struct{}

func (ElephantFlowDetector) Name() string { return "Elephant Flow Detector" }

const (
	// elephantFlowMinBytes is the minimum byte count for a single flow (5-tuple)
	// to be flagged as an elephant flow (1 GB).
	elephantFlowMinBytes = 1000000000
)

// Analyze returns advisories about connections exceeding the elephant flow threshold.
func (ElephantFlowDetector) Analyze(store storage.Storage, cfg config.AnalysisConfig) []Advisory {
	flows, err := store.Recent(queryWindow(cfg), 0)
	if err != nil {
		logging.Default().Error("ElephantFlowDetector: failed to query recent flows: %v", err)
		return nil
	}
	if len(flows) == 0 {
		return nil
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

	aggregated := make(map[flowKey]*flowStats)

	for _, f := range flows {
		fk := flowKey{
			src: model.SafeIPString(f.SrcAddr), dst: model.SafeIPString(f.DstAddr),
			srcPort: f.SrcPort, dstPort: f.DstPort, proto: f.Protocol,
		}

		if s, ok := aggregated[fk]; ok {
			s.bytes += f.Bytes
			s.packets += f.Packets
		} else {
			aggregated[fk] = &flowStats{
				bytes:   f.Bytes,
				packets: f.Packets,
			}
		}
	}

	type result struct {
		fk    flowKey
		stats *flowStats
	}
	results := make([]result, 0)

	for k, v := range aggregated {
		if v.bytes >= elephantFlowMinBytes {
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

		desc := fmt.Sprintf(
			"Elephant flow detected: %s:%d → %s:%d (%s). Transferred %s in %d packets.",
			r.fk.src, r.fk.srcPort, r.fk.dst, r.fk.dstPort, protoName,
			util.FormatBytes(r.stats.bytes), r.stats.packets,
		)

		sev := WARNING
		if r.stats.bytes >= elephantFlowMinBytes*10 {
			sev = CRITICAL
		}

		advisories = append(advisories, Advisory{
			Severity:    sev,
			Timestamp:   now,
			Title:       fmt.Sprintf("Elephant Flow: %s ↔ %s", r.fk.src, r.fk.dst),
			Description: desc,
			Action:      "Investigate large data transfer. May cause network congestion or indicate large downloads, backups, or data exfiltration.",
		})
	}

	return advisories
}
