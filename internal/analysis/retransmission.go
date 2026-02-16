package analysis

import (
	"fmt"
	"sort"
	"time"

	"github.com/darkace1998/FlowLens/internal/config"
	"github.com/darkace1998/FlowLens/internal/logging"
	"github.com/darkace1998/FlowLens/internal/storage"
)

// RetransmissionDetector identifies TCP flows with a high packet-to-byte ratio,
// which often indicates retransmissions, congestion, or MTU issues.
type RetransmissionDetector struct{}

func (RetransmissionDetector) Name() string { return "Retransmission Detector" }

// smallPacketThreshold is the average bytes-per-packet below which a TCP flow
// is considered to have abnormally small packets (likely retransmissions).
const smallPacketThreshold = 100

// retransmissionMinPackets is the minimum packet count for a flow to be
// considered — filters out noise from tiny flows.
const retransmissionMinPackets = 50

// Analyze returns advisories about flows with abnormally high packet-to-byte ratios.
func (RetransmissionDetector) Analyze(store *storage.RingBuffer, cfg config.AnalysisConfig) []Advisory {
	flows, err := store.Recent(10*time.Minute, 0)
	if err != nil {
		logging.Default().Error("RetransmissionDetector: failed to query recent flows: %v", err)
		return nil
	}
	if len(flows) == 0 {
		return nil
	}

	// Aggregate by source→destination pair for TCP only.
	type pairKey struct {
		src, dst     string
		srcPort, dstPort uint16
	}
	type pairStats struct {
		bytes   uint64
		packets uint64
	}

	pairs := make(map[pairKey]*pairStats)

	for _, f := range flows {
		if f.Protocol != 6 { // TCP only
			continue
		}
		pk := pairKey{
			src: f.SrcAddr.String(), dst: f.DstAddr.String(),
			srcPort: f.SrcPort, dstPort: f.DstPort,
		}
		if s, ok := pairs[pk]; ok {
			s.bytes += f.Bytes
			s.packets += f.Packets
		} else {
			pairs[pk] = &pairStats{bytes: f.Bytes, packets: f.Packets}
		}
	}

	type result struct {
		pk       pairKey
		avgBytes float64
		packets  uint64
	}
	var results []result

	for pk, s := range pairs {
		if s.packets < retransmissionMinPackets {
			continue
		}
		avg := float64(s.bytes) / float64(s.packets)
		if avg < smallPacketThreshold {
			results = append(results, result{pk: pk, avgBytes: avg, packets: s.packets})
		}
	}

	// Sort by avg bytes ascending (worst first).
	sort.Slice(results, func(i, j int) bool {
		return results[i].avgBytes < results[j].avgBytes
	})

	if len(results) > 10 {
		results = results[:10]
	}

	now := time.Now()
	var advisories []Advisory

	for _, r := range results {
		sev := WARNING
		if r.avgBytes < 50 {
			sev = CRITICAL
		}

		advisories = append(advisories, Advisory{
			Severity:  sev,
			Timestamp: now,
			Title: fmt.Sprintf("Small Packets: %s:%d → %s:%d",
				r.pk.src, r.pk.srcPort, r.pk.dst, r.pk.dstPort),
			Description: fmt.Sprintf(
				"TCP flow averaging %.0f bytes/packet (%d packets total). "+
					"Likely retransmissions, congestion, or MTU issues.",
				r.avgBytes, r.packets,
			),
			Action: retransmissionAction(sev),
		})
	}

	return advisories
}

func retransmissionAction(sev Severity) string {
	switch sev {
	case CRITICAL:
		return "Investigate immediately — extremely small TCP packets suggest severe congestion or path MTU problems."
	default:
		return "Review TCP flow — high packet-to-byte ratio may indicate retransmissions or congestion."
	}
}
