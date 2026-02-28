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

// RetransmissionDetector identifies TCP flows with retransmissions, out-of-order
// segments, or packet loss. It uses IPFIX/NetFlow counters when available, falling
// back to a heuristic based on packet-to-byte ratio.
type RetransmissionDetector struct{}

func (RetransmissionDetector) Name() string { return "Retransmission Detector" }

// smallPacketThreshold is the average bytes-per-packet below which a TCP flow
// is considered to have abnormally small packets (likely retransmissions).
const smallPacketThreshold = 100

// retransmissionMinPackets is the minimum packet count for a flow to be
// considered — filters out noise from tiny flows.
const retransmissionMinPackets = 50

// retransmissionRateThreshold is the retransmission rate (%) above which
// an advisory is generated when actual counters are available.
const retransmissionRateThreshold = 1.0

// criticalRetransmissionRateThreshold is the retransmission rate (%) above
// which the advisory severity is elevated to CRITICAL.
const criticalRetransmissionRateThreshold = 5.0

// Analyze returns advisories about flows with retransmissions, OOO, or loss.
func (RetransmissionDetector) Analyze(store *storage.RingBuffer, cfg config.AnalysisConfig) []Advisory {
	flows, err := store.Recent(queryWindow(cfg), 0)
	if err != nil {
		logging.Default().Error("RetransmissionDetector: failed to query recent flows: %v", err)
		return nil
	}
	if len(flows) == 0 {
		return nil
	}

	// Check if any flows have actual TCP counter data.
	hasCounters := false
	for _, f := range flows {
		if f.Retransmissions > 0 || f.OutOfOrder > 0 || f.PacketLoss > 0 {
			hasCounters = true
			break
		}
	}

	if hasCounters {
		return analyzeWithCounters(flows)
	}
	return analyzeWithHeuristic(flows)
}

// analyzeWithCounters uses actual IPFIX/NetFlow TCP quality counters.
func analyzeWithCounters(flows []model.Flow) []Advisory {
	type pairKey struct {
		src, dst         string
		srcPort, dstPort uint16
	}
	type pairStats struct {
		retrans uint32
		ooo     uint32
		loss    uint32
		packets uint64
	}

	pairs := make(map[pairKey]*pairStats)

	for _, f := range flows {
		if f.Protocol != 6 {
			continue
		}
		if f.Retransmissions == 0 && f.OutOfOrder == 0 && f.PacketLoss == 0 {
			continue
		}
		pk := pairKey{
			src: model.SafeIPString(f.SrcAddr), dst: model.SafeIPString(f.DstAddr),
			srcPort: f.SrcPort, dstPort: f.DstPort,
		}
		if s, ok := pairs[pk]; ok {
			s.retrans += f.Retransmissions
			s.ooo += f.OutOfOrder
			s.loss += f.PacketLoss
			s.packets += f.Packets
		} else {
			pairs[pk] = &pairStats{
				retrans: f.Retransmissions, ooo: f.OutOfOrder,
				loss: f.PacketLoss, packets: f.Packets,
			}
		}
	}

	type result struct {
		pk      pairKey
		retrans uint32
		ooo     uint32
		loss    uint32
		rate    float64
	}
	var results []result

	for pk, s := range pairs {
		rate := 0.0
		if s.packets > 0 {
			rate = float64(s.retrans) / float64(s.packets) * 100
		}
		if rate >= retransmissionRateThreshold || s.ooo > 0 || s.loss > 0 {
			results = append(results, result{pk: pk, retrans: s.retrans, ooo: s.ooo, loss: s.loss, rate: rate})
		}
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].retrans+results[i].ooo+results[i].loss >
			results[j].retrans+results[j].ooo+results[j].loss
	})
	if len(results) > 10 {
		results = results[:10]
	}

	now := time.Now()
	var advisories []Advisory

	for _, r := range results {
		sev := WARNING
		if r.rate >= criticalRetransmissionRateThreshold || r.loss > 0 {
			sev = CRITICAL
		}

		desc := fmt.Sprintf(
			"TCP flow: %d retransmissions (%.1f%%), %d out-of-order, %d packet loss.",
			r.retrans, r.rate, r.ooo, r.loss,
		)

		advisories = append(advisories, Advisory{
			Severity:    sev,
			Timestamp:   now,
			Title:       fmt.Sprintf("TCP Issues: %s:%d → %s:%d", r.pk.src, r.pk.srcPort, r.pk.dst, r.pk.dstPort),
			Description: desc,
			Action:      retransmissionAction(sev),
		})
	}

	return advisories
}

// analyzeWithHeuristic falls back to packet-to-byte ratio analysis.
func analyzeWithHeuristic(flows []model.Flow) []Advisory {
	// Aggregate by source→destination pair for TCP only.
	type pairKey struct {
		src, dst         string
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
			src: model.SafeIPString(f.SrcAddr), dst: model.SafeIPString(f.DstAddr),
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
