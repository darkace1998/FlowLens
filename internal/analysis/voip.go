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

// VoIPQualityDetector generates advisories when VoIP flows have poor MOS
// scores or excessive jitter.
type VoIPQualityDetector struct{}

func (VoIPQualityDetector) Name() string { return "VoIP Quality Detector" }

// mosWarningThreshold is the MOS below which a WARNING advisory is generated.
const mosWarningThreshold = 3.5

// mosCriticalThreshold is the MOS below which a CRITICAL advisory is generated.
const mosCriticalThreshold = 3.0

// Analyze inspects recent VoIP flows and flags those with degraded quality.
func (VoIPQualityDetector) Analyze(store *storage.RingBuffer, cfg config.AnalysisConfig) []Advisory {
	flows, err := store.Recent(queryWindow(cfg), 0)
	if err != nil {
		logging.Default().Error("VoIPQualityDetector: failed to query recent flows: %v", err)
		return nil
	}
	if len(flows) == 0 {
		return nil
	}

	type voipKey struct {
		src, dst         string
		srcPort, dstPort uint16
	}
	type voipStats struct {
		mosSum  float32
		count   int
		minMOS  float32
		jitter  int64
		loss    uint32
		packets uint64
	}

	agg := make(map[voipKey]*voipStats)

	for _, f := range flows {
		if !f.IsVoIP() {
			continue
		}

		mos := f.MOS
		if mos == 0 && (f.JitterMicros > 0 || f.RTTMicros > 0 || f.PacketLoss > 0) {
			mos = model.CalcMOS(f.JitterMicros, f.RTTMicros, f.PacketLossRate())
		}
		if mos == 0 {
			continue
		}

		key := voipKey{
			src: model.SafeIPString(f.SrcAddr), dst: model.SafeIPString(f.DstAddr),
			srcPort: f.SrcPort, dstPort: f.DstPort,
		}
		if s, ok := agg[key]; ok {
			s.mosSum += mos
			s.count++
			if mos < s.minMOS {
				s.minMOS = mos
			}
			if f.JitterMicros > s.jitter {
				s.jitter = f.JitterMicros
			}
			s.loss += f.PacketLoss
			s.packets += f.Packets
		} else {
			agg[key] = &voipStats{
				mosSum:  mos,
				count:   1,
				minMOS:  mos,
				jitter:  f.JitterMicros,
				loss:    f.PacketLoss,
				packets: f.Packets,
			}
		}
	}

	type result struct {
		key    voipKey
		avgMOS float32
		minMOS float32
		jitter int64
		loss   uint32
	}
	var results []result

	for key, s := range agg {
		avg := s.mosSum / float32(s.count)
		if avg < mosWarningThreshold {
			results = append(results, result{
				key: key, avgMOS: avg, minMOS: s.minMOS,
				jitter: s.jitter, loss: s.loss,
			})
		}
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].avgMOS < results[j].avgMOS
	})
	if len(results) > 10 {
		results = results[:10]
	}

	now := time.Now()
	var advisories []Advisory

	for _, r := range results {
		sev := WARNING
		if r.avgMOS < mosCriticalThreshold {
			sev = CRITICAL
		}

		desc := fmt.Sprintf(
			"VoIP call quality degraded: avg MOS %.2f, min MOS %.2f. "+
				"Jitter: %dµs, Packet loss: %d.",
			r.avgMOS, r.minMOS, r.jitter, r.loss,
		)

		action := "Review network path for congestion, jitter, or packet loss affecting VoIP quality."
		if sev == CRITICAL {
			action = "Investigate immediately — call quality is unacceptable (MOS < 3.0). Check for congestion, QoS policy, or network path issues."
		}

		advisories = append(advisories, Advisory{
			Severity:    sev,
			Timestamp:   now,
			Title:       fmt.Sprintf("VoIP Quality: %s:%d → %s:%d", r.key.src, r.key.srcPort, r.key.dst, r.key.dstPort),
			Description: desc,
			Action:      action,
		})
	}

	return advisories
}
