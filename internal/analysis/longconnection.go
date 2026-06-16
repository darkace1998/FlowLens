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

// LongConnectionDetector identifies TCP/UDP connections that have been active
// for an unusually long time, which could indicate persistent backdoors,
// large downloads, or stale connections.
type LongConnectionDetector struct{}

func (LongConnectionDetector) Name() string { return "Long Connection Detector" }

// Analyze returns advisories about flows exceeding the configured long connection threshold.
func (LongConnectionDetector) Analyze(store storage.Storage, cfg config.AnalysisConfig) []Advisory {
	flows, err := store.Recent(queryWindow(cfg), 0)
	if err != nil {
		logging.Default().Error("LongConnectionDetector: failed to query recent flows: %v", err)
		return nil
	}
	if len(flows) == 0 {
		return nil
	}

	threshold := cfg.LongConnectionThreshold
	if threshold <= 0 {
		threshold = 1 * time.Hour
	}

	type flowKey struct {
		src, dst         string
		srcPort, dstPort uint16
		proto            uint8
	}

	type flowStats struct {
		duration time.Duration
		bytes    uint64
		packets  uint64
	}

	longest := make(map[flowKey]*flowStats)

	for _, f := range flows {
		// Only consider TCP and UDP
		if f.Protocol != 6 && f.Protocol != 17 {
			continue
		}

		if f.Duration >= threshold {
			fk := flowKey{
				src: model.SafeIPString(f.SrcAddr), dst: model.SafeIPString(f.DstAddr),
				srcPort: f.SrcPort, dstPort: f.DstPort, proto: f.Protocol,
			}

			if s, ok := longest[fk]; ok {
				if f.Duration > s.duration {
					s.duration = f.Duration
				}
				s.bytes += f.Bytes
				s.packets += f.Packets
			} else {
				longest[fk] = &flowStats{
					duration: f.Duration,
					bytes:    f.Bytes,
					packets:  f.Packets,
				}
			}
		}
	}

	if len(longest) == 0 {
		return nil
	}

	type result struct {
		fk    flowKey
		stats *flowStats
	}
	var results []result
	for k, v := range longest {
		results = append(results, result{fk: k, stats: v})
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].stats.duration > results[j].stats.duration
	})

	if len(results) > 10 {
		results = results[:10]
	}

	now := time.Now()
	advisories := make([]Advisory, 0, len(results))

	for _, r := range results {
		protoName := "TCP"
		if r.fk.proto == 17 {
			protoName = "UDP"
		}

		desc := fmt.Sprintf(
			"Long-running %s connection detected: %s. Transferred %s in %d packets.",
			protoName, formatDurationShort(r.stats.duration),
			formatBytesShort(r.stats.bytes), r.stats.packets,
		)

		advisories = append(advisories, Advisory{
			Severity:    WARNING,
			Timestamp:   now,
			Title:       fmt.Sprintf("Long Connection: %s:%d → %s:%d", r.fk.src, r.fk.srcPort, r.fk.dst, r.fk.dstPort),
			Description: desc,
			Action:      "Investigate connection — may indicate a persistent backdoor, large file transfer, or stalled application state.",
		})
	}

	return advisories
}

func formatDurationShort(d time.Duration) string {
	if d < time.Second {
		return d.String()
	}
	totalSecs := int(d.Seconds())
	h := totalSecs / 3600
	m := (totalSecs % 3600) / 60
	s := totalSecs % 60
	switch {
	case h > 0 && m > 0:
		return fmt.Sprintf("%dh %dm", h, m)
	case h > 0:
		return fmt.Sprintf("%dh", h)
	case m > 0 && s > 0:
		return fmt.Sprintf("%dm %ds", m, s)
	case m > 0:
		return fmt.Sprintf("%dm", m)
	default:
		return fmt.Sprintf("%ds", s)
	}
}
