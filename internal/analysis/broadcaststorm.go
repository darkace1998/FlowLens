package analysis

import (
	"bytes"
	"fmt"
	"net"
	"sort"
	"time"

	"github.com/darkace1998/FlowLens/internal/config"
	"github.com/darkace1998/FlowLens/internal/logging"
	"github.com/darkace1998/FlowLens/internal/model"
	"github.com/darkace1998/FlowLens/internal/storage"
	"github.com/darkace1998/FlowLens/internal/util"
)

// BroadcastStormDetector identifies an abnormally high volume of broadcast or
// multicast traffic originating from a single source, which may indicate a
// broadcast storm or a misconfigured/malfunctioning device on the local network.
type BroadcastStormDetector struct{}

func (BroadcastStormDetector) Name() string { return "Broadcast Storm Detector" }

const broadcastStormMinPackets = 10000

// Analyze returns advisories about potential broadcast storms.
func (BroadcastStormDetector) Analyze(store storage.Storage, cfg config.AnalysisConfig) []Advisory {
	flows, err := store.Recent(queryWindow(cfg), 0)
	if err != nil {
		logging.Default().Error("BroadcastStormDetector: failed to query recent flows: %v", err)
		return nil
	}
	if len(flows) == 0 {
		return nil
	}

	type srcStats struct {
		bytes   uint64
		packets uint64
	}

	sources := make(map[string]*srcStats)

	macBcast := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	for _, f := range flows {
		// Identify broadcast/multicast traffic:
		// 1. Destination MAC is ff:ff:ff:ff:ff:ff
		// 2. Destination IP is 255.255.255.255
		// 3. Destination IP is multicast (e.g., 224.x.x.x, ff02::x)
		isBcastOrMcast := bytes.Equal(f.DstMAC, macBcast) ||
			(f.DstAddr != nil && (f.DstAddr.Equal(net.IPv4bcast) || f.DstAddr.IsMulticast()))

		if isBcastOrMcast {
			srcIP := model.SafeIPString(f.SrcAddr)
			s, ok := sources[srcIP]
			if !ok {
				s = &srcStats{}
				sources[srcIP] = s
			}
			s.bytes += f.Bytes
			s.packets += f.Packets
		}
	}

	type result struct {
		srcIP string
		stats *srcStats
	}
	results := make([]result, 0, len(sources))

	for srcIP, s := range sources {
		if s.packets < broadcastStormMinPackets {
			continue
		}
		results = append(results, result{
			srcIP: srcIP,
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
		if r.stats.packets >= broadcastStormMinPackets*5 {
			sev = CRITICAL
		}

		advisories = append(advisories, Advisory{
			Severity:  sev,
			Timestamp: now,
			Title:     fmt.Sprintf("Broadcast Storm Detected: %s", r.srcIP),
			Description: fmt.Sprintf(
				"%s originated %s broadcast/multicast packets (%s) in the last %s. "+
					"This strongly indicates a broadcast storm or misconfigured local device.",
				r.srcIP, util.FormatCount(r.stats.packets), util.FormatBytes(r.stats.bytes), formatWindowShort(queryWindow(cfg)),
			),
			Action: broadcastStormAction(sev),
		})
	}

	return advisories
}

func broadcastStormAction(sev Severity) string {
	switch sev {
	case CRITICAL:
		return "Investigate source immediately — extreme broadcast/multicast traffic is likely degrading local network performance."
	default:
		return "Monitor source — elevated broadcast/multicast traffic detected, possibly indicating a network loop or noisy protocol."
	}
}
