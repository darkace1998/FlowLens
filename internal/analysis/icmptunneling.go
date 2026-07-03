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

// ICMPTunnelingDetector identifies potential ICMP tunneling activity.
// It flags internal hosts sending a massive amount of data via ICMP/ICMPv6,
// especially when the average packet size is unusually large.
type ICMPTunnelingDetector struct{}

func (ICMPTunnelingDetector) Name() string { return "ICMP Tunneling Detector" }

const (
	// icmpTunnelingMinBytes is the minimum outbound bytes on ICMP to evaluate.
	icmpTunnelingMinBytes = 100000 // 100 KB
	// icmpTunnelingMinAvgPacketSize is the average bytes per packet threshold.
	// Normal ICMP echo requests are typically small (e.g. 64 bytes).
	icmpTunnelingMinAvgPacketSize = 250
)

// Analyze returns advisories about potential ICMP tunneling attacks.
func (ICMPTunnelingDetector) Analyze(store storage.Storage, cfg config.AnalysisConfig) []Advisory {
	flows, err := store.Recent(queryWindow(cfg), 0)
	if err != nil {
		logging.Default().Error("ICMPTunnelingDetector: failed to query recent flows: %v", err)
		return nil
	}
	if len(flows) == 0 {
		return nil
	}

	type stats struct {
		bytes   uint64
		packets uint64
		targets map[string]struct{}
	}

	sources := make(map[string]*stats)

	for _, f := range flows {
		// Look for ICMP (1) or ICMPv6 (58) traffic
		if f.Protocol == 1 || f.Protocol == 58 {
			srcIP := model.SafeIPString(f.SrcAddr)
			dstIP := model.SafeIPString(f.DstAddr)

			s, ok := sources[srcIP]
			if !ok {
				s = &stats{targets: make(map[string]struct{})}
				sources[srcIP] = s
			}
			s.bytes += f.Bytes
			s.packets += f.Packets
			s.targets[dstIP] = struct{}{}
		}
	}

	type result struct {
		srcIP    string
		stats    *stats
		avgBytes float64
	}
	results := make([]result, 0, len(sources))

	for srcIP, s := range sources {
		if s.bytes < icmpTunnelingMinBytes || s.packets == 0 {
			continue
		}

		avgBytes := float64(s.bytes) / float64(s.packets)
		if avgBytes >= icmpTunnelingMinAvgPacketSize {
			results = append(results, result{
				srcIP:    srcIP,
				stats:    s,
				avgBytes: avgBytes,
			})
		}
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
		sev := WARNING
		if r.stats.bytes >= icmpTunnelingMinBytes*10 || r.avgBytes > 500 {
			sev = CRITICAL
		}

		advisories = append(advisories, Advisory{
			Severity:  sev,
			Timestamp: now,
			Title:     fmt.Sprintf("ICMP Tunneling Activity: %s", r.srcIP),
			Description: fmt.Sprintf(
				"%s sent %s of ICMP traffic (%d packets) to %d unique destinations. "+
					"The average packet size is %.0f bytes/packet, which is unusually large and strongly indicates ICMP tunneling or data exfiltration.",
				r.srcIP, util.FormatBytes(r.stats.bytes), r.stats.packets, len(r.stats.targets), r.avgBytes,
			),
			Action: icmpTunnelingAction(sev),
		})
	}

	return advisories
}

func icmpTunnelingAction(sev Severity) string {
	switch sev {
	case CRITICAL:
		return "Investigate immediately — large, high-volume ICMP packets strongly indicate data exfiltration or malware command-and-control via ICMP tunneling."
	default:
		return "Monitor host — unusually large ICMP packets detected. Verify if legitimate or tunneling."
	}
}
