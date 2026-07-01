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

// DNSTunnelingDetector identifies potential DNS tunneling activity.
// It flags internal hosts sending a massive amount of data to port 53,
// especially when the average packet size of DNS queries is unusually large.
type DNSTunnelingDetector struct{}

func (DNSTunnelingDetector) Name() string { return "DNS Tunneling Detector" }

const (
	// dnsTunnelingMinBytes is the minimum outbound bytes on port 53 to evaluate.
	dnsTunnelingMinBytes = 500000 // 500 KB
	// dnsTunnelingMinAvgPacketSize is the average bytes per packet threshold.
	// Normal DNS queries are typically small (< 100 bytes).
	dnsTunnelingMinAvgPacketSize = 200
)

// Analyze returns advisories about potential DNS tunneling attacks.
func (DNSTunnelingDetector) Analyze(store storage.Storage, cfg config.AnalysisConfig) []Advisory {
	flows, err := store.Recent(queryWindow(cfg), 0)
	if err != nil {
		logging.Default().Error("DNSTunnelingDetector: failed to query recent flows: %v", err)
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
		// Look for outbound traffic to port 53 (TCP or UDP)
		if (f.Protocol == 17 || f.Protocol == 6) && f.DstPort == 53 {
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
		if s.bytes < dnsTunnelingMinBytes || s.packets == 0 {
			continue
		}

		avgBytes := float64(s.bytes) / float64(s.packets)
		if avgBytes >= dnsTunnelingMinAvgPacketSize {
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
		if r.stats.bytes >= dnsTunnelingMinBytes*10 || r.avgBytes > 400 {
			sev = CRITICAL
		}

		advisories = append(advisories, Advisory{
			Severity:  sev,
			Timestamp: now,
			Title:     fmt.Sprintf("DNS Tunneling Activity: %s", r.srcIP),
			Description: fmt.Sprintf(
				"%s sent %s of DNS queries (%d packets) to %d unique resolvers. "+
					"The average query size is %.0f bytes/packet, which is unusually large and strongly indicates DNS tunneling or data exfiltration.",
				r.srcIP, util.FormatBytes(r.stats.bytes), r.stats.packets, len(r.stats.targets), r.avgBytes,
			),
			Action: dnsTunnelingAction(sev),
		})
	}

	return advisories
}

func dnsTunnelingAction(sev Severity) string {
	switch sev {
	case CRITICAL:
		return "Investigate immediately — large, high-volume DNS queries strongly indicate data exfiltration or malware command-and-control via DNS tunneling."
	default:
		return "Monitor host — unusually large DNS queries detected. Verify if legitimate (e.g., DNSSEC, large TXT lookups) or tunneling."
	}
}
