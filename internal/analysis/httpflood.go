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

// HTTPFloodDetector identifies destinations receiving a large number of HTTP/HTTPS requests,
// which could indicate a layer 7 DoS/DDoS attack.
type HTTPFloodDetector struct{}

func (HTTPFloodDetector) Name() string { return "HTTP Flood Detector" }

const httpFloodMinFlows = 1000

// Analyze returns advisories about potential HTTP flood attacks.
func (HTTPFloodDetector) Analyze(store storage.Storage, cfg config.AnalysisConfig) []Advisory {
	flows, err := store.Recent(queryWindow(cfg), 0)
	if err != nil {
		logging.Default().Error("HTTPFloodDetector: failed to query recent flows: %v", err)
		return nil
	}
	if len(flows) == 0 {
		return nil
	}

	type targetStats struct {
		flows   uint64
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
		// Only consider HTTP/HTTPS ports
		if f.DstPort != 80 && f.DstPort != 443 {
			continue
		}

		dstIP := model.SafeIPString(f.DstAddr)
		s, ok := targets[dstIP]
		if !ok {
			s = &targetStats{sources: make(map[string]struct{})}
			targets[dstIP] = s
		}
		s.flows++
		s.bytes += f.Bytes
		s.packets += f.Packets
		s.sources[model.SafeIPString(f.SrcAddr)] = struct{}{}
	}

	type result struct {
		dstIP string
		stats *targetStats
	}
	results := make([]result, 0, len(targets))

	for dstIP, s := range targets {
		if s.flows < httpFloodMinFlows {
			continue
		}
		results = append(results, result{
			dstIP: dstIP,
			stats: s,
		})
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].stats.flows > results[j].stats.flows
	})

	if len(results) > 10 {
		results = results[:10]
	}

	now := time.Now()
	advisories := make([]Advisory, 0, len(results))

	for _, r := range results {
		sev := WARNING
		if r.stats.flows >= httpFloodMinFlows*3 {
			sev = CRITICAL
		}

		advisories = append(advisories, Advisory{
			Severity:  sev,
			Timestamp: now,
			Title:     fmt.Sprintf("HTTP Flood Attack: %s", r.dstIP),
			Description: fmt.Sprintf(
				"%s received %s HTTP/HTTPS connections (%s bytes) from %d unique sources. "+
					"This strongly indicates a layer 7 HTTP flood (DoS/DDoS) attack.",
				r.dstIP, util.FormatCount(r.stats.flows), util.FormatBytes(r.stats.bytes), len(r.stats.sources),
			),
			Action: httpFloodAction(sev),
		})
	}

	return advisories
}

func httpFloodAction(sev Severity) string {
	switch sev {
	case CRITICAL:
		return "Investigate immediately — target is actively under a severe HTTP flood attack. Consider applying rate limiting or web application firewall (WAF) rules."
	default:
		return "Monitor destination — elevated HTTP traffic detected, possibly an HTTP flood."
	}
}
