package analysis

import (
	"fmt"
	"sort"
	"time"

	"github.com/darkace1998/FlowLens/internal/config"
	"github.com/darkace1998/FlowLens/internal/storage"
)

// NewTalkerDetector identifies hosts that are active in the recent window
// but were not present in the baseline period, which may indicate rogue
// devices, misconfigured DHCP, or unauthorized access.
type NewTalkerDetector struct{}

func (NewTalkerDetector) Name() string { return "New Talker Detector" }

// newTalkerMinBytes is the minimum bytes a new talker must generate to be
// flagged — filters out single-packet noise.
const newTalkerMinBytes = 10000 // 10 KB

// Analyze returns advisories about hosts that appear for the first time.
func (NewTalkerDetector) Analyze(store *storage.RingBuffer, cfg config.AnalysisConfig) []Advisory {
	// Use the analysis interval as the "recent" window.
	recentWindow := cfg.Interval
	if recentWindow <= 0 {
		recentWindow = 60 * time.Second
	}

	allFlows, _ := store.Recent(10*time.Minute, 0)
	if len(allFlows) == 0 {
		return nil
	}

	now := time.Now()
	recentCutoff := now.Add(-recentWindow)

	// Separate flows into recent and baseline sets.
	baselineHosts := make(map[string]struct{})
	type hostInfo struct {
		bytes   uint64
		packets uint64
		flows   int
	}
	recentHosts := make(map[string]*hostInfo)

	for _, f := range allFlows {
		src := f.SrcAddr.String()
		if f.Timestamp.Before(recentCutoff) {
			baselineHosts[src] = struct{}{}
		} else {
			if h, ok := recentHosts[src]; ok {
				h.bytes += f.Bytes
				h.packets += f.Packets
				h.flows++
			} else {
				recentHosts[src] = &hostInfo{bytes: f.Bytes, packets: f.Packets, flows: 1}
			}
		}
	}

	// Need baseline data to compare against.
	if len(baselineHosts) == 0 {
		return nil
	}

	type result struct {
		ip      string
		bytes   uint64
		packets uint64
		flows   int
	}
	var results []result

	for ip, info := range recentHosts {
		if _, inBaseline := baselineHosts[ip]; inBaseline {
			continue
		}
		if info.bytes < newTalkerMinBytes {
			continue
		}
		results = append(results, result{ip: ip, bytes: info.bytes, packets: info.packets, flows: info.flows})
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].bytes > results[j].bytes
	})

	if len(results) > 10 {
		results = results[:10]
	}

	var advisories []Advisory

	for _, r := range results {
		sev := WARNING
		if r.bytes > 1000000 { // > 1 MB
			sev = CRITICAL
		}

		advisories = append(advisories, Advisory{
			Severity:  sev,
			Timestamp: now,
			Title:     fmt.Sprintf("New Talker: %s", r.ip),
			Description: fmt.Sprintf(
				"%s was not seen in the baseline period but generated %s (%s packets, %d flows) in the last interval. "+
					"May indicate a rogue device, misconfigured DHCP, or unauthorized access.",
				r.ip, formatBytesShort(r.bytes), formatCountShort(r.packets), r.flows,
			),
			Action: newTalkerAction(sev),
		})
	}

	return advisories
}

func newTalkerAction(sev Severity) string {
	switch sev {
	case CRITICAL:
		return "Investigate immediately — new host generating significant traffic. Verify it is authorized."
	default:
		return "Verify host identity — new device on network not seen in baseline."
	}
}
