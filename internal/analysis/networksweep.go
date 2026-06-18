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

// NetworkSweepDetector identifies hosts that connect to a large number of
// distinct destination IP addresses within a short period, which is characteristic
// of a network sweep (ping sweep) or worm propagation.
type NetworkSweepDetector struct{}

func (NetworkSweepDetector) Name() string { return "Network Sweep Detector" }

// Analyze returns advisories for sources performing network sweeps.
func (NetworkSweepDetector) Analyze(store storage.Storage, cfg config.AnalysisConfig) []Advisory {
	window := queryWindow(cfg)
	flows, err := store.Recent(window, 0)
	if err != nil {
		logging.Default().Error("NetworkSweepDetector: failed to query flows: %v", err)
		return nil
	}
	if len(flows) == 0 {
		return nil
	}

	threshold := cfg.SweepThreshold
	if threshold <= 0 {
		threshold = 250 // Default threshold
	}

	type hostStats struct {
		targets map[string]struct{}
		bytes   uint64
		packets uint64
	}
	scanners := make(map[string]*hostStats)

	// Build a map of Source IP -> Set of unique Destination IPs
	for _, f := range flows {
		src := model.SafeIPString(f.SrcAddr)
		dst := model.SafeIPString(f.DstAddr)

		// A sweep typically involves initiating traffic, so we focus on outgoing.
		// Since flow direction isn't strictly known, we just count unique dst IPs per src IP.

		s, ok := scanners[src]
		if !ok {
			s = &hostStats{targets: make(map[string]struct{})}
			scanners[src] = s
		}
		s.targets[dst] = struct{}{}
		s.bytes += f.Bytes
		s.packets += f.Packets
	}

	type result struct {
		src         string
		targetCount int
		bytes       uint64
		packets     uint64
	}
	var results []result

	for src, stats := range scanners {
		if len(stats.targets) >= threshold {
			results = append(results, result{
				src:         src,
				targetCount: len(stats.targets),
				bytes:       stats.bytes,
				packets:     stats.packets,
			})
		}
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].targetCount > results[j].targetCount
	})

	// Limit to top 10 sweepers to avoid alert fatigue
	if len(results) > 10 {
		results = results[:10]
	}

	now := time.Now()
	advisories := make([]Advisory, 0, len(results))
	windowStr := formatWindowShort(window)

	for _, r := range results {
		sev := WARNING
		if r.targetCount >= threshold*5 {
			sev = CRITICAL
		}

		desc := fmt.Sprintf(
			"Host %s contacted %d unique IP addresses in %s "+
				"(%s bytes, %s packets). This pattern strongly suggests a network sweep, worm propagation, or aggressive crawling.",
			r.src, r.targetCount, windowStr,
			formatBytesShort(r.bytes), formatCountShort(r.packets),
		)

		advisories = append(advisories, Advisory{
			Severity:    sev,
			Timestamp:   now,
			Title:       fmt.Sprintf("Network Sweep Detected: %s", r.src),
			Description: desc,
			Action:      sweepAction(sev, r.src),
		})
	}

	return advisories
}

func sweepAction(sev Severity, src string) string {
	switch sev {
	case CRITICAL:
		return fmt.Sprintf("Isolate host %s immediately — actively performing wide-scale network sweep/scanning.", src)
	default:
		return fmt.Sprintf("Investigate host %s — network sweep behavior detected. Check for malware or unauthorized discovery tools.", src)
	}
}
