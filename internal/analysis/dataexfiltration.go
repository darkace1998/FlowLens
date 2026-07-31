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

// DataExfiltrationDetector identifies large data transfers from internal (private)
// IP addresses to external (public) IP addresses, which could indicate data exfiltration.
type DataExfiltrationDetector struct{}

func (DataExfiltrationDetector) Name() string { return "Data Exfiltration Detector" }

// Analyze returns advisories about potential data exfiltration.
func (DataExfiltrationDetector) Analyze(store storage.Storage, cfg config.AnalysisConfig) []Advisory {
	flows, err := store.Recent(queryWindow(cfg), 0)
	if err != nil {
		logging.Default().Error("DataExfiltrationDetector: failed to query flows: %v", err)
		return nil
	}
	if len(flows) == 0 {
		return nil
	}

	thresholdMB := cfg.ExfiltrationThresholdMB
	if thresholdMB <= 0 {
		thresholdMB = 500
	}
	thresholdBytes := uint64(thresholdMB) * 1024 * 1024

	type hostStats struct {
		bytes   uint64
		targets map[string]struct{}
	}

	sources := make(map[string]*hostStats)

	for _, f := range flows {
		// Only consider flows from a private IP to a public IP
		if f.SrcAddr != nil && f.DstAddr != nil {
			if f.SrcAddr.IsPrivate() && f.DstAddr.IsGlobalUnicast() && !f.DstAddr.IsPrivate() {
				srcIP := model.SafeIPString(f.SrcAddr)
				dstIP := model.SafeIPString(f.DstAddr)

				s, ok := sources[srcIP]
				if !ok {
					s = &hostStats{targets: make(map[string]struct{})}
					sources[srcIP] = s
				}
				s.bytes += f.Bytes
				s.targets[dstIP] = struct{}{}
			}
		}
	}

	type result struct {
		srcIP string
		stats *hostStats
	}
	results := make([]result, 0, len(sources))

	for srcIP, s := range sources {
		if s.bytes >= thresholdBytes {
			results = append(results, result{
				srcIP: srcIP,
				stats: s,
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
		if r.stats.bytes >= thresholdBytes*5 {
			sev = CRITICAL
		}

		advisories = append(advisories, Advisory{
			Severity:  sev,
			Timestamp: now,
			Title:     fmt.Sprintf("Data Exfiltration: %s", r.srcIP),
			Description: fmt.Sprintf(
				"%s transferred %s of data to %d external destinations in the last %s. "+
					"This large outbound transfer may indicate data exfiltration or unauthorized backup.",
				r.srcIP, util.FormatBytes(r.stats.bytes), len(r.stats.targets), formatWindowShort(queryWindow(cfg)),
			),
			Action: fmt.Sprintf(
				"Investigate %s for unauthorized outbound data transfers or compromised accounts. Confirm if transfer is expected.",
				r.srcIP,
			),
		})
	}

	return advisories
}
