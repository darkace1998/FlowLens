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

// DataExfiltrationDetector identifies potential data exfiltration by monitoring
// internal hosts transferring unusually large amounts of data to external
// (public) destinations.
type DataExfiltrationDetector struct{}

func (DataExfiltrationDetector) Name() string { return "Data Exfiltration Detector" }

// exfiltrationMinBytes is the minimum amount of outbound data (500 MB)
// to a public IP required to trigger an advisory.
const exfiltrationMinBytes = 500 * 1024 * 1024

// Analyze returns advisories about potential data exfiltration.
func (DataExfiltrationDetector) Analyze(store storage.Storage, cfg config.AnalysisConfig) []Advisory {
	flows, err := store.Recent(queryWindow(cfg), 0)
	if err != nil {
		logging.Default().Error("DataExfiltrationDetector: failed to query recent flows: %v", err)
		return nil
	}
	if len(flows) == 0 {
		return nil
	}

	type stats struct {
		bytes   uint64
		targets map[string]struct{}
	}

	sources := make(map[string]*stats)

	for _, f := range flows {
		// Only consider traffic from internal to external hosts
		if f.SrcAddr.IsPrivate() && !f.DstAddr.IsPrivate() && f.DstAddr.IsGlobalUnicast() {
			srcIP := model.SafeIPString(f.SrcAddr)
			dstIP := model.SafeIPString(f.DstAddr)

			s, ok := sources[srcIP]
			if !ok {
				s = &stats{targets: make(map[string]struct{})}
				sources[srcIP] = s
			}
			s.bytes += f.Bytes
			s.targets[dstIP] = struct{}{}
		}
	}

	type result struct {
		srcIP string
		stats *stats
	}
	results := make([]result, 0, len(sources))

	for srcIP, s := range sources {
		if s.bytes >= exfiltrationMinBytes {
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
		if r.stats.bytes >= exfiltrationMinBytes*5 { // 2.5 GB
			sev = CRITICAL
		}

		advisories = append(advisories, Advisory{
			Severity:  sev,
			Timestamp: now,
			Title:     fmt.Sprintf("Data Exfiltration: %s", r.srcIP),
			Description: fmt.Sprintf(
				"%s transferred %s of data to %d external destinations in the last %s. "+
					"This large outbound transfer may indicate data exfiltration.",
				r.srcIP, util.FormatBytes(r.stats.bytes), len(r.stats.targets), formatWindowShort(queryWindow(cfg)),
			),
			Action: exfiltrationAction(sev),
		})
	}

	return advisories
}

func exfiltrationAction(sev Severity) string {
	switch sev {
	case CRITICAL:
		return "Investigate immediately — large, high-volume outbound transfer to external networks strongly indicates data exfiltration or malware command-and-control."
	default:
		return "Monitor host — unusually large outbound transfer detected. Verify if legitimate (e.g., backups, cloud sync)."
	}
}
