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

// DataExfiltrationDetector identifies potential data exfiltration or unauthorized backups
// by monitoring internal hosts transferring an unusually large amount of data to external,
// non-private IP addresses.
type DataExfiltrationDetector struct{}

func (DataExfiltrationDetector) Name() string { return "Data Exfiltration Detector" }

// exfiltrationMinBytes is the minimum outbound bytes to an external IP to evaluate (e.g., 500 MB).
const exfiltrationMinBytes = 500000000

// Analyze returns advisories about potential data exfiltration attacks.
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
		packets uint64
		targets map[string]struct{}
	}

	sources := make(map[string]*stats)

	for _, f := range flows {
		if len(f.SrcAddr) == 0 || len(f.DstAddr) == 0 {
			continue
		}

		// Identify internal to external traffic.
		// Source must be private, destination must be global unicast and NOT private.
		if f.SrcAddr.IsPrivate() && f.DstAddr.IsGlobalUnicast() && !f.DstAddr.IsPrivate() {
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
		if r.stats.bytes >= exfiltrationMinBytes*2 {
			sev = CRITICAL
		}

		advisories = append(advisories, Advisory{
			Severity:  sev,
			Timestamp: now,
			Title:     fmt.Sprintf("Data Exfiltration Activity: %s", r.srcIP),
			Description: fmt.Sprintf(
				"%s transferred %s of data (%d packets) to %d unique external destinations. "+
					"This large outbound transfer strongly indicates potential data exfiltration or unauthorized backups.",
				r.srcIP, util.FormatBytes(r.stats.bytes), r.stats.packets, len(r.stats.targets),
			),
			Action: dataExfiltrationAction(sev),
		})
	}

	return advisories
}

func dataExfiltrationAction(sev Severity) string {
	switch sev {
	case CRITICAL:
		return "Investigate immediately — very large data transfer to external networks suggests active data exfiltration or unauthorized bulk backup."
	default:
		return "Monitor host — unusually large outbound data transfer to external networks detected. Verify if legitimate."
	}
}
