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

// DataExfiltrationDetector identifies large volumes of outbound data from internal
// hosts to external destinations.
type DataExfiltrationDetector struct{}

func (DataExfiltrationDetector) Name() string { return "Data Exfiltration Detector" }

const dataExfiltrationMinBytes = 100000000 // 100 MB

// Analyze returns advisories about potential data exfiltration attempts.
func (DataExfiltrationDetector) Analyze(store storage.Storage, cfg config.AnalysisConfig) []Advisory {
	flows, err := store.Recent(queryWindow(cfg), 0)
	if err != nil {
		logging.Default().Error("DataExfiltrationDetector: failed to query flows: %v", err)
		return nil
	}
	if len(flows) == 0 {
		return nil
	}

	type exfilStats struct {
		bytes   uint64
		targets map[string]struct{}
	}

	sources := make(map[string]*exfilStats)

	for _, f := range flows {
		// Only consider flows from private IPs to public IPs
		if f.SrcAddr == nil || f.DstAddr == nil {
			continue
		}
		if !f.SrcAddr.IsPrivate() {
			continue
		}
		if f.DstAddr.IsPrivate() || !f.DstAddr.IsGlobalUnicast() {
			continue
		}

		srcIP := model.SafeIPString(f.SrcAddr)
		dstIP := model.SafeIPString(f.DstAddr)

		s, ok := sources[srcIP]
		if !ok {
			s = &exfilStats{targets: make(map[string]struct{})}
			sources[srcIP] = s
		}
		s.bytes += f.Bytes
		s.targets[dstIP] = struct{}{}
	}

	type result struct {
		srcIP string
		stats *exfilStats
	}

	results := make([]result, 0, len(sources))

	for srcIP, s := range sources {
		if s.bytes >= dataExfiltrationMinBytes {
			results = append(results, result{srcIP: srcIP, stats: s})
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
		if r.stats.bytes >= dataExfiltrationMinBytes*5 {
			sev = CRITICAL
		}

		advisories = append(advisories, Advisory{
			Severity:  sev,
			Timestamp: now,
			Title:     fmt.Sprintf("Potential Data Exfiltration: %s", r.srcIP),
			Description: fmt.Sprintf(
				"%s transferred %s of data to %d external destinations in the last %s. "+
					"This large outbound transfer may indicate data exfiltration or unauthorized backup activity.",
				r.srcIP, util.FormatBytes(r.stats.bytes), len(r.stats.targets), formatWindowShort(queryWindow(cfg)),
			),
			Action: fmt.Sprintf(
				"Investigate outbound connections from %s to identify the external destinations and determine if the transfer is legitimate.",
				r.srcIP,
			),
		})
	}

	return advisories
}
