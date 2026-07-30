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

// DataExfiltrationDetector identifies potential data exfiltration by detecting
// large data transfers from internal hosts to external (public) destinations.
type DataExfiltrationDetector struct{}

func (DataExfiltrationDetector) Name() string { return "Data Exfiltration Detector" }

const (
	// exfiltrationMinBytes is the minimum outbound bytes to consider for exfiltration.
	exfiltrationMinBytes = 500000000 // 500 MB
)

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

	type pairKey struct {
		srcIP string
		dstIP string
	}

	type stats struct {
		bytes   uint64
		packets uint64
	}

	pairs := make(map[pairKey]*stats)

	for _, f := range flows {
		if len(f.SrcAddr) == 0 || len(f.DstAddr) == 0 {
			continue
		}

		// Only look at internal -> external traffic
		if f.SrcAddr.IsPrivate() && f.DstAddr.IsGlobalUnicast() && !f.DstAddr.IsPrivate() {
			srcIP := model.SafeIPString(f.SrcAddr)
			dstIP := model.SafeIPString(f.DstAddr)

			pk := pairKey{srcIP: srcIP, dstIP: dstIP}
			s, ok := pairs[pk]
			if !ok {
				s = &stats{}
				pairs[pk] = s
			}
			s.bytes += f.Bytes
			s.packets += f.Packets
		}
	}

	type result struct {
		pk    pairKey
		stats *stats
	}
	results := make([]result, 0, len(pairs))

	for pk, s := range pairs {
		if s.bytes >= exfiltrationMinBytes {
			results = append(results, result{
				pk:    pk,
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
			Title:     fmt.Sprintf("Data Exfiltration Activity: %s → %s", r.pk.srcIP, r.pk.dstIP),
			Description: fmt.Sprintf(
				"%s transferred %s (%s packets) to an external host %s. "+
					"This large outbound transfer may indicate data exfiltration, backups, or excessive uploads.",
				r.pk.srcIP, util.FormatBytes(r.stats.bytes), util.FormatCount(r.stats.packets), r.pk.dstIP,
			),
			Action: dataExfiltrationAction(sev),
		})
	}

	return advisories
}

func dataExfiltrationAction(sev Severity) string {
	switch sev {
	case CRITICAL:
		return "Investigate immediately — massive data transfer to an external host strongly suggests data exfiltration."
	default:
		return "Monitor host — unusually large outbound data transfer to an external host detected. Verify if legitimate."
	}
}
