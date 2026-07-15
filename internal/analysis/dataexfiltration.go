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

// DataExfiltrationDetector analyzes flow data to identify large data transfers
// from internal (private) IP addresses to external (public) IP addresses,
// which could indicate data exfiltration.
type DataExfiltrationDetector struct{}

func (DataExfiltrationDetector) Name() string { return "Data Exfiltration Detector" }

const (
	// Default minimum bytes transferred to an external IP to trigger an advisory (500 MB).
	exfiltrationMinBytes = 500 * 1024 * 1024
)

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

	type exfilKey struct {
		srcIP string
		dstIP string
	}

	type exfilStats struct {
		bytes   uint64
		packets uint64
	}

	transfers := make(map[exfilKey]*exfilStats)

	for _, f := range flows {
		// Only care about flows with valid IP addresses
		if len(f.SrcAddr) == 0 || len(f.DstAddr) == 0 {
			continue
		}

		// Check if traffic originates from a private IP and goes to a public IP
		if f.SrcAddr.IsPrivate() && !f.DstAddr.IsPrivate() && f.DstAddr.IsGlobalUnicast() {
			key := exfilKey{
				srcIP: model.SafeIPString(f.SrcAddr),
				dstIP: model.SafeIPString(f.DstAddr),
			}

			s, ok := transfers[key]
			if !ok {
				s = &exfilStats{}
				transfers[key] = s
			}
			s.bytes += f.Bytes
			s.packets += f.Packets
		}
	}

	type result struct {
		key   exfilKey
		stats *exfilStats
	}
	var results []result

	for key, s := range transfers {
		if s.bytes >= exfiltrationMinBytes {
			results = append(results, result{
				key:   key,
				stats: s,
			})
		}
	}

	// Sort by highest data transfer first
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
		// Escalate to critical if volume exceeds 5x the minimum (2.5 GB)
		if r.stats.bytes >= exfiltrationMinBytes*5 {
			sev = CRITICAL
		}

		advisories = append(advisories, Advisory{
			Severity:  sev,
			Timestamp: now,
			Title:     fmt.Sprintf("Data Exfiltration: %s → %s", r.key.srcIP, r.key.dstIP),
			Description: fmt.Sprintf(
				"%s transferred %s (%s packets) to external IP %s in the last %s. "+
					"This large outbound transfer may indicate data exfiltration, unauthorized backup, or compromised host activity.",
				r.key.srcIP, util.FormatBytes(r.stats.bytes), util.FormatCount(r.stats.packets),
				r.key.dstIP, formatWindowShort(queryWindow(cfg)),
			),
			Action: fmt.Sprintf(
				"Investigate host %s to determine if the large data transfer to %s is legitimate. Consider blocking the destination IP if unauthorized.",
				r.key.srcIP, r.key.dstIP,
			),
		})
	}

	return advisories
}
