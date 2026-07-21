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

// DataExfiltrationDetector identifies unusually large outbound data transfers
// from private internal IP addresses to public external IP addresses, which
// could indicate data exfiltration, unauthorized backups, or compromised hosts.
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
		thresholdMB = 1024 // Fallback to 1GB
	}
	thresholdBytes := uint64(thresholdMB) * 1024 * 1024

	// Aggregate outbound bytes by (SrcAddr, DstAddr).
	type flowKey struct {
		src string
		dst string
	}

	transfers := make(map[flowKey]uint64)

	for _, f := range flows {
		if len(f.SrcAddr) == 0 || len(f.DstAddr) == 0 {
			continue
		}

		// Only look at traffic from private IPs to global unicast non-private IPs.
		if f.SrcAddr.IsPrivate() && f.DstAddr.IsGlobalUnicast() && !f.DstAddr.IsPrivate() {
			k := flowKey{
				src: model.SafeIPString(f.SrcAddr),
				dst: model.SafeIPString(f.DstAddr),
			}
			transfers[k] += f.Bytes
		}
	}

	type result struct {
		src   string
		dst   string
		bytes uint64
	}
	var results []result

	for k, b := range transfers {
		if b >= thresholdBytes {
			results = append(results, result{src: k.src, dst: k.dst, bytes: b})
		}
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].bytes > results[j].bytes
	})

	if len(results) > 10 {
		results = results[:10]
	}

	now := time.Now()
	var advisories []Advisory

	for _, r := range results {
		sev := WARNING
		// Escalate severity if the transfer is 5x the threshold
		if r.bytes >= thresholdBytes*5 {
			sev = CRITICAL
		}

		advisories = append(advisories, Advisory{
			Severity:  sev,
			Timestamp: now,
			Title:     fmt.Sprintf("Data Exfiltration: %s → %s", r.src, r.dst),
			Description: fmt.Sprintf(
				"%s transferred %s to external host %s in the last %s. "+
					"This exceeds the threshold of %d MB and may indicate data exfiltration or unauthorized upload.",
				r.src, util.FormatBytes(r.bytes), r.dst, formatWindowShort(queryWindow(cfg)), thresholdMB,
			),
			Action: fmt.Sprintf(
				"Investigate host %s and destination %s to determine if this large outbound transfer is legitimate.",
				r.src, r.dst,
			),
		})
	}

	return advisories
}
