package analysis

import (
	"fmt"
	"time"

	"github.com/darkace1998/FlowLens/internal/config"
	"github.com/darkace1998/FlowLens/internal/storage"
)

// ScanDetector analyzes flow data to identify potential port scans and
// network sweeps based on the number of unique destination ports contacted
// by a single source within the analysis window.
type ScanDetector struct{}

func (ScanDetector) Name() string { return "Port Scan Detector" }

// Analyze returns advisories about potential port scans or sweeps.
func (ScanDetector) Analyze(store *storage.RingBuffer, cfg config.AnalysisConfig) []Advisory {
	flows, _ := store.Recent(10*time.Minute, 0)
	if len(flows) == 0 {
		return nil
	}

	// Track unique destination (IP:port) pairs per source IP.
	type scanKey struct {
		DstIP   string
		DstPort uint16
	}
	srcPorts := make(map[string]map[scanKey]struct{})

	for _, f := range flows {
		// Only consider TCP and UDP flows for scan detection.
		if f.Protocol != 6 && f.Protocol != 17 {
			continue
		}

		src := f.SrcAddr.String()
		key := scanKey{DstIP: f.DstAddr.String(), DstPort: f.DstPort}

		if _, ok := srcPorts[src]; !ok {
			srcPorts[src] = make(map[scanKey]struct{})
		}
		srcPorts[src][key] = struct{}{}
	}

	threshold := cfg.ScanThreshold
	if threshold <= 0 {
		threshold = 500
	}

	now := time.Now()
	var advisories []Advisory

	for src, ports := range srcPorts {
		uniqueCount := len(ports)
		if uniqueCount < threshold {
			continue
		}

		sev := WARNING
		if uniqueCount >= threshold*3 {
			sev = CRITICAL
		}

		advisories = append(advisories, Advisory{
			Severity:  sev,
			Timestamp: now,
			Title:     fmt.Sprintf("Port Scan Detected: %s", src),
			Description: fmt.Sprintf(
				"%s contacted %d unique destination port/IP combinations in the last 10 minutes (threshold: %d).",
				src, uniqueCount, threshold,
			),
			Action: fmt.Sprintf(
				"Investigate %s for potential reconnaissance activity. Consider blocking if unauthorized.",
				src,
			),
		})
	}

	return advisories
}
