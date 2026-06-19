package analysis

import (
	"fmt"
	"time"

	"github.com/darkace1998/FlowLens/internal/config"
	"github.com/darkace1998/FlowLens/internal/logging"
	"github.com/darkace1998/FlowLens/internal/model"
	"github.com/darkace1998/FlowLens/internal/storage"
)

// ScanDetector analyzes flow data to identify potential port scans and
// network sweeps based on the number of unique destination ports contacted
// by a single source within the analysis window.
type ScanDetector struct{}

func (ScanDetector) Name() string { return "Port Scan Detector" }

// Analyze returns advisories about potential port scans or sweeps.
func (ScanDetector) Analyze(store storage.Storage, cfg config.AnalysisConfig) []Advisory {
	flows, err := store.Recent(queryWindow(cfg), 0)
	if err != nil {
		logging.Default().Error("ScanDetector: failed to query flows: %v", err)
		return nil
	}
	if len(flows) == 0 {
		return nil
	}

	// Track unique destination (IP:port) pairs per source IP.
	type scanKey struct {
		DstIP   [16]byte
		DstPort uint16
	}
	srcPorts := make(map[[16]byte]map[scanKey]struct{})

	to16 := func(ip []byte) [16]byte {
		var k [16]byte
		if len(ip) == 16 {
			copy(k[:], ip)
		} else if len(ip) == 4 {
			k[10] = 0xff
			k[11] = 0xff
			copy(k[12:], ip)
		}
		return k
	}

	for _, f := range flows {
		// Only consider TCP and UDP flows for scan detection.
		if f.Protocol != 6 && f.Protocol != 17 {
			continue
		}

		src := to16(f.SrcAddr)
		key := scanKey{DstIP: to16(f.DstAddr), DstPort: f.DstPort}

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
	advisories := make([]Advisory, 0, len(srcPorts))

	for src, ports := range srcPorts {
		uniqueCount := len(ports)
		if uniqueCount < threshold {
			continue
		}

		srcStr := ""
		if src == [16]byte{} {
			srcStr = "0.0.0.0"
		} else {
			// Convert back using net.IP
			// We can format it explicitly or rely on fmt %v but we need net package or we need to import it
			srcStr = model.SafeIPString(src[:])
		}

		sev := WARNING
		if uniqueCount >= threshold*3 {
			sev = CRITICAL
		}

		advisories = append(advisories, Advisory{
			Severity:  sev,
			Timestamp: now,
			Title:     fmt.Sprintf("Port Scan Detected: %s", srcStr),
			Description: fmt.Sprintf(
				"%s contacted %d unique destination port/IP combinations in the last %s (threshold: %d).",
				srcStr, uniqueCount, formatWindowShort(queryWindow(cfg)), threshold,
			),
			Action: fmt.Sprintf(
				"Investigate %s for potential reconnaissance activity. Consider blocking if unauthorized.",
				srcStr,
			),
		})
	}

	return advisories
}
