package analysis

import (
	"fmt"
	"time"

	"github.com/darkace1998/FlowLens/internal/config"
	"github.com/darkace1998/FlowLens/internal/logging"
	"github.com/darkace1998/FlowLens/internal/model"
	"github.com/darkace1998/FlowLens/internal/storage"
)

// PortZeroDetector identifies traffic that uses TCP or UDP port 0.
// Port 0 is a reserved port and should not be used in legitimate traffic.
// Traffic on this port often indicates OS fingerprinting, port scanning,
// evasion techniques, or malicious attacks.
type PortZeroDetector struct{}

func (PortZeroDetector) Name() string { return "Port Zero Traffic Detector" }

// Analyze returns advisories about traffic involving port 0.
func (PortZeroDetector) Analyze(store storage.Storage, cfg config.AnalysisConfig) []Advisory {
	flows, err := store.Recent(queryWindow(cfg), 0)
	if err != nil {
		logging.Default().Error("PortZeroDetector: failed to query flows: %v", err)
		return nil
	}
	if len(flows) == 0 {
		return nil
	}

	// We will group by source IP to aggregate the alerts.
	type stats struct {
		targets map[string]struct{}
		packets uint64
		bytes   uint64
	}
	sources := make(map[string]*stats)

	for _, f := range flows {
		// Only consider TCP and UDP where Port 0 is invalid
		if f.Protocol != 6 && f.Protocol != 17 {
			continue
		}

		if f.SrcPort == 0 || f.DstPort == 0 {
			srcStr := model.SafeIPString(f.SrcAddr)
			s, ok := sources[srcStr]
			if !ok {
				s = &stats{targets: make(map[string]struct{})}
				sources[srcStr] = s
			}
			s.targets[model.SafeIPString(f.DstAddr)] = struct{}{}
			s.packets += f.Packets
			s.bytes += f.Bytes
		}
	}

	if len(sources) == 0 {
		return nil
	}

	now := time.Now()
	advisories := make([]Advisory, 0, len(sources))

	for src, s := range sources {
		sev := WARNING
		if s.packets > 100 || len(s.targets) > 10 {
			sev = CRITICAL
		}

		advisories = append(advisories, Advisory{
			Severity:  sev,
			Timestamp: now,
			Title:     fmt.Sprintf("Invalid Port 0 Traffic: %s", src),
			Description: fmt.Sprintf(
				"%s sent or received %d packets (%d bytes) using TCP/UDP port 0 to %d unique targets. "+
					"Port 0 is reserved and typically indicates OS fingerprinting, network scanning, or malicious evasion.",
				src, s.packets, s.bytes, len(s.targets),
			),
			Action: fmt.Sprintf(
				"Investigate %s for malicious activity or misconfiguration. Ensure firewall rules explicitly drop all traffic to and from port 0.",
				src,
			),
		})
	}

	return advisories
}
