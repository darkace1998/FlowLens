package analysis

import (
	"fmt"
	"time"

	"github.com/darkace1998/FlowLens/internal/config"
	"github.com/darkace1998/FlowLens/internal/logging"
	"github.com/darkace1998/FlowLens/internal/model"
	"github.com/darkace1998/FlowLens/internal/storage"
)

// LandAttackDetector identifies traffic where the source and destination
// IP addresses are identical. This is typically indicative of a spoofed
// LAND attack attempting to cause a denial of service.
type LandAttackDetector struct{}

func (LandAttackDetector) Name() string { return "LAND Attack Detector" }

// Analyze returns advisories about potential LAND attacks (src == dst).
func (LandAttackDetector) Analyze(store storage.Storage, cfg config.AnalysisConfig) []Advisory {
	flows, err := store.Recent(queryWindow(cfg), 0)
	if err != nil {
		logging.Default().Error("LandAttackDetector: failed to query flows: %v", err)
		return nil
	}
	if len(flows) == 0 {
		return nil
	}

	// Group by target IP to avoid spamming the same advisory repeatedly
	// if an attack sends multiple packets.
	type attackStats struct {
		Packets uint64
		Bytes   uint64
		Port    uint16
	}
	attacks := make(map[string]*attackStats)

	for _, f := range flows {
		// Only consider flows where the IP is the same. Loopback (127.0.0.0/8)
		// might legitimately communicate with itself, but usually src and dst
		// IP are both 127.0.0.1. Wait, loopback is normal. Should we exclude 127.0.0.1?
		// Actually, standard loopback communication (127.0.0.1 to 127.0.0.1) is normal.
		// Let's exclude loopback addresses from this detection.
		if len(f.SrcAddr) == 0 || len(f.DstAddr) == 0 {
			continue
		}
		if f.SrcAddr.IsLoopback() || f.DstAddr.IsLoopback() {
			continue
		}
		if f.SrcAddr.IsUnspecified() || f.DstAddr.IsUnspecified() {
			continue
		}

		if f.SrcAddr.Equal(f.DstAddr) {
			ipStr := model.SafeIPString(f.SrcAddr)
			if s, ok := attacks[ipStr]; ok {
				s.Packets += f.Packets
				s.Bytes += f.Bytes
			} else {
				attacks[ipStr] = &attackStats{
					Packets: f.Packets,
					Bytes:   f.Bytes,
					Port:    f.DstPort, // keep a sample port
				}
			}
		}
	}

	if len(attacks) == 0 {
		return nil
	}

	now := time.Now()
	advisories := make([]Advisory, 0, len(attacks))

	for ip, stats := range attacks {
		advisories = append(advisories, Advisory{
			Severity:  CRITICAL,
			Timestamp: now,
			Title:     fmt.Sprintf("LAND Attack Detected: %s", ip),
			Description: fmt.Sprintf(
				"%d packets (%d bytes) were detected where the source and destination IP addresses are identically %s. "+
					"This is highly indicative of a spoofed LAND attack.",
				stats.Packets, stats.Bytes, ip,
			),
			Action: fmt.Sprintf(
				"Investigate the network segment for IP spoofing. Ensure anti-spoofing (BCP38) and drop rules for same-source-destination traffic are in place.",
			),
		})
	}

	return advisories
}
