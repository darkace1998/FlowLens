package analysis

import (
	"fmt"
	"time"

	"github.com/darkace1998/FlowLens/internal/config"
	"github.com/darkace1998/FlowLens/internal/logging"
	"github.com/darkace1998/FlowLens/internal/storage"
)

// DNSVolume analyzes flow data to detect excessive DNS query rates.
// It counts TCP and UDP flows to port 53 and compares against total flow volume.
type DNSVolume struct{}

func (DNSVolume) Name() string { return "DNS Volume" }

// dnsRateThreshold is the minimum DNS flows per minute to trigger any advisory.
const dnsRateThreshold = 100

// dnsRatioThreshold is the percentage of DNS flows relative to total.
// Above this, an advisory is generated.
const dnsRatioThreshold = 30.0

// Analyze returns advisories about excessive DNS traffic.
func (DNSVolume) Analyze(store *storage.RingBuffer, cfg config.AnalysisConfig) []Advisory {
	flows, err := store.Recent(queryWindow(cfg), 0)
	if err != nil {
		logging.Default().Error("DNSVolume: failed to query recent flows: %v", err)
		return nil
	}
	if len(flows) == 0 {
		return nil
	}

	var dnsFlows, dnsBytes, dnsPackets, totalFlows uint64

	for _, f := range flows {
		totalFlows++
		// DNS: UDP (17) to port 53, or TCP (6) to port 53.
		if (f.Protocol == 17 || f.Protocol == 6) && (f.DstPort == 53 || f.SrcPort == 53) {
			dnsFlows++
			dnsBytes += f.Bytes
			dnsPackets += f.Packets
		}
	}

	if dnsFlows == 0 {
		return nil
	}

	dnsRatePerMin := float64(dnsFlows) / 10.0 // flows per minute over 10-min window
	dnsRatio := float64(dnsFlows) / float64(totalFlows) * 100

	now := time.Now()
	var advisories []Advisory

	// Check absolute rate threshold.
	if dnsRatePerMin >= dnsRateThreshold {
		sev := WARNING
		if dnsRatePerMin >= dnsRateThreshold*5 {
			sev = CRITICAL
		}

		advisories = append(advisories, Advisory{
			Severity:  sev,
			Timestamp: now,
			Title:     "High DNS Query Rate",
			Description: fmt.Sprintf(
				"%.0f DNS flows/min detected (%d total DNS flows, %s bytes, %s packets in last 10 minutes). "+
					"Threshold: %d flows/min.",
				dnsRatePerMin, dnsFlows,
				formatBytesShort(dnsBytes), formatCountShort(dnsPackets),
				dnsRateThreshold,
			),
			Action: dnsRateAction(sev),
		})
	}

	// Check ratio threshold.
	if dnsRatio >= dnsRatioThreshold {
		sev := WARNING
		if dnsRatio >= 60 {
			sev = CRITICAL
		}

		advisories = append(advisories, Advisory{
			Severity:  sev,
			Timestamp: now,
			Title:     "High DNS Traffic Ratio",
			Description: fmt.Sprintf(
				"DNS traffic accounts for %.1f%% of all flows (%d/%d). "+
					"This may indicate DNS tunneling, amplification, or misconfigured resolvers.",
				dnsRatio, dnsFlows, totalFlows,
			),
			Action: dnsRatioAction(sev),
		})
	}

	return advisories
}

func dnsRateAction(sev Severity) string {
	switch sev {
	case CRITICAL:
		return "Investigate DNS traffic immediately — extremely high query rate may indicate tunneling or amplification attack."
	default:
		return "Review DNS query sources — elevated rate may indicate misconfigured resolver or data exfiltration."
	}
}

func dnsRatioAction(sev Severity) string {
	switch sev {
	case CRITICAL:
		return "Investigate immediately — DNS is dominating traffic, likely tunneling or amplification."
	default:
		return "Review DNS sources and destinations — disproportionate DNS volume detected."
	}
}
