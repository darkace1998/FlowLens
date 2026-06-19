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

// AmplificationDetector identifies potential DDoS reflection/amplification
// attacks by monitoring UDP traffic originating from common amplification
// ports (like DNS, NTP, SSDP) directed at a single destination.
type AmplificationDetector struct{}

func (AmplificationDetector) Name() string { return "Amplification Attack Detector" }

// commonAmplificationPorts maps source ports commonly used in amplification
// attacks to their service names.
var commonAmplificationPorts = map[uint16]string{
	19:    "Chargen",
	53:    "DNS",
	111:   "Portmap",
	123:   "NTP",
	137:   "NetBIOS",
	161:   "SNMP",
	389:   "LDAP",
	1900:  "SSDP",
	3389:  "RDP",
	11211: "Memcached",
}

// amplificationMinBytes is the minimum byte volume required from an
// amplification port to a single destination to generate an advisory.
const amplificationMinBytes = 1000000 // 1 MB

// Analyze returns advisories about potential amplification attacks.
func (AmplificationDetector) Analyze(store storage.Storage, cfg config.AnalysisConfig) []Advisory {
	flows, err := store.Recent(queryWindow(cfg), 0)
	if err != nil {
		logging.Default().Error("AmplificationDetector: failed to query recent flows: %v", err)
		return nil
	}
	if len(flows) == 0 {
		return nil
	}

	// Track volume per destination IP and source port.
	type targetKey struct {
		dstIP   string
		srcPort uint16
	}
	type targetStats struct {
		bytes   uint64
		packets uint64
		sources map[string]struct{}
	}

	targets := make(map[targetKey]*targetStats)

	for _, f := range flows {
		// Reflection/amplification relies on connectionless UDP.
		if f.Protocol != 17 {
			continue
		}

		if _, isAmpPort := commonAmplificationPorts[f.SrcPort]; !isAmpPort {
			continue
		}

		tk := targetKey{dstIP: model.SafeIPString(f.DstAddr), srcPort: f.SrcPort}
		s, ok := targets[tk]
		if !ok {
			s = &targetStats{sources: make(map[string]struct{})}
			targets[tk] = s
		}
		s.bytes += f.Bytes
		s.packets += f.Packets
		s.sources[model.SafeIPString(f.SrcAddr)] = struct{}{}
	}

	type result struct {
		tk      targetKey
		stats   *targetStats
		service string
	}
	results := make([]result, 0, len(targets))

	for tk, s := range targets {
		if s.bytes < amplificationMinBytes {
			continue
		}
		// A true DDoS typically involves many reflectors.
		if len(s.sources) < 5 {
			continue
		}

		results = append(results, result{
			tk:      tk,
			stats:   s,
			service: commonAmplificationPorts[tk.srcPort],
		})
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
		if r.stats.bytes >= amplificationMinBytes*10 {
			sev = CRITICAL
		}

		advisories = append(advisories, Advisory{
			Severity:  sev,
			Timestamp: now,
			Title:     fmt.Sprintf("Amplification Attack: %s (%s)", r.tk.dstIP, r.service),
			Description: fmt.Sprintf(
				"%s received %s (%s packets) of %s UDP traffic (port %d) from %d unique sources. "+
					"This strongly indicates a reflection/amplification DDoS attack.",
				r.tk.dstIP, util.FormatBytes(r.stats.bytes), util.FormatCount(r.stats.packets),
				r.service, r.tk.srcPort, len(r.stats.sources),
			),
			Action: amplificationAction(sev),
		})
	}

	return advisories
}

func amplificationAction(sev Severity) string {
	switch sev {
	case CRITICAL:
		return "Investigate immediately — target is actively under a significant reflection/amplification DDoS attack."
	default:
		return "Monitor destination — elevated UDP traffic from common amplification ports detected."
	}
}
