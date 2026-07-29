package analysis

import (
	"fmt"
	"sort"
	"time"

	"github.com/darkace1998/FlowLens/internal/config"
	"github.com/darkace1998/FlowLens/internal/logging"
	"github.com/darkace1998/FlowLens/internal/model"
	"github.com/darkace1998/FlowLens/internal/storage"
)

// ExposedServiceDetector analyzes flow data to identify traffic from public
// Internet IP addresses connecting to sensitive internal administrative or
// database ports (e.g., Telnet, SMB, RDP, databases).
type ExposedServiceDetector struct{}

func (ExposedServiceDetector) Name() string { return "Exposed Service Detector" }

// sensitivePorts maps destination ports that should generally not be exposed
// to the public internet.
var sensitivePorts = map[uint16]string{
	23:    "Telnet",
	139:   "NetBIOS",
	445:   "SMB",
	1433:  "MSSQL",
	1521:  "Oracle",
	3306:  "MySQL",
	3389:  "RDP",
	5432:  "PostgreSQL",
	5900:  "VNC",
	6379:  "Redis",
	27017: "MongoDB",
}

// Analyze returns advisories about internal services exposed to public IPs.
func (ExposedServiceDetector) Analyze(store storage.Storage, cfg config.AnalysisConfig) []Advisory {
	flows, err := store.Recent(queryWindow(cfg), 0)
	if err != nil {
		logging.Default().Error("ExposedServiceDetector: failed to query flows: %v", err)
		return nil
	}
	if len(flows) == 0 {
		return nil
	}

	type targetKey struct {
		dstIP   string
		dstPort uint16
	}

	// Count connections per targeted service
	exposures := make(map[targetKey]int)

	for _, f := range flows {
		// Ensure IPs are valid before checking
		if len(f.SrcAddr) == 0 || len(f.DstAddr) == 0 {
			continue
		}

		// Only check TCP (most sensitive services) and UDP (some like NetBIOS)
		if f.Protocol != 6 && f.Protocol != 17 {
			continue
		}

		// Check if destination port is a sensitive service
		if _, ok := sensitivePorts[f.DstPort]; !ok {
			continue
		}

		// A public IP is one that is global unicast, not private, and not loopback
		isPublicSrc := f.SrcAddr.IsGlobalUnicast() && !f.SrcAddr.IsPrivate() && !f.SrcAddr.IsLoopback()
		if !isPublicSrc {
			continue
		}

		// Optional: filter out cases where destination is also public.
		// Usually we care when a private/internal IP is targeted by a public IP.
		// For simplicity we'll alert on any public source hitting these ports.

		tk := targetKey{
			dstIP:   model.SafeIPString(f.DstAddr),
			dstPort: f.DstPort,
		}
		exposures[tk]++
	}

	type result struct {
		tk    targetKey
		count int
	}
	var results []result

	for tk, count := range exposures {
		results = append(results, result{tk: tk, count: count})
	}

	// Sort by highest number of hits first
	sort.Slice(results, func(i, j int) bool {
		return results[i].count > results[j].count
	})

	if len(results) > 10 {
		results = results[:10]
	}

	now := time.Now()
	advisories := make([]Advisory, 0, len(results))

	for _, r := range results {
		service := sensitivePorts[r.tk.dstPort]

		advisories = append(advisories, Advisory{
			Severity:  CRITICAL,
			Timestamp: now,
			Title:     fmt.Sprintf("Exposed Service: %s on %s", service, r.tk.dstIP),
			Description: fmt.Sprintf(
				"%s received %d connection(s) on sensitive port %d (%s) from public Internet IPs in the last %s. "+
					"This strongly indicates the service is dangerously exposed.",
				r.tk.dstIP, r.count, r.tk.dstPort, service, formatWindowShort(queryWindow(cfg)),
			),
			Action: fmt.Sprintf(
				"Investigate %s firewall rules immediately. Block public access to port %d.",
				r.tk.dstIP, r.tk.dstPort,
			),
		})
	}

	return advisories
}
