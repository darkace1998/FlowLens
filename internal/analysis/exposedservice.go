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

// ExposedServiceDetector identifies connections from public IP addresses
// to internal hosts on sensitive ports (e.g., SSH, RDP, databases).
// This can highlight unintended exposure of internal services to the internet.
type ExposedServiceDetector struct{}

func (ExposedServiceDetector) Name() string { return "Exposed Service Detector" }

// sensitivePorts maps destination ports that should typically not be
// exposed to the internet to their service names.
var sensitivePorts = map[uint16]string{
	22:    "SSH",
	23:    "Telnet",
	445:   "SMB",
	1433:  "MSSQL",
	3306:  "MySQL",
	3389:  "RDP",
	5432:  "PostgreSQL",
	5900:  "VNC",
	6379:  "Redis",
	11211: "Memcached",
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

	// We want to detect connections where the destination is an internal IP
	// and the source is a public IP, targeting a sensitive port.
	type targetKey struct {
		dstIP   string
		dstPort uint16
	}

	type stats struct {
		sources map[string]struct{}
		packets uint64
		bytes   uint64
	}

	exposed := make(map[targetKey]*stats)

	for _, f := range flows {
		// Only TCP/UDP flows make sense for these exposed services
		if f.Protocol != 6 && f.Protocol != 17 {
			continue
		}

		if _, isSensitive := sensitivePorts[f.DstPort]; !isSensitive {
			continue
		}

		// Check if destination is internal (private)
		if !f.DstAddr.IsPrivate() {
			continue
		}

		// Check if source is public
		// Needs to be global unicast and not private
		if !f.SrcAddr.IsGlobalUnicast() || f.SrcAddr.IsPrivate() {
			continue
		}

		tk := targetKey{
			dstIP:   model.SafeIPString(f.DstAddr),
			dstPort: f.DstPort,
		}

		s, ok := exposed[tk]
		if !ok {
			s = &stats{sources: make(map[string]struct{})}
			exposed[tk] = s
		}
		s.sources[model.SafeIPString(f.SrcAddr)] = struct{}{}
		s.packets += f.Packets
		s.bytes += f.Bytes
	}

	type result struct {
		tk      targetKey
		stats   *stats
		service string
	}
	var results []result

	for tk, s := range exposed {
		results = append(results, result{
			tk:      tk,
			stats:   s,
			service: sensitivePorts[tk.dstPort],
		})
	}

	// Sort by number of unique sources, then by bytes
	sort.Slice(results, func(i, j int) bool {
		li, lj := len(results[i].stats.sources), len(results[j].stats.sources)
		if li == lj {
			return results[i].stats.bytes > results[j].stats.bytes
		}
		return li > lj
	})

	if len(results) > 10 {
		results = results[:10]
	}

	now := time.Now()
	advisories := make([]Advisory, 0, len(results))

	for _, r := range results {
		sev := WARNING
		// If multiple public IPs are interacting with the exposed service, it might be heavily scanned or compromised.
		if len(r.stats.sources) > 5 {
			sev = CRITICAL
		}

		advisories = append(advisories, Advisory{
			Severity:  sev,
			Timestamp: now,
			Title:     fmt.Sprintf("Exposed Service: %s (%s)", r.tk.dstIP, r.service),
			Description: fmt.Sprintf(
				"Internal host %s received traffic on sensitive port %d (%s) from %d unique public IP(s).",
				r.tk.dstIP, r.tk.dstPort, r.service, len(r.stats.sources),
			),
			Action: fmt.Sprintf(
				"Verify if %s should be accessible from the internet on port %d. Consider restricting access via firewall or VPN.",
				r.tk.dstIP, r.tk.dstPort,
			),
		})
	}

	return advisories
}
