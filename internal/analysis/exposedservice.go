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

// ExposedServiceDetector analyzes flow data to identify traffic from public IPs
// to private IPs on common sensitive ports.
type ExposedServiceDetector struct{}

func (ExposedServiceDetector) Name() string { return "Exposed Service Detector" }

// sensitivePorts maps destination ports commonly considered sensitive to their services.
var sensitivePorts = map[uint16]string{
	20:    "FTP",
	21:    "FTP",
	22:    "SSH",
	23:    "Telnet",
	135:   "RPC",
	139:   "NetBIOS",
	445:   "SMB",
	1433:  "MSSQL",
	3306:  "MySQL",
	3389:  "RDP",
	5432:  "PostgreSQL",
	5900:  "VNC",
	5985:  "WinRM",
	5986:  "WinRM",
	6379:  "Redis",
	27017: "MongoDB",
}

// Analyze returns advisories about potential exposed services.
func (ExposedServiceDetector) Analyze(store storage.Storage, cfg config.AnalysisConfig) []Advisory {
	flows, err := store.Recent(queryWindow(cfg), 0)
	if err != nil {
		logging.Default().Error("ExposedServiceDetector: failed to query flows: %v", err)
		return nil
	}
	if len(flows) == 0 {
		return nil
	}

	// We want to detect a public source IP targeting a private destination IP + port.
	type targetKey struct {
		dstIP   string
		dstPort uint16
	}

	// Track the distinct public source IPs connecting to the exposed service.
	exposures := make(map[targetKey]map[string]struct{})

	for _, f := range flows {
		// Only consider TCP and UDP flows for exposed services.
		if f.Protocol != 6 && f.Protocol != 17 {
			continue
		}

		// Only check common sensitive ports.
		if _, ok := sensitivePorts[f.DstPort]; !ok {
			continue
		}

		// Ensure SrcAddr is populated
		if len(f.SrcAddr) == 0 {
			continue
		}

		// Check if source IP is public (Global Unicast and not Private)
		if !f.SrcAddr.IsGlobalUnicast() || f.SrcAddr.IsPrivate() {
			continue
		}

		// Ensure DstAddr is populated
		if len(f.DstAddr) == 0 {
			continue
		}

		// Check if destination IP is private
		if !f.DstAddr.IsPrivate() {
			continue
		}

		tk := targetKey{
			dstIP:   model.SafeIPString(f.DstAddr),
			dstPort: f.DstPort,
		}

		if _, ok := exposures[tk]; !ok {
			exposures[tk] = make(map[string]struct{})
		}
		exposures[tk][model.SafeIPString(f.SrcAddr)] = struct{}{}
	}

	type result struct {
		tk          targetKey
		sourceCount int
	}
	var results []result

	for tk, sources := range exposures {
		results = append(results, result{tk: tk, sourceCount: len(sources)})
	}

	// Sort by highest number of sources first
	sort.Slice(results, func(i, j int) bool {
		return results[i].sourceCount > results[j].sourceCount
	})

	if len(results) > 10 {
		results = results[:10]
	}

	now := time.Now()
	advisories := make([]Advisory, 0, len(results))

	for _, r := range results {
		service := sensitivePorts[r.tk.dstPort]

		sev := WARNING
		if r.sourceCount > 5 {
			sev = CRITICAL
		}

		sourceStr := fmt.Sprintf("%d distinct public IP", r.sourceCount)
		if r.sourceCount > 1 {
			sourceStr += "s"
		}

		advisories = append(advisories, Advisory{
			Severity:  sev,
			Timestamp: now,
			Title:     fmt.Sprintf("Exposed Service: %s (%s)", r.tk.dstIP, service),
			Description: fmt.Sprintf(
				"%s received traffic from %s on port %d (%s) in the last %s. "+
					"This indicates a potentially unintended exposed sensitive service.",
				r.tk.dstIP, sourceStr, r.tk.dstPort, service, formatWindowShort(queryWindow(cfg)),
			),
			Action: fmt.Sprintf(
				"Investigate %s for unintended internet exposure on port %d. Verify firewall and NAT rules.",
				r.tk.dstIP, r.tk.dstPort,
			),
		})
	}

	return advisories
}
