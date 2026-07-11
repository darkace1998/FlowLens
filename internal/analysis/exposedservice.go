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

// ExposedServiceDetector identifies potentially dangerous exposure of internal
// management or database services (e.g., RDP, SMB, Telnet, Databases) to the
// public internet by looking for established connections from public IPs to
// private IPs on these ports.
type ExposedServiceDetector struct{}

func (ExposedServiceDetector) Name() string { return "Exposed Service Detector" }

var riskyPorts = map[uint16]string{
	23:    "Telnet",
	139:   "NetBIOS",
	445:   "SMB",
	1433:  "MSSQL",
	3306:  "MySQL",
	3389:  "RDP",
	5432:  "PostgreSQL",
	5900:  "VNC",
	6379:  "Redis",
	9200:  "Elasticsearch",
	11211: "Memcached",
	27017: "MongoDB",
}

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
		srcIP   string
	}

	type stats struct {
		packets uint64
		bytes   uint64
	}

	exposures := make(map[targetKey]*stats)

	for _, f := range flows {
		if f.Protocol != 6 && f.Protocol != 17 {
			continue
		}

		_, isRisky := riskyPorts[f.DstPort]
		if !isRisky {
			continue
		}

		// Require at least 3 packets to filter out simple dropped scanner SYN packets.
		if f.Packets < 3 {
			continue
		}

		if len(f.SrcAddr) == 0 || len(f.DstAddr) == 0 {
			continue
		}

		// Source must be a public IP.
		if f.SrcAddr.IsLoopback() || f.SrcAddr.IsUnspecified() || f.SrcAddr.IsPrivate() {
			continue
		}

		// Destination must be a private internal IP.
		if !f.DstAddr.IsPrivate() {
			continue
		}

		tk := targetKey{
			dstIP:   model.SafeIPString(f.DstAddr),
			dstPort: f.DstPort,
			srcIP:   model.SafeIPString(f.SrcAddr),
		}

		s, ok := exposures[tk]
		if !ok {
			s = &stats{}
			exposures[tk] = s
		}
		s.packets += f.Packets
		s.bytes += f.Bytes
	}

	type serviceKey struct {
		dstIP   string
		dstPort uint16
	}
	type serviceStats struct {
		sources map[string]struct{}
		packets uint64
		bytes   uint64
	}

	services := make(map[serviceKey]*serviceStats)
	for tk, s := range exposures {
		sk := serviceKey{dstIP: tk.dstIP, dstPort: tk.dstPort}
		ss, ok := services[sk]
		if !ok {
			ss = &serviceStats{sources: make(map[string]struct{})}
			services[sk] = ss
		}
		ss.sources[tk.srcIP] = struct{}{}
		ss.packets += s.packets
		ss.bytes += s.bytes
	}

	type result struct {
		sk    serviceKey
		stats *serviceStats
	}
	var results []result
	for sk, ss := range services {
		results = append(results, result{sk: sk, stats: ss})
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].stats.packets > results[j].stats.packets
	})

	if len(results) > 10 {
		results = results[:10]
	}

	now := time.Now()
	advisories := make([]Advisory, 0, len(results))

	for _, r := range results {
		serviceName := riskyPorts[r.sk.dstPort]
		advisories = append(advisories, Advisory{
			Severity:  CRITICAL,
			Timestamp: now,
			Title:     fmt.Sprintf("Exposed %s Service: %s", serviceName, r.sk.dstIP),
			Description: fmt.Sprintf(
				"Internal host %s accepted connections on port %d (%s) from %d public external IP(s). "+
					"This is highly insecure and exposes the network to ransomware or data breaches.",
				r.sk.dstIP, r.sk.dstPort, serviceName, len(r.stats.sources),
			),
			Action: fmt.Sprintf(
				"Immediately block external access to %s port %d at the firewall. Require a VPN or Zero Trust proxy for remote access.",
				r.sk.dstIP, r.sk.dstPort,
			),
		})
	}

	return advisories
}
