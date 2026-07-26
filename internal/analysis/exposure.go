package analysis

import (
	"fmt"
	"net"
	"sort"
	"time"

	"github.com/darkace1998/FlowLens/internal/config"
	"github.com/darkace1998/FlowLens/internal/logging"
	"github.com/darkace1998/FlowLens/internal/model"
	"github.com/darkace1998/FlowLens/internal/storage"
)

// ExposedServiceDetector analyzes flow data to identify sensitive internal services
// exposed to the public internet, or internal hosts initiating connections to public sensitive services.
type ExposedServiceDetector struct{}

func (ExposedServiceDetector) Name() string { return "Exposed Service Detector" }

// sensitivePorts maps destination ports considered sensitive to their services.
// Exposing these to the public internet is generally a security risk.
var sensitivePorts = map[uint16]string{
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
	5985:  "WinRM (HTTP)",
	5986:  "WinRM (HTTPS)",
	6379:  "Redis",
	9200:  "Elasticsearch",
	11211: "Memcached",
	27017: "MongoDB",
}

func isPublic(ip net.IP) bool {
	if len(ip) == 0 || ip.IsLoopback() || ip.IsUnspecified() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() || !ip.IsGlobalUnicast() {
		return false
	}
	return true
}

func isPrivate(ip net.IP) bool {
	if len(ip) == 0 {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
}

// Analyze returns advisories about exposed sensitive services.
func (ExposedServiceDetector) Analyze(store storage.Storage, cfg config.AnalysisConfig) []Advisory {
	flows, err := store.Recent(queryWindow(cfg), 0)
	if err != nil {
		logging.Default().Error("ExposedServiceDetector: failed to query flows: %v", err)
		return nil
	}
	if len(flows) == 0 {
		return nil
	}

	type exposureKey struct {
		PrivateIP string
		PublicIP  string
		Port      uint16
		IsInbound bool // true if Public -> Private, false if Private -> Public
	}

	type exposureStats struct {
		Packets uint64
		Bytes   uint64
	}

	exposures := make(map[exposureKey]*exposureStats)

	for _, f := range flows {
		// Only consider TCP flows for sensitive services.
		if f.Protocol != 6 {
			continue
		}

		if _, ok := sensitivePorts[f.DstPort]; !ok {
			continue
		}

		// Require at least 3 packets to filter out background scanning (like single SYN packets).
		// A full TCP handshake and some data transfer requires 3+ packets.
		if f.Packets < 3 {
			continue
		}

		srcIsPub := isPublic(f.SrcAddr)
		srcIsPriv := isPrivate(f.SrcAddr)
		dstIsPub := isPublic(f.DstAddr)
		dstIsPriv := isPrivate(f.DstAddr)

		var key exposureKey
		var valid bool

		// Inbound: Public IP -> Private IP
		if srcIsPub && dstIsPriv {
			key = exposureKey{
				PrivateIP: model.SafeIPString(f.DstAddr),
				PublicIP:  model.SafeIPString(f.SrcAddr),
				Port:      f.DstPort,
				IsInbound: true,
			}
			valid = true
		} else if srcIsPriv && dstIsPub {
			// Outbound: Private IP -> Public IP
			key = exposureKey{
				PrivateIP: model.SafeIPString(f.SrcAddr),
				PublicIP:  model.SafeIPString(f.DstAddr),
				Port:      f.DstPort,
				IsInbound: false,
			}
			valid = true
		}

		if valid {
			if s, ok := exposures[key]; ok {
				s.Packets += f.Packets
				s.Bytes += f.Bytes
			} else {
				exposures[key] = &exposureStats{
					Packets: f.Packets,
					Bytes:   f.Bytes,
				}
			}
		}
	}

	type result struct {
		Key   exposureKey
		Stats *exposureStats
	}

	var results []result
	for k, s := range exposures {
		results = append(results, result{Key: k, Stats: s})
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Stats.Packets > results[j].Stats.Packets
	})

	if len(results) > 15 {
		results = results[:15]
	}

	now := time.Now()
	advisories := make([]Advisory, 0, len(results))
	windowStr := formatWindowShort(queryWindow(cfg))

	for _, r := range results {
		service := sensitivePorts[r.Key.Port]

		var title, description, action string
		sev := WARNING // Outbound is warning, inbound is critical

		if r.Key.IsInbound {
			sev = CRITICAL
			title = fmt.Sprintf("Exposed Sensitive Service: %s:%d (%s)", r.Key.PrivateIP, r.Key.Port, service)
			description = fmt.Sprintf(
				"Internal host %s received traffic on sensitive port %d (%s) from public IP %s (%d packets, %d bytes) in the last %s. "+
					"Exposing this service to the internet is highly risky.",
				r.Key.PrivateIP, r.Key.Port, service, r.Key.PublicIP, r.Stats.Packets, r.Stats.Bytes, windowStr,
			)
			action = fmt.Sprintf("Investigate firewall rules exposing %s:%d to the internet and restrict access.", r.Key.PrivateIP, r.Key.Port)
		} else {
			title = fmt.Sprintf("Outbound Sensitive Traffic: %s → %s:%d (%s)", r.Key.PrivateIP, r.Key.PublicIP, r.Key.Port, service)
			description = fmt.Sprintf(
				"Internal host %s connected to public IP %s on sensitive port %d (%s) (%d packets, %d bytes) in the last %s. "+
					"This could indicate data exfiltration or policy violation.",
				r.Key.PrivateIP, r.Key.PublicIP, r.Key.Port, service, r.Stats.Packets, r.Stats.Bytes, windowStr,
			)
			action = fmt.Sprintf("Verify if outbound %s traffic from %s is authorized.", service, r.Key.PrivateIP)
		}

		advisories = append(advisories, Advisory{
			Severity:    sev,
			Timestamp:   now,
			Title:       title,
			Description: description,
			Action:      action,
		})
	}

	return advisories
}
