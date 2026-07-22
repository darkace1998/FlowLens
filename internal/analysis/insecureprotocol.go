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

// InsecureProtocolDetector identifies the use of well-known insecure (plaintext)
// protocols such as Telnet, FTP, TFTP, and POP3, and generates advisories for
// the servers exposing them.
type InsecureProtocolDetector struct{}

func (InsecureProtocolDetector) Name() string { return "Insecure Protocol Detector" }

// insecurePorts maps insecure service ports to their names.
var insecurePorts = map[uint16]string{
	21:  "FTP",
	23:  "Telnet",
	69:  "TFTP",
	110: "POP3",
	143: "IMAP",
	513: "rlogin",
	514: "rsh", // Note: 514 UDP is syslog, 514 TCP is rsh. We handle proto in Analyze.
}

// Analyze returns advisories about the use of insecure protocols.
func (InsecureProtocolDetector) Analyze(store storage.Storage, cfg config.AnalysisConfig) []Advisory {
	flows, err := store.Recent(queryWindow(cfg), 0)
	if err != nil {
		logging.Default().Error("InsecureProtocolDetector: failed to query recent flows: %v", err)
		return nil
	}
	if len(flows) == 0 {
		return nil
	}

	// Track stats per server IP and Port.
	type serverKey struct {
		ip   string
		port uint16
	}
	type serverStats struct {
		service string
		bytes   uint64
		packets uint64
		sources map[string]struct{}
	}

	servers := make(map[serverKey]*serverStats)

	for _, f := range flows {
		// Only consider TCP and UDP.
		if f.Protocol != 6 && f.Protocol != 17 {
			continue
		}

		// Identify if this flow involves an insecure port.
		// A flow might be client->server (DstPort is insecure) or
		// server->client (SrcPort is insecure).
		var serverIP string
		var clientIP string
		var insecurePort uint16

		if svc, ok := insecurePorts[f.DstPort]; ok {
			// Specific check: rsh is TCP only on 514. UDP 514 is syslog, not considered insecure for this detector in the same way.
			if f.DstPort == 514 && f.Protocol != 6 {
				goto CheckSrc // check the other port just in case
			}
			serverIP = model.SafeIPString(f.DstAddr)
			clientIP = model.SafeIPString(f.SrcAddr)
			insecurePort = f.DstPort
			_ = svc
		} else {
			goto CheckSrc
		}
		goto AddFlow

	CheckSrc:
		if svc, ok := insecurePorts[f.SrcPort]; ok {
			if f.SrcPort == 514 && f.Protocol != 6 {
				continue
			}
			serverIP = model.SafeIPString(f.SrcAddr)
			clientIP = model.SafeIPString(f.DstAddr)
			insecurePort = f.SrcPort
			_ = svc
		} else {
			continue
		}

	AddFlow:
		sk := serverKey{ip: serverIP, port: insecurePort}
		s, ok := servers[sk]
		if !ok {
			s = &serverStats{
				service: insecurePorts[insecurePort],
				sources: make(map[string]struct{}),
			}
			servers[sk] = s
		}
		s.bytes += f.Bytes
		s.packets += f.Packets
		s.sources[clientIP] = struct{}{}
	}

	if len(servers) == 0 {
		return nil
	}

	type result struct {
		sk    serverKey
		stats *serverStats
	}
	results := make([]result, 0, len(servers))
	for sk, stats := range servers {
		results = append(results, result{sk: sk, stats: stats})
	}

	// Sort by bytes descending
	sort.Slice(results, func(i, j int) bool {
		return results[i].stats.bytes > results[j].stats.bytes
	})

	if len(results) > 10 {
		results = results[:10]
	}

	now := time.Now()
	advisories := make([]Advisory, 0, len(results))

	for _, r := range results {
		// All insecure protocol usage is at least a WARNING.
		advisories = append(advisories, Advisory{
			Severity:  WARNING,
			Timestamp: now,
			Title:     fmt.Sprintf("Insecure Protocol Used: %s (%s)", r.stats.service, r.sk.ip),
			Description: fmt.Sprintf(
				"%s traffic (%s) was observed involving server %s. "+
					"%s (%s packets) exchanged with %d unique client(s). "+
					"Plaintext protocols expose credentials and data to interception.",
				r.stats.service, r.stats.service, r.sk.ip,
				util.FormatBytes(r.stats.bytes), util.FormatCount(r.stats.packets),
				len(r.stats.sources),
			),
			Action: fmt.Sprintf(
				"Investigate %s for exposing %s. Migrate to a secure alternative (e.g., SSH, SFTP, IMAPS) or restrict access.",
				r.sk.ip, r.stats.service,
			),
		})
	}

	return advisories
}
