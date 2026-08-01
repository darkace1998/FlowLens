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

// CleartextProtocolDetector analyzes flow data to identify the use of insecure,
// unencrypted cleartext protocols (such as FTP, Telnet, POP3, IMAP, TFTP).
type CleartextProtocolDetector struct{}

func (CleartextProtocolDetector) Name() string { return "Cleartext Protocol Detector" }

type cleartextService struct {
	Name     string
	Protocol uint8 // 6 for TCP, 17 for UDP
}

// cleartextPorts maps ports to their insecure service definitions.
var cleartextPorts = map[uint16]cleartextService{
	21:  {"FTP", 6},
	23:  {"Telnet", 6},
	69:  {"TFTP", 17},
	110: {"POP3", 6},
	143: {"IMAP", 6},
	512: {"rexec", 6},
	513: {"rlogin", 6},
	514: {"rsh", 6},
}

// Analyze returns advisories about the use of cleartext protocols.
func (CleartextProtocolDetector) Analyze(store storage.Storage, cfg config.AnalysisConfig) []Advisory {
	flows, err := store.Recent(queryWindow(cfg), 0)
	if err != nil {
		logging.Default().Error("CleartextProtocolDetector: failed to query flows: %v", err)
		return nil
	}
	if len(flows) == 0 {
		return nil
	}

	type targetKey struct {
		ServerIP   string
		ServerPort uint16
	}

	type stats struct {
		Service string
		Clients map[string]struct{}
		Bytes   uint64
		Packets uint64
	}

	servers := make(map[targetKey]*stats)

	for _, f := range flows {
		// Filter out very short flows (e.g., port scans) to reduce false positives
		if f.Packets < 3 {
			continue
		}

		var serverIP string
		var clientIP string
		var serverPort uint16

		if svc, ok := cleartextPorts[f.DstPort]; ok && f.Protocol == svc.Protocol {
			serverIP = model.SafeIPString(f.DstAddr)
			clientIP = model.SafeIPString(f.SrcAddr)
			serverPort = f.DstPort
		} else if svc, ok := cleartextPorts[f.SrcPort]; ok && f.Protocol == svc.Protocol {
			serverIP = model.SafeIPString(f.SrcAddr)
			clientIP = model.SafeIPString(f.DstAddr)
			serverPort = f.SrcPort
		} else {
			continue
		}

		tk := targetKey{ServerIP: serverIP, ServerPort: serverPort}
		s, ok := servers[tk]
		if !ok {
			s = &stats{
				Service: cleartextPorts[serverPort].Name,
				Clients: make(map[string]struct{}),
			}
			servers[tk] = s
		}
		s.Clients[clientIP] = struct{}{}
		s.Bytes += f.Bytes
		s.Packets += f.Packets
	}

	type result struct {
		tk targetKey
		s  *stats
	}
	var results []result

	for tk, s := range servers {
		results = append(results, result{tk: tk, s: s})
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].s.Bytes > results[j].s.Bytes
	})

	if len(results) > 10 {
		results = results[:10]
	}

	now := time.Now()
	advisories := make([]Advisory, 0, len(results))

	for _, r := range results {
		sev := WARNING
		if r.s.Service == "Telnet" || r.s.Service == "FTP" || r.s.Service == "rlogin" || r.s.Service == "rsh" || r.s.Service == "rexec" {
			sev = CRITICAL
		}

		advisories = append(advisories, Advisory{
			Severity:  sev,
			Timestamp: now,
			Title:     fmt.Sprintf("Cleartext Protocol (%s): %s", r.s.Service, r.tk.ServerIP),
			Description: fmt.Sprintf(
				"Insecure cleartext protocol %s (port %d) was accessed by %d unique client(s). "+
					"A total of %s (%s packets) were transferred. Credentials and data transmitted are vulnerable to interception.",
				r.s.Service, r.tk.ServerPort, len(r.s.Clients), util.FormatBytes(r.s.Bytes), util.FormatCount(r.s.Packets),
			),
			Action: fmt.Sprintf(
				"Investigate %s for insecure %s usage. Migrate to an encrypted alternative (e.g., SSH, SFTP) immediately.",
				r.tk.ServerIP, r.s.Service,
			),
		})
	}

	return advisories
}
