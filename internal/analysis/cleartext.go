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

// CleartextProtocolDetector analyzes flow data to identify the usage of insecure,
// unencrypted cleartext protocols such as Telnet, FTP, POP3, IMAP, and HTTP.
type CleartextProtocolDetector struct{}

func (CleartextProtocolDetector) Name() string { return "Cleartext Protocol Detector" }

var cleartextPorts = map[uint16]string{
	20:  "FTP-DATA",
	21:  "FTP",
	23:  "Telnet",
	80:  "HTTP",
	110: "POP3",
	143: "IMAP",
}

// Analyze returns advisories about cleartext protocol usage.
func (CleartextProtocolDetector) Analyze(store storage.Storage, cfg config.AnalysisConfig) []Advisory {
	flows, err := store.Recent(queryWindow(cfg), 0)
	if err != nil {
		logging.Default().Error("CleartextProtocolDetector: failed to query flows: %v", err)
		return nil
	}
	if len(flows) == 0 {
		return nil
	}

	type connectionKey struct {
		srcIP   [16]byte
		dstIP   string
		dstPort uint16
	}

	type stats struct {
		bytes   uint64
		packets uint64
	}

	connections := make(map[connectionKey]*stats)

	to16 := func(ip []byte) [16]byte {
		var k [16]byte
		if len(ip) == 16 {
			copy(k[:], ip)
		} else if len(ip) == 4 {
			k[10] = 0xff
			k[11] = 0xff
			copy(k[12:], ip)
		}
		return k
	}

	for _, f := range flows {
		// Only consider TCP
		if f.Protocol != 6 {
			continue
		}

		if _, ok := cleartextPorts[f.DstPort]; !ok {
			continue
		}

		key := connectionKey{
			srcIP:   to16(f.SrcAddr),
			dstIP:   model.SafeIPString(f.DstAddr),
			dstPort: f.DstPort,
		}

		s, ok := connections[key]
		if !ok {
			s = &stats{}
			connections[key] = s
		}
		s.bytes += f.Bytes
		s.packets += f.Packets
	}

	type result struct {
		key connectionKey
		s   *stats
	}
	var results []result

	for key, s := range connections {
		results = append(results, result{key: key, s: s})
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].s.bytes > results[j].s.bytes
	})

	if len(results) > 10 {
		results = results[:10]
	}

	now := time.Now()
	advisories := make([]Advisory, 0, len(results))

	for _, r := range results {
		srcStr := model.SafeIPString(r.key.srcIP[:])
		service := cleartextPorts[r.key.dstPort]

		advisories = append(advisories, Advisory{
			Severity:  WARNING,
			Timestamp: now,
			Title:     fmt.Sprintf("Cleartext Protocol Detected: %s → %s (%s)", srcStr, r.key.dstIP, service),
			Description: fmt.Sprintf(
				"%s sent %d packets (%d bytes) to %s on port %d (%s). "+
					"This is an insecure, unencrypted protocol that may expose sensitive information.",
				srcStr, r.s.packets, r.s.bytes, r.key.dstIP, r.key.dstPort, service,
			),
			Action: fmt.Sprintf(
				"Investigate why %s is communicating over %s to %s. Consider migrating to encrypted alternatives (e.g., SSH, HTTPS, SFTP, IMAPS, POP3S).",
				srcStr, service, r.key.dstIP,
			),
		})
	}

	return advisories
}
