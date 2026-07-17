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

// InsecureProtocolDetector identifies usage of well-known unencrypted protocols
// (like FTP, Telnet, HTTP, POP3, IMAP) to encourage migration to secure alternatives.
type InsecureProtocolDetector struct{}

func (InsecureProtocolDetector) Name() string { return "Insecure Protocol Detector" }

// insecurePorts maps insecure destination ports to their service names and secure alternatives.
var insecurePorts = map[uint16]struct {
	name        string
	alternative string
}{
	21:  {"FTP", "SFTP or FTPS"},
	23:  {"Telnet", "SSH"},
	80:  {"HTTP", "HTTPS"},
	110: {"POP3", "POP3S"},
	143: {"IMAP", "IMAPS"},
}

// insecureProtocolMinPackets prevents flagging single-packet scans as active service usage.
const insecureProtocolMinPackets = 10

// Analyze returns advisories about the usage of unencrypted protocols.
func (InsecureProtocolDetector) Analyze(store storage.Storage, cfg config.AnalysisConfig) []Advisory {
	flows, err := store.Recent(queryWindow(cfg), 0)
	if err != nil {
		logging.Default().Error("InsecureProtocolDetector: failed to query flows: %v", err)
		return nil
	}
	if len(flows) == 0 {
		return nil
	}

	type targetKey struct {
		ip   string
		port uint16
	}

	type stats struct {
		bytes   uint64
		packets uint64
		clients map[string]struct{}
	}

	targets := make(map[targetKey]*stats)

	for _, f := range flows {
		// Only consider TCP for these specific insecure protocols.
		if f.Protocol != 6 {
			continue
		}

		// Assume the server is the one using the well-known port.
		// Check both src and dst, standardizing on the server IP.
		var tKey targetKey
		var clientIP string

		if _, ok := insecurePorts[f.DstPort]; ok {
			tKey = targetKey{ip: model.SafeIPString(f.DstAddr), port: f.DstPort}
			clientIP = model.SafeIPString(f.SrcAddr)
		} else if _, ok := insecurePorts[f.SrcPort]; ok {
			tKey = targetKey{ip: model.SafeIPString(f.SrcAddr), port: f.SrcPort}
			clientIP = model.SafeIPString(f.DstAddr)
		} else {
			continue
		}

		s, ok := targets[tKey]
		if !ok {
			s = &stats{clients: make(map[string]struct{})}
			targets[tKey] = s
		}
		s.bytes += f.Bytes
		s.packets += f.Packets
		s.clients[clientIP] = struct{}{}
	}

	type result struct {
		tKey  targetKey
		stats *stats
	}
	results := make([]result, 0, len(targets))

	for tKey, s := range targets {
		if s.packets >= insecureProtocolMinPackets {
			results = append(results, result{tKey: tKey, stats: s})
		}
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
		portInfo := insecurePorts[r.tKey.port]

		desc := fmt.Sprintf(
			"%s was observed serving %s traffic (port %d) to %d unique clients "+
				"(%s bytes, %d packets). %s is unencrypted and transmits data in plaintext.",
			r.tKey.ip, portInfo.name, r.tKey.port, len(r.stats.clients),
			util.FormatBytes(r.stats.bytes), r.stats.packets, portInfo.name,
		)

		advisories = append(advisories, Advisory{
			Severity:    WARNING,
			Timestamp:   now,
			Title:       fmt.Sprintf("Insecure Protocol Usage: %s (%s)", r.tKey.ip, portInfo.name),
			Description: desc,
			Action:      fmt.Sprintf("Migrate %s service on %s to a secure alternative such as %s.", portInfo.name, r.tKey.ip, portInfo.alternative),
		})
	}

	return advisories
}
