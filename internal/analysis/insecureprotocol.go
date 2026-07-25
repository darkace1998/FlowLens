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

// InsecureProtocolDetector identifies the use of cleartext protocols
// (like Telnet, FTP, POP3, IMAP) that transmit data without encryption.
type InsecureProtocolDetector struct{}

func (InsecureProtocolDetector) Name() string { return "Insecure Protocol Detector" }

// insecurePorts maps insecure destination ports to their service names.
var insecurePorts = map[uint16]string{
	20:  "FTP-Data",
	21:  "FTP",
	23:  "Telnet",
	69:  "TFTP",
	110: "POP3",
	143: "IMAP",
}

// Analyze returns advisories about the usage of insecure protocols.
func (InsecureProtocolDetector) Analyze(store storage.Storage, cfg config.AnalysisConfig) []Advisory {
	flows, err := store.Recent(queryWindow(cfg), 0)
	if err != nil {
		logging.Default().Error("InsecureProtocolDetector: failed to query flows: %v", err)
		return nil
	}
	if len(flows) == 0 {
		return nil
	}

	type usageStats struct {
		flows   uint64
		bytes   uint64
		sources map[string]struct{}
		targets map[string]struct{}
	}

	// Track usage per service
	services := make(map[string]*usageStats)

	for _, f := range flows {
		// Mostly TCP, TFTP is UDP
		if f.Protocol != 6 && f.Protocol != 17 {
			continue
		}

		service, ok := insecurePorts[f.DstPort]
		if !ok {
			continue
		}

		s, ok := services[service]
		if !ok {
			s = &usageStats{
				sources: make(map[string]struct{}),
				targets: make(map[string]struct{}),
			}
			services[service] = s
		}

		s.flows++
		s.bytes += f.Bytes
		s.sources[model.SafeIPString(f.SrcAddr)] = struct{}{}
		s.targets[model.SafeIPString(f.DstAddr)] = struct{}{}
	}

	type result struct {
		service string
		stats   *usageStats
	}

	results := make([]result, 0, len(services))
	for svc, s := range services {
		results = append(results, result{service: svc, stats: s})
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].stats.bytes > results[j].stats.bytes
	})

	now := time.Now()
	advisories := make([]Advisory, 0, len(results))

	for _, r := range results {
		sev := WARNING

		advisories = append(advisories, Advisory{
			Severity:  sev,
			Timestamp: now,
			Title:     fmt.Sprintf("Insecure Protocol Usage: %s", r.service),
			Description: fmt.Sprintf(
				"Detected %d flows (%d bytes) of %s traffic involving %d unique sources and %d unique destinations. "+
					"%s transmits data in cleartext, exposing credentials and sensitive information.",
				r.stats.flows, r.stats.bytes, r.service, len(r.stats.sources), len(r.stats.targets), r.service,
			),
			Action: fmt.Sprintf("Review %s usage and migrate to secure alternatives (e.g., SSH, SFTP, IMAPS, POP3S).", r.service),
		})
	}

	return advisories
}
