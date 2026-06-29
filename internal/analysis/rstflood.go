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

// RSTFloodDetector identifies targets receiving an abnormally high number of TCP RST packets,
// which could indicate a TCP RST flood DDoS attack or aggressive backscatter from spoofed scans.
type RSTFloodDetector struct{}

func (RSTFloodDetector) Name() string { return "TCP RST Flood Detector" }

// rstFloodMinPackets is the minimum number of RST packets a target must
// receive within the query window to trigger an advisory.
const rstFloodMinPackets = 10000

// Analyze returns advisories about potential TCP RST floods.
func (RSTFloodDetector) Analyze(store storage.Storage, cfg config.AnalysisConfig) []Advisory {
	flows, err := store.Recent(queryWindow(cfg), 0)
	if err != nil {
		logging.Default().Error("RSTFloodDetector: failed to query flows: %v", err)
		return nil
	}
	if len(flows) == 0 {
		return nil
	}

	type targetStats struct {
		packets uint64
		bytes   uint64
		sources map[string]struct{}
	}
	targets := make(map[string]*targetStats)

	for _, f := range flows {
		if f.Protocol != 6 {
			continue
		}

		// TCP RST flag is 0x04.
		if f.TCPFlags&0x04 != 0 {
			dst := model.SafeIPString(f.DstAddr)
			s, ok := targets[dst]
			if !ok {
				s = &targetStats{sources: make(map[string]struct{})}
				targets[dst] = s
			}
			s.packets += f.Packets
			s.bytes += f.Bytes
			s.sources[model.SafeIPString(f.SrcAddr)] = struct{}{}
		}
	}

	type result struct {
		ip      string
		packets uint64
		bytes   uint64
		sources int
	}
	var results []result

	for ip, s := range targets {
		if s.packets >= rstFloodMinPackets {
			results = append(results, result{
				ip:      ip,
				packets: s.packets,
				bytes:   s.bytes,
				sources: len(s.sources),
			})
		}
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].packets > results[j].packets
	})

	if len(results) > 10 {
		results = results[:10]
	}

	now := time.Now()
	advisories := make([]Advisory, 0, len(results))

	for _, r := range results {
		sev := WARNING
		if r.packets >= rstFloodMinPackets*5 {
			sev = CRITICAL
		}

		advisories = append(advisories, Advisory{
			Severity:  sev,
			Timestamp: now,
			Title:     fmt.Sprintf("TCP RST Flood: %s", r.ip),
			Description: fmt.Sprintf(
				"%s received %s TCP RST packets (%s) from %d unique sources in the last %s. "+
					"This may indicate a RST flood DDoS attack, or aggressive backscatter from spoofed scans.",
				r.ip, util.FormatCount(r.packets), util.FormatBytes(r.bytes),
				r.sources, formatWindowShort(queryWindow(cfg)),
			),
			Action: fmt.Sprintf(
				"Investigate traffic to %s. If malicious, implement rate limiting or block anomalous sources.",
				r.ip,
			),
		})
	}

	return advisories
}
