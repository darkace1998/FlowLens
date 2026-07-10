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

// CryptominingDetector analyzes flow data to identify potential cryptomining
// activity by identifying hosts that connect to common mining pool ports.
type CryptominingDetector struct{}

func (CryptominingDetector) Name() string { return "Cryptomining Detector" }

// miningPorts maps destination ports commonly used by cryptomining pools.
var miningPorts = map[uint16]struct{}{
	3333:  {},
	4444:  {},
	5555:  {},
	7777:  {},
	8333:  {}, // Bitcoin mainnet
	14433: {},
	14444: {},
}

// Analyze returns advisories about potential cryptomining activity.
func (CryptominingDetector) Analyze(store storage.Storage, cfg config.AnalysisConfig) []Advisory {
	flows, err := store.Recent(queryWindow(cfg), 0)
	if err != nil {
		logging.Default().Error("CryptominingDetector: failed to query flows: %v", err)
		return nil
	}
	if len(flows) == 0 {
		return nil
	}

	type hostStats struct {
		targets map[string]struct{}
		ports   map[uint16]struct{}
		bytes   uint64
		packets uint64
	}

	miners := make(map[string]*hostStats)

	for _, f := range flows {
		if f.Protocol != 6 && f.Protocol != 17 {
			continue // mostly TCP, sometimes UDP
		}

		if _, ok := miningPorts[f.DstPort]; !ok {
			continue
		}

		srcIP := model.SafeIPString(f.SrcAddr)
		dstIP := model.SafeIPString(f.DstAddr)

		s, ok := miners[srcIP]
		if !ok {
			s = &hostStats{
				targets: make(map[string]struct{}),
				ports:   make(map[uint16]struct{}),
			}
			miners[srcIP] = s
		}
		s.targets[dstIP] = struct{}{}
		s.ports[f.DstPort] = struct{}{}
		s.bytes += f.Bytes
		s.packets += f.Packets
	}

	if len(miners) == 0 {
		return nil
	}

	type result struct {
		srcIP string
		stats *hostStats
	}
	results := make([]result, 0, len(miners))

	for srcIP, s := range miners {
		results = append(results, result{srcIP: srcIP, stats: s})
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].stats.bytes > results[j].stats.bytes
	})

	if len(results) > 10 {
		results = results[:10]
	}

	now := time.Now()
	advisories := make([]Advisory, 0, len(results))
	windowStr := formatWindowShort(queryWindow(cfg))

	for _, r := range results {
		sev := WARNING
		if r.stats.bytes > 500000 || len(r.stats.targets) > 3 {
			sev = CRITICAL
		}

		var portsDesc []uint16
		for p := range r.stats.ports {
			portsDesc = append(portsDesc, p)
		}
		sort.Slice(portsDesc, func(i, j int) bool { return portsDesc[i] < portsDesc[j] })

		portsStr := ""
		for i, p := range portsDesc {
			if i > 0 {
				portsStr += ", "
			}
			portsStr += fmt.Sprintf("%d", p)
		}

		advisories = append(advisories, Advisory{
			Severity:  sev,
			Timestamp: now,
			Title:     fmt.Sprintf("Cryptomining Activity Detected: %s", r.srcIP),
			Description: fmt.Sprintf(
				"%s connected to %d distinct hosts on common cryptomining ports (%s) in the last %s. "+
					"This is a strong indicator of unauthorized cryptomining (e.g., Stratum protocol) or malware infection.",
				r.srcIP, len(r.stats.targets), portsStr, windowStr,
			),
			Action: fmt.Sprintf(
				"Investigate %s for unauthorized mining software or malware compromise. Isolate the host and block outbound connections to mining pools.",
				r.srcIP,
			),
		})
	}

	return advisories
}
