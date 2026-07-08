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

// LateralMovementDetector analyzes flow data to identify potential lateral
// movement within a network by identifying a single source IP that connects
// to many distinct destination IPs on common administrative/lateral movement ports.
type LateralMovementDetector struct{}

func (LateralMovementDetector) Name() string { return "Lateral Movement Detector" }

// lateralMovementPorts maps destination ports commonly used for lateral movement to their services.
var lateralMovementPorts = map[uint16]string{
	135:  "RPC",
	139:  "NetBIOS",
	445:  "SMB",
	3389: "RDP",
	5985: "WinRM",
	5986: "WinRM",
}

const lateralMovementMinTargets = 20

// Analyze returns advisories about potential lateral movement.
func (LateralMovementDetector) Analyze(store storage.Storage, cfg config.AnalysisConfig) []Advisory {
	flows, err := store.Recent(queryWindow(cfg), 0)
	if err != nil {
		logging.Default().Error("LateralMovementDetector: failed to query flows: %v", err)
		return nil
	}
	if len(flows) == 0 {
		return nil
	}

	// Track distinct targets per source IP on common lateral movement ports.
	type sourceKey struct {
		srcIP [16]byte
	}

	type targetStats struct {
		targets map[string]struct{}
		ports   map[uint16]struct{}
	}

	scanners := make(map[sourceKey]*targetStats)

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
		// Only consider TCP flows for these specific services.
		if f.Protocol != 6 {
			continue
		}

		if _, ok := lateralMovementPorts[f.DstPort]; !ok {
			continue
		}

		key := sourceKey{srcIP: to16(f.SrcAddr)}
		s, ok := scanners[key]
		if !ok {
			s = &targetStats{
				targets: make(map[string]struct{}),
				ports:   make(map[uint16]struct{}),
			}
			scanners[key] = s
		}
		s.targets[model.SafeIPString(f.DstAddr)] = struct{}{}
		s.ports[f.DstPort] = struct{}{}
	}

	type result struct {
		key         sourceKey
		targetCount int
		portsHit    []uint16
	}
	var results []result

	for key, s := range scanners {
		if len(s.targets) >= lateralMovementMinTargets {
			var ports []uint16
			for p := range s.ports {
				ports = append(ports, p)
			}
			sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
			results = append(results, result{
				key:         key,
				targetCount: len(s.targets),
				portsHit:    ports,
			})
		}
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].targetCount > results[j].targetCount
	})

	if len(results) > 10 {
		results = results[:10]
	}

	now := time.Now()
	advisories := make([]Advisory, 0, len(results))
	windowStr := formatWindowShort(queryWindow(cfg))

	for _, r := range results {
		srcStr := model.SafeIPString(r.key.srcIP[:])
		sev := WARNING
		if r.targetCount >= lateralMovementMinTargets*3 {
			sev = CRITICAL
		}

		portsDesc := ""
		for i, p := range r.portsHit {
			if i > 0 {
				portsDesc += ", "
			}
			portsDesc += fmt.Sprintf("%d (%s)", p, lateralMovementPorts[p])
		}

		advisories = append(advisories, Advisory{
			Severity:  sev,
			Timestamp: now,
			Title:     fmt.Sprintf("Lateral Movement Detected: %s", srcStr),
			Description: fmt.Sprintf(
				"%s connected to %d distinct hosts on administrative/lateral movement ports (%s) in the last %s. "+
					"This is a strong indicator of lateral movement, reconnaissance, or worm propagation.",
				srcStr, r.targetCount, portsDesc, windowStr,
			),
			Action: fmt.Sprintf(
				"Investigate %s for unauthorized network scanning, compromised credentials, or malware behavior. Isolate the host if unauthorized.",
				srcStr,
			),
		})
	}

	return advisories
}
