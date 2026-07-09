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

// MassEmailDetector analyzes flow data to identify potential mass email sending
// (spam) by identifying a single source IP that connects to many distinct
// destination IPs on SMTP ports.
type MassEmailDetector struct{}

func (MassEmailDetector) Name() string { return "Mass Email Detector" }

// smtpPorts maps destination ports commonly used for email to their services.
var smtpPorts = map[uint16]string{
	25:  "SMTP",
	465: "SMTPS",
	587: "Submission",
}

const massEmailMinTargets = 20

// Analyze returns advisories about potential mass email sending.
func (MassEmailDetector) Analyze(store storage.Storage, cfg config.AnalysisConfig) []Advisory {
	flows, err := store.Recent(queryWindow(cfg), 0)
	if err != nil {
		logging.Default().Error("MassEmailDetector: failed to query flows: %v", err)
		return nil
	}
	if len(flows) == 0 {
		return nil
	}

	// Track distinct targets per source IP on common SMTP ports.
	type sourceKey struct {
		srcIP [16]byte
	}

	type targetStats struct {
		targets map[string]struct{}
		ports   map[uint16]struct{}
	}

	senders := make(map[sourceKey]*targetStats)

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
		// Only consider TCP flows for SMTP.
		if f.Protocol != 6 {
			continue
		}

		if _, ok := smtpPorts[f.DstPort]; !ok {
			continue
		}

		key := sourceKey{srcIP: to16(f.SrcAddr)}
		s, ok := senders[key]
		if !ok {
			s = &targetStats{
				targets: make(map[string]struct{}),
				ports:   make(map[uint16]struct{}),
			}
			senders[key] = s
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

	for key, s := range senders {
		if len(s.targets) >= massEmailMinTargets {
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
		if r.targetCount >= massEmailMinTargets*3 {
			sev = CRITICAL
		}

		portsDesc := ""
		for i, p := range r.portsHit {
			if i > 0 {
				portsDesc += ", "
			}
			portsDesc += fmt.Sprintf("%d (%s)", p, smtpPorts[p])
		}

		advisories = append(advisories, Advisory{
			Severity:  sev,
			Timestamp: now,
			Title:     fmt.Sprintf("Mass Email Sending Detected: %s", srcStr),
			Description: fmt.Sprintf(
				"%s connected to %d distinct hosts on SMTP ports (%s) in the last %s. "+
					"This is a strong indicator of spam botnet activity or mass email sending.",
				srcStr, r.targetCount, portsDesc, windowStr,
			),
			Action: fmt.Sprintf(
				"Investigate %s for unauthorized email sending or spam botnet infections. Consider blocking outbound SMTP if unauthorized.",
				srcStr,
			),
		})
	}

	return advisories
}
