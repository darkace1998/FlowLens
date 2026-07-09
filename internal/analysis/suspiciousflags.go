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

// SuspiciousFlagsDetector identifies network scanning activity that relies
// on abnormal TCP flag combinations such as SYN-FIN, SYN-RST, NULL,
// or XMAS scans.
type SuspiciousFlagsDetector struct{}

func (SuspiciousFlagsDetector) Name() string { return "Suspicious TCP Flags Detector" }

// Analyze returns advisories about potential stealth scans using invalid TCP flags.
func (SuspiciousFlagsDetector) Analyze(store storage.Storage, cfg config.AnalysisConfig) []Advisory {
	flows, err := store.Recent(queryWindow(cfg), 0)
	if err != nil {
		logging.Default().Error("SuspiciousFlagsDetector: failed to query flows: %v", err)
		return nil
	}
	if len(flows) == 0 {
		return nil
	}

	type scanType string
	const (
		synFin   scanType = "SYN-FIN"
		synRst   scanType = "SYN-RST"
		xmas     scanType = "XMAS"
		fin      scanType = "FIN"
		nullScan scanType = "NULL"
	)

	type scanKey struct {
		srcIP [16]byte
		sType scanType
	}

	type scanStats struct {
		targets map[string]struct{}
		packets uint64
	}

	scans := make(map[scanKey]*scanStats)

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
		if f.Protocol != 6 {
			continue
		}

		flags := f.TCPFlags
		var st scanType

		if flags == 0 {
			// To reduce false positives from exporters that don't send flags,
			// we only consider it a NULL scan probe if it's a single packet flow.
			if f.Packets == 1 {
				st = nullScan
			} else {
				continue
			}
		} else {
			synfin := flags&0x03 == 0x03
			synrst := flags&0x06 == 0x06
			xmasFlag := flags&0x39 == 0x29 // FIN, PSH, URG, without ACK
			finonly := flags&0x13 == 0x01  // FIN without SYN and ACK

			if synfin {
				st = synFin
			} else if synrst {
				st = synRst
			} else if xmasFlag {
				st = xmas
			} else if finonly {
				st = fin
			} else {
				continue
			}
		}

		key := scanKey{srcIP: to16(f.SrcAddr), sType: st}
		s, ok := scans[key]
		if !ok {
			s = &scanStats{targets: make(map[string]struct{})}
			scans[key] = s
		}
		s.targets[model.SafeIPString(f.DstAddr)] = struct{}{}
		s.packets += f.Packets
	}

	type result struct {
		srcIP   string
		sType   scanType
		targets int
		packets uint64
	}
	var results []result

	for key, s := range scans {
		if len(s.targets) == 0 {
			continue
		}

		results = append(results, result{
			srcIP:   model.SafeIPString(key.srcIP[:]),
			sType:   key.sType,
			targets: len(s.targets),
			packets: s.packets,
		})
	}

	sort.Slice(results, func(i, j int) bool {
		if results[i].targets == results[j].targets {
			return results[i].packets > results[j].packets
		}
		return results[i].targets > results[j].targets
	})

	if len(results) > 10 {
		results = results[:10]
	}

	now := time.Now()
	advisories := make([]Advisory, 0, len(results))

	for _, r := range results {
		sev := WARNING
		if r.targets > 50 {
			sev = CRITICAL
		}

		advisories = append(advisories, Advisory{
			Severity:  sev,
			Timestamp: now,
			Title:     fmt.Sprintf("Suspicious TCP Flags (%s): %s", r.sType, r.srcIP),
			Description: fmt.Sprintf(
				"%s sent %d packets with suspicious %s TCP flags to %d unique targets. "+
					"This is a strong indicator of stealth port scanning or OS fingerprinting.",
				r.srcIP, r.packets, r.sType, r.targets,
			),
			Action: fmt.Sprintf(
				"Investigate %s for reconnaissance activity (e.g., Nmap stealth scans). Consider blocking the IP.",
				r.srcIP,
			),
		})
	}

	return advisories
}
