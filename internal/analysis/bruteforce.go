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

// BruteForceDetector analyzes flow data to identify potential brute-force
// login attempts based on a single source IP making many distinct connections
// (different source ports) to a target destination IP on common login ports.
type BruteForceDetector struct{}

func (BruteForceDetector) Name() string { return "Brute Force Detector" }

// commonLoginPorts maps destination ports commonly targeted for brute-force attacks.
var commonLoginPorts = map[uint16]string{
	21:   "FTP",
	22:   "SSH",
	23:   "Telnet",
	1433: "MSSQL",
	3306: "MySQL",
	3389: "RDP",
	5432: "PostgreSQL",
	5900: "VNC",
}

const bruteForceMinAttempts = 100

// Analyze returns advisories about potential brute-force attacks.
func (BruteForceDetector) Analyze(store storage.Storage, cfg config.AnalysisConfig) []Advisory {
	flows, err := store.Recent(queryWindow(cfg), 0)
	if err != nil {
		logging.Default().Error("BruteForceDetector: failed to query flows: %v", err)
		return nil
	}
	if len(flows) == 0 {
		return nil
	}

	// We want to detect a single source IP targeting a single destination IP + port.
	type targetKey struct {
		srcIP   [16]byte
		dstIP   string
		dstPort uint16
	}

	// Track the unique source ports to count connection attempts.
	attempts := make(map[targetKey]map[uint16]struct{})

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
		// Only consider TCP flows for login brute-force attempts.
		if f.Protocol != 6 {
			continue
		}

		// Only check common login ports.
		if _, ok := commonLoginPorts[f.DstPort]; !ok {
			continue
		}

		tk := targetKey{
			srcIP:   to16(f.SrcAddr),
			dstIP:   model.SafeIPString(f.DstAddr),
			dstPort: f.DstPort,
		}

		if _, ok := attempts[tk]; !ok {
			attempts[tk] = make(map[uint16]struct{})
		}
		attempts[tk][f.SrcPort] = struct{}{}
	}

	type result struct {
		tk           targetKey
		attemptCount int
	}
	var results []result

	for tk, ports := range attempts {
		count := len(ports)
		if count >= bruteForceMinAttempts {
			results = append(results, result{tk: tk, attemptCount: count})
		}
	}

	// Sort by highest number of attempts first
	sort.Slice(results, func(i, j int) bool {
		return results[i].attemptCount > results[j].attemptCount
	})

	if len(results) > 10 {
		results = results[:10]
	}

	now := time.Now()
	advisories := make([]Advisory, 0, len(results))

	for _, r := range results {
		srcStr := model.SafeIPString(r.tk.srcIP[:])
		service := commonLoginPorts[r.tk.dstPort]

		sev := WARNING
		if r.attemptCount >= bruteForceMinAttempts*5 {
			sev = CRITICAL
		}

		advisories = append(advisories, Advisory{
			Severity:  sev,
			Timestamp: now,
			Title:     fmt.Sprintf("Brute Force Attack: %s → %s (%s)", srcStr, r.tk.dstIP, service),
			Description: fmt.Sprintf(
				"%s made %d distinct connection attempts to %s on port %d (%s) in the last %s. "+
					"This indicates a potential brute-force login attack.",
				srcStr, r.attemptCount, r.tk.dstIP, r.tk.dstPort, service, formatWindowShort(queryWindow(cfg)),
			),
			Action: fmt.Sprintf(
				"Investigate %s for unauthorized access attempts. Consider blocking the source IP or employing rate limiting/fail2ban.",
				srcStr,
			),
		})
	}

	return advisories
}
