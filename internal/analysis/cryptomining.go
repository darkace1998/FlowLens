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

// CryptoMiningDetector analyzes flow data to identify potential cryptocurrency
// mining activity by monitoring connections to common mining pool ports.
type CryptoMiningDetector struct{}

func (CryptoMiningDetector) Name() string { return "Crypto Mining Detector" }

// commonMiningPorts maps destination ports commonly used by cryptocurrency mining pools (e.g., Stratum protocol).
var commonMiningPorts = map[uint16]string{
	3333:  "Stratum (Monero/General)",
	4444:  "Stratum (Monero/General)",
	5555:  "Stratum (Monero/General)",
	6666:  "Stratum (General)",
	7777:  "Stratum (Monero/General)",
	8888:  "Stratum (General)",
	14433: "Stratum (Monero TLS)",
	14444: "Stratum (Monero/General)",
}

const cryptoMiningMinPackets = 10

// Analyze returns advisories about potential cryptocurrency mining activity.
func (CryptoMiningDetector) Analyze(store storage.Storage, cfg config.AnalysisConfig) []Advisory {
	flows, err := store.Recent(queryWindow(cfg), 0)
	if err != nil {
		logging.Default().Error("CryptoMiningDetector: failed to query flows: %v", err)
		return nil
	}
	if len(flows) == 0 {
		return nil
	}

	type targetKey struct {
		srcIP   [16]byte
		dstIP   string
		dstPort uint16
	}

	type minerStats struct {
		packets uint64
		bytes   uint64
	}

	miners := make(map[targetKey]*minerStats)

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
		// Only consider TCP/UDP for mining protocols (mostly TCP).
		if f.Protocol != 6 && f.Protocol != 17 {
			continue
		}

		if _, ok := commonMiningPorts[f.DstPort]; !ok {
			continue
		}

		tk := targetKey{
			srcIP:   to16(f.SrcAddr),
			dstIP:   model.SafeIPString(f.DstAddr),
			dstPort: f.DstPort,
		}

		if _, ok := miners[tk]; !ok {
			miners[tk] = &minerStats{}
		}
		miners[tk].packets += f.Packets
		miners[tk].bytes += f.Bytes
	}

	type result struct {
		tk    targetKey
		stats *minerStats
	}
	var results []result

	for tk, stats := range miners {
		if stats.packets >= cryptoMiningMinPackets {
			results = append(results, result{tk: tk, stats: stats})
		}
	}

	// Sort by highest packet count first
	sort.Slice(results, func(i, j int) bool {
		return results[i].stats.packets > results[j].stats.packets
	})

	if len(results) > 10 {
		results = results[:10]
	}

	now := time.Now()
	advisories := make([]Advisory, 0, len(results))

	for _, r := range results {
		srcStr := model.SafeIPString(r.tk.srcIP[:])
		service := commonMiningPorts[r.tk.dstPort]

		sev := WARNING
		if r.stats.packets >= cryptoMiningMinPackets*10 {
			sev = CRITICAL
		}

		advisories = append(advisories, Advisory{
			Severity:  sev,
			Timestamp: now,
			Title:     fmt.Sprintf("Crypto Mining Activity: %s → %s:%d", srcStr, r.tk.dstIP, r.tk.dstPort),
			Description: fmt.Sprintf(
				"%s sent %d packets (%d bytes) to %s on port %d (%s) in the last %s. "+
					"This indicates potential cryptocurrency mining activity (e.g. Stratum protocol).",
				srcStr, r.stats.packets, r.stats.bytes, r.tk.dstIP, r.tk.dstPort, service, formatWindowShort(queryWindow(cfg)),
			),
			Action: fmt.Sprintf(
				"Investigate %s for unauthorized crypto mining malware or misconfiguration.",
				srcStr,
			),
		})
	}

	return advisories
}
